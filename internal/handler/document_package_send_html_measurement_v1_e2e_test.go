//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

func packageReviseHTML232(t *testing.T, q *ownedPublicReadFixtureV1, d *generated.Document, scope string) *generated.Document {
	t.Helper()
	origin := bytes.Clone(d.HtmlSourceJson)
	commitment, err := htmlsource.Commitment(d)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(htmlDocumentRevisionInput{ExpectedUpdatedAt: d.UpdatedAt.Time.Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"scope": scope}, Summary: "Actual root-package measurement revision"})
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+d.ID.String()+"/html/revisions", string(raw), q.cookie)
	if w.Code != http.StatusCreated {
		t.Fatalf("genuine HTML revision=%d %s", w.Code, w.Body.String())
	}
	fresh := ownedDetailsDocumentV1(t, q, d)
	if fresh.HtmlCurrentMaterializationSequence.Int32 != d.HtmlCurrentMaterializationSequence.Int32+1 || fresh.HtmlCurrentMaterializationSequence.Int32 < 2 || fresh.HtmlCurrentMaterializationID == d.HtmlCurrentMaterializationID || !bytes.Equal(fresh.HtmlSourceJson, origin) {
		t.Fatal("genuine normalized current/original source identity absent")
	}
	return reviewPackageHTML221(t, q, fresh)
}

// Real HTML creation/review/revision and attachment routes, original auth and
// native PG/isolated parser; synthetic HTML renderer and versioned S3 peers.
func TestDocumentPackageSendHTMLMeasurementV1E2E(t *testing.T) {
	q := newOwnedDocumentPackageMeasurementFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	main := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	annex := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	var reply map[string]any
	arguments := packageAPIArguments225(t, [2]*generated.Document{main, annex}, "REST")
	selectionBefore := packageMeasurementState232(t, q)
	selectionResponse := packageAPISubmit225(q, "REST", "add_document_attachment", main.ID, "", arguments)
	if selectionResponse.Code != http.StatusCreated {
		if selectionResponse.Code != http.StatusConflict || packageMeasurementState232(t, q) != selectionBefore {
			t.Fatal("selection failed without a proven unchanged409", selectionResponse.Code)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
		ctx, cancel := context.WithTimeout(q.f.ctx, 15*time.Second)
		defer cancel()
		input, e := q.runtime.SessionsV1().NewDocumentPackageHTTPInputV1(ctx, q.f.org)
		if e != nil {
			t.Fatal(e)
		}
		defer input.CloseConsumerV1()
		if e = input.ReadHTTPV1(ctx, main.ID, io.NopCloser(strings.NewReader(arguments))); e != nil {
			t.Fatal(e)
		}
		out, e := packageauthoring.SelectV1(ctx, packageauthoring.DependenciesV1{Sessions: q.runtime.SessionsV1(), Storage: q.f.s.Storage, Audit: q.f.s.Audit}, packageActor220(t, q), input, "", "bounded synthetic selection diagnostic")
		var parentDetail *pdfadmission.HTMLRevisionSourceParentErrorV1
		if errors.As(e, &parentDetail) {
			t.Logf("exact source-parent refusal: %+v", parentDetail.DetailsV1())
		}
		t.Fatalf("original API selection=%d; diagnostic state=%s error=%v cause=%v", selectionResponse.Code, out.State, e, out.Cause)
	}
	packageAPIReply225(t, selectionResponse, "REST", http.StatusCreated, &reply)
	view := packageLayoutView226(t, q, main.ID)
	id, err := uuid.Parse(view.PackageID)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := strconv.ParseInt(view.Generation, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	expected := pdfadmission.DocumentPackageDraftExpectedV1{PackageID: id, Generation: generation}
	check := func(t *testing.T) {
		t.Helper()
		before := packageMeasurementState232(t, q)
		requests := q.storagePeer.requests.Load()
		var mu sync.Mutex
		var trace []string
		var invalid atomic.Bool
		var bucketProbes atomic.Int32
		pins := map[string]string{main.PdfStorageKey.String: main.PdfStorageVersionID.String, annex.PdfStorageKey.String: annex.PdfStorageVersionID.String}
		client := packageMeasurementClient232(t, q, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") {
				key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
				if version, ok := pins[key]; !ok || r.URL.Query().Get("versionId") != version || (r.Method != http.MethodHead && r.Method != http.MethodGet) {
					invalid.Store(true)
					http.Error(w, "unexpected selected HTML version", http.StatusForbidden)
					return
				}
				mu.Lock()
				trace = append(trace, r.Method+" "+key)
				mu.Unlock()
			}
			if !strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") {
				bucketProbes.Add(1)
				if r.Method != http.MethodHead || r.URL.Path != "/hash-import-fixture/" || r.URL.RawQuery != "" {
					invalid.Store(true)
					http.Error(w, "unexpected storage client probe", http.StatusForbidden)
					return
				}
			}
			q.storagePeer.ServeHTTP(w, r)
		}))
		// storage.New performs a separate BucketExists HEAD. Prove that exact
		// constructor work, then require exactly four measured-object requests.
		mu.Lock()
		constructorObjectRequests := len(trace)
		mu.Unlock()
		if invalid.Load() || bucketProbes.Load() != 1 || constructorObjectRequests != 0 || q.storagePeer.requests.Load() != requests+1 {
			t.Fatal("storage client initialization differed from its exact bucket HEAD")
		}
		requests = q.storagePeer.requests.Load()
		err := withPackageSendDraft231(t, q, main.ID, expected, true, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if err := draft.MeasurePDFsV1(client); err != nil {
				return err
			}
			got, count, err := draft.MeasurementsV1()
			if err != nil || count != 2 || got[0].DocumentID != main.ID || got[1].DocumentID != annex.ID || got[0].Pages != 2 || got[1].Pages != 2 {
				t.Fatal("HTML main/frozen annex measurement differs", got, count, err)
			}
			return nil
		})
		mu.Lock()
		gotTrace := strings.Join(trace, "\n")
		mu.Unlock()
		wantTrace := strings.Join([]string{"HEAD " + main.PdfStorageKey.String, "HEAD " + annex.PdfStorageKey.String, "GET " + main.PdfStorageKey.String, "GET " + annex.PdfStorageKey.String}, "\n")
		if err != nil || invalid.Load() || gotTrace != wantTrace || q.storagePeer.requests.Load() != requests+4 || packageMeasurementState232(t, q) != before {
			t.Fatalf("HTML package measure postconditions: err=%v invalid=%t trace=%q want=%q requestsBefore=%d requestsAfter=%d stateEqual=%t", err, invalid.Load(), gotTrace, wantTrace, requests, q.storagePeer.requests.Load(), packageMeasurementState232(t, q) == before)
		}
	}
	t.Run("reviewed original HTML main and selected HTML attachment", func(t *testing.T) { check(t) })
	main = packageReviseHTML232(t, q, packageLatest223(t, q, main.ID), "Revised main agreement")
	laterAnnex := packageReviseHTML232(t, q, packageLatest223(t, q, annex.ID), "Later unselected source revision")
	if laterAnnex.HtmlCurrentMaterializationID == annex.HtmlCurrentMaterializationID || (laterAnnex.PdfStorageKey == annex.PdfStorageKey && laterAnnex.PdfStorageVersionID == annex.PdfStorageVersionID && bytes.Equal(laterAnnex.PdfSha256, annex.PdfSha256)) {
		t.Fatal("live annex did not actually move away from selected materialization")
	}
	t.Run("reviewed normalized main keeps selected older HTML attachment", func(t *testing.T) { check(t) })
	t.Run("unreviewed HTML root refuses before measurement provider", func(t *testing.T) {
		unreviewed := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
		before := packageMeasurementState232(t, q)
		requests := q.storagePeer.requests.Load()
		err := withPackageSendDraft231(t, q, unreviewed.ID, pdfadmission.DocumentPackageDraftExpectedV1{}, false, func(*pdfadmission.ApplicationHTMLSendPackageDraftV1, *pdfadmission.ApplicationHTMLSendWorkV1) error {
			t.Fatal("unreviewed source reached measurement")
			return nil
		})
		if !errors.Is(err, htmlsource.ErrReviewRequired) || q.storagePeer.requests.Load() != requests || packageMeasurementState232(t, q) != before {
			t.Fatal("unreviewed HTML root accepted or changed state", err)
		}
	})
}
