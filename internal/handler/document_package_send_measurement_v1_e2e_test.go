//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Extend the original state oracle so accidental capture/intent creation also
// fails this read/measurement qualification. Actual PG; no synthetic receipts.
func packageMeasurementState232(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	base := packageFullState223(t, q)
	var extra string
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT jsonb_build_object('attempts',(SELECT jsonb_agg(to_jsonb(a) ORDER BY attempt_id) FROM document_package_send_attempts_v1 a WHERE org_id=$1),'captures',(SELECT jsonb_agg(to_jsonb(c) ORDER BY package_id,revision) FROM document_package_captures_v1 c WHERE org_id=$1),'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY package_id,revision,member_position) FROM document_package_capture_members_v1 m WHERE org_id=$1),'intents',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM send_sealing_intents i WHERE org_id=$1))::text", q.f.org).Scan(&extra); err != nil {
		t.Fatal(err)
	}
	return base + extra
}

func packageMeasurementClient232(t *testing.T, q *ownedPublicReadFixtureV1, handler http.Handler) *storage.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package-measurement", SecretKey: "synthetic-package-measurement-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func packageMeasurementUnavailable232(t *testing.T, draft *pdfadmission.ApplicationHTMLSendPackageDraftV1) {
	t.Helper()
	if _, _, err := draft.MeasurementsV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
		t.Fatal("incomplete measurement exposed results", err)
	}
}

// Actual original-root native Work/PG/auth, exact provider protocol and isolated
// page worker; synthetic S3/renderer peers. No package capture/Send activation.
func TestDocumentPackageSendPDFMeasurementV1E2E(t *testing.T) {
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
	root := packageImported220(t, q, "Measured main agreement")
	a := packageImported220(t, q, "Frozen DPA")
	b := packageImported220(t, q, "Frozen specifications")
	p := packageCreate223(t, q, root, a, b)
	expected := pdfadmission.DocumentPackageDraftExpectedV1{PackageID: p.ID, Generation: p.DraftGeneration}
	t.Run("original root and sparse frozen annexes measured exactly", func(t *testing.T) {
		if _, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name='Later source',metadata_redaction_report='{\"later\":true}',deleted_at=clock_timestamp() WHERE id=$1 AND org_id=$2", a.ID, q.f.org); err != nil {
			t.Fatal(err)
		}
		tx := beginHTMLQueryFixtureV1(t, q.f.ctx, q.f)
		defer rollbackHTMLQueryFixtureV1(t, tx)
		if _, err := tx.Exec(q.f.ctx, "SELECT id FROM documents WHERE id=ANY($1::uuid[]) FOR UPDATE", []uuid.UUID{a.ID, b.ID}); err != nil {
			t.Fatal(err)
		}
		pins := map[string]string{root.PdfStorageKey.String: root.PdfStorageVersionID.String, a.PdfStorageKey.String: a.PdfStorageVersionID.String, b.PdfStorageKey.String: b.PdfStorageVersionID.String}
		var mu sync.Mutex
		var trace []string
		var invalid atomic.Bool
		client := packageMeasurementClient232(t, q, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") {
				key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
				if version, ok := pins[key]; !ok || r.URL.Query().Get("versionId") != version || (r.Method != http.MethodHead && r.Method != http.MethodGet) {
					invalid.Store(true)
					http.Error(w, "unexpected exact object", http.StatusForbidden)
					return
				}
				mu.Lock()
				trace = append(trace, r.Method+" "+key)
				mu.Unlock()
			}
			q.storagePeer.ServeHTTP(w, r)
		}))
		before := packageMeasurementState232(t, q)
		err := withPackageSendDraft231(t, q, root.ID, expected, true, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if err := draft.MeasurePDFsV1(client); err != nil {
				return err
			}
			got, count, err := draft.MeasurementsV1()
			if err != nil || count != 3 {
				t.Fatal("original root measurement count", count, err)
			}
			for i, d := range []*generated.Document{root, a, b} {
				q.storagePeer.mu.Lock()
				size := int64(len(q.storagePeer.objects[d.PdfStorageKey.String]))
				q.storagePeer.mu.Unlock()
				if got[i].DocumentID != d.ID || got[i].Bytes != size || got[i].Pages != 1 {
					t.Fatal("measurement switched selected version or sparse ordering", i, got[i], size)
				}
			}
			got[0].Pages = 999
			again, _, err := draft.MeasurementsV1()
			if err != nil || again[0].Pages != 1 {
				t.Fatal("caller mutation changed private measurement", err)
			}
			if err = draft.MeasurePDFsV1(client); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
				t.Fatal("measurement provider replay permitted", err)
			}
			snapshot, err := q.runtime.SnapshotV1(q.f.org)
			if err != nil || snapshot.Organisation.ProviderStreams != 0 || snapshot.Organisation.PDFWorkers != 0 || snapshot.Organisation.ChildAddressBytes != 0 || snapshot.Organisation.ParentBytes <= 0 || snapshot.Organisation.DBStagingBytes <= 0 {
				t.Fatal("transient work unjoined or source debt refunded", snapshot, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		want := []string{"HEAD " + root.PdfStorageKey.String, "HEAD " + a.PdfStorageKey.String, "HEAD " + b.PdfStorageKey.String, "GET " + root.PdfStorageKey.String, "GET " + a.PdfStorageKey.String, "GET " + b.PdfStorageKey.String}
		if invalid.Load() || fmt.Sprint(trace) != fmt.Sprint(want) || packageMeasurementState232(t, q) != before {
			t.Fatal("exact all-HEAD-before-GET protocol or read-only state changed", trace, want)
		}
	})
	t.Run("active original SQL refuses before provider and cannot retry", func(t *testing.T) {
		requests := q.storagePeer.requests.Load()
		err := withPackageSendDraft231(t, q, root.ID, expected, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			packageMeasurementUnavailable232(t, draft)
			if err := draft.MeasurePDFsV1(q.f.s.Storage); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
				t.Fatal("early measurement replayed after SQL retirement", err)
			}
			return nil
		}, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if err := draft.MeasurePDFsV1(q.f.s.Storage); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
				t.Fatal("active SQL accepted provider work", err)
			}
			return nil
		})
		if err != nil || q.storagePeer.requests.Load() != requests {
			t.Fatal("active SQL refusal touched provider", err)
		}
	})
	t.Run("root-inclusive HEAD overflow precedes every GET", func(t *testing.T) {
		var heads, gets atomic.Int32
		client := packageMeasurementClient232(t, q, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") && r.Method == http.MethodHead {
				heads.Add(1)
				rr := httptest.NewRecorder()
				q.storagePeer.ServeHTTP(rr, r)
				for key, values := range rr.Header() {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
				if r.URL.Path == "/hash-import-fixture/"+root.PdfStorageKey.String {
					w.Header().Set("Content-Length", fmt.Sprint(documentpackage.MaxPDFBytesV1))
				}
				w.WriteHeader(rr.Code)
				return
			}
			if strings.HasPrefix(r.URL.Path, "/hash-import-fixture/org/") && r.Method == http.MethodGet {
				gets.Add(1)
			}
			q.storagePeer.ServeHTTP(w, r)
		}))
		before := packageMeasurementState232(t, q)
		err := withPackageSendDraft231(t, q, root.ID, expected, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if err := draft.MeasurePDFsV1(client); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
				t.Fatal("aggregate HEAD overflow accepted", err)
			}
			packageMeasurementUnavailable232(t, draft)
			if err := draft.MeasurePDFsV1(client); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
				t.Fatal("overflow allowed retry", err)
			}
			return nil
		})
		if err != nil || heads.Load() != 2 || gets.Load() != 0 || packageMeasurementState232(t, q) != before {
			t.Fatal("overflow allocated/read a PDF or changed state", heads.Load(), gets.Load(), err)
		}
	})
	t.Run("strict isolated worker remains required", func(t *testing.T) {
		before := packageMeasurementState232(t, q)
		err := withPackageSendDraft231(t, q, root.ID, expected, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
			if err := sanitize.ConfigurePDFWorker(q.f.ctx, "", "development"); err != nil {
				return err
			}
			defer func() {
				ctx, stop := context.WithTimeout(context.WithoutCancel(q.f.ctx), 5*time.Second)
				defer stop()
				if err := sanitize.ConfigurePDFWorker(ctx, os.Getenv("HASH_E2E_PDF_WORKER_PATH"), "production"); err != nil {
					t.Error(err)
				}
			}()
			if err := draft.MeasurePDFsV1(q.f.s.Storage); !errors.Is(err, sanitize.ErrPDFWorkerUnavailable) {
				t.Fatal("unconfigured worker accepted", err)
			}
			packageMeasurementUnavailable232(t, draft)
			requests := q.storagePeer.requests.Load()
			if err := draft.MeasurePDFsV1(q.f.s.Storage); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) || q.storagePeer.requests.Load() != requests {
				t.Fatal("worker refusal replayed", err)
			}
			return nil
		})
		if err != nil || packageMeasurementState232(t, q) != before {
			t.Fatal("worker refusal changed state", err)
		}
	})
	for _, mode := range []string{"version", "missing", "digest"} {
		t.Run("exact selected "+mode+" refuses", func(t *testing.T) {
			peer := packagePreviewStorage227(t, q, b, mode, false)
			before := packageMeasurementState232(t, q)
			err := withPackageSendDraft231(t, q, root.ID, expected, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
				if err := draft.MeasurePDFsV1(q.f.s.Storage); err == nil {
					t.Fatal("wrong or absent selected object accepted")
				}
				packageMeasurementUnavailable232(t, draft)
				wantGets := int32(0)
				if mode == "digest" {
					wantGets = 1
				}
				if peer.heads.Load() != 1 || peer.gets.Load() != wantGets {
					t.Fatal("injected selected-object fault was not reached", mode, peer.heads.Load(), peer.gets.Load())
				}
				heads, gets := peer.heads.Load(), peer.gets.Load()
				if err := draft.MeasurePDFsV1(q.f.s.Storage); !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) || peer.heads.Load() != heads || peer.gets.Load() != gets {
					t.Fatal("exact object refusal replayed", err)
				}
				return nil
			})
			if err != nil || packageMeasurementState232(t, q) != before {
				t.Fatal("exact selected refusal changed state", err)
			}
		})
	}
	for _, annexPages := range []int32{499, 500} {
		t.Run(fmt.Sprintf("actual root-inclusive %d pages", annexPages+1), func(t *testing.T) {
			main := packageImported220(t, q, fmt.Sprintf("Page bound %d", annexPages+1))
			annex := packageImportPDF223(t, q, packagePagesPDF223(int(annexPages)))
			header := packageHeader218(t, q.f, main)
			q.storagePeer.mu.Lock()
			size := int64(len(q.storagePeer.objects[annex.PdfStorageKey.String]))
			q.storagePeer.mu.Unlock()
			if _, err := q.f.q.InsertDocumentAttachmentDraftV1(q.f.ctx, generated.InsertDocumentAttachmentDraftV1Params{PackageID: header.ID, OrgID: q.f.org, ExpectedGeneration: header.DraftGeneration, MemberDocumentID: annex.ID, Ordinal: 16, Title: "Measured multipage attachment", PdfKey: annex.PdfStorageKey.String, PdfVersionID: annex.PdfStorageVersionID.String, PdfSha256: annex.PdfSha256, PdfBytes: size, PdfPages: annexPages, SourceKind: "pdf-import"}); err != nil {
				t.Fatal(err)
			}
			header = packageFresh218(t, q.f, header.ID)
			before := packageMeasurementState232(t, q)
			requests := q.storagePeer.requests.Load()
			err := withPackageSendDraft231(t, q, main.ID, pdfadmission.DocumentPackageDraftExpectedV1{PackageID: header.ID, Generation: header.DraftGeneration}, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, _ *pdfadmission.ApplicationHTMLSendWorkV1) error {
				err := draft.MeasurePDFsV1(q.f.s.Storage)
				if annexPages == 499 {
					got, count, readErr := draft.MeasurementsV1()
					if err != nil || readErr != nil || count != 2 || got[0].Pages != 1 || got[1].Pages != annexPages {
						t.Fatal("actual500-page bound refused", got, count, err, readErr)
					}
				} else {
					if !errors.Is(err, pdfadmission.ErrDocumentPackageMeasurementV1) {
						t.Fatal("actual501-page package accepted", err)
					}
					packageMeasurementUnavailable232(t, draft)
				}
				return nil
			})
			if err != nil || q.storagePeer.requests.Load() != requests+4 || packageMeasurementState232(t, q) != before {
				t.Fatal("page measurement did not read both exact PDFs or changed state", err)
			}
		})
	}
	t.Run("Work close cancels and joins actual held GET", func(t *testing.T) {
		peer := packagePreviewStorage227(t, q, b, "", true)
		before := packageMeasurementState232(t, q)
		err := withPackageSendDraft231(t, q, root.ID, expected, false, func(draft *pdfadmission.ApplicationHTMLSendPackageDraftV1, work *pdfadmission.ApplicationHTMLSendWorkV1) error {
			result := make(chan error, 1)
			joined := false
			go func() { result <- draft.MeasurePDFsV1(q.f.s.Storage) }()
			defer func() {
				peer.unblock()
				if !joined {
					select {
					case <-result:
					case <-time.After(3 * time.Second):
						t.Error("original measure did not join")
					}
				}
			}()
			select {
			case <-peer.entered:
			case err := <-result:
				joined = true
				t.Fatal("original measure did not reach actual GET", err)
			case <-time.After(3 * time.Second):
				t.Fatal("actual selected GET not observed")
			}
			snapshot, err := q.runtime.SnapshotV1(q.f.org)
			if err != nil || snapshot.Organisation.ProviderStreams != 1 || snapshot.Organisation.ParentBytes <= 0 || q.runtime.SessionsV1().PendingV1().WorkSessions != 0 {
				t.Fatal("held original GET lacks actual debt or SQL remained live", snapshot, err)
			}
			work.CloseConsumerV1()
			select {
			case err := <-result:
				joined = true
				if err == nil {
					t.Fatal("closed original measurement succeeded")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("closed actual GET did not join")
			}
			packageMeasurementUnavailable232(t, draft)
			snapshot, err = q.runtime.SnapshotV1(q.f.org)
			if err != nil || snapshot.Organisation.ProviderStreams != 0 || snapshot.Organisation.PDFWorkers != 0 || snapshot.Organisation.ChildAddressBytes != 0 {
				t.Fatal("canceled native provider/worker survived join", snapshot, err)
			}
			return nil
		})
		if err != nil || packageMeasurementState232(t, q) != before {
			t.Fatal("cancel changed original state", err)
		}
	})
}
