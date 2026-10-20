//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

// Real native PG/isolated worker and original signed-cookie policy, with the
// existing synthetic renderer/S3 peers. This does not enable package mutation.
func reviewPackageHTML221(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) *generated.Document {
	t.Helper()
	commitment, err := htmlsource.Commitment(doc)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+doc.ID.String()+"/html/review", string(raw), q.cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("genuine review=%d %s", response.Code, response.Body.String())
	}
	fresh, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}
func withPackageOperation221(t *testing.T, q *ownedPublicReadFixtureV1, pair [2]*generated.Document, mutateDTO bool, run func(*pdfadmission.ApplicationDocumentPackageOperationV1, context.Context, pdfadmission.DocumentPackageSourcePolicyV1, *int)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(q.f.ctx, 30*time.Second)
	defer cancel()
	actor := packageActor220(t, q)
	calls := 0
	var pid int32
	var backendStart time.Time
	policy := func(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1) (func(context.Context) error, error) {
		docs, guards, err := readDocumentPackageSelectionV1(call, db, owner, actor, [2]uuid.UUID{pair[0].ID, pair[1].ID}, [2]time.Time{pair[0].UpdatedAt.Time, pair[1].UpdatedAt.Time})
		if err != nil {
			return nil, err
		}
		calls++
		if calls == 1 {
			//nolint:rawsql -- exact native test-backend identity, never retirement credit
			if err = db.QueryRow(call, "SELECT pid,backend_start FROM pg_stat_activity WHERE pid=pg_backend_pid()").Scan(&pid, &backendStart); err != nil {
				return nil, err
			}
			if mutateDTO {
				docs[0].Name = "caller changed copy"
				docs[0].PdfStorageKey.String = "caller-switched-key"
				docs[0].PdfStorageVersionID.String = "caller-switched-version"
				docs[0].PdfSha256[0] ^= 0xff
			}
		}
		return func(recheck context.Context) error {
			for _, guard := range guards {
				if err := guard.Recheck(recheck); err != nil {
					return err
				}
			}
			return nil
		}, nil
	}
	operation, err := q.runtime.SessionsV1().NewDocumentPackageOperationV1(ctx, q.f.org, pair[0].ID, pair[1].ID, actor.UserID, q.f.s.Storage)
	// Keep a possibly partial owner, and install cleanup before checking its error.
	defer func() {
		if operation != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if err := operation.CloseV1(cleanup); err != nil {
				t.Error("same package owner cleanup", err)
			}
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	}()
	if err != nil {
		t.Fatal(err)
	}
	requests := q.storagePeer.requests.Load()
	if err = operation.ReadSourcesV1(policy); err != nil {
		t.Fatal("initial native source stage", err)
	}
	if q.storagePeer.requests.Load() != requests || calls != 1 {
		t.Fatal("initial SQL made external calls or wrong policy count")
	}
	var live int
	//nolint:rawsql -- independent actual PG identity witness, not caller pending hint
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM pg_stat_activity WHERE pid=$1 AND backend_start=$2", pid, backendStart).Scan(&live); err != nil || live != 0 {
		t.Fatal("initial physical SQL backend survived", live, err)
	}
	pending := q.runtime.SessionsV1().PendingV1()
	snapshot, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || pending.WorkSessions != 0 || pending.DocumentPackageOperations != 1 || snapshot.Organisation.SQLSessions != 1 || snapshot.Organisation.ParentBytes <= 0 || snapshot.Organisation.DBStagingBytes <= 0 || snapshot.Organisation.ProviderStreams != 0 || snapshot.Organisation.PDFWorkers != 0 || snapshot.Organisation.ChildAddressBytes != 0 {
		t.Fatal("initial retirement refunded source consumers or retained SQL", pending, snapshot, err)
	}
	run(operation, ctx, policy, &calls)
}
func assertPackageMeasurement221(t *testing.T, q *ownedPublicReadFixtureV1, operation *pdfadmission.ApplicationDocumentPackageOperationV1, pair [2]*generated.Document, wantPages [2]int32) {
	t.Helper()
	beforeRequests := q.storagePeer.requests.Load()
	if err := operation.MeasurePDFsV1(); err != nil {
		t.Fatal("actual exact PDF measurement", err)
	}
	if q.storagePeer.requests.Load() != beforeRequests+4 {
		t.Fatal("measurement did not make exactly two HEAD/two GET requests")
	}
	measurements, err := operation.MeasurementsV1()
	if err != nil {
		t.Fatal(err)
	}
	q.storagePeer.mu.Lock()
	var sizes [2]int64
	for i, d := range pair {
		sizes[i] = int64(len(q.storagePeer.objects[d.PdfStorageKey.String]))
	}
	q.storagePeer.mu.Unlock()
	for i, got := range measurements {
		if sizes[i] <= 0 || got.DocumentID != pair[i].ID || got.Bytes != sizes[i] || got.Pages != wantPages[i] {
			t.Fatal("actual immutable PDF tuple measurement differs", i, got, sizes[i], wantPages[i])
		}
	}
	snapshot, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || snapshot.Organisation.ChildAddressBytes != 0 || snapshot.Organisation.PDFWorkers != 0 || snapshot.Organisation.ProviderStreams != 0 || snapshot.Organisation.SQLSessions != 1 || snapshot.Organisation.ParentBytes <= 0 {
		t.Fatal("provider/parser join or retained source accounting differs", snapshot, err)
	}
	if err = operation.MeasurePDFsV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || q.storagePeer.requests.Load() != beforeRequests+4 {
		t.Fatal("one-shot measurement replayed provider work", err)
	}
}
func TestDocumentPackageOwnedPDFMeasurementV1E2E(t *testing.T) {
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
	main := packageImported220(t, q, "Main exact package terms")
	annex := packageImported220(t, q, "Exact DPA")
	html := reviewPackageHTML221(t, q, createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie))
	t.Run("constructor-only owner is visible and releases", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(q.f.ctx, 10*time.Second)
		defer cancel()
		requests := q.storagePeer.requests.Load()
		operation, err := q.runtime.SessionsV1().NewDocumentPackageOperationV1(ctx, q.f.org, main.ID, annex.ID, q.f.user.ID, q.f.s.Storage)
		if operation != nil {
			defer func() {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer stop()
				if err := operation.CloseV1(cleanup); err != nil {
					t.Error(err)
				}
			}()
		}
		if err != nil {
			t.Fatal(err)
		}
		pending := q.runtime.SessionsV1().PendingV1()
		snapshot, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil || pending.DocumentPackageOperations != 1 || pending.WorkSessions != 0 || snapshot.Organisation.ParentBytes <= 0 || q.storagePeer.requests.Load() != requests {
			t.Fatal("constructor ownership unregistered or performed I/O", pending, snapshot, err)
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		if err = operation.CloseV1(cleanup); err != nil {
			t.Fatal(err)
		}
		ownedCreationAssertDrainedV1(t, q, 2)
	})
	positive := func(t *testing.T, pair [2]*generated.Document, pages [2]int32, mutate bool) {
		before := packageState220(t, q)
		withPackageOperation221(t, q, pair, mutate, func(operation *pdfadmission.ApplicationDocumentPackageOperationV1, _ context.Context, policy pdfadmission.DocumentPackageSourcePolicyV1, calls *int) {
			assertPackageMeasurement221(t, q, operation, pair, pages)
			if operation.CommitDispatchedV1() {
				t.Fatal("measurement dispatched SQL commit")
			}
			if err := operation.RevalidateSourcesV1(policy); err != nil {
				t.Fatal("fresh original policy/source stage", err)
			}
			if *calls != 2 || !operation.CommitDispatchedV1() {
				t.Fatal("fresh native final boundary not dispatched exactly once", *calls)
			}
			if err := operation.RevalidateSourcesV1(policy); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || *calls != 2 {
				t.Fatal("final attempt replayed", err)
			}
			if packageState220(t, q) != before {
				t.Fatal("read-only source/measurement mutated document/package/events")
			}
		})
	}
	t.Run("imported pair private pins survive caller DTO mutation", func(t *testing.T) { positive(t, [2]*generated.Document{main, annex}, [2]int32{1, 1}, true) })
	t.Run("reviewed origin HTML exact PDF", func(t *testing.T) { positive(t, [2]*generated.Document{main, html}, [2]int32{1, 2}, false) })
	origin := bytes.Clone(html.HtmlSourceJson)
	beforeRevision := html
	commitment, err := htmlsource.Commitment(html)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := json.Marshal(htmlDocumentRevisionInput{ExpectedUpdatedAt: html.UpdatedAt.Time.Format(time.RFC3339Nano), ExpectedHTMLSourceCommitment: commitment, Values: htmlStringMap{"scope": "Revised exact annex scope"}, Summary: "Actual package measurement revision"})
	if err != nil {
		t.Fatal(err)
	}
	response := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+html.ID.String()+"/html/revisions", string(revision), q.cookie)
	if response.Code != http.StatusCreated {
		t.Fatalf("genuine revision=%d %s", response.Code, response.Body.String())
	}
	html = ownedDetailsDocumentV1(t, q, beforeRevision)
	if html.HtmlCurrentMaterializationSequence.Int32 != beforeRevision.HtmlCurrentMaterializationSequence.Int32+1 || html.HtmlCurrentMaterializationSequence.Int32 < 2 || html.HtmlCurrentMaterializationID == beforeRevision.HtmlCurrentMaterializationID || !bytes.Equal(html.HtmlSourceJson, origin) {
		t.Fatal("genuine normalized revision/origin absent")
	}
	html = reviewPackageHTML221(t, q, html)
	t.Run("reviewed normalized revision exact current PDF", func(t *testing.T) { positive(t, [2]*generated.Document{html, main}, [2]int32{2, 1}, false) })
	t.Run("strict worker absence refuses and cannot commit", func(t *testing.T) {
		pair := [2]*generated.Document{main, annex}
		before := packageState220(t, q)
		withPackageOperation221(t, q, pair, false, func(operation *pdfadmission.ApplicationDocumentPackageOperationV1, ctx context.Context, policy pdfadmission.DocumentPackageSourcePolicyV1, calls *int) {
			if err := sanitize.ConfigurePDFWorker(ctx, "", "development"); err != nil {
				t.Fatal(err)
			}
			defer func() {
				restore, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer stop()
				if err := sanitize.ConfigurePDFWorker(restore, os.Getenv("HASH_E2E_PDF_WORKER_PATH"), "production"); err != nil {
					t.Error(err)
				}
			}()
			if err := operation.MeasurePDFsV1(); !errors.Is(err, sanitize.ErrPDFWorkerUnavailable) {
				t.Fatal("unconfigured isolated worker accepted", err)
			}
			if _, err := operation.MeasurementsV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) {
				t.Fatal("failed measurement exposed receipt", err)
			}
			if err := operation.RevalidateSourcesV1(policy); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || operation.CommitDispatchedV1() || *calls != 1 {
				t.Fatal("unmeasured operation reached final SQL", err)
			}
			if packageState220(t, q) != before {
				t.Fatal("strict worker refusal mutated state")
			}
		})
	})
	t.Run("source changes after measurement require fresh policy", func(t *testing.T) {
		pair := [2]*generated.Document{main, annex}
		withPackageOperation221(t, q, pair, false, func(operation *pdfadmission.ApplicationDocumentPackageOperationV1, _ context.Context, policy pdfadmission.DocumentPackageSourcePolicyV1, calls *int) {
			assertPackageMeasurement221(t, q, operation, pair, [2]int32{1, 1})
			//nolint:rawsql -- controlled concurrent fixture edit; no cache repair/credit
			if tag, err := q.f.pool.Exec(q.f.ctx, "UPDATE documents SET name=name || ' changed',updated_at=clock_timestamp() WHERE id=$1 AND org_id=$2", annex.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
				t.Fatal("controlled source edit failed", err)
			}
			before := packageState220(t, q)
			if err := operation.RevalidateSourcesV1(policy); !errors.Is(err, errDocumentPackageChangedV1) || operation.CommitDispatchedV1() {
				t.Fatal("stale source reached commit", err)
			}
			if packageState220(t, q) != before {
				t.Fatal("stale source refusal mutated state")
			}
		})
	})
	// Fresh expected timestamp after the controlled edit above.
	annex, err = q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: annex.ID, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("original cancellation prevents provider work", func(t *testing.T) {
		withPackageOperation221(t, q, [2]*generated.Document{main, annex}, false, func(operation *pdfadmission.ApplicationDocumentPackageOperationV1, _ context.Context, policy pdfadmission.DocumentPackageSourcePolicyV1, calls *int) {
			requests := q.storagePeer.requests.Load()
			operation.CloseConsumerV1()
			if err := operation.MeasurePDFsV1(); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || q.storagePeer.requests.Load() != requests {
				t.Fatal("canceled owner made provider work", err)
			}
			if err := operation.RevalidateSourcesV1(policy); !errors.Is(err, pdfadmission.ErrDocumentPackageOperationV1) || operation.CommitDispatchedV1() || *calls != 1 {
				t.Fatal("canceled owner reached final SQL", err)
			}
		})
	})
}
