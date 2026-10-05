// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

type purgeDeleterStub struct {
	err     error
	key     string
	version string
	digest  []byte
	calls   int
}

type protectedPurgeQueriesStub struct {
	doc          *generated.Document
	lockErr      error
	fence        bool
	fenceErr     error
	pending      bool
	pendingErr   error
	shared       bool
	sharedErr    error
	retained     bool
	retainedErr  error
	deleteRows   int64
	deleteErr    error
	rowDeletes   int
	lockDocument func(context.Context) error
	deleteRow    func(context.Context) error
}

func (s *protectedPurgeQueriesStub) LockClaimedSoftDeletedDocumentForPurge(ctx context.Context, _ generated.LockClaimedSoftDeletedDocumentForPurgeParams) (*generated.Document, error) {
	if s.lockDocument != nil {
		if err := s.lockDocument(ctx); err != nil {
			return nil, err
		}
	}
	return s.doc, s.lockErr
}

func (s *protectedPurgeQueriesStub) TryCollabArchivePrivacyFence(context.Context, uuid.UUID) (bool, error) {
	return s.fence, s.fenceErr
}

func (s *protectedPurgeQueriesStub) HasPendingDocumentPrivacyRequests(context.Context, generated.HasPendingDocumentPrivacyRequestsParams) (bool, error) {
	return s.pending, s.pendingErr
}

func (s *protectedPurgeQueriesStub) HasOtherDocumentSourceReferences(context.Context, generated.HasOtherDocumentSourceReferencesParams) (bool, error) {
	return s.shared, s.sharedErr
}

func (s *protectedPurgeQueriesStub) HasRetainedDraftEvidenceForPurge(context.Context, generated.HasRetainedDraftEvidenceForPurgeParams) (bool, error) {
	return s.retained, s.retainedErr
}

func (s *protectedPurgeQueriesStub) DeleteClaimedSoftDeletedDocument(ctx context.Context, _ generated.DeleteClaimedSoftDeletedDocumentParams) (int64, error) {
	s.rowDeletes++
	if s.deleteRow != nil {
		if err := s.deleteRow(ctx); err != nil {
			return 0, err
		}
	}
	return s.deleteRows, s.deleteErr
}

type purgeDeleteFunc func(context.Context, string, string) error

func (f purgeDeleteFunc) DeleteVersion(ctx context.Context, key, version string, digest []byte) error {
	if len(digest) != 32 {
		return errors.New("exact source digest missing")
	}
	return f(ctx, key, version)
}

func protectedPurgeTestClaim() (*generated.Document, pgtype.Timestamptz) {
	at := time.Now().UTC()
	orgID := uuid.New()
	return &generated.Document{
		ID: uuid.New(), OrgID: orgID, Status: "draft", SourceKind: "pdf",
		PdfStorageKey:       pgtype.Text{String: "org/" + orgID.String() + "/documents/" + uuid.NewString() + ".pdf", Valid: true},
		PdfStorageVersionID: pgtype.Text{String: "fixture-source-version-1", Valid: true},
		PdfSha256:           make([]byte, 32), EvidenceVersionPinsRequired: true,
		UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true},
	}, pgtype.Timestamptz{Time: at.Add(-softDeleteGraceWindow), Valid: true}
}

func TestProtectedSoftDeletePurgeStopsObjectIOForUnsafeAdmission(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*protectedPurgeQueriesStub)
		wantError bool
	}{
		{"stale or locked lease", func(q *protectedPurgeQueriesStub) { q.lockErr = pgx.ErrNoRows }, false},
		{"lock database failure", func(q *protectedPurgeQueriesStub) { q.lockErr = errors.New("db unavailable") }, true},
		{"contested global request fence", func(q *protectedPurgeQueriesStub) { q.fence = false }, false},
		{"fence database failure", func(q *protectedPurgeQueriesStub) { q.fenceErr = errors.New("fence failed") }, true},
		{"pending linked or global request", func(q *protectedPurgeQueriesStub) { q.pending = true }, false},
		{"privacy database failure", func(q *protectedPurgeQueriesStub) { q.pendingErr = errors.New("privacy check failed") }, true},
		{"retained evidence or sealing state", func(q *protectedPurgeQueriesStub) { q.retained = true }, true},
		{"retained evidence database failure", func(q *protectedPurgeQueriesStub) { q.retainedErr = errors.New("evidence check failed") }, true},
		{"shared-reference database failure", func(q *protectedPurgeQueriesStub) { q.sharedErr = errors.New("reference check failed") }, true},
		{"unowned source namespace", func(q *protectedPurgeQueriesStub) {
			q.doc.PdfStorageKey.String = "org/other/documents/" + uuid.NewString() + ".pdf"
		}, true},
		{"missing exact source version", func(q *protectedPurgeQueriesStub) { q.doc.PdfStorageVersionID = pgtype.Text{} }, true},
		{"non-PDF cleanup reference", func(q *protectedPurgeQueriesStub) { q.doc.SourceKind = "blocks" }, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			claim, cutoff := protectedPurgeTestClaim()
			q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
			test.configure(q)
			objects := &purgeDeleterStub{}
			commits, rollbacks := 0, 0
			begin := func(context.Context) (softDeletePurgeTransaction, error) {
				return softDeletePurgeTransaction{
					queries: q,
					commit:  func(context.Context) error { commits++; return nil },
					rollback: func(context.Context) error {
						rollbacks++
						return nil
					},
				}, nil
			}
			rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
			if rows != 0 || (err != nil) != test.wantError || objects.calls != 0 || q.rowDeletes != 0 || commits != 0 || rollbacks != 1 {
				t.Fatalf("rows/error/object/row/commit/rollback=%d/%v/%d/%d/%d/%d", rows, err, objects.calls, q.rowDeletes, commits, rollbacks)
			}
		})
	}
}

func TestProtectedSoftDeletePurgePreservesReferencedSourceAndDeletesExpiredParent(t *testing.T) {
	claim, cutoff := protectedPurgeTestClaim()
	q := &protectedPurgeQueriesStub{doc: claim, fence: true, shared: true, deleteRows: 1}
	objects := &purgeDeleterStub{}
	committed := false
	begin := func(context.Context) (softDeletePurgeTransaction, error) {
		return softDeletePurgeTransaction{
			queries:  q,
			commit:   func(context.Context) error { committed = true; return nil },
			rollback: func(context.Context) error { return pgx.ErrTxClosed },
		}, nil
	}
	rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
	if err != nil || rows != 1 || q.rowDeletes != 1 || objects.calls != 0 || !committed {
		t.Fatalf("shared-source cleanup rows=%d deletes=%d objects=%d committed=%v err=%v", rows, q.rowDeletes, objects.calls, committed, err)
	}
}

func TestOwnedPurgeSourceKeyRequiresExactIntakeNamespace(t *testing.T) {
	claim, _ := protectedPurgeTestClaim()
	for _, invalid := range []string{
		"org/" + uuid.NewString() + "/documents/" + uuid.NewString() + ".pdf",
		"org/" + claim.OrgID.String() + "/documents/" + uuid.NewString() + "/source.pdf",
		"org/" + claim.OrgID.String() + "/documents/../source.pdf",
		"org/" + claim.OrgID.String() + "/documents/source.pdf",
		"org/" + claim.OrgID.String() + "/documents/" + uuid.NewString() + ".pdf/extra",
		"",
	} {
		doc := *claim
		doc.PdfStorageKey.String = invalid
		if _, err := ownedPurgeSourceKey(&doc); err == nil {
			t.Errorf("unsafe source namespace accepted: %q", invalid)
		}
	}
	if key, err := ownedPurgeSourceKey(claim); err != nil || key != claim.PdfStorageKey.String {
		t.Fatalf("valid independent object UUID refused: key=%q err=%v", key, err)
	}
}

func TestProtectedSoftDeletePurgeKeepsTransactionUntilSourceAndRowCleanup(t *testing.T) {
	claim, cutoff := protectedPurgeTestClaim()
	q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
	started, objectDeleted, rowDeleted, committed := false, false, false, false
	q.deleteRow = func(context.Context) error {
		if !started || !objectDeleted || committed {
			t.Fatal("row deletion escaped the protected source cleanup transaction")
		}
		rowDeleted = true
		return nil
	}
	objects := purgeDeleteFunc(func(ctx context.Context, key, version string) error {
		if !started || committed || rowDeleted || key != claim.PdfStorageKey.String || version != claim.PdfStorageVersionID.String {
			t.Fatal("source deletion escaped the protected transaction")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > softDeleteObjectTimeout {
			t.Fatal("source cleanup has no bounded 15-second context")
		}
		objectDeleted = true
		return nil
	})
	begin := func(ctx context.Context) (softDeletePurgeTransaction, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > softDeleteTotalTimeout {
			t.Fatal("protected purge has no bounded total context")
		}
		started = true
		return softDeletePurgeTransaction{
			queries: q,
			commit: func(context.Context) error {
				if !objectDeleted || !rowDeleted {
					t.Fatal("purge committed before completing source and row deletion")
				}
				committed = true
				return nil
			},
			rollback: func(context.Context) error { return pgx.ErrTxClosed },
		}, nil
	}
	rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
	if err != nil || rows != 1 || !committed {
		t.Fatalf("protected cleanup rows=%d committed=%v err=%v", rows, committed, err)
	}
}

func TestProtectedSoftDeletePurgeDoesNotReportSuccessAfterCleanupFailure(t *testing.T) {
	for _, failure := range []string{"storage", "row delete", "row count", "commit"} {
		t.Run(failure, func(t *testing.T) {
			claim, cutoff := protectedPurgeTestClaim()
			q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
			objects := &purgeDeleterStub{}
			failureErr := errors.New("forced cleanup failure")
			switch failure {
			case "storage":
				objects.err = failureErr
			case "row delete":
				q.deleteErr = failureErr
			case "row count":
				q.deleteRows = 0
			}
			commits, rollbacks := 0, 0
			begin := func(context.Context) (softDeletePurgeTransaction, error) {
				return softDeletePurgeTransaction{
					queries: q,
					commit: func(context.Context) error {
						commits++
						if failure == "commit" {
							return failureErr
						}
						return nil
					},
					rollback: func(context.Context) error { rollbacks++; return nil },
				}, nil
			}
			rows, err := purgeClaimedSoftDeletedDocument(context.Background(), claim, cutoff, objects, begin)
			if err == nil || rows != 0 || rollbacks != 1 {
				t.Fatalf("failed cleanup rows=%d rollback=%d err=%v", rows, rollbacks, err)
			}
			if failure != "commit" && commits != 0 {
				t.Fatal("failed storage or row deletion attempted a commit")
			}
			if failure == "storage" && q.rowDeletes != 0 {
				t.Fatal("storage failure attempted to remove the retry row")
			}
		})
	}
}

func TestProtectedSoftDeletePurgePropagatesCallerDeadlineAndBoundsRollback(t *testing.T) {
	claim, cutoff := protectedPurgeTestClaim()
	q := &protectedPurgeQueriesStub{doc: claim, fence: true, deleteRows: 1}
	q.lockDocument = func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}
	objects := &purgeDeleterStub{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rolledBack := false
	begin := func(context.Context) (softDeletePurgeTransaction, error) {
		return softDeletePurgeTransaction{
			queries: q, commit: func(context.Context) error { t.Fatal("expired purge committed"); return nil },
			rollback: func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if ctx.Err() != nil || !ok || time.Until(deadline) > softDeleteRollbackTimeout {
					t.Fatal("rollback did not get a bounded cleanup context independent of caller cancellation")
				}
				rolledBack = true
				return nil
			},
		}, nil
	}
	rows, err := purgeClaimedSoftDeletedDocument(ctx, claim, cutoff, objects, begin)
	if !errors.Is(err, context.DeadlineExceeded) || rows != 0 || objects.calls != 0 || !rolledBack {
		t.Fatalf("deadline cleanup rows=%d object=%d rollback=%v err=%v", rows, objects.calls, rolledBack, err)
	}
}

func (s *purgeDeleterStub) DeleteVersion(_ context.Context, key, version string, digest []byte) error {
	s.digest = append([]byte(nil), digest...)
	s.calls++
	s.key = key
	s.version = version
	return s.err
}

func TestPurgeOwnedSourceKeyPreservesSharedAndEvidenceObjects(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/source.pdf", Valid: true}
	tests := []struct {
		name string
		doc  *generated.Document
		want string
	}{
		{"owned draft", &generated.Document{Status: "draft", SourceKind: "pdf", PdfStorageKey: source}, source.String},
		{"template clone", &generated.Document{Status: "draft", SourceKind: "pdf", TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PdfStorageKey: source}, ""},
		{"final alias", &generated.Document{Status: "draft", SourceKind: "pdf", PdfStorageKey: source, FinalPdfKey: source}, ""},
		{"audit alias", &generated.Document{Status: "draft", SourceKind: "pdf", PdfStorageKey: source, AuditCertKey: source}, ""},
		{"audit payload alias", &generated.Document{Status: "draft", SourceKind: "pdf", PdfStorageKey: source, AuditPayloadKey: source}, ""},
		{"audit signature alias", &generated.Document{Status: "draft", SourceKind: "pdf", PdfStorageKey: source, AuditSignatureKey: source}, ""},
		{"non-PDF source reference", &generated.Document{Status: "draft", SourceKind: "blocks", PdfStorageKey: source}, ""},
		{"terminal", &generated.Document{Status: "completed", PdfStorageKey: source}, ""},
		{"blocks draft", &generated.Document{Status: "draft"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := purgeOwnedSourceKey(tt.doc); got != tt.want {
				t.Fatalf("purgeOwnedSourceKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCleanupClaimedSoftDeletedDocument_RetriesStorageBeforeDeletingRow(t *testing.T) {
	doc, _ := protectedPurgeTestClaim()
	storageErr := errors.New("object store unavailable")
	objects := &purgeDeleterStub{err: storageErr}
	rowDeletes := 0
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if !errors.Is(err, storageErr) || rows != 0 {
		t.Fatalf("cleanup result = rows %d, err %v", rows, err)
	}
	if rowDeletes != 0 {
		t.Fatal("DB row must remain when source-object cleanup fails")
	}

	objects.err = nil
	rows, err = cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if err != nil || rows != 1 || rowDeletes != 1 {
		t.Fatalf("retry result = rows %d, deletes %d, err %v", rows, rowDeletes, err)
	}
	if objects.key != doc.PdfStorageKey.String {
		t.Fatalf("deleted key = %q", objects.key)
	}
	if objects.version != doc.PdfStorageVersionID.String || len(objects.digest) != 32 {
		t.Fatalf("deleted version = %q", objects.version)
	}
}

func TestCleanupClaimedSoftDeletedDocument_PreservesSharedSourceWithoutStorage(t *testing.T) {
	doc := &generated.Document{
		Status:        "draft",
		SourceKind:    "pdf",
		TemplateID:    pgtype.UUID{Bytes: uuid.New(), Valid: true},
		PdfStorageKey: pgtype.Text{String: "templates/shared.pdf", Valid: true},
	}
	rowDeletes := 0
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), doc, nil, func(context.Context, *generated.Document) (int64, error) {
		rowDeletes++
		return 1, nil
	})
	if err != nil || rows != 1 || rowDeletes != 1 {
		t.Fatalf("shared-source cleanup = rows %d, deletes %d, err %v", rows, rowDeletes, err)
	}
}

func TestCleanupClaimedSoftDeletedDocument_DelegatesExactDevelopmentSentinelToStorage(t *testing.T) {
	doc, _ := protectedPurgeTestClaim()
	doc.PdfStorageVersionID.String = "hash:unversioned-development"
	objects := &purgeDeleterStub{}
	rows, err := cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		return 1, nil
	})
	if err != nil || rows != 1 || objects.calls != 1 || objects.version != doc.PdfStorageVersionID.String {
		t.Fatalf("development sentinel forwarding rows=%d objects=%d version=%q err=%v", rows, objects.calls, objects.version, err)
	}
	// The storage implementation chooses development/production policy. A
	// production rejection must keep the row without changing the stored pin.
	objects.err = errors.New("development sentinel forbidden in production")
	rows, err = cleanupClaimedSoftDeletedDocument(context.Background(), doc, objects, func(context.Context, *generated.Document) (int64, error) {
		t.Fatal("storage sentinel rejection deleted the retry row")
		return 0, nil
	})
	if err == nil || rows != 0 || doc.PdfStorageVersionID.String != "hash:unversioned-development" {
		t.Fatalf("sentinel rejection rows=%d version=%q err=%v", rows, doc.PdfStorageVersionID.String, err)
	}
}

func TestPurgeOwnedSourceVersionPreservesSharedAndEvidenceObjects(t *testing.T) {
	source := pgtype.Text{String: "org/o/documents/source.pdf", Valid: true}
	tests := []struct {
		name string
		doc  *generated.Document
		want bool
	}{
		{"owned draft", &generated.Document{Status: "draft", PdfStorageKey: source, PdfSha256: make([]byte, 32), PdfStorageVersionID: pgtype.Text{String: "version-1", Valid: true}, EvidenceVersionPinsRequired: true}, true},
		{"template clone", &generated.Document{Status: "draft", TemplateID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, PdfStorageKey: source}, false},
		{"final alias", &generated.Document{Status: "draft", PdfStorageKey: source, FinalPdfKey: source}, false},
		{"audit alias", &generated.Document{Status: "draft", PdfStorageKey: source, AuditCertKey: source}, false},
		{"terminal", &generated.Document{Status: "completed", PdfStorageKey: source}, false},
		{"blocks draft", &generated.Document{Status: "draft"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := purgeOwnedSourceVersion(tt.doc)
			if err != nil || (got != nil) != tt.want {
				t.Fatalf("purgeOwnedSourceVersion() = %#v, %v; want present=%v", got, err, tt.want)
			}
		})
	}
	if got, err := purgeOwnedSourceVersion(&generated.Document{Status: "draft", PdfStorageKey: source}); err == nil || got != nil {
		t.Fatalf("unpinned source cleanup = %#v, %v; want fail-closed refusal", got, err)
	}
}
