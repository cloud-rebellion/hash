// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This strict query mock proves adapter dispatch/refusal only. It does not run
// PostgreSQL, validate SQL86 publication/retention triggers, authenticate signed
// bytes or establish provider retention, encryption or legal acceptance.
type fitsCommitmentQueriesStubV1 struct {
	t                             *testing.T
	org, document                 uuid.UUID
	ctx                           context.Context
	doc                           *generated.Document
	completed                     *generated.GetCompletedFittedFinalizationRow
	docErr, completedErr          error
	calls                         []string
	afterDocument, afterCompleted func()
}

func (q *fitsCommitmentQueriesStubV1) GetDocument(ctx context.Context, params generated.GetDocumentParams) (*generated.Document, error) {
	q.t.Helper()
	if ctx != q.ctx || params.ID != q.document || params.OrgID != q.org || len(q.calls) != 0 {
		q.t.Fatal("unscoped, reordered or repeated document dispatch")
	}
	q.calls = append(q.calls, "document")
	if q.afterDocument != nil {
		q.afterDocument()
	}
	return q.doc, q.docErr
}
func (q *fitsCommitmentQueriesStubV1) GetCompletedFittedFinalization(ctx context.Context, params generated.GetCompletedFittedFinalizationParams) (*generated.GetCompletedFittedFinalizationRow, error) {
	q.t.Helper()
	if ctx != q.ctx || params.DocumentID != q.document || params.OrgID != q.org || len(q.calls) != 1 || q.calls[0] != "document" {
		q.t.Fatal("unscoped, reordered or repeated completed journal dispatch")
	}
	q.calls = append(q.calls, "completed")
	if q.afterCompleted != nil {
		q.afterCompleted()
	}
	return q.completed, q.completedErr
}

func fitsCommitmentStoreFixtureV1(t *testing.T, completion time.Time) (*PostgresFitsIndexCommitmentStoreV1, *fitsCommitmentQueriesStubV1) {
	t.Helper()
	org := uuid.MustParse("20000000-0000-4000-8000-000000000001")
	document := uuid.MustParse("20000000-0000-4000-8000-000000000002")
	operation := uuid.MustParse("20000000-0000-4000-8000-000000000003")
	stamp := func(value time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: value, Valid: true} }
	text := func(value string) pgtype.Text { return pgtype.Text{String: value, Valid: true} }
	prefix := "org/" + org.String() + "/documents/" + document.String() + "/"
	doc := &generated.Document{
		ID: document, OrgID: org, Status: "completed", Name: "[erased projection]",
		FitsIndexRequired: true, EvidenceVersionPinsRequired: true, CompletionEffectiveAtBound: true,
		FitsIndexPreparationID: pgtype.UUID{Bytes: operation, Valid: true},
		FitsIndexStorageKey:    text(manualfit.IndexStorageKeyV1(org, document, operation)),
		FitsIndexVersionID:     text(" opaque exact+/= version "),
		FitsIndexSha256:        bytes.Repeat([]byte{1}, 32), FitsIndexBytes: pgtype.Int8{Int64: 4096, Valid: true},
		SentAt: stamp(completion.Add(-time.Hour)), CompletionEffectiveAt: stamp(completion), CompletedAt: stamp(completion),
		FinalizationRetainUntil: stamp(storage.EvidenceRetentionDeadline(completion, article13.RetentionYearsV1)),
		FinalPdfKey:             text(prefix + "final.pdf"), FinalPdfVersionID: text("final exact+/= version"), FinalPdfSha: bytes.Repeat([]byte{2}, 32),
		AuditCertKey: text(prefix + "audit.pdf"), AuditCertVersionID: text("certificate exact+/= version"), AuditCertSha256: bytes.Repeat([]byte{3}, 32),
		AuditPayloadKey: text(prefix + "payload.txt"), AuditPayloadVersionID: text("payload exact+/= version"), AuditPayloadSha256: bytes.Repeat([]byte{4}, 32),
		AuditSignatureKey: text(prefix + "signature.txt"), AuditSignatureVersionID: text("signature exact+/= version"), AuditSignatureSha256: bytes.Repeat([]byte{5}, 32),
	}
	completed := &generated.GetCompletedFittedFinalizationRow{
		ID: document, OrgID: org, FitsIndexRequired: true, FitsIndexPreparationID: doc.FitsIndexPreparationID,
		FitsIndexStorageKey: doc.FitsIndexStorageKey, FitsIndexVersionID: doc.FitsIndexVersionID,
		FitsIndexSha256: append([]byte(nil), doc.FitsIndexSha256...), FitsIndexBytes: doc.FitsIndexBytes,
		FinalPdfKey: doc.FinalPdfKey, FinalPdfVersionID: doc.FinalPdfVersionID, FinalPdfSha: append([]byte(nil), doc.FinalPdfSha...),
		AuditCertKey: doc.AuditCertKey, AuditCertVersionID: doc.AuditCertVersionID, AuditCertSha256: append([]byte(nil), doc.AuditCertSha256...),
		AuditPayloadKey: doc.AuditPayloadKey, AuditPayloadVersionID: doc.AuditPayloadVersionID, AuditPayloadSha256: append([]byte(nil), doc.AuditPayloadSha256...),
		AuditSignatureKey: doc.AuditSignatureKey, AuditSignatureVersionID: doc.AuditSignatureVersionID, AuditSignatureSha256: append([]byte(nil), doc.AuditSignatureSha256...),
		OriginalDocumentName: "Original retained document", CeremonyEpoch: doc.SentAt, CompletionEffectiveAt: doc.CompletionEffectiveAt,
		RetainUntil: doc.FinalizationRetainUntil, PublishedAt: stamp(completion.Add(time.Second)),
		FieldSnapshotSha256: bytes.Repeat([]byte{6}, 32), GeometrySha256: bytes.Repeat([]byte{7}, 32), FinalPdfBytes: 1024,
	}
	q := &fitsCommitmentQueriesStubV1{t: t, org: org, document: document, ctx: context.Background(), doc: doc, completed: completed}
	store, err := NewPostgresFitsIndexCommitmentStoreV1(q)
	if err != nil {
		t.Fatal(err)
	}
	return store, q
}
func fitsCommitmentDefaultFixtureV1(t *testing.T) (*PostgresFitsIndexCommitmentStoreV1, *fitsCommitmentQueriesStubV1) {
	return fitsCommitmentStoreFixtureV1(t, time.Date(2026, 10, 12, 1, 2, 3, 456789000, time.UTC))
}

func TestPostgresFitsCommitmentUsesExactScopedImmutablePin(t *testing.T) {
	store, q := fitsCommitmentDefaultFixtureV1(t)
	result, err := store.LoadCommittedFitsIndexV1(q.ctx, q.org, q.document)
	if err != nil {
		t.Fatal(err)
	}
	want := manualfit.ObjectPinV1{Key: q.doc.FitsIndexStorageKey.String, VersionID: q.doc.FitsIndexVersionID.String, SHA256: hex.EncodeToString(q.doc.FitsIndexSha256), Bytes: q.doc.FitsIndexBytes.Int64, ContentType: "application/json"}
	if !result.Required || result.Object != want || len(q.calls) != 2 || q.calls[1] != "completed" {
		t.Fatal("immutable scoped commitment or opaque version changed")
	}
	// The pin owns its digest string, and the mutable DSR name is not authority.
	q.doc.FitsIndexSha256[0] ^= 0xff
	q.completed.FitsIndexSha256[0] ^= 0xff
	q.doc.Name = "another projected name"
	if result.Object != want {
		t.Fatal("returned pin aliases mutable query data")
	}
}

func TestPostgresFitsCommitmentHistoricalFlagDoesNotQueryFittedJournal(t *testing.T) {
	store, q := fitsCommitmentDefaultFixtureV1(t)
	q.doc.FitsIndexRequired = false
	q.doc.FitsIndexPreparationID = pgtype.UUID{}
	q.doc.FitsIndexStorageKey, q.doc.FitsIndexVersionID = pgtype.Text{}, pgtype.Text{}
	q.doc.FitsIndexSha256, q.doc.FitsIndexBytes = nil, pgtype.Int8{}
	q.doc.EvidenceVersionPinsRequired, q.doc.CompletionEffectiveAtBound = false, false
	q.doc.SentAt, q.doc.CompletionEffectiveAt, q.doc.CompletedAt, q.doc.FinalizationRetainUntil = pgtype.Timestamptz{}, pgtype.Timestamptz{}, pgtype.Timestamptz{}, pgtype.Timestamptz{}
	q.completedErr = errors.New("this query must not be dispatched")
	result, err := store.LoadCommittedFitsIndexV1(q.ctx, q.org, q.document)
	if err != nil || result != (manualfit.CommittedFitsIndexV1{}) || len(q.calls) != 1 {
		t.Fatal("historical required=false path queried or reconstructed a fitted pin")
	}
}

func TestPostgresFitsCommitmentRefusesDocumentAndJournalContradictions(t *testing.T) {
	for _, item := range []struct {
		name      string
		completed bool
		change    func(*fitsCommitmentQueriesStubV1)
	}{
		{name: "missing-document", change: func(q *fitsCommitmentQueriesStubV1) { q.doc = nil }},
		{name: "document-cross-org", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.OrgID = uuid.New() }},
		{name: "document-cross-id", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.ID = uuid.New() }},
		{name: "not-completed", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.Status = "finalizing" }},
		{name: "soft-deleted", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.DeletedAt.Valid = true }},
		{name: "flag-downgrade-with-pins", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexRequired = false }},
		{name: "missing-preparation", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexPreparationID.Valid = false }},
		{name: "zero-preparation", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexPreparationID.Bytes = uuid.Nil }},
		{name: "version-pins-not-required", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.EvidenceVersionPinsRequired = false }},
		{name: "completion-not-bound", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.CompletionEffectiveAtBound = false }},
		{name: "missing-epoch", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.SentAt.Valid = false }},
		{name: "infinite-epoch", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.SentAt.InfinityModifier = pgtype.Infinity }},
		{name: "missing-completion", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.CompletionEffectiveAt.Valid = false }},
		{name: "completion-not-after-epoch", change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.CompletionEffectiveAt = q.doc.SentAt
			q.doc.CompletedAt = q.doc.SentAt
		}},
		{name: "completed-timestamp-drift", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.CompletedAt.Time = q.doc.CompletedAt.Time.Add(time.Second) }},
		{name: "retention-too-short", change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.FinalizationRetainUntil.Time = q.doc.FinalizationRetainUntil.Time.Add(-time.Second)
		}},
		{name: "retention-fraction", change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.FinalizationRetainUntil.Time = q.doc.FinalizationRetainUntil.Time.Add(time.Nanosecond)
		}},
		{name: "missing-index-key", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexStorageKey.Valid = false }},
		{name: "other-operation-key", change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.FitsIndexStorageKey.String = manualfit.IndexStorageKeyV1(q.org, q.document, uuid.New())
		}},
		{name: "cross-tenant-index-key", change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.FitsIndexStorageKey.String = manualfit.IndexStorageKeyV1(uuid.New(), q.document, uuid.UUID(q.doc.FitsIndexPreparationID.Bytes))
		}},
		{name: "index-key-suffix", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexStorageKey.String += "/extra" }},
		{name: "missing-index-version", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexVersionID.Valid = false }},
		{name: "null-index-version", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexVersionID.String = " null " }},
		{name: "development-index-version", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexVersionID.String = "hash:unversioned-development" }},
		{name: "control-index-version", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexVersionID.String = "version\n" }},
		{name: "short-index-sha", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexSha256 = q.doc.FitsIndexSha256[:31] }},
		{name: "oversized-index-sha", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexSha256 = bytes.Repeat([]byte{1}, 1024) }},
		{name: "missing-index-size", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexBytes.Valid = false }},
		{name: "zero-index-size", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexBytes.Int64 = 0 }},
		{name: "oversized-index", change: func(q *fitsCommitmentQueriesStubV1) { q.doc.FitsIndexBytes.Int64 = manualfit.MaxFitsIndexBytesV1 + 1 }},
		{name: "missing-completed-journal", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed = nil }},
		{name: "unpublished-query-refusal", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completedErr = pgx.ErrNoRows }},
		{name: "journal-cross-org", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.OrgID = uuid.New() }},
		{name: "journal-cross-id", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.ID = uuid.New() }},
		{name: "journal-required-false", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexRequired = false }},
		{name: "journal-preparation-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexPreparationID.Bytes = uuid.New() }},
		{name: "journal-preparation-null", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexPreparationID.Valid = false }},
		{name: "journal-key-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexStorageKey.String += "-changed" }},
		{name: "journal-version-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexVersionID.String += "changed" }},
		{name: "journal-sha-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexSha256[0] ^= 0xff }},
		{name: "journal-size-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FitsIndexBytes.Int64++ }},
		{name: "journal-epoch-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) {
			q.completed.CeremonyEpoch.Time = q.completed.CeremonyEpoch.Time.Add(time.Second)
		}},
		{name: "journal-completion-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) {
			q.completed.CompletionEffectiveAt.Time = q.completed.CompletionEffectiveAt.Time.Add(time.Second)
		}},
		{name: "journal-retention-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) {
			q.completed.RetainUntil.Time = q.completed.RetainUntil.Time.Add(time.Second)
		}},
		{name: "journal-missing-publication", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.PublishedAt.Valid = false }},
		{name: "journal-infinite-publication", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.PublishedAt.InfinityModifier = pgtype.Infinity }},
		{name: "journal-missing-field-sha", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FieldSnapshotSha256 = nil }},
		{name: "journal-missing-geometry-sha", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.GeometrySha256 = nil }},
		{name: "journal-original-name-empty", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.OriginalDocumentName = "  " }},
		{name: "journal-original-name-invalid", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.OriginalDocumentName = string([]byte{0xff}) }},
		{name: "journal-original-name-oversized", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.OriginalDocumentName = strings.Repeat("a", 65537) }},
		{name: "journal-final-size-zero", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FinalPdfBytes = 0 }},
		{name: "journal-final-size-oversized", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FinalPdfBytes = manualfit.MaxFinalPDFBytesV1 + 1 }},
		{name: "final-key-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.FinalPdfKey.String += "changed" }},
		{name: "final-cross-tenant", completed: true, change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.FinalPdfKey.String = "org/other/documents/other/final.pdf"
			q.completed.FinalPdfKey = q.doc.FinalPdfKey
		}},
		{name: "certificate-version-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.AuditCertVersionID.String += "changed" }},
		{name: "payload-sha-drift", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.AuditPayloadSha256[0] ^= 0xff }},
		{name: "signature-missing-version", completed: true, change: func(q *fitsCommitmentQueriesStubV1) { q.completed.AuditSignatureVersionID.Valid = false }},
		{name: "sidecar-unversioned", completed: true, change: func(q *fitsCommitmentQueriesStubV1) {
			q.doc.AuditSignatureVersionID.String = "null"
			q.completed.AuditSignatureVersionID = q.doc.AuditSignatureVersionID
		}},
	} {
		t.Run(item.name, func(t *testing.T) {
			store, q := fitsCommitmentDefaultFixtureV1(t)
			item.change(q)
			result, err := store.LoadCommittedFitsIndexV1(q.ctx, q.org, q.document)
			wantCalls := 1
			if item.completed {
				wantCalls = 2
			}
			if !errors.Is(err, ErrArtifactIntegrity) || result != (manualfit.CommittedFitsIndexV1{}) || len(q.calls) != wantCalls {
				t.Fatalf("contradictory/missing completed authority accepted or dispatch changed: %v", err)
			}
		})
	}
}

func TestPostgresFitsCommitmentRejectsNilConfigurationAndUnscopedRequests(t *testing.T) {
	var typedNil *fitsCommitmentQueriesStubV1
	for _, query := range []FitsIndexCommitmentQueriesV1{nil, typedNil, (*generated.Queries)(nil)} {
		if store, err := NewPostgresFitsIndexCommitmentStoreV1(query); store != nil || !errors.Is(err, ErrArtifactIntegrity) {
			t.Fatal("missing query configuration became a historical fallback")
		}
	}
	for _, store := range []*PostgresFitsIndexCommitmentStoreV1{nil, {}} {
		if result, err := store.LoadCommittedFitsIndexV1(context.Background(), uuid.New(), uuid.New()); result != (manualfit.CommittedFitsIndexV1{}) || !errors.Is(err, ErrArtifactIntegrity) {
			t.Fatal("zero store accepted a required/unread ceremony")
		}
	}
	for _, name := range []string{"nil-org", "nil-document"} {
		t.Run(name, func(t *testing.T) {
			store, q := fitsCommitmentDefaultFixtureV1(t)
			org, document := q.org, q.document
			if name == "nil-org" {
				org = uuid.Nil
			} else {
				document = uuid.Nil
			}
			if _, err := store.LoadCommittedFitsIndexV1(q.ctx, org, document); !errors.Is(err, ErrArtifactIntegrity) || len(q.calls) != 0 {
				t.Fatal("invalid scope reached a query")
			}
		})
	}
}

func TestPostgresFitsCommitmentRetentionUsesExistingLeapAndCeilingPolicy(t *testing.T) {
	for _, item := range []struct{ name, completion, expected string }{
		{name: "leap-normalizes-march-first", completion: "2020-02-29T12:13:14Z", expected: "2027-03-01T12:13:14Z"},
		{name: "fraction-ceils-second", completion: "2020-02-29T12:13:14.123456Z", expected: "2027-03-01T12:13:15Z"},
		{name: "utc-calendar-from-offset", completion: "2020-03-01T00:13:14.123456+02:00", expected: "2027-03-01T22:13:15Z"},
	} {
		t.Run(item.name, func(t *testing.T) {
			completion, err := time.Parse(time.RFC3339Nano, item.completion)
			if err != nil {
				t.Fatal(err)
			}
			store, q := fitsCommitmentStoreFixtureV1(t, completion)
			if q.doc.FinalizationRetainUntil.Time.Format(time.RFC3339Nano) != item.expected {
				t.Fatal("fixture/policy does not match literal expected UTC target")
			}
			result, err := store.LoadCommittedFitsIndexV1(q.ctx, q.org, q.document)
			if err != nil || !result.Required {
				t.Fatalf("canonical retained commitment rejected: %v", err)
			}
		})
	}
}

func TestPostgresFitsCommitmentQueryErrorsAndCancellationStayPrivate(t *testing.T) {
	for _, name := range []string{"document-error", "completed-error", "cancel-before", "cancel-after-document", "cancel-after-completed"} {
		t.Run(name, func(t *testing.T) {
			store, q := fitsCommitmentDefaultFixtureV1(t)
			privateCause := errors.New("private-query-or-cancellation-detail")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			q.ctx = ctx
			wantCalls := 0
			cancelled := strings.HasPrefix(name, "cancel-")
			switch name {
			case "document-error":
				q.docErr = privateCause
				wantCalls = 1
			case "completed-error":
				q.completedErr = privateCause
				wantCalls = 2
			case "cancel-before":
				cancel(privateCause)
			case "cancel-after-document":
				q.afterDocument = func() { cancel(privateCause) }
				wantCalls = 1
			case "cancel-after-completed":
				q.afterCompleted = func() { cancel(privateCause) }
				wantCalls = 2
			}
			result, err := store.LoadCommittedFitsIndexV1(ctx, q.org, q.document)
			if !errors.Is(err, ErrArtifactIntegrity) || !errors.Is(err, privateCause) || result != (manualfit.CommittedFitsIndexV1{}) || len(q.calls) != wantCalls || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatalf("private failure lost, disclosed or accepted: %v", err)
			}
			if cancelled && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation kind lost")
			}
		})
	}
}
