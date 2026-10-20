// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Integrity-only reconstruction fixtures reuse frozen historical package
// bytes, not renderer/S3/SQL acceptance. The production constructor requires
// generated.Queries; this private test adapter cannot be injected through it.
type fittedRecoveryQueriesTestV1 struct {
	*fittedFinalizeQueriesTestV1
	doc        *generated.GetFittedFinalizationRecoveryDocumentMetadataRow
	op         *generated.DocumentFinalizationPreparation
	signatures []*generated.ListFittedFinalizationRecoverySignatureMetadataRow
	outputs    []*generated.ListFittedFinalizationOutputsRow
	refs       []*generated.DocumentFinalizationReference
	completed  *generated.GetCompletedFittedFinalizationRow
	calls      int
	hook       func(string) error
}

func (q *fittedRecoveryQueriesTestV1) before(label string) error {
	q.calls++
	if q.hook != nil {
		return q.hook(label)
	}
	return nil
}
func (q *fittedRecoveryQueriesTestV1) GetFittedFinalizationRecoveryDocumentMetadata(ctx context.Context, p generated.GetFittedFinalizationRecoveryDocumentMetadataParams) (*generated.GetFittedFinalizationRecoveryDocumentMetadataRow, error) {
	if err := q.before("document"); err != nil {
		return nil, err
	}
	if p.ID != q.doc.ID || p.OrgID != q.doc.OrgID {
		return nil, errors.New("private scoped document refusal")
	}
	return q.doc, nil
}
func (q *fittedRecoveryQueriesTestV1) GetFittedFinalizationPreparation(ctx context.Context, p generated.GetFittedFinalizationPreparationParams) (*generated.DocumentFinalizationPreparation, error) {
	if err := q.before("journal"); err != nil {
		return nil, err
	}
	if p.ID != q.op.ID || p.OrgID != q.op.OrgID || p.DocumentID != q.op.DocumentID {
		return nil, errors.New("private scoped journal refusal")
	}
	return q.op, nil
}
func (q *fittedRecoveryQueriesTestV1) ListFittedFinalizationRecoverySignatureMetadata(ctx context.Context, p generated.ListFittedFinalizationRecoverySignatureMetadataParams) ([]*generated.ListFittedFinalizationRecoverySignatureMetadataRow, error) {
	if err := q.before("signatures"); err != nil {
		return nil, err
	}
	if p.DocumentID != q.op.DocumentID || p.OrgID != q.op.OrgID {
		return nil, errors.New("private signature scope")
	}
	return q.signatures, nil
}
func (q *fittedRecoveryQueriesTestV1) ListFittedFinalizationOutputs(ctx context.Context, p generated.ListFittedFinalizationOutputsParams) ([]*generated.ListFittedFinalizationOutputsRow, error) {
	if err := q.before("outputs"); err != nil {
		return nil, err
	}
	if p.PreparationID != q.op.ID || p.DocumentID != q.op.DocumentID || p.OrgID != q.op.OrgID {
		return nil, errors.New("private output scope")
	}
	return q.outputs, nil
}
func (q *fittedRecoveryQueriesTestV1) ListFittedFinalizationReferences(ctx context.Context, p generated.ListFittedFinalizationReferencesParams) ([]*generated.DocumentFinalizationReference, error) {
	if err := q.before("references"); err != nil {
		return nil, err
	}
	if p.PreparationID != q.op.ID || p.DocumentID != q.op.DocumentID || p.OrgID != q.op.OrgID {
		return nil, errors.New("private reference scope")
	}
	return q.refs, nil
}
func (q *fittedRecoveryQueriesTestV1) GetCompletedFittedFinalization(ctx context.Context, p generated.GetCompletedFittedFinalizationParams) (*generated.GetCompletedFittedFinalizationRow, error) {
	if err := q.before("completed"); err != nil {
		return nil, err
	}
	if p.DocumentID != q.op.DocumentID || p.OrgID != q.op.OrgID {
		return nil, errors.New("private completed scope")
	}
	return q.completed, nil
}

func (q *fittedRecoveryQueriesTestV1) ListFittedFinalizationRecoveryCompanions(ctx context.Context, p generated.ListFittedFinalizationRecoveryCompanionsParams) ([]*generated.SignatureFitCompanion, error) {
	if err := q.before("companions"); err != nil {
		return nil, err
	}
	if p.DocumentID != q.op.DocumentID || p.OrgID != q.op.OrgID {
		return nil, errors.New("private companion scope")
	}
	return q.companions, nil
}

var _ fittedRecoveryQueriesV1 = (*fittedRecoveryQueriesTestV1)(nil)

func fittedRecoveryStampTestV1(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func fittedRecoveryFixtureTestV1(t *testing.T, ordinary bool, legacyKind string) (*FittedFinalizationRecoveryV1, *fittedRecoveryQueriesTestV1, *fittedFinalizeStoreTestV1) {
	t.Helper()
	var doc *generated.Document
	var old *fittedFinalizeQueriesTestV1
	var store *fittedFinalizeStoreTestV1
	if legacyKind != "" {
		doc, old, store, _, _ = fittedMixedLegacyFixtureTestV1(t, legacyKind)
	} else {
		doc, old, store = fittedFinalizeFixtureTestV1(t)
	}
	if ordinary {
		old.fields = append(old.fields, &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: old.signatures[0].RecipientID, Valid: true}, Type: "text", Page: 2, Required: true, XPct: fittedNumericTestV1(t, "5.0000"), YPct: fittedNumericTestV1(t, "5.0000"), WPct: fittedNumericTestV1(t, "80.0000"), HPct: fittedNumericTestV1(t, "10.0000"), Value: pgtype.Text{String: "Original ordinary value\nsecond line", Valid: true}})
	}
	captured, err := LoadFittedFinalizationV1(context.Background(), old, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	g := captured.Geometry()
	geometry, err := json.Marshal(g.Pages)
	if err != nil {
		t.Fatal(err)
	}
	completion := doc.CompletionEffectiveAt.Time
	op := &generated.DocumentFinalizationPreparation{ID: uuid.New(), OrgID: doc.OrgID, DocumentID: doc.ID, CeremonyEpoch: doc.Article13NoticeEpochAt, CompletionEffectiveAt: doc.CompletionEffectiveAt, RetainUntil: doc.FinalizationRetainUntil, OriginalDocumentName: "Original immutable contract name", SourceStorageKey: captured.Source().Key, SourceVersionID: captured.Source().VersionID, SourceSha256: fittedHexTestV1(captured.Source().SHA256), SourceBytes: captured.Source().Bytes, SourcePages: int32(len(g.Pages)), GeometryPagesPayload: geometry, GeometrySha256: fittedHexTestV1(g.GeometrySHA256), FieldSnapshotPayload: captured.FieldSnapshotBytes(), FieldSnapshotSha256: fittedHexTestV1(captured.FieldSnapshotSHA256()), ExpectedOutputs: int32(len(captured.RequiredBasePages()) + 5), ExpectedReferences: int32(1 + len(old.objects) + len(captured.LegacySignatures())), FitReservedBytes: doc.SignatureFitReservedBytes, FinalPdfBytesLimit: 4096, FitsIndexBytesLimit: 65536, CertificatePdfBytesLimit: 4096, CertificatePayloadBytesLimit: 4096, CertificateSignatureBytesLimit: 256, ArchiveBudgetBytes: 32 << 20, OwnerID: uuid.New(), LeaseUntil: fittedRecoveryStampTestV1(completion.Add(time.Minute)), Attempts: 1, Status: "staging", CreatedAt: fittedRecoveryStampTestV1(completion), UpdatedAt: fittedRecoveryStampTestV1(completion), RetentionStartedAt: fittedRecoveryStampTestV1(completion.Add(time.Minute))}
	audit := []byte("original synthetic audit context; no private key")
	op.AuditSnapshotPayload = audit
	op.AuditSnapshotSha256 = fittedHexTestV1(fittedSHA256V1(audit))
	for _, n := range captured.RequiredBasePages() {
		op.RequiredBasePages = append(op.RequiredBasePages, int32(n))
	}
	if len(op.RequiredBasePages) > 0 {
		op.BaseBytesLimit = 4096
	}
	q := &fittedRecoveryQueriesTestV1{fittedFinalizeQueriesTestV1: old, op: op, doc: &generated.GetFittedFinalizationRecoveryDocumentMetadataRow{ID: doc.ID, OrgID: doc.OrgID, Status: doc.Status, SourceKind: doc.SourceKind, RequiresSignature: doc.RequiresSignature, SentAt: doc.SentAt, PdfStorageKey: doc.PdfStorageKey, PdfStorageVersionID: doc.PdfStorageVersionID, PdfSha256: bytes.Clone(doc.PdfSha256), EvidenceVersionPinsRequired: true, Article13NoticeEpochAt: doc.Article13NoticeEpochAt, Article13NoticeEpochV61Committed: true, CompletionEffectiveAt: doc.CompletionEffectiveAt, CompletionEffectiveAtBound: true, FinalizationRetainUntil: doc.FinalizationRetainUntil, SignatureFitReservedBytes: doc.SignatureFitReservedBytes, FitsIndexRequired: true}}
	for _, s := range old.signatures {
		q.signatures = append(q.signatures, &generated.ListFittedFinalizationRecoverySignatureMetadataRow{ID: s.ID, DocumentID: s.DocumentID, RecipientID: s.RecipientID, FieldID: s.FieldID, SignedAt: s.SignedAt, SignatureKind: s.SignatureKind, ImageStorageKey: s.ImageStorageKey, ImageVersionID: s.ImageVersionID.String, ImageSha256: bytes.Clone(s.ImageSha256), ImageVersionPinRequired: s.ImageVersionPinRequired, PresignExecutionID: s.PresignExecutionID, MetadataValid: true})
	}
	q.refs = append(q.refs, &generated.DocumentFinalizationReference{PreparationID: op.ID, Kind: "source", StorageKey: op.SourceStorageKey, VersionID: op.SourceVersionID, Sha256: bytes.Clone(op.SourceSha256), Bytes: op.SourceBytes, ContentType: "application/pdf", OwnerKey: doc.ID})
	for _, o := range old.objects {
		q.refs = append(q.refs, &generated.DocumentFinalizationReference{PreparationID: op.ID, Kind: "fit_" + o.Kind, SignatureID: pgtype.UUID{Bytes: old.signatures[0].ID, Valid: true}, SelectionID: pgtype.UUID{Bytes: old.selected.ID, Valid: true}, Page: o.Page, StorageKey: o.StorageKey, VersionID: o.VersionID.String, Sha256: bytes.Clone(o.Sha256), Bytes: o.Bytes, ContentType: o.ContentType, OwnerKey: old.signatures[0].ID})
	}
	for _, l := range captured.LegacySignatures() {
		q.refs = append(q.refs, &generated.DocumentFinalizationReference{PreparationID: op.ID, Kind: "legacy_span", SignatureID: pgtype.UUID{Bytes: l.SignatureID, Valid: true}, StorageKey: l.Object.Key, VersionID: l.Object.VersionID, Sha256: fittedHexTestV1(l.Object.SHA256), Bytes: l.Object.Bytes, ContentType: "text/html", OwnerKey: l.SignatureID})
	}
	for _, page := range op.RequiredBasePages {
		body := []byte("synthetic exact already-staged ordinary and legacy base; no rendering proof")
		pin := manualfit.ObjectPinV1{Key: "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/finalization/base/" + op.ID.String() + "/page-" + strconvRecoveryTestV1(int(page)) + ".pdf", VersionID: " original base+/opaque=version ", SHA256: fittedSHA256V1(body), Bytes: int64(len(body)), ContentType: "application/pdf"}
		store.blobs[fittedFinalizeBlobIDTestV1(pin.Key, pin.VersionID)] = fittedFinalizeBlobTestV1{pin, body}
		q.outputs = append(q.outputs, &generated.ListFittedFinalizationOutputsRow{PreparationID: op.ID, Kind: "base_pdf", Page: page, StorageKey: pin.Key, Sha256: fittedHexTestV1(pin.SHA256), Bytes: pin.Bytes, ContentType: pin.ContentType, UploadAttemptedAt: fittedRecoveryStampTestV1(op.RetentionStartedAt.Time.Add(time.Second)), UploadOwnerID: pgtype.UUID{Bytes: op.OwnerID, Valid: true}, VersionID: pgtype.Text{String: pin.VersionID, Valid: true}, ReadbackVerifiedAt: fittedRecoveryStampTestV1(op.RetentionStartedAt.Time.Add(2 * time.Second)), RetentionStartedAt: op.RetentionStartedAt})
	}
	store.reads = nil
	old.fitReads = 0
	return &FittedFinalizationRecoveryV1{queries: q, reader: store}, q, store
}
func strconvRecoveryTestV1(n int) string {
	if n == 1 {
		return "1"
	}
	if n == 2 {
		return "2"
	}
	panic("fixture page")
}
func fittedRecoveryRunTestV1(ctx context.Context, r *FittedFinalizationRecoveryV1, q *fittedRecoveryQueriesTestV1) (*FittedJournalRecoveryV1, error) {
	return r.RecoverV1(ctx, q.op.OrgID, q.op.DocumentID, q.op.ID)
}

func TestFittedRecoveryUsesOriginalJournalAndArchivesAfterProjectionV1(t *testing.T) {
	for _, kind := range []string{"", "manual", "delegated_grant_v1"} {
		t.Run(kind, func(t *testing.T) {
			r, q, store := fittedRecoveryFixtureTestV1(t, false, kind)
			originalBasis := bytes.Clone(q.op.FieldSnapshotPayload)
			for _, s := range q.fittedFinalizeQueriesTestV1.signatures {
				s.TypedName = "redacted name"
				s.Font = "redacted font"
			}
			for _, f := range q.fields {
				f.Value = pgtype.Text{String: "redacted"}
				f.XPct = fittedNumericTestV1(t, "90.0000")
			}
			// Unselected inventory cleanup may lower the live mutable counter. The
			// admitted original86 ceiling, not that projection, governs reconstruction.
			q.doc.SignatureFitReservedBytes = 0
			recovered, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if err != nil {
				t.Fatal(err)
			}
			s := recovered.Snapshot()
			if recovered.PreparationID() != q.op.ID || recovered.OriginalDocumentName() != q.op.OriginalDocumentName || !bytes.Equal(s.FieldSnapshotBytes(), originalBasis) || len(s.Entries()) != 1 || s.Entries()[0].OriginalName() == "redacted name" || s.Entries()[0].Font() == "redacted font" || len(store.retained) != 0 {
				t.Fatal("recovery used hot fields/names, lost source authority, or performed an effect")
			}
			if kind != "" {
				l := s.LegacySignatures()
				if len(l) != 1 || l[0].Kind != kind || l[0].OriginalName != "Original\u00a0Legacy Name" || l[0].Font != "historical unknown font" {
					t.Fatal("lost frozen legacy adoption")
				}
				raw, err := s.LegacySpanBytes(l[0].SignatureID)
				if err != nil || !bytes.Contains(raw, []byte("Original&nbsp;Legacy Name")) {
					t.Fatal("lost exact legacy bytes")
				}
				raw[0] = '!'
				again, _ := s.LegacySpanBytes(l[0].SignatureID)
				if bytes.Equal(raw, again) {
					t.Fatal("legacy accessor aliases")
				}
			}
			copied := s.FieldSnapshotBytes()
			copied[0] = '!'
			if bytes.Equal(copied, s.FieldSnapshotBytes()) {
				t.Fatal("basis aliases generated row")
			}
			q.op.FieldSnapshotPayload[0] = '!'
			if !bytes.Equal(s.FieldSnapshotBytes(), originalBasis) {
				t.Fatal("snapshot retains query bytea alias")
			}
			for _, pin := range store.reads {
				if !manualfit.ValidObjectVersionV1(pin.VersionID) {
					t.Fatal("nonpositive version")
				}
			}
		})
	}
}

func TestEngineFittedCompositionRefusesOldHotRowSnapshotV1(t *testing.T) {
	doc, hot, store := fittedFinalizeFixtureTestV1(t)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), hot, store, doc)
	if err != nil || snapshot == nil {
		t.Fatalf("capture fixture failed before the application dispatch boundary: %v", err)
	}
	before := len(store.reads)
	engine := &Engine{}
	if _, err := engine.ComposeFittedPDFV1(context.Background(), snapshot); !errors.Is(err, ErrFittedJournalRecoveryRequiredV1) || len(store.reads) != before {
		t.Fatal("application composition accepted a hot-row snapshot without locked journal recovery")
	}
	r, q, _ := fittedRecoveryFixtureTestV1(t, false, "")
	recovered, err := fittedRecoveryRunTestV1(context.Background(), r, q)
	if err != nil || !recovered.Snapshot().journalRecoveryBound {
		t.Fatalf("durable recovery did not bind its immutable snapshot: %v", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.ComposeFittedPDFV1(canceled, snapshot); !errors.Is(err, context.Canceled) {
		t.Fatal("composition dispatch lost cancellation behind its journal refusal")
	}
}

func TestFittedRecoveryOrdinaryValuesAndOriginalBaseV1(t *testing.T) {
	r, q, store := fittedRecoveryFixtureTestV1(t, true, "")
	result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
	if err != nil {
		t.Fatal(err)
	}
	s := result.Snapshot()
	if len(s.BasePages()) != 1 || s.BasePages()[0].Page != 2 || !bytes.Contains(s.FieldSnapshotBytes(), []byte("Original ordinary value")) {
		t.Fatal("missing frozen ordinary values/base")
	}
	raw, err := s.BasePDFBytes(2)
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = '!'
	again, _ := s.BasePDFBytes(2)
	if bytes.Equal(raw, again) {
		t.Fatal("base accessor aliases provider bytes")
	}
	if len(store.retained) != 0 {
		t.Fatal("read adapter retained an object")
	}
}

func TestFittedRecoveryMetadataRefusalsBeforeProviderReadsV1(t *testing.T) {
	cases := []struct {
		name   string
		change func(*fittedRecoveryQueriesTestV1)
	}{
		{"tenant", func(q *fittedRecoveryQueriesTestV1) { q.doc.OrgID = uuid.New() }},
		{"operation document", func(q *fittedRecoveryQueriesTestV1) { q.op.DocumentID = uuid.New() }},
		{"envelope", func(q *fittedRecoveryQueriesTestV1) { q.doc.IsEnvelope = true }},
		{"unsafe parent", func(q *fittedRecoveryQueriesTestV1) {
			q.doc.ParentEnvelopeID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}},
		{"epoch", func(q *fittedRecoveryQueriesTestV1) {
			q.op.CeremonyEpoch.Time = q.op.CeremonyEpoch.Time.Add(time.Second)
		}},
		{"completion", func(q *fittedRecoveryQueriesTestV1) { q.doc.CompletionEffectiveAtBound = false }},
		{"retention ceil", func(q *fittedRecoveryQueriesTestV1) { q.op.RetainUntil.Time = q.op.RetainUntil.Time.Add(time.Second) }},
		{"source version", func(q *fittedRecoveryQueriesTestV1) { q.op.SourceVersionID = "replacement" }},
		{"geometry original hash", func(q *fittedRecoveryQueriesTestV1) { q.op.GeometryPagesPayload[1] = '!' }},
		{"basis original hash", func(q *fittedRecoveryQueriesTestV1) { q.op.FieldSnapshotPayload[1] = '!' }},
		{"canonical basis", func(q *fittedRecoveryQueriesTestV1) {
			q.op.FieldSnapshotPayload = append([]byte(" "), q.op.FieldSnapshotPayload...)
			q.op.FieldSnapshotSha256 = fittedHexTestV1(fittedSHA256V1(q.op.FieldSnapshotPayload))
		}},
		{"invalid signature metadata", func(q *fittedRecoveryQueriesTestV1) { q.signatures[0].MetadataValid = false }},
		{"101 sentinel", func(q *fittedRecoveryQueriesTestV1) {
			for len(q.signatures) < 101 {
				q.signatures = append(q.signatures, q.signatures[0])
			}
		}},
		{"opaque null version", func(q *fittedRecoveryQueriesTestV1) { q.signatures[0].ImageVersionID = "null" }},
		{"incomplete signed set", func(q *fittedRecoveryQueriesTestV1) { q.signatures = nil }},
		{"missing companion", func(q *fittedRecoveryQueriesTestV1) { q.companions = nil }},
		{"wrong selected identity", func(q *fittedRecoveryQueriesTestV1) { q.selected.ID = uuid.New() }},
		{"selection floor", func(q *fittedRecoveryQueriesTestV1) {
			q.selected.RetainUntil.Time = q.selected.RetainUntil.Time.Add(time.Second)
		}},
		{"page version", func(q *fittedRecoveryQueriesTestV1) { q.objects[1].VersionID.String = "null" }},
		{"missing page", func(q *fittedRecoveryQueriesTestV1) { q.objects = q.objects[:2] }},
		{"original attempt missing", func(q *fittedRecoveryQueriesTestV1) { q.objects[0].UploadAttemptedAt.Valid = false }},
		{"reference version", func(q *fittedRecoveryQueriesTestV1) { q.refs[0].VersionID = "different" }},
		{"reference owner", func(q *fittedRecoveryQueriesTestV1) { q.refs[0].OwnerKey = uuid.New() }},
		{"archive cap", func(q *fittedRecoveryQueriesTestV1) { q.op.ArchiveBudgetBytes = manualfit.MaxEvidenceBytesV1 + 1 }},
		{"archive too small", func(q *fittedRecoveryQueriesTestV1) { q.op.ArchiveBudgetBytes = 1 }},
		{"reserved budget", func(q *fittedRecoveryQueriesTestV1) { q.op.FitReservedBytes = 1 }},
		{"staging terminal retention", func(q *fittedRecoveryQueriesTestV1) {
			q.op.RetentionCompletedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(time.Second))
		}},
		{"finalizing completed timestamp", func(q *fittedRecoveryQueriesTestV1) { q.doc.CompletedAt = q.op.CompletionEffectiveAt }},
		{"finalizing index pair", func(q *fittedRecoveryQueriesTestV1) {
			q.doc.FitsIndexPreparationID = pgtype.UUID{Bytes: q.op.ID, Valid: true}
		}},
		{"oversized companion set", func(q *fittedRecoveryQueriesTestV1) {
			for len(q.companions) < 101 {
				q.companions = append(q.companions, q.companions[0])
			}
		}},
		{"cancelled lease attempts", func(q *fittedRecoveryQueriesTestV1) { q.op.Attempts = 9 }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
			test.change(q)
			result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if result != nil || err == nil || len(store.reads) != 0 || len(store.retained) != 0 {
				t.Fatalf("metadata refusal performed provider work: result=%v reads=%d error=%v", result, len(store.reads), err)
			}
			if strings.Contains(err.Error(), "private") {
				t.Fatal("private error exposed")
			}
		})
	}
}
func TestFittedRecoveryRequiredBaseUnknownRefusesBeforeProviderReadsV1(t *testing.T) {
	for _, mode := range []string{"missing", "reserved", "unknown attempted", "version without readback", "wrong operation", "wrong media", "unsafe key", "processing ceiling"} {
		t.Run(mode, func(t *testing.T) {
			r, q, store := fittedRecoveryFixtureTestV1(t, true, "")
			switch mode {
			case "missing":
				q.outputs = nil
			case "reserved":
				o := q.outputs[0]
				o.UploadAttemptedAt = pgtype.Timestamptz{}
				o.UploadOwnerID = pgtype.UUID{}
				o.VersionID = pgtype.Text{}
				o.ReadbackVerifiedAt = pgtype.Timestamptz{}
			case "unknown attempted":
				q.outputs[0].VersionID = pgtype.Text{}
				q.outputs[0].ReadbackVerifiedAt = pgtype.Timestamptz{}
			case "version without readback":
				q.outputs[0].ReadbackVerifiedAt = pgtype.Timestamptz{}
			case "wrong operation":
				q.outputs[0].StorageKey = strings.Replace(q.outputs[0].StorageKey, q.op.ID.String(), uuid.New().String(), 1)
			case "wrong media":
				q.outputs[0].ContentType = "text/html"
			case "unsafe key":
				q.outputs[0].StorageKey += "\n"
			case "processing ceiling":
				q.op.BaseBytesLimit = int64(sanitize.MaxPDFBytes)
				q.op.ArchiveBudgetBytes = manualfit.MaxEvidenceBytesV1
				q.outputs[0].Bytes = int64(sanitize.MaxPDFBytes)
			}
			result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if err == nil || result != nil || len(store.reads) != 0 {
				t.Fatalf("unstaged/unsafe base admitted provider work: %v", err)
			}
		})
	}
}
func TestFittedRecoveryUnknownFinalReservationSurvivesReadOnlySnapshotV1(t *testing.T) {
	r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
	body := []byte("original nondeterministic final bytes reserved in durable journal")
	digest := fittedSHA256V1(body)
	q.outputs = append(q.outputs, &generated.ListFittedFinalizationOutputsRow{PreparationID: q.op.ID, Kind: "final_pdf", StorageKey: "org/" + q.op.OrgID.String() + "/documents/" + q.op.DocumentID.String() + "/final-" + digest + ".pdf", Sha256: fittedHexTestV1(digest), Bytes: int64(len(body)), ContentType: "application/pdf", UploadAttemptedAt: fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(time.Second)), UploadOwnerID: pgtype.UUID{Bytes: q.op.OwnerID, Valid: true}, RetentionStartedAt: q.op.RetentionStartedAt})
	result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
	if err != nil {
		t.Fatal(err)
	}
	outputs := result.ReservedOutputs()
	if len(outputs) != 1 || outputs[0].Kind != "final_pdf" || !outputs[0].UploadAttempted || outputs[0].Object.VersionID != "" || outputs[0].ReadbackVerified {
		t.Fatal("unknown original attempt was erased")
	}
	outputs[0].Object.Key = "replacement"
	if result.ReservedOutputs()[0].Object.Key == "replacement" {
		t.Fatal("reservation accessor aliases")
	}
	for _, pin := range store.reads {
		if strings.Contains(pin.Key, "/final-") {
			t.Fatal("recovery inferred a final version or retried an unknown upload")
		}
	}
	if len(store.retained) != 0 {
		t.Fatal("recovery made irreversible effects")
	}
	before := len(store.reads)
	if _, err = ComposeFittedPDFV1(context.Background(), store, result.Snapshot()); !errors.Is(err, ErrFittedOriginalOutputsRequiredV1) || len(store.reads) != before {
		t.Fatal("reserved output recovery dispatched regeneration")
	}
}
func TestFittedRecoveryCancellationPreservesPrivateCauseAndStopsV1(t *testing.T) {
	private := errors.New("private recovery cancellation owner")
	for _, phase := range []string{"before", "journal", "provider manifest", "provider source"} {
		t.Run(phase, func(t *testing.T) {
			r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			switch phase {
			case "before":
				cancel(private)
			case "journal":
				q.hook = func(label string) error {
					if label == "journal" {
						cancel(private)
					}
					return nil
				}
			case "provider manifest", "provider source":
				store.readHook = func(pin manualfit.ObjectPinV1) error {
					if phase == "provider manifest" && strings.HasSuffix(pin.Key, "manifest.json") || phase == "provider source" && pin.Key == q.op.SourceStorageKey {
						cancel(private)
					}
					return nil
				}
			}
			result, err := fittedRecoveryRunTestV1(ctx, r, q)
			if result != nil || !errors.Is(err, context.Canceled) || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
				t.Fatalf("lost cancellation ownership: %v", err)
			}
			if phase == "before" && (q.calls != 0 || len(store.reads) != 0) || phase == "journal" && len(store.reads) != 0 || phase == "provider manifest" && len(store.reads) != 1 {
				t.Fatal("continued after caller cancellation")
			}
		})
	}
}
func TestFittedRecoveryCanonicalPayloadRefusesNestedDuplicateAndUnknownV1(t *testing.T) {
	var wire fittedFieldBasisDocumentV1
	for _, raw := range [][]byte{[]byte(strings.Repeat("[", 17) + strings.Repeat("]", 17)), []byte("{\"Schema\":\"x\",\"Schema\":\"y\",\"DocumentID\":\"00000000-0000-0000-0000-000000000000\",\"Fields\":null,\"Legacy\":null}"), []byte("{\"Schema\":\"x\",\"DocumentID\":\"00000000-0000-0000-0000-000000000000\",\"Fields\":null,\"Legacy\":null,\"New\":true}"), bytes.Repeat([]byte(" "), (1<<20)+1)} {
		if fittedRecoveryCanonicalV1(raw, &wire, 1<<20) == nil {
			t.Fatal("accepted ambiguous/unbounded original basis")
		}
	}
}

type fittedRecoveryNilTxTestV1 struct{ pgx.Tx }

func TestFittedRecoveryProductionConstructorRejectsTypedNilV1(t *testing.T) {
	var tx pgx.Tx
	var typedNilTx *fittedRecoveryNilTxTestV1
	var reader *fittedFinalizeStoreTestV1
	if _, err := NewFittedFinalizationRecoveryV1(tx, reader); err == nil {
		t.Fatal("accepted nil transaction/reader")
	}
	if _, err := NewFittedFinalizationRecoveryV1(typedNilTx, &fittedFinalizeStoreTestV1{}); err == nil {
		t.Fatal("accepted typed nil transaction")
	}
	if _, err := NewFittedFinalizationRecoveryV1(&fittedRecoveryNilTxTestV1{}, reader); err == nil {
		t.Fatal("accepted typed nil reader")
	}
}

func TestFittedRecoveryExactDescriptorBudgetBeforeSourceCopyV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	s, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.entries[0].retained.PDFByteCount(1)
	if err != nil {
		t.Fatal(err)
	}
	s.source.Bytes = int64(sanitize.MaxPDFBytes - n)
	before := len(store.reads)
	err = fittedRecoveryProcessingV1(context.Background(), s, nil, int64(sanitize.MaxPDFBytes))
	if !errors.Is(err, sanitize.ErrPDFTooLarge) || len(store.reads) != before {
		t.Fatal("descriptor admission copied/read source before refusal")
	}
}

// Prepared/published history requires the complete inventory and immutable
// completed callback. A staging snapshot is not publication evidence.
func TestFittedRecoveryPreparedAndPublishedRequireCompleteTerminalPairV1(t *testing.T) {
	for _, status := range []string{"prepared", "published"} {
		t.Run(status, func(t *testing.T) {
			r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
			q.op.Status = status
			if status == "published" {
				q.doc.Status = "completed"
				q.doc.CompletedAt = q.op.CompletionEffectiveAt
				q.doc.FitsIndexPreparationID = pgtype.UUID{Bytes: q.op.ID, Valid: true}
				q.op.RetentionCompletedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(time.Second))
				q.op.PublicationCommitAttemptedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(2 * time.Second))
				q.op.PublishedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(3 * time.Second))
			}
			result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if err == nil || result != nil || len(store.reads) != 0 {
				t.Fatal("partial inventory became prepared/published authority")
			}
		})
	}
}

func TestFittedRecoveryOutputCheckpointOrderMatchesDurableProtocolV1(t *testing.T) {
	for _, state := range []string{"reserved", "retention started", "attempted unknown", "known version", "readback", "retention complete"} {
		t.Run(state, func(t *testing.T) {
			_, q, _ := fittedRecoveryFixtureTestV1(t, false, "")
			body := []byte("original once-reserved final bytes")
			digest := fittedSHA256V1(body)
			o := &generated.ListFittedFinalizationOutputsRow{PreparationID: q.op.ID, Kind: "final_pdf", StorageKey: "org/" + q.op.OrgID.String() + "/documents/" + q.op.DocumentID.String() + "/final-" + digest + ".pdf", Sha256: fittedHexTestV1(digest), Bytes: int64(len(body)), ContentType: "application/pdf"}
			if state != "reserved" {
				o.RetentionStartedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(time.Second))
			}
			if state != "reserved" && state != "retention started" {
				o.UploadAttemptedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(2 * time.Second))
				o.UploadOwnerID = pgtype.UUID{Bytes: q.op.OwnerID, Valid: true}
			}
			if state == "known version" || state == "readback" || state == "retention complete" {
				o.VersionID = pgtype.Text{String: " exact original+/opaque=version ", Valid: true}
			}
			if state == "readback" || state == "retention complete" {
				o.ReadbackVerifiedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(3 * time.Second))
			}
			if state == "retention complete" {
				o.RetentionCompletedAt = fittedRecoveryStampTestV1(q.op.RetentionStartedAt.Time.Add(4 * time.Second))
			}
			rows, _, err := fittedRecoveryOutputsV1(context.Background(), q.op, []*generated.ListFittedFinalizationOutputsRow{o})
			if err != nil || len(rows) != 1 {
				t.Fatalf("valid retained-before-upload state refused: %v", err)
			}
			if rows[0].UploadAttempted != o.UploadAttemptedAt.Valid || rows[0].ReadbackVerified != o.ReadbackVerifiedAt.Valid || rows[0].RetentionStarted != o.RetentionStartedAt.Valid {
				t.Fatal("checkpoint states conflated")
			}
		})
	}
}
func TestFittedRecoveryUnusedBaseCeilingDoesNotBecomeActualProcessingV1(t *testing.T) {
	r, q, _ := fittedRecoveryFixtureTestV1(t, true, "")
	q.op.BaseBytesLimit = int64(sanitize.MaxPDFBytes)
	q.op.ArchiveBudgetBytes = manualfit.MaxEvidenceBytesV1
	if _, err := fittedRecoveryRunTestV1(context.Background(), r, q); err != nil {
		t.Fatalf("unused producer headroom replaced exact processing bytes: %v", err)
	}
}
func fittedRecoveryCompleteFixtureTestV1(t *testing.T, published bool) (*FittedFinalizationRecoveryV1, *fittedRecoveryQueriesTestV1, *fittedFinalizeStoreTestV1) {
	t.Helper()
	r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
	p := q.op
	p.Status = "prepared"
	p.CertificateInputPayload = []byte("original frozen signed certificate HTML; synthetic integrity fixture")
	p.CertificateInputSha256 = fittedHexTestV1(fittedSHA256V1(p.CertificateInputPayload))
	prefix := "org/" + p.OrgID.String() + "/documents/" + p.DocumentID.String() + "/"
	for _, kind := range []string{"final_pdf", "fits_index", "certificate_pdf", "certificate_payload", "certificate_signature"} {
		body := []byte("synthetic original reserved " + kind)
		if kind == "certificate_payload" {
			body = bytes.Clone(p.CertificateInputPayload)
		}
		digest := fittedSHA256V1(body)
		mime, key := "application/pdf", ""
		switch kind {
		case "final_pdf":
			key = prefix + "final-" + digest + ".pdf"
		case "fits_index":
			key = manualfit.IndexStorageKeyV1(p.OrgID, p.DocumentID, p.ID)
			mime = "application/json"
		case "certificate_pdf":
			key = prefix + "audit-" + digest + ".pdf"
		case "certificate_payload":
			key = prefix + "audit-payload-" + digest + ".txt"
			mime = "text/plain"
		case "certificate_signature":
			key = prefix + "audit-signature-" + digest + ".txt"
			mime = "text/plain"
		}
		q.outputs = append(q.outputs, &generated.ListFittedFinalizationOutputsRow{PreparationID: p.ID, Kind: kind, StorageKey: key, Sha256: fittedHexTestV1(digest), Bytes: int64(len(body)), ContentType: mime, RetentionStartedAt: fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(time.Second)), UploadAttemptedAt: fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(2 * time.Second)), UploadOwnerID: pgtype.UUID{Bytes: p.OwnerID, Valid: true}, VersionID: pgtype.Text{String: " frozen terminal+/opaque=version ", Valid: true}, ReadbackVerifiedAt: fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(3 * time.Second))})
	}
	if !published {
		return r, q, store
	}
	p.Status = "published"
	p.RetentionCompletedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(6 * time.Second))
	p.PublicationCommitAttemptedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(7 * time.Second))
	p.PublishedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(8 * time.Second))
	q.doc.Status = "completed"
	q.doc.CompletedAt = p.CompletionEffectiveAt
	q.doc.FitsIndexPreparationID = pgtype.UUID{Bytes: p.ID, Valid: true}
	c := &generated.GetCompletedFittedFinalizationRow{ID: p.DocumentID, OrgID: p.OrgID, FitsIndexRequired: true, FitsIndexPreparationID: q.doc.FitsIndexPreparationID, OriginalDocumentName: p.OriginalDocumentName, CeremonyEpoch: p.CeremonyEpoch, CompletionEffectiveAt: p.CompletionEffectiveAt, RetainUntil: p.RetainUntil, FieldSnapshotSha256: bytes.Clone(p.FieldSnapshotSha256), GeometrySha256: bytes.Clone(p.GeometrySha256), PublishedAt: p.PublishedAt}
	for _, o := range q.outputs {
		o.RetentionCompletedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(4 * time.Second))
		key := pgtype.Text{String: o.StorageKey, Valid: true}
		switch o.Kind {
		case "final_pdf":
			q.doc.FinalPdfKey = key
			q.doc.FinalPdfVersionID = o.VersionID
			q.doc.FinalPdfSha = bytes.Clone(o.Sha256)
			c.FinalPdfKey = key
			c.FinalPdfVersionID = o.VersionID
			c.FinalPdfSha = bytes.Clone(o.Sha256)
			c.FinalPdfBytes = o.Bytes
		case "fits_index":
			q.doc.FitsIndexStorageKey = key
			q.doc.FitsIndexVersionID = o.VersionID
			q.doc.FitsIndexSha256 = bytes.Clone(o.Sha256)
			q.doc.FitsIndexBytes = pgtype.Int8{Int64: o.Bytes, Valid: true}
			c.FitsIndexStorageKey = key
			c.FitsIndexVersionID = o.VersionID
			c.FitsIndexSha256 = bytes.Clone(o.Sha256)
			c.FitsIndexBytes = q.doc.FitsIndexBytes
		case "certificate_pdf":
			q.doc.AuditCertKey = key
			q.doc.AuditCertVersionID = o.VersionID
			q.doc.AuditCertSha256 = bytes.Clone(o.Sha256)
			c.AuditCertKey = key
			c.AuditCertVersionID = o.VersionID
			c.AuditCertSha256 = bytes.Clone(o.Sha256)
		case "certificate_payload":
			q.doc.AuditPayloadKey = key
			q.doc.AuditPayloadVersionID = o.VersionID
			q.doc.AuditPayloadSha256 = bytes.Clone(o.Sha256)
			c.AuditPayloadKey = key
			c.AuditPayloadVersionID = o.VersionID
			c.AuditPayloadSha256 = bytes.Clone(o.Sha256)
		case "certificate_signature":
			q.doc.AuditSignatureKey = key
			q.doc.AuditSignatureVersionID = o.VersionID
			q.doc.AuditSignatureSha256 = bytes.Clone(o.Sha256)
			c.AuditSignatureKey = key
			c.AuditSignatureVersionID = o.VersionID
			c.AuditSignatureSha256 = bytes.Clone(o.Sha256)
		}
	}
	for _, ref := range q.refs {
		ref.RetentionStartedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(4 * time.Second))
		ref.RetentionCompletedAt = fittedRecoveryStampTestV1(p.RetentionStartedAt.Time.Add(5 * time.Second))
	}
	q.completed = c
	return r, q, store
}
func TestFittedRecoveryPreparedAndPublishedReadOnlyOriginalsV1(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "published"}[published], func(t *testing.T) {
			r, q, store := fittedRecoveryCompleteFixtureTestV1(t, published)
			result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.ReservedOutputs()) != 5 || len(store.retained) != 0 {
				t.Fatal("terminal reservation set lost or retention effects made")
			}
			before := len(store.reads)
			if _, err = ComposeFittedPDFV1(context.Background(), store, result.Snapshot()); !errors.Is(err, ErrFittedOriginalOutputsRequiredV1) || len(store.reads) != before {
				t.Fatal("terminal snapshot regenerated reserved output")
			}
		})
	}
}
func TestFittedRecoveryPublishedCallbackTupleRefusalsBeforeProviderV1(t *testing.T) {
	for _, field := range []string{"missing callback", "different index version", "different final bytes", "different basis", "different completion", "unretained reference"} {
		t.Run(field, func(t *testing.T) {
			r, q, store := fittedRecoveryCompleteFixtureTestV1(t, true)
			switch field {
			case "missing callback":
				q.completed = nil
			case "different index version":
				q.completed.FitsIndexVersionID.String = "different"
			case "different final bytes":
				q.completed.FinalPdfBytes++
			case "different basis":
				q.completed.FieldSnapshotSha256[0] ^= 1
			case "different completion":
				q.completed.CompletionEffectiveAt.Time = q.completed.CompletionEffectiveAt.Time.Add(time.Second)
			case "unretained reference":
				q.refs[0].RetentionCompletedAt.Valid = false
			}
			result, err := fittedRecoveryRunTestV1(context.Background(), r, q)
			if err == nil || result != nil || len(store.reads) != 0 {
				t.Fatal("published pairing refusal performed provider work")
			}
		})
	}
}

func TestFittedRecoveryArrayCardinalityBeforeTypedDecodeV1(t *testing.T) {
	for _, test := range []struct {
		raw       string
		max, want int
		refuse    bool
	}{{"[]", 0, 0, false}, {"[{},{}]", 2, 2, false}, {"[\"comma,bracket[]\",[1,2],{}]", 3, 3, false}, {"[null,null,null]", 2, 0, true}, {"[{},{}]", 1, 0, true}} {
		got, err := fittedRecoveryArrayCountV1(context.Background(), []byte(test.raw), test.max)
		if test.refuse {
			if err == nil {
				t.Fatal("oversized typed cardinality admitted")
			}
		} else if err != nil || got != test.want {
			t.Fatalf("array member count changed: got=%d error=%v", got, err)
		}
	}
	r, q, store := fittedRecoveryFixtureTestV1(t, false, "")
	q.op.GeometryPagesPayload = []byte("[" + strings.Repeat("null,", int(q.op.SourcePages)) + "null]")
	q.op.GeometrySha256 = fittedHexTestV1(fittedSHA256V1(q.op.GeometryPagesPayload))
	if _, err := fittedRecoveryRunTestV1(context.Background(), r, q); err == nil || len(store.reads) != 0 {
		t.Fatal("oversized geometry decoded/retrieved")
	}
}
