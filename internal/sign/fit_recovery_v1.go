// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This private seam permits source tests without exposing caller-supplied
// metadata as production authority. Production construction requires the real
// generated scoped journal queries, normally bound to the caller's locked tx.
type fittedRecoveryQueriesV1 interface {
	GetFittedFinalizationRecoveryDocumentMetadata(context.Context, generated.GetFittedFinalizationRecoveryDocumentMetadataParams) (*generated.GetFittedFinalizationRecoveryDocumentMetadataRow, error)
	ListFittedFinalizationRecoverySignatureMetadata(context.Context, generated.ListFittedFinalizationRecoverySignatureMetadataParams) ([]*generated.ListFittedFinalizationRecoverySignatureMetadataRow, error)
	GetFittedFinalizationPreparation(context.Context, generated.GetFittedFinalizationPreparationParams) (*generated.DocumentFinalizationPreparation, error)
	ListFittedFinalizationOutputs(context.Context, generated.ListFittedFinalizationOutputsParams) ([]*generated.ListFittedFinalizationOutputsRow, error)
	ListFittedFinalizationReferences(context.Context, generated.ListFittedFinalizationReferencesParams) ([]*generated.DocumentFinalizationReference, error)
	ListFittedFinalizationRecoveryCompanions(context.Context, generated.ListFittedFinalizationRecoveryCompanionsParams) ([]*generated.SignatureFitCompanion, error)
	GetSignatureFitSelection(context.Context, generated.GetSignatureFitSelectionParams) (*generated.SignatureFitSelection, error)
	GetSignatureFitPreparation(context.Context, generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error)
	ListSignatureFitObjects(context.Context, generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error)
	GetCompletedFittedFinalization(context.Context, generated.GetCompletedFittedFinalizationParams) (*generated.GetCompletedFittedFinalizationRow, error)
}

var _ fittedRecoveryQueriesV1 = (*generated.Queries)(nil)

type FittedFinalizationRecoveryV1 struct {
	queries fittedRecoveryQueriesV1
	reader  manualfit.BoundedReaderV1
}

// NewFittedFinalizationRecoveryV1 requires the actual caller-owned pgx
// transaction and builds the real generated queries itself. RecoverV1 takes
// the bounded document FOR UPDATE lock on a read-committed transaction. Hold it through
// composition/original-body handoff; committing early removes the reservation
// fence. This does not acquire signing authority, a lease, credential admission
// or physical reconciliation of an older unknown SQL session/commit.
func NewFittedFinalizationRecoveryV1(tx pgx.Tx, reader manualfit.BoundedReaderV1) (*FittedFinalizationRecoveryV1, error) {
	if fittedRecoveryNilV1(tx) || fittedRecoveryNilV1(reader) {
		return nil, ErrFittedFinalizationV1
	}
	return &FittedFinalizationRecoveryV1{queries: generated.New(tx), reader: reader}, nil
}
func fittedRecoveryNilV1(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return v.IsNil()
	}
	return false
}

// FittedReservedOutputV1 records an existing reservation, including unknown
// upload attempts. Its presence requires recovery of the original journal
// bytea; it never permits rendering, signing or uploading replacement bytes.
type FittedReservedOutputV1 struct {
	Kind               string
	Page               int
	Object             manualfit.ObjectPinV1
	UploadAttempted    bool
	ReadbackVerified   bool
	RetentionStarted   bool
	RetentionCompleted bool
}
type FittedJournalRecoveryV1 struct {
	preparationID                uuid.UUID
	originalDocumentName, status string
	snapshot                     *FittedFinalizationV1
	outputs                      []FittedReservedOutputV1
}

func (r *FittedJournalRecoveryV1) PreparationID() uuid.UUID {
	if r == nil {
		return uuid.Nil
	}
	return r.preparationID
}
func (r *FittedJournalRecoveryV1) OriginalDocumentName() string {
	if r == nil {
		return ""
	}
	return r.originalDocumentName
}
func (r *FittedJournalRecoveryV1) Status() string {
	if r == nil {
		return ""
	}
	return r.status
}
func (r *FittedJournalRecoveryV1) Snapshot() *FittedFinalizationV1 {
	if r == nil {
		return nil
	}
	return r.snapshot
}
func (r *FittedJournalRecoveryV1) ReservedOutputs() []FittedReservedOutputV1 {
	if r == nil {
		return nil
	}
	return append([]FittedReservedOutputV1(nil), r.outputs...)
}

// RecoverV1 reconstructs original frozen authority and exact archived inputs.
// It performs reads only: no renderer, worker dispatch, PUT, retention, cleanup,
// authorization, completion or fallback to current DSR-projected field/name
// rows. Staging can be incomplete, but every required ordinary/legacy base must
// already have a positive readback pin before a composition snapshot exists.
func (r *FittedFinalizationRecoveryV1) RecoverV1(ctx context.Context, orgID, documentID, preparationID uuid.UUID) (result *FittedJournalRecoveryV1, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			result = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || r == nil || fittedRecoveryNilV1(r.queries) || fittedRecoveryNilV1(r.reader) || orgID == uuid.Nil || documentID == uuid.Nil || preparationID == uuid.Nil {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	meta, err := r.queries.GetFittedFinalizationRecoveryDocumentMetadata(ctx, generated.GetFittedFinalizationRecoveryDocumentMetadataParams{ID: documentID, OrgID: orgID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	p, err := r.queries.GetFittedFinalizationPreparation(ctx, generated.GetFittedFinalizationPreparationParams{ID: preparationID, OrgID: orgID, DocumentID: documentID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	doc, err := fittedRecoveryDocumentV1(meta, p, orgID, documentID, preparationID)
	if err != nil {
		return nil, err
	}
	geometry, fields, basis, err := fittedRecoveryBasisV1(ctx, p)
	if err != nil {
		return nil, err
	}
	rows, err := r.queries.ListFittedFinalizationRecoverySignatureMetadata(ctx, generated.ListFittedFinalizationRecoverySignatureMetadataParams{DocumentID: documentID, OrgID: orgID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	signatures, legacy, err := fittedRecoverySignaturesV1(ctx, p, fields, basis, rows)
	if err != nil {
		return nil, err
	}
	outputs, err := r.queries.ListFittedFinalizationOutputs(ctx, generated.ListFittedFinalizationOutputsParams{PreparationID: preparationID, OrgID: orgID, DocumentID: documentID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	reserved, bases, err := fittedRecoveryOutputsV1(ctx, p, outputs)
	if err != nil {
		return nil, err
	}
	refs, err := r.queries.ListFittedFinalizationReferences(ctx, generated.ListFittedFinalizationReferencesParams{PreparationID: preparationID, OrgID: orgID, DocumentID: documentID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	if len(refs) > int(p.ExpectedReferences) {
		return nil, ErrFittedFinalizationV1
	}
	companions, err := r.queries.ListFittedFinalizationRecoveryCompanions(ctx, generated.ListFittedFinalizationRecoveryCompanionsParams{DocumentID: documentID, OrgID: orgID})
	if err != nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	if len(companions) > len(signatures) || len(companions) > pdflayout.MaxParties {
		return nil, ErrFittedFinalizationV1
	}
	byID := map[uuid.UUID]*generated.SignatureFitCompanion{}
	for _, c := range companions {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if c == nil || c.SignatureID == uuid.Nil || c.OrgID != orgID || c.DocumentID != documentID || c.RecipientID == uuid.Nil || c.FieldID == uuid.Nil || c.SelectionID == uuid.Nil || len(c.SpanSha256) != sha256.Size || byID[c.SignatureID] != nil {
			return nil, ErrFittedFinalizationV1
		}
		byID[c.SignatureID] = c
	}
	expected := map[string]fittedRecoveryReferenceV1{}
	source := manualfit.SourceTupleV1{Key: p.SourceStorageKey, VersionID: p.SourceVersionID, SHA256: hex.EncodeToString(p.SourceSha256), Bytes: p.SourceBytes}
	expected[fittedRecoveryReferenceIDV1("source", uuid.Nil, 0)] = fittedRecoveryReferenceV1{owner: documentID, pin: manualfit.ObjectPinV1{Key: source.Key, VersionID: source.VersionID, SHA256: source.SHA256, Bytes: source.Bytes, ContentType: "application/pdf"}}
	for _, l := range legacy {
		expected[fittedRecoveryReferenceIDV1("legacy_span", l.SignatureID, 0)] = fittedRecoveryReferenceV1{owner: l.SignatureID, pin: l.Object}
	}
	candidates := make([]fittedRecoveryCandidateV1, 0, len(companions))
	var archived int64
	layerCount := len(bases)
	for _, s := range signatures {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if s.SignatureKind != manualfit.AuthoritySchemaV1 {
			if byID[s.ID] != nil {
				return nil, ErrFittedFinalizationV1
			}
			continue
		}
		c := byID[s.ID]
		if c == nil || c.RecipientID != s.RecipientID || c.FieldID != s.FieldID || !bytes.Equal(c.SpanSha256, s.ImageSha256) {
			return nil, ErrFittedFinalizationV1
		}
		x, err := r.queries.GetSignatureFitSelection(ctx, generated.GetSignatureFitSelectionParams{OrgID: orgID, DocumentID: documentID, RecipientID: s.RecipientID, CeremonyEpoch: p.CeremonyEpoch})
		if err != nil || ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		if fittedRecoverySelectionV1(p, s, c, x) != nil {
			return nil, ErrFittedFinalizationV1
		}
		a, err := r.queries.GetSignatureFitPreparation(ctx, generated.GetSignatureFitPreparationParams{ID: x.PreparationID, OrgID: orgID})
		if err != nil || ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		objects, err := r.queries.ListSignatureFitObjects(ctx, generated.ListSignatureFitObjectsParams{ID: x.PreparationID, OrgID: orgID})
		if err != nil || ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		total, pages, err := fittedRecoveryInventoryV1(ctx, p, x, a, objects)
		if err != nil {
			return nil, err
		}
		if total > p.FitReservedBytes-archived || pages > sanitize.MaxPDFManualLayersV1-layerCount {
			return nil, sanitize.ErrPDFTooLarge
		}
		archived += total
		layerCount += pages
		for _, o := range objects {
			kind := "fit_" + o.Kind
			expected[fittedRecoveryReferenceIDV1(kind, s.ID, int(o.Page))] = fittedRecoveryReferenceV1{owner: s.ID, selection: x.ID, pin: manualfit.ObjectPinV1{Key: o.StorageKey, VersionID: o.VersionID.String, SHA256: hex.EncodeToString(o.Sha256), Bytes: o.Bytes, ContentType: o.ContentType}}
		}
		candidates = append(candidates, fittedRecoveryCandidateV1{s: s, x: x, a: a, objects: objects, pin: manualfit.ObjectPinV1{Key: x.ManifestStorageKey, VersionID: x.ManifestVersionID, SHA256: hex.EncodeToString(x.ManifestSha256), Bytes: x.ManifestBytes, ContentType: "application/json"}})
	}
	if len(candidates) < 1 || len(candidates) != len(companions) || len(expected) != int(p.ExpectedReferences) {
		return nil, ErrFittedFinalizationV1
	}
	if err = fittedRecoveryReferencesV1(ctx, p, refs, expected); err != nil {
		return nil, err
	}
	// Journal producer ceilings and actual metadata inventories are admitted
	// before the first provider read. The complete archive writer must still
	// enforce its exact expanded ZIP framing/event/field budget independently.
	var legacyBytes int64
	for _, l := range legacy {
		legacyBytes += l.Object.Bytes
	}
	minimum := p.FitReservedBytes + p.SourceBytes + legacyBytes + p.BaseBytesLimit + p.FinalPdfBytesLimit + p.FitsIndexBytesLimit + p.CertificatePdfBytesLimit + p.CertificatePayloadBytesLimit + p.CertificateSignatureBytesLimit + 9*(1<<20) + 2*16384 + 22 + int64(p.ExpectedOutputs+p.ExpectedReferences+5)*(92+2*128)
	if minimum > p.ArchiveBudgetBytes {
		return nil, ErrFittedFinalizationV1
	}
	if p.Status == "published" {
		completed, err := r.queries.GetCompletedFittedFinalization(ctx, generated.GetCompletedFittedFinalizationParams{DocumentID: documentID, OrgID: orgID})
		if err != nil || ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		if fittedRecoveryCompletedV1(meta, p, completed, outputs) != nil {
			return nil, ErrFittedFinalizationV1
		}
	}
	out := &FittedFinalizationV1{orgID: orgID, documentID: documentID, ceremonyEpoch: p.CeremonyEpoch.Time.UTC().Round(0), completionEffectiveAt: p.CompletionEffectiveAt.Time.UTC().Round(0), retainUntil: p.RetainUntil.Time.UTC().Round(0), source: source, geometry: geometry, legacySignatures: legacy, fieldSnapshotSHA256: hex.EncodeToString(p.FieldSnapshotSha256), fieldSnapshotJSON: bytes.Clone(p.FieldSnapshotPayload), baseReady: len(p.RequiredBasePages) == 0}
	out.journalRecoveryBound = true
	for _, o := range reserved {
		if o.Kind != "base_pdf" {
			out.originalOutputsRequired = true
			break
		}
	}
	for _, n := range p.RequiredBasePages {
		out.requiredBasePages = append(out.requiredBasePages, int(n))
	}
	// First read only bounded manifests, rebind every target/page/source tuple,
	// and compare all actual85 object identities before retrieving any package.
	for i := range candidates {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		c := &candidates[i]
		raw, err := readFittedPinV1(ctx, r.reader, c.pin, manualfit.MaxManifestBytesV1)
		if err != nil {
			return nil, err
		}
		c.binding = manualfit.BindingV1{OperationID: c.x.PreparationID, OrgID: orgID, DocumentID: documentID, RecipientID: c.s.RecipientID, CeremonyEpoch: out.ceremonyEpoch, AuthoritySHA256: hex.EncodeToString(c.x.AuthoritySha256)}
		m, err := manualfit.DecodeManifestV1(raw, c.binding)
		if err != nil || validateFittedArchiveRebindV1(doc, c.s, c.x, c.a, fields, c.objects, m, c.pin) != nil || m.Authority().Input().Source != source || !reflect.DeepEqual(m.Authority().Geometry(), geometry) {
			return nil, ErrFittedFinalizationV1
		}
	}
	var processing int64 = p.SourceBytes
	for _, b := range bases {
		processing += b.Object.Bytes
	}
	// Package headers declare PDF section lengths only inside the exact package.
	// Bounded archive admission precedes those reads; actual section counts then
	// gate source/base retrieval and layer copies. No mutable declaration can
	// replace this frozen decode, and no worker is dispatched by recovery.
	for _, c := range candidates {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		kept, err := manualfit.VerifyRetainedV1(ctx, r.reader, c.pin, c.binding)
		if err != nil || ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		m := kept.Manifest()
		if m == nil || validateFittedArchiveRebindV1(doc, c.s, c.x, c.a, fields, c.objects, m, c.pin) != nil {
			return nil, ErrFittedFinalizationV1
		}
		for _, page := range m.Pages() {
			if ctx.Err() != nil {
				return nil, fittedErrorV1(ctx, nil)
			}
			n, err := kept.PDFByteCount(page.Page)
			if err != nil || n < 1 || int64(n) > int64(sanitize.MaxPDFBytes)-processing {
				return nil, sanitize.ErrPDFTooLarge
			}
			processing += int64(n)
		}
		out.entries = append(out.entries, &FittedSignatureFinalizationV1{signatureID: c.s.ID, selectionID: c.x.ID, recipientID: c.s.RecipientID, fieldID: c.s.FieldID, signedAt: c.s.SignedAt.Time.UTC().Round(0), retentionFloor: c.x.RetainUntil.Time.UTC().Round(0), retained: kept})
	}
	sort.Slice(out.entries, func(i, j int) bool {
		a, b := out.entries[i], out.entries[j]
		if !a.signedAt.Equal(b.signedAt) {
			return a.signedAt.Before(b.signedAt)
		}
		return bytes.Compare(a.signatureID[:], b.signatureID[:]) < 0
	})
	if err = fittedRecoveryProcessingV1(ctx, out, bases, processing); err != nil {
		return nil, err
	}
	if _, err = readFittedPinV1(ctx, r.reader, expected[fittedRecoveryReferenceIDV1("source", uuid.Nil, 0)].pin, int64(sanitize.MaxPDFBytes)); err != nil {
		return nil, err
	}
	out, err = LoadFittedBasePagesV1(ctx, r.reader, out, bases)
	if err != nil {
		return nil, err
	}
	out.legacySpans, err = verifyFittedLegacySpansV1(ctx, r.reader, out)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	return &FittedJournalRecoveryV1{preparationID: preparationID, originalDocumentName: p.OriginalDocumentName, status: p.Status, snapshot: out, outputs: reserved}, nil
}

type fittedRecoveryCandidateV1 struct {
	s       *generated.Signature
	x       *generated.SignatureFitSelection
	a       *generated.SignatureFitPreparation
	objects []*generated.SignatureFitObject
	pin     manualfit.ObjectPinV1
	binding manualfit.BindingV1
}

func fittedRecoveryKeyV1(key string) bool {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) || key != strings.TrimSpace(key) {
		return false
	}
	for _, c := range key {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func fittedRecoveryPinV1(pin manualfit.ObjectPinV1, max int64) bool {
	return fittedRecoveryKeyV1(pin.Key) && validFittedPinV1(pin, max)
}
func fittedRecoveryOptionalPayloadV1(payload, digest []byte, max int) bool {
	return (len(payload) == 0 && len(digest) == 0) || (len(payload) > 0 && len(payload) <= max && utf8.Valid(payload) && len(digest) == sha256.Size && fittedSHA256V1(payload) == hex.EncodeToString(digest))
}
func fittedRecoveryDocumentV1(d *generated.GetFittedFinalizationRecoveryDocumentMetadataRow, p *generated.DocumentFinalizationPreparation, org, doc, op uuid.UUID) (*generated.Document, error) {
	if d == nil || p == nil || d.ID != doc || d.OrgID != org || p.ID != op || p.OrgID != org || p.DocumentID != doc || d.SourceKind != "pdf" || !d.RequiresSignature || d.IsEnvelope || d.ParentEnvelopeID.Valid || d.DeletedAt.Valid || !d.FitsIndexRequired || !d.EvidenceVersionPinsRequired || !d.Article13NoticeEpochV61Committed || !d.CompletionEffectiveAtBound || (d.Status != "finalizing" && d.Status != "completed") || (p.Status != "staging" && p.Status != "prepared" && p.Status != "published") {
		return nil, ErrFittedFinalizationV1
	}
	for _, stamp := range []pgtype.Timestamptz{d.SentAt, d.Article13NoticeEpochAt, d.CompletionEffectiveAt, d.FinalizationRetainUntil, p.CeremonyEpoch, p.CompletionEffectiveAt, p.RetainUntil, p.LeaseUntil, p.CreatedAt, p.UpdatedAt} {
		if !finiteFittedTimeV1(stamp) {
			return nil, ErrFittedFinalizationV1
		}
	}
	if !d.SentAt.Time.Equal(p.CeremonyEpoch.Time) || !d.Article13NoticeEpochAt.Time.Equal(p.CeremonyEpoch.Time) || !d.CompletionEffectiveAt.Time.Equal(p.CompletionEffectiveAt.Time) || !d.FinalizationRetainUntil.Time.Equal(p.RetainUntil.Time) || !p.CompletionEffectiveAt.Time.After(p.CeremonyEpoch.Time) || !p.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(p.CompletionEffectiveAt.Time, article13.RetentionYearsV1)) || p.RetainUntil.Time.Nanosecond() != 0 {
		return nil, ErrFittedFinalizationV1
	}
	if p.OwnerID == uuid.Nil || p.Attempts < 1 || p.Attempts > 8 || p.OriginalDocumentName == "" || len(p.OriginalDocumentName) > 65536 || !utf8.ValidString(p.OriginalDocumentName) || strings.TrimSpace(p.OriginalDocumentName) == "" || p.SourcePages < 1 || p.SourcePages > sanitize.MaxPDFPages || !d.PdfStorageKey.Valid || !d.PdfStorageVersionID.Valid || len(d.PdfSha256) != sha256.Size || d.PdfStorageKey.String != p.SourceStorageKey || d.PdfStorageVersionID.String != p.SourceVersionID || !bytes.Equal(d.PdfSha256, p.SourceSha256) {
		return nil, ErrFittedFinalizationV1
	}
	source := manualfit.ObjectPinV1{Key: p.SourceStorageKey, VersionID: p.SourceVersionID, SHA256: hex.EncodeToString(p.SourceSha256), Bytes: p.SourceBytes, ContentType: "application/pdf"}
	if !fittedRecoveryPinV1(source, int64(sanitize.MaxPDFBytes)) {
		return nil, ErrFittedFinalizationV1
	}
	if len(p.RequiredBasePages) > sanitize.MaxPDFPages || p.ExpectedOutputs != int32(len(p.RequiredBasePages)+5) || p.ExpectedReferences < 4 || p.ExpectedReferences > 9990 || p.FitReservedBytes < 1 || p.FitReservedBytes > manualfit.MaxEvidenceBytesV1 || p.BaseBytesLimit < 0 || p.BaseBytesLimit > int64(sanitize.MaxPDFBytes) || p.FinalPdfBytesLimit < 1 || p.FinalPdfBytesLimit > int64(sanitize.MaxPDFBytes) || p.FitsIndexBytesLimit < 1 || p.FitsIndexBytesLimit > 8<<20 || p.CertificatePdfBytesLimit < 1 || p.CertificatePdfBytesLimit > 8<<20 || p.CertificatePayloadBytesLimit < 1 || p.CertificatePayloadBytesLimit > 4<<20 || p.CertificateSignatureBytesLimit < 1 || p.CertificateSignatureBytesLimit > 256 || p.ArchiveBudgetBytes < 1 || p.ArchiveBudgetBytes > manualfit.MaxEvidenceBytesV1 {
		return nil, ErrFittedFinalizationV1
	}
	if (len(p.RequiredBasePages) == 0) != (p.BaseBytesLimit == 0) || p.BaseBytesLimit < int64(len(p.RequiredBasePages)) {
		return nil, sanitize.ErrPDFTooLarge
	}
	if !fittedRecoveryOptionalPayloadV1(p.AuditSnapshotPayload, p.AuditSnapshotSha256, 4<<20) || !fittedRecoveryOptionalPayloadV1(p.CertificateInputPayload, p.CertificateInputSha256, 4<<20) {
		return nil, ErrFittedFinalizationV1
	}
	if p.RetentionStartedAt.Valid && (!finiteFittedTimeV1(p.RetentionStartedAt) || len(p.AuditSnapshotPayload) == 0) || p.RetentionCompletedAt.Valid && (!finiteFittedTimeV1(p.RetentionCompletedAt) || !p.RetentionStartedAt.Valid || p.RetentionCompletedAt.Time.Before(p.RetentionStartedAt.Time)) || p.PublicationCommitAttemptedAt.Valid && (!finiteFittedTimeV1(p.PublicationCommitAttemptedAt) || !p.RetentionCompletedAt.Valid) || p.PublishedAt.Valid && (!finiteFittedTimeV1(p.PublishedAt) || !p.PublicationCommitAttemptedAt.Valid || p.PublishedAt.Time.Before(p.PublicationCommitAttemptedAt.Time)) {
		return nil, ErrFittedFinalizationV1
	}
	if (p.Status == "published") != p.PublishedAt.Valid || (d.Status == "completed") != (p.Status == "published") || p.Status != "staging" && (len(p.AuditSnapshotPayload) == 0 || len(p.CertificateInputPayload) == 0 || !p.RetentionStartedAt.Valid) {
		return nil, ErrFittedFinalizationV1
	}
	if d.Status == "completed" && (!finiteFittedTimeV1(d.CompletedAt) || !d.CompletedAt.Time.Equal(p.CompletionEffectiveAt.Time) || !d.FitsIndexPreparationID.Valid || uuid.UUID(d.FitsIndexPreparationID.Bytes) != op || !p.RetentionCompletedAt.Valid) {
		return nil, ErrFittedFinalizationV1
	}
	if p.Status == "staging" && (p.RetentionCompletedAt.Valid || p.PublicationCommitAttemptedAt.Valid || p.PublishedAt.Valid) {
		return nil, ErrFittedFinalizationV1
	}
	if d.Status == "finalizing" && (d.CompletedAt.Valid || d.FitsIndexPreparationID.Valid || d.FitsIndexStorageKey.Valid || d.FitsIndexVersionID.Valid || len(d.FitsIndexSha256) != 0 || d.FitsIndexBytes.Valid) {
		return nil, ErrFittedFinalizationV1
	}
	return &generated.Document{ID: doc, OrgID: org, Status: d.Status, SourceKind: "pdf", RequiresSignature: true, SentAt: d.SentAt, Article13NoticeEpochAt: d.Article13NoticeEpochAt, Article13NoticeEpochV61Committed: true, CompletionEffectiveAtBound: true, CompletionEffectiveAt: d.CompletionEffectiveAt, FinalizationRetainUntil: d.FinalizationRetainUntil, PdfStorageKey: d.PdfStorageKey, PdfStorageVersionID: d.PdfStorageVersionID, PdfSha256: bytes.Clone(d.PdfSha256), EvidenceVersionPinsRequired: true, FitsIndexRequired: true, SignatureFitReservedBytes: p.FitReservedBytes}, nil
}

func fittedRecoveryCanonicalV1(raw []byte, destination any, max int) error {
	if len(raw) < 1 || len(raw) > max || !utf8.Valid(raw) {
		return ErrFittedFinalizationV1
	}
	depth := 0
	quoted, escaped := false, false
	for _, b := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		switch b {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > 16 {
				return ErrFittedFinalizationV1
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return ErrFittedFinalizationV1
			}
		}
	}
	if quoted || depth != 0 {
		return ErrFittedFinalizationV1
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(destination) != nil {
		return ErrFittedFinalizationV1
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrFittedFinalizationV1
	}
	canonical, err := json.Marshal(destination)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrFittedFinalizationV1
	}
	return nil
}

// Count top-level array members without allocating a typed member slice.
// Captured86 records are already shape-guarded; this check also makes the Go
// refusal allocation bound explicit before decoding immutable journal bytes.
func fittedRecoveryArrayCountV1(ctx context.Context, raw []byte, max int) (int, error) {
	if ctx.Err() != nil {
		return 0, fittedErrorV1(ctx, nil)
	}
	if len(raw) < 2 || raw[0] != '[' || raw[len(raw)-1] != ']' || max < 0 {
		return 0, ErrFittedFinalizationV1
	}
	depth, count := 0, 0
	quoted, escaped, member := false, false, false
	for i, b := range raw {
		if i%4096 == 0 && ctx.Err() != nil {
			return 0, fittedErrorV1(ctx, nil)
		}
		if quoted {
			if escaped {
				escaped = false
			} else if b == '\\' {
				escaped = true
			} else if b == '"' {
				quoted = false
			}
			continue
		}
		if depth == 1 && !member && b != ']' && b != ',' && b != ' ' && b != '\t' && b != '\r' && b != '\n' {
			count++
			if count > max {
				return 0, ErrFittedFinalizationV1
			}
			member = true
		}
		switch b {
		case '"':
			quoted = true
		case '[', '{':
			depth++
			if depth > 16 {
				return 0, ErrFittedFinalizationV1
			}
		case ']', '}':
			depth--
			if depth < 0 {
				return 0, ErrFittedFinalizationV1
			}
		case ',':
			if depth == 1 {
				member = false
			}
		}
	}
	if quoted || depth != 0 {
		return 0, ErrFittedFinalizationV1
	}
	return count, nil
}

func fittedRecoveryBasisV1(ctx context.Context, p *generated.DocumentFinalizationPreparation) (sanitize.PDFManualGeometry, []*generated.DocumentField, fittedFieldBasisDocumentV1, error) {
	var g sanitize.PDFManualGeometry
	var basis fittedFieldBasisDocumentV1
	fail := func() (sanitize.PDFManualGeometry, []*generated.DocumentField, fittedFieldBasisDocumentV1, error) {
		return g, nil, basis, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return g, nil, basis, fittedErrorV1(ctx, nil)
	}
	if len(p.GeometryPagesPayload) < 1 || len(p.GeometryPagesPayload) > 1<<20 || len(p.GeometrySha256) != sha256.Size || fittedSHA256V1(p.GeometryPagesPayload) != hex.EncodeToString(p.GeometrySha256) || len(p.FieldSnapshotPayload) < 1 || len(p.FieldSnapshotPayload) > 1<<20 || len(p.FieldSnapshotSha256) != sha256.Size || fittedSHA256V1(p.FieldSnapshotPayload) != hex.EncodeToString(p.FieldSnapshotSha256) {
		return fail()
	}
	count, err := fittedRecoveryArrayCountV1(ctx, p.GeometryPagesPayload, int(p.SourcePages))
	if err != nil {
		return g, nil, basis, err
	}
	if count != int(p.SourcePages) {
		return fail()
	}
	if fittedRecoveryCanonicalV1(p.GeometryPagesPayload, &g.Pages, 1<<20) != nil || len(g.Pages) != int(p.SourcePages) {
		return fail()
	}
	g.SchemaVersion = 1
	g.SourceSHA256 = hex.EncodeToString(p.SourceSha256)
	g.SourceBytes = p.SourceBytes
	g.GeometrySHA256 = hex.EncodeToString(p.GeometrySha256)
	for _, page := range g.Pages {
		if ctx.Err() != nil {
			return g, nil, basis, fittedErrorV1(ctx, nil)
		}
		if _, _, err := page.ViewportPoints(); err != nil {
			return fail()
		}
	}
	var shape struct {
		Schema         string
		DocumentID     uuid.UUID
		Fields, Legacy json.RawMessage
	}
	if fittedRecoveryCanonicalV1(p.FieldSnapshotPayload, &shape, 1<<20) != nil {
		return fail()
	}
	fieldCount, err := fittedRecoveryArrayCountV1(ctx, shape.Fields, pdflayout.MaxFields)
	if err != nil {
		return g, nil, basis, err
	}
	if fieldCount < 1 {
		return fail()
	}
	if _, err = fittedRecoveryArrayCountV1(ctx, shape.Legacy, pdflayout.MaxParties); err != nil {
		return g, nil, basis, err
	}
	if fittedRecoveryCanonicalV1(p.FieldSnapshotPayload, &basis, 1<<20) != nil || basis.Schema != "hash-manual-finalization-field-basis-v1" || basis.DocumentID != p.DocumentID || len(basis.Fields) < 1 || len(basis.Fields) > pdflayout.MaxFields || len(basis.Legacy) > pdflayout.MaxParties {
		return fail()
	}
	fields := make([]*generated.DocumentField, 0, len(basis.Fields))
	var previous uuid.UUID
	for i, f := range basis.Fields {
		if ctx.Err() != nil {
			return g, nil, basis, fittedErrorV1(ctx, nil)
		}
		if f.ID == uuid.Nil || i > 0 && bytes.Compare(previous[:], f.ID[:]) >= 0 || !f.RecipientValid || f.RecipientID == uuid.Nil || !utf8.ValidString(f.Value) || !f.ValueValid && f.Value != "" {
			return fail()
		}
		previous = f.ID
		switch f.Type {
		case "signature":
			if !f.Required {
				return fail()
			}
		case "text", "date", "checkbox", "dropdown", "initial":
		default:
			return fail()
		}
		row := &generated.DocumentField{ID: f.ID, DocumentID: p.DocumentID, RecipientID: pgtype.UUID{Bytes: f.RecipientID, Valid: true}, Type: f.Type, Page: f.Page, Required: f.Required, Value: pgtype.Text{String: f.Value, Valid: f.ValueValid}}
		for i, s := range []string{f.X, f.Y, f.W, f.H} {
			if len(s) < 1 || len(s) > 96 {
				return fail()
			}
			var n pgtype.Numeric
			if n.Scan(s) != nil {
				return fail()
			}
			exact, err := fittedDecimalV1(n)
			if err != nil || exact != s {
				return fail()
			}
			switch i {
			case 0:
				row.XPct = n
			case 1:
				row.YPct = n
			case 2:
				row.WPct = n
			case 3:
				row.HPct = n
			}
		}
		if !pdflayout.ValidPlacement(row, len(g.Pages)) {
			return fail()
		}
		fields = append(fields, row)
	}
	previous = uuid.Nil
	for i, l := range basis.Legacy {
		if ctx.Err() != nil {
			return g, nil, basis, fittedErrorV1(ctx, nil)
		}
		if l.ID == uuid.Nil || i > 0 && bytes.Compare(previous[:], l.ID[:]) >= 0 || l.DocumentID != p.DocumentID || l.RecipientID == uuid.Nil || l.FieldID == uuid.Nil || (l.Kind != "manual" && l.Kind != "delegated_grant_v1") || l.SignedAt.IsZero() || l.SignedAt.Year() < 1 || l.SignedAt.Year() > 9999 || l.SignedAt.Location() != time.UTC || l.SignedAt.Before(p.CeremonyEpoch.Time) || !l.SignedAt.Before(p.CompletionEffectiveAt.Time) || !fittedRecoveryPinV1(l.Object, int64(render.MaxArchivedSignatureSpanBytes)) || l.Object.ContentType != "text/html" || l.SpanSHA256 != l.Object.SHA256 || render.ValidateSignatureName(l.Name) != nil || !utf8.ValidString(l.Font) || len(l.Font) > 128 {
			return fail()
		}
		previous = l.ID
	}
	return g, fields, basis, nil
}

func fittedRecoverySignaturesV1(ctx context.Context, p *generated.DocumentFinalizationPreparation, fields []*generated.DocumentField, basis fittedFieldBasisDocumentV1, rows []*generated.ListFittedFinalizationRecoverySignatureMetadataRow) ([]*generated.Signature, []manualfit.FitsIndexLegacySignatureV1, error) {
	if len(rows) < 1 || len(rows) > pdflayout.MaxParties {
		return nil, nil, ErrFittedFinalizationV1
	}
	byField := map[uuid.UUID]*generated.DocumentField{}
	for _, f := range fields {
		byField[f.ID] = f
	}
	byRecipient := map[uuid.UUID]bool{}
	bySignature := map[uuid.UUID]bool{}
	legacyByID := map[uuid.UUID]fittedLegacyBasisV1{}
	for _, l := range basis.Legacy {
		legacyByID[l.ID] = l
	}
	signatures := make([]*generated.Signature, 0, len(rows))
	legacy := make([]manualfit.FitsIndexLegacySignatureV1, 0, len(basis.Legacy))
	for _, row := range rows {
		if ctx.Err() != nil {
			return nil, nil, fittedErrorV1(ctx, nil)
		}
		if row == nil || !row.MetadataValid || row.ID == uuid.Nil || row.DocumentID != p.DocumentID || row.RecipientID == uuid.Nil || byRecipient[row.RecipientID] || bySignature[row.ID] || !finiteFittedTimeV1(row.SignedAt) || row.SignedAt.Time.Before(p.CeremonyEpoch.Time) || !row.SignedAt.Time.Before(p.CompletionEffectiveAt.Time) || !row.ImageVersionPinRequired || !fittedRecoveryKeyV1(row.ImageStorageKey) || !manualfit.ValidObjectVersionV1(row.ImageVersionID) || len(row.ImageSha256) != sha256.Size {
			return nil, nil, ErrFittedFinalizationV1
		}
		f := byField[row.FieldID]
		if f == nil || f.Type != "signature" || !f.Required || uuid.UUID(f.RecipientID.Bytes) != row.RecipientID {
			return nil, nil, ErrFittedFinalizationV1
		}
		s := &generated.Signature{ID: row.ID, DocumentID: row.DocumentID, RecipientID: row.RecipientID, FieldID: row.FieldID, SignedAt: row.SignedAt, SignatureKind: row.SignatureKind, ImageStorageKey: row.ImageStorageKey, ImageVersionID: pgtype.Text{String: row.ImageVersionID, Valid: true}, ImageSha256: bytes.Clone(row.ImageSha256), ImageVersionPinRequired: true, PresignExecutionID: row.PresignExecutionID}
		if row.SignatureKind == manualfit.AuthoritySchemaV1 {
			if row.PresignExecutionID.Valid || legacyByID[row.ID].ID != uuid.Nil {
				return nil, nil, ErrFittedFinalizationV1
			}
		} else {
			l, ok := legacyByID[row.ID]
			if !ok || (row.SignatureKind != "manual" && row.SignatureKind != "delegated_grant_v1") || l.Kind != row.SignatureKind || l.RecipientID != row.RecipientID || l.FieldID != row.FieldID || !l.SignedAt.Equal(row.SignedAt.Time) || l.Object.Key != row.ImageStorageKey || l.Object.VersionID != row.ImageVersionID || l.Object.SHA256 != hex.EncodeToString(row.ImageSha256) || row.SignatureKind == "delegated_grant_v1" && (!row.PresignExecutionID.Valid || uuid.UUID(row.PresignExecutionID.Bytes) == uuid.Nil) || row.SignatureKind == "manual" && row.PresignExecutionID.Valid {
				return nil, nil, ErrFittedFinalizationV1
			}
			legacy = append(legacy, manualfit.FitsIndexLegacySignatureV1{DocumentID: p.DocumentID, SignatureID: l.ID, RecipientID: l.RecipientID, FieldID: l.FieldID, Kind: l.Kind, SignedAt: l.SignedAt, Object: l.Object, OriginalName: l.Name, Font: l.Font, SpanSHA256: l.SpanSHA256})
			delete(legacyByID, row.ID)
		}
		byRecipient[row.RecipientID] = true
		bySignature[row.ID] = true
		signatures = append(signatures, s)
	}
	if len(legacyByID) != 0 {
		return nil, nil, ErrFittedFinalizationV1
	}
	for _, f := range fields {
		if !byRecipient[uuid.UUID(f.RecipientID.Bytes)] || f.Type != "signature" && len(rows) != 1 {
			return nil, nil, ErrFittedFinalizationV1
		}
	}
	digest, pages, raw, err := fittedFieldSnapshotWithLegacyV1(p.DocumentID, fields, signatures, legacy)
	if err != nil || digest != hex.EncodeToString(p.FieldSnapshotSha256) || !bytes.Equal(raw, p.FieldSnapshotPayload) || len(pages) != len(p.RequiredBasePages) {
		return nil, nil, ErrFittedFinalizationV1
	}
	for i, n := range pages {
		if n != int(p.RequiredBasePages[i]) {
			return nil, nil, ErrFittedFinalizationV1
		}
	}
	sort.Slice(legacy, func(i, j int) bool {
		a, b := legacy[i], legacy[j]
		if !a.SignedAt.Equal(b.SignedAt) {
			return a.SignedAt.Before(b.SignedAt)
		}
		return bytes.Compare(a.SignatureID[:], b.SignatureID[:]) < 0
	})
	return signatures, legacy, nil
}

func fittedRecoverySelectionV1(p *generated.DocumentFinalizationPreparation, s *generated.Signature, c *generated.SignatureFitCompanion, x *generated.SignatureFitSelection) error {
	if x == nil || x.ID != c.SelectionID || x.PreparationID == uuid.Nil || x.OrgID != p.OrgID || x.DocumentID != p.DocumentID || x.RecipientID != s.RecipientID || !finiteFittedTimeV1(x.CeremonyEpoch) || !x.CeremonyEpoch.Time.Equal(p.CeremonyEpoch.Time) || !finiteFittedTimeV1(x.RetainUntil) || !x.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(p.CeremonyEpoch.Time, article13.RetentionYearsV1)) || !finiteFittedTimeV1(x.RetentionStartedAt) || !finiteFittedTimeV1(x.RetentionCompletedAt) || x.RetentionCompletedAt.Time.Before(x.RetentionStartedAt.Time) || x.RetentionCompletedAt.Time.After(s.SignedAt.Time) || x.SourceStorageKey != p.SourceStorageKey || x.SourceVersionID != p.SourceVersionID || !bytes.Equal(x.SourceSha256, p.SourceSha256) || x.SourceBytes != p.SourceBytes || !bytes.Equal(x.GeometrySha256, p.GeometrySha256) || len(x.AuthoritySha256) != sha256.Size || x.SpanStorageKey != s.ImageStorageKey || x.SpanVersionID != s.ImageVersionID.String || !bytes.Equal(x.SpanSha256, s.ImageSha256) {
		return ErrFittedFinalizationV1
	}
	for _, pin := range []manualfit.ObjectPinV1{{Key: x.SpanStorageKey, VersionID: x.SpanVersionID, SHA256: hex.EncodeToString(x.SpanSha256), Bytes: x.SpanBytes, ContentType: "text/html"}, {Key: x.ManifestStorageKey, VersionID: x.ManifestVersionID, SHA256: hex.EncodeToString(x.ManifestSha256), Bytes: x.ManifestBytes, ContentType: "application/json"}} {
		max := manualfit.MaxSpanBytesV1
		if pin.ContentType == "application/json" {
			max = manualfit.MaxManifestBytesV1
		}
		if !fittedRecoveryPinV1(pin, max) {
			return ErrFittedFinalizationV1
		}
	}
	return nil
}
func fittedRecoveryInventoryV1(ctx context.Context, p *generated.DocumentFinalizationPreparation, x *generated.SignatureFitSelection, a *generated.SignatureFitPreparation, objects []*generated.SignatureFitObject) (int64, int, error) {
	if a == nil || a.ID != x.PreparationID || a.OrgID != p.OrgID || a.DocumentID != p.DocumentID || a.RecipientID != x.RecipientID || a.Status != "prepared" || !finiteFittedTimeV1(a.CeremonyEpoch) || !a.CeremonyEpoch.Time.Equal(p.CeremonyEpoch.Time) || !bytes.Equal(a.AuthoritySha256, x.AuthoritySha256) || a.SourceStorageKey != p.SourceStorageKey || a.SourceVersionID != p.SourceVersionID || !bytes.Equal(a.SourceSha256, p.SourceSha256) || a.SourceBytes != p.SourceBytes || !bytes.Equal(a.GeometrySha256, p.GeometrySha256) || !bytes.Equal(a.SpanSha256, x.SpanSha256) || a.ExpectedObjects < 3 || a.ExpectedObjects > 502 || len(objects) != int(a.ExpectedObjects) || a.ReservedBytes < 1 || a.ReservedBytes > manualfit.MaxEvidenceBytesV1 {
		return 0, 0, ErrFittedFinalizationV1
	}
	seen := map[string]bool{}
	var total int64
	pages := 0
	for _, o := range objects {
		if ctx.Err() != nil {
			return 0, 0, fittedErrorV1(ctx, nil)
		}
		if o == nil || o.PreparationID != a.ID || !finiteFittedTimeV1(o.UploadAttemptedAt) || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) == uuid.Nil || !o.VersionID.Valid || !finiteFittedTimeV1(o.ReadbackVerifiedAt) || o.ReadbackVerifiedAt.Time.Before(o.UploadAttemptedAt.Time) || o.CleanupCompletedAt.Valid {
			return 0, 0, ErrFittedFinalizationV1
		}
		pin := manualfit.ObjectPinV1{Key: o.StorageKey, VersionID: o.VersionID.String, SHA256: hex.EncodeToString(o.Sha256), Bytes: o.Bytes, ContentType: o.ContentType}
		max := manualfit.MaxSpanBytesV1
		key := manualfit.ObjectPrefixV1(a.ID, p.OrgID, p.DocumentID)
		switch o.Kind {
		case "span":
			key += "span.html"
			if o.Page != 0 || o.ContentType != "text/html" || o.StorageKey != x.SpanStorageKey || o.VersionID.String != x.SpanVersionID || !bytes.Equal(o.Sha256, x.SpanSha256) || o.Bytes != x.SpanBytes {
				return 0, 0, ErrFittedFinalizationV1
			}
		case "manifest":
			key += "manifest.json"
			max = manualfit.MaxManifestBytesV1
			if o.Page != 0 || o.ContentType != "application/json" || o.StorageKey != x.ManifestStorageKey || o.VersionID.String != x.ManifestVersionID || !bytes.Equal(o.Sha256, x.ManifestSha256) || o.Bytes != x.ManifestBytes {
				return 0, 0, ErrFittedFinalizationV1
			}
		case "page":
			key += "page-" + strconv.Itoa(int(o.Page)) + ".fit"
			max = signaturefit.MaxPackageBytes
			if o.Page < 1 || o.Page > p.SourcePages || o.ContentType != signaturefit.MediaType {
				return 0, 0, ErrFittedFinalizationV1
			}
			pages++
		default:
			return 0, 0, ErrFittedFinalizationV1
		}
		id := o.Kind + ":" + strconv.Itoa(int(o.Page))
		if seen[id] || pin.Key != key || !fittedRecoveryPinV1(pin, max) || o.Bytes > a.ReservedBytes-total {
			return 0, 0, ErrFittedFinalizationV1
		}
		seen[id] = true
		total += o.Bytes
	}
	if !seen["span:0"] || !seen["manifest:0"] || pages < 1 {
		return 0, 0, ErrFittedFinalizationV1
	}
	return total, pages, nil
}

func fittedRecoveryOutputsV1(ctx context.Context, p *generated.DocumentFinalizationPreparation, rows []*generated.ListFittedFinalizationOutputsRow) ([]FittedReservedOutputV1, []FittedBasePagePinV1, error) {
	if len(rows) > int(p.ExpectedOutputs) || p.Status != "staging" && len(rows) != int(p.ExpectedOutputs) {
		return nil, nil, ErrFittedFinalizationV1
	}
	if len(rows) > 0 && len(p.AuditSnapshotPayload) == 0 {
		return nil, nil, ErrFittedFinalizationV1
	}
	seen := map[string]bool{}
	baseByPage := map[int]FittedBasePagePinV1{}
	reserved := make([]FittedReservedOutputV1, 0, len(rows))
	var baseBytes int64
	prefix := "org/" + p.OrgID.String() + "/documents/" + p.DocumentID.String() + "/"
	for _, o := range rows {
		if ctx.Err() != nil {
			return nil, nil, fittedErrorV1(ctx, nil)
		}
		if o == nil || o.PreparationID != p.ID || len(o.Sha256) != sha256.Size {
			return nil, nil, ErrFittedFinalizationV1
		}
		digest := hex.EncodeToString(o.Sha256)
		mime := "application/pdf"
		var max int64
		key := ""
		switch o.Kind {
		case "base_pdf":
			max = p.BaseBytesLimit
			key = prefix + "finalization/base/" + p.ID.String() + "/page-" + strconv.Itoa(int(o.Page)) + ".pdf"
		case "final_pdf":
			max = p.FinalPdfBytesLimit
			key = prefix + "final-" + digest + ".pdf"
		case "fits_index":
			max = p.FitsIndexBytesLimit
			mime = "application/json"
			key = manualfit.IndexStorageKeyV1(p.OrgID, p.DocumentID, p.ID)
		case "certificate_pdf":
			max = p.CertificatePdfBytesLimit
			key = prefix + "audit-" + digest + ".pdf"
		case "certificate_payload":
			max = p.CertificatePayloadBytesLimit
			mime = "text/plain"
			key = prefix + "audit-payload-" + digest + ".txt"
		case "certificate_signature":
			max = p.CertificateSignatureBytesLimit
			mime = "text/plain"
			key = prefix + "audit-signature-" + digest + ".txt"
		default:
			return nil, nil, ErrFittedFinalizationV1
		}
		if strings.HasPrefix(o.Kind, "certificate_") && len(p.CertificateInputPayload) == 0 {
			return nil, nil, ErrFittedFinalizationV1
		}
		id := o.Kind + ":" + strconv.Itoa(int(o.Page))
		if seen[id] || o.StorageKey != key || !fittedRecoveryKeyV1(key) || o.ContentType != mime || o.Bytes < 1 || o.Bytes > max || o.Kind != "base_pdf" && o.Page != 0 {
			return nil, nil, ErrFittedFinalizationV1
		}
		seen[id] = true
		// The output start is durable BEFORE its sole original upload attempt.
		// It may exist while attempt/version/readback are still absent.
		if o.RetentionStartedAt.Valid && (!finiteFittedTimeV1(o.RetentionStartedAt) || !finiteFittedTimeV1(p.RetentionStartedAt) || o.RetentionStartedAt.Time.Before(p.RetentionStartedAt.Time)) {
			return nil, nil, ErrFittedFinalizationV1
		}
		if o.UploadAttemptedAt.Valid {
			if !finiteFittedTimeV1(o.UploadAttemptedAt) || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) == uuid.Nil || !o.RetentionStartedAt.Valid || o.UploadAttemptedAt.Time.Before(o.RetentionStartedAt.Time) {
				return nil, nil, ErrFittedFinalizationV1
			}
		} else if o.UploadOwnerID.Valid || o.VersionID.Valid || o.ReadbackVerifiedAt.Valid || o.RetentionCompletedAt.Valid {
			return nil, nil, ErrFittedFinalizationV1
		}
		if o.VersionID.Valid && !manualfit.ValidObjectVersionV1(o.VersionID.String) || !o.VersionID.Valid && o.VersionID.String != "" {
			return nil, nil, ErrFittedFinalizationV1
		}
		if o.ReadbackVerifiedAt.Valid && (!finiteFittedTimeV1(o.ReadbackVerifiedAt) || !o.VersionID.Valid || o.ReadbackVerifiedAt.Time.Before(o.UploadAttemptedAt.Time)) {
			return nil, nil, ErrFittedFinalizationV1
		}
		if o.RetentionCompletedAt.Valid && (!finiteFittedTimeV1(o.RetentionCompletedAt) || !o.RetentionStartedAt.Valid || !o.ReadbackVerifiedAt.Valid || o.RetentionCompletedAt.Time.Before(o.RetentionStartedAt.Time) || o.RetentionCompletedAt.Time.Before(o.ReadbackVerifiedAt.Time)) {
			return nil, nil, ErrFittedFinalizationV1
		}
		if p.Status != "staging" && !o.ReadbackVerifiedAt.Valid || p.RetentionCompletedAt.Valid && !o.RetentionCompletedAt.Valid {
			return nil, nil, ErrFittedFinalizationV1
		}
		if o.Kind == "certificate_payload" && (len(p.CertificateInputPayload) == 0 || o.Bytes != int64(len(p.CertificateInputPayload)) || !bytes.Equal(o.Sha256, p.CertificateInputSha256)) {
			return nil, nil, ErrFittedFinalizationV1
		}
		pin := manualfit.ObjectPinV1{Key: key, VersionID: o.VersionID.String, SHA256: digest, Bytes: o.Bytes, ContentType: mime}
		reserved = append(reserved, FittedReservedOutputV1{Kind: o.Kind, Page: int(o.Page), Object: pin, UploadAttempted: o.UploadAttemptedAt.Valid, ReadbackVerified: o.ReadbackVerifiedAt.Valid, RetentionStarted: o.RetentionStartedAt.Valid, RetentionCompleted: o.RetentionCompletedAt.Valid})
		if o.Kind == "base_pdf" {
			if !o.ReadbackVerifiedAt.Valid {
				return nil, nil, ErrFittedBaseDurabilityRequiredV1
			}
			baseBytes += o.Bytes
			baseByPage[int(o.Page)] = FittedBasePagePinV1{Page: int(o.Page), Object: pin, SourceSHA256: hex.EncodeToString(p.SourceSha256), GeometrySHA256: hex.EncodeToString(p.GeometrySha256), FieldSnapshotSHA256: hex.EncodeToString(p.FieldSnapshotSha256)}
		}
	}
	if baseBytes > p.BaseBytesLimit || p.SourceBytes > int64(sanitize.MaxPDFBytes)-baseBytes {
		return nil, nil, sanitize.ErrPDFTooLarge
	}
	bases := make([]FittedBasePagePinV1, 0, len(p.RequiredBasePages))
	previous := 0
	for _, page := range p.RequiredBasePages {
		n := int(page)
		if n <= previous || n > int(p.SourcePages) {
			return nil, nil, ErrFittedFinalizationV1
		}
		previous = n
		b, ok := baseByPage[n]
		if !ok {
			return nil, nil, ErrFittedBaseDurabilityRequiredV1
		}
		bases = append(bases, b)
		delete(baseByPage, n)
	}
	if len(baseByPage) != 0 {
		return nil, nil, ErrFittedFinalizationV1
	}
	sort.Slice(reserved, func(i, j int) bool {
		if reserved[i].Kind != reserved[j].Kind {
			return reserved[i].Kind < reserved[j].Kind
		}
		return reserved[i].Page < reserved[j].Page
	})
	return reserved, bases, nil
}

type fittedRecoveryReferenceV1 struct {
	owner, selection uuid.UUID
	pin              manualfit.ObjectPinV1
}

func fittedRecoveryReferenceIDV1(kind string, signature uuid.UUID, page int) string {
	return kind + ":" + signature.String() + ":" + strconv.Itoa(page)
}
func fittedRecoveryReferencesV1(ctx context.Context, p *generated.DocumentFinalizationPreparation, rows []*generated.DocumentFinalizationReference, expected map[string]fittedRecoveryReferenceV1) error {
	if p.Status != "staging" && len(rows) != len(expected) {
		return ErrFittedFinalizationV1
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		if r == nil || r.PreparationID != p.ID {
			return ErrFittedFinalizationV1
		}
		signature, selection := uuid.Nil, uuid.Nil
		if r.SignatureID.Valid {
			signature = uuid.UUID(r.SignatureID.Bytes)
		}
		if r.SelectionID.Valid {
			selection = uuid.UUID(r.SelectionID.Bytes)
		}
		id := fittedRecoveryReferenceIDV1(r.Kind, signature, int(r.Page))
		want, ok := expected[id]
		got := manualfit.ObjectPinV1{Key: r.StorageKey, VersionID: r.VersionID, SHA256: hex.EncodeToString(r.Sha256), Bytes: r.Bytes, ContentType: r.ContentType}
		if !ok || seen[id] || r.OwnerKey != want.owner || selection != want.selection || got != want.pin || r.Kind == "source" && (r.SignatureID.Valid || r.SelectionID.Valid) || r.Kind == "legacy_span" && r.SelectionID.Valid || strings.HasPrefix(r.Kind, "fit_") && (!r.SignatureID.Valid || !r.SelectionID.Valid || signature == uuid.Nil || selection == uuid.Nil) {
			return ErrFittedFinalizationV1
		}
		seen[id] = true
		if r.RetentionStartedAt.Valid && (!finiteFittedTimeV1(r.RetentionStartedAt) || p.Status == "staging" || !p.RetentionStartedAt.Valid || r.RetentionStartedAt.Time.Before(p.RetentionStartedAt.Time)) {
			return ErrFittedFinalizationV1
		}
		if r.RetentionCompletedAt.Valid && (!finiteFittedTimeV1(r.RetentionCompletedAt) || !r.RetentionStartedAt.Valid || r.RetentionCompletedAt.Time.Before(r.RetentionStartedAt.Time)) {
			return ErrFittedFinalizationV1
		}
		if p.RetentionCompletedAt.Valid && !r.RetentionCompletedAt.Valid {
			return ErrFittedFinalizationV1
		}
	}
	return nil
}

// Build the exact worker descriptor from cheap frozen section counts before
// any source/base fetch or PDF-section copy. Order matches the core composer:
// page ascending, base first, then SignedAt/raw-UUID ordered fitted parties.
func fittedRecoveryProcessingV1(ctx context.Context, s *FittedFinalizationV1, bases []FittedBasePagePinV1, total int64) error {
	byPage := map[int][]fittedLayerDescriptorV1{}
	for _, b := range bases {
		byPage[b.Page] = append(byPage[b.Page], fittedLayerDescriptorV1{Page: b.Page, Kind: sanitize.PDFManualLayerBaseV1, Identity: "base-page-" + strconv.Itoa(b.Page), Bytes: int(b.Object.Bytes), SHA256: b.Object.SHA256})
	}
	count := len(bases)
	for _, entry := range s.entries {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		m := entry.retained.Manifest()
		if m == nil {
			return ErrFittedFinalizationV1
		}
		for _, page := range m.Pages() {
			if ctx.Err() != nil {
				return fittedErrorV1(ctx, nil)
			}
			n, err := entry.retained.PDFByteCount(page.Page)
			if err != nil {
				return ErrFittedFinalizationV1
			}
			count++
			if count > sanitize.MaxPDFManualLayersV1 {
				return sanitize.ErrPDFTooLarge
			}
			byPage[page.Page] = append(byPage[page.Page], fittedLayerDescriptorV1{Page: page.Page, Kind: sanitize.PDFManualLayerSignatureV1, Identity: "signature:" + entry.signatureID.String(), Bytes: n, SHA256: page.PDFSHA256})
		}
	}
	pages := make([]int, 0, len(byPage))
	for page := range byPage {
		pages = append(pages, page)
	}
	sort.Ints(pages)
	batch := fittedLayersBatchV1{SchemaVersion: 1, SourceSHA256: s.source.SHA256, SourceBytes: s.source.Bytes, GeometrySHA256: s.geometry.GeometrySHA256, Pages: len(s.geometry.Pages), Layers: make([]fittedLayerDescriptorV1, 0, count)}
	for _, page := range pages {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		for i, d := range byPage[page] {
			d.Order = i + 1
			batch.Layers = append(batch.Layers, d)
		}
	}
	raw, err := json.Marshal(batch)
	if ctx.Err() != nil {
		return fittedErrorV1(ctx, nil)
	}
	if err != nil || len(raw) > 1<<20 || total < 1 || int64(len(raw)) > int64(sanitize.MaxPDFBytes)-total {
		return sanitize.ErrPDFTooLarge
	}
	return nil
}
func fittedRecoveryCompletedV1(d *generated.GetFittedFinalizationRecoveryDocumentMetadataRow, p *generated.DocumentFinalizationPreparation, c *generated.GetCompletedFittedFinalizationRow, outputs []*generated.ListFittedFinalizationOutputsRow) error {
	if c == nil || c.ID != p.DocumentID || c.OrgID != p.OrgID || !c.FitsIndexRequired || !c.FitsIndexPreparationID.Valid || uuid.UUID(c.FitsIndexPreparationID.Bytes) != p.ID || !finiteFittedTimeV1(c.CeremonyEpoch) || !c.CeremonyEpoch.Time.Equal(p.CeremonyEpoch.Time) || !finiteFittedTimeV1(c.CompletionEffectiveAt) || !c.CompletionEffectiveAt.Time.Equal(p.CompletionEffectiveAt.Time) || !finiteFittedTimeV1(c.RetainUntil) || !c.RetainUntil.Time.Equal(p.RetainUntil.Time) || !finiteFittedTimeV1(c.PublishedAt) || !c.PublishedAt.Time.Equal(p.PublishedAt.Time) || c.OriginalDocumentName != p.OriginalDocumentName || !bytes.Equal(c.FieldSnapshotSha256, p.FieldSnapshotSha256) || !bytes.Equal(c.GeometrySha256, p.GeometrySha256) {
		return ErrFittedFinalizationV1
	}
	type pair struct {
		key, version pgtype.Text
		digest       []byte
	}
	docPins := map[string]pair{"final_pdf": {d.FinalPdfKey, d.FinalPdfVersionID, d.FinalPdfSha}, "fits_index": {d.FitsIndexStorageKey, d.FitsIndexVersionID, d.FitsIndexSha256}, "certificate_pdf": {d.AuditCertKey, d.AuditCertVersionID, d.AuditCertSha256}, "certificate_payload": {d.AuditPayloadKey, d.AuditPayloadVersionID, d.AuditPayloadSha256}, "certificate_signature": {d.AuditSignatureKey, d.AuditSignatureVersionID, d.AuditSignatureSha256}}
	callbackPins := map[string]pair{"final_pdf": {c.FinalPdfKey, c.FinalPdfVersionID, c.FinalPdfSha}, "fits_index": {c.FitsIndexStorageKey, c.FitsIndexVersionID, c.FitsIndexSha256}, "certificate_pdf": {c.AuditCertKey, c.AuditCertVersionID, c.AuditCertSha256}, "certificate_payload": {c.AuditPayloadKey, c.AuditPayloadVersionID, c.AuditPayloadSha256}, "certificate_signature": {c.AuditSignatureKey, c.AuditSignatureVersionID, c.AuditSignatureSha256}}
	for _, o := range outputs {
		if o.Kind == "base_pdf" {
			continue
		}
		a, b := docPins[o.Kind], callbackPins[o.Kind]
		if !a.key.Valid || !a.version.Valid || !b.key.Valid || !b.version.Valid || a.key.String != o.StorageKey || b.key.String != o.StorageKey || a.version.String != o.VersionID.String || b.version.String != o.VersionID.String || !bytes.Equal(a.digest, o.Sha256) || !bytes.Equal(b.digest, o.Sha256) {
			return ErrFittedFinalizationV1
		}
		if o.Kind == "fits_index" && (!d.FitsIndexBytes.Valid || !c.FitsIndexBytes.Valid || d.FitsIndexBytes.Int64 != o.Bytes || c.FitsIndexBytes.Int64 != o.Bytes) || o.Kind == "final_pdf" && c.FinalPdfBytes != o.Bytes {
			return ErrFittedFinalizationV1
		}
	}
	return nil
}
