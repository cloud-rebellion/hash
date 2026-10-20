// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
)

var (
	ErrFittedFinalizationV1            = errors.New("sign: exact fitted finalization unavailable")
	ErrFittedBaseDurabilityRequiredV1  = errors.New("sign: frozen ordinary-field and legacy-signature base pages must be durably staged")
	ErrFittedCompositionRequiredV1     = errors.New("sign: fitted signatures require retained ordered composition")
	ErrFittedOriginalOutputsRequiredV1 = errors.New("sign: recover the original reserved fitted finalization outputs")
	ErrFittedJournalRecoveryRequiredV1 = errors.New("sign: composition requires locked fitted journal recovery")
)

// FittedFinalizationQueriesV1 is satisfied by the real generated SQL adapter.
// Callers must first commit the finalizing state and completion target under
// the document lock. These reads do not replace signing authorization.
type FittedFinalizationQueriesV1 interface {
	ListSignaturesByDocument(context.Context, uuid.UUID) ([]*generated.Signature, error)
	ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error)
	ListFieldsByDocument(context.Context, uuid.UUID) ([]*generated.DocumentField, error)
	ListDocumentSignatureFitCompanions(context.Context, generated.ListDocumentSignatureFitCompanionsParams) ([]*generated.SignatureFitCompanion, error)
	GetSignatureFitSelection(context.Context, generated.GetSignatureFitSelectionParams) (*generated.SignatureFitSelection, error)
	GetSignatureFitPreparation(context.Context, generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error)
	ListSignatureFitObjects(context.Context, generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error)
}

var _ FittedFinalizationQueriesV1 = (*generated.Queries)(nil)

type FittedFinalizationRetentionQueriesV1 interface {
	GetDocumentFinalizationIntent(context.Context, generated.GetDocumentFinalizationIntentParams) (*generated.DocumentFinalizationIntent, error)
}

var _ FittedFinalizationRetentionQueriesV1 = (*generated.Queries)(nil)

// FittedSignatureFinalizationV1 owns a completely verified archived package set.
// Original names and fonts come from its manifest, never mutable row metadata.
type FittedSignatureFinalizationV1 struct {
	signatureID, selectionID, recipientID, fieldID uuid.UUID
	signedAt, retentionFloor                       time.Time
	retained                                       *manualfit.RetainedV1
}

func (s *FittedSignatureFinalizationV1) SignatureID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.signatureID
}
func (s *FittedSignatureFinalizationV1) SelectionID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.selectionID
}
func (s *FittedSignatureFinalizationV1) RecipientID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.recipientID
}
func (s *FittedSignatureFinalizationV1) FieldID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.fieldID
}
func (s *FittedSignatureFinalizationV1) SignedAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.signedAt
}
func (s *FittedSignatureFinalizationV1) RetentionFloor() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.retentionFloor
}
func (s *FittedSignatureFinalizationV1) Manifest() *manualfit.ManifestV1 {
	if s == nil || s.retained == nil {
		return nil
	}
	return s.retained.Manifest()
}
func (s *FittedSignatureFinalizationV1) ManifestObject() manualfit.ObjectPinV1 {
	if s == nil || s.retained == nil {
		return manualfit.ObjectPinV1{}
	}
	return s.retained.ManifestObject()
}
func (s *FittedSignatureFinalizationV1) SpanBytes() []byte {
	if s == nil || s.retained == nil {
		return nil
	}
	return s.retained.SpanBytes()
}
func (s *FittedSignatureFinalizationV1) PackageBytes(page int) ([]byte, error) {
	if s == nil || s.retained == nil {
		return nil, ErrFittedFinalizationV1
	}
	return s.retained.PackageBytes(page)
}
func (s *FittedSignatureFinalizationV1) PDFBytes(page int) ([]byte, error) {
	if s == nil || s.retained == nil {
		return nil, ErrFittedFinalizationV1
	}
	return s.retained.PDFBytes(page)
}
func (s *FittedSignatureFinalizationV1) OriginalName() string {
	if s == nil || s.retained == nil {
		return ""
	}
	return s.retained.Manifest().Authority().Input().TypedName
}
func (s *FittedSignatureFinalizationV1) Font() string {
	if s == nil || s.retained == nil {
		return ""
	}
	return s.retained.Manifest().Authority().Input().Font
}

// FittedBasePagePinV1 is a descriptor from the document-wide durable base-page
// journal, not permission to render or write a replacement. One operation owns
// the entire exact page set. The constructor reads every pinned version.
type FittedBasePagePinV1 struct {
	Page                int
	Object              manualfit.ObjectPinV1
	SourceSHA256        string
	GeometrySHA256      string
	FieldSnapshotSHA256 string
}
type fittedBasePageV1 struct {
	descriptor FittedBasePagePinV1
	pdf        []byte
}

// FittedFinalizationV1 is immutable through its accessors. It is an application
// rebind plus exact archive read, not proof that Sign or an index was published.
// baseReady is false until all ordinary-field/legacy-overlay pages have exact
// durable pins. Renderer-independent composition refuses an incomplete set.
type FittedFinalizationV1 struct {
	orgID, documentID                                 uuid.UUID
	ceremonyEpoch, completionEffectiveAt, retainUntil time.Time
	source                                            manualfit.SourceTupleV1
	geometry                                          sanitize.PDFManualGeometry
	entries                                           []*FittedSignatureFinalizationV1
	legacySignatures                                  []manualfit.FitsIndexLegacySignatureV1
	legacySpans                                       map[uuid.UUID][]byte
	fieldSnapshotSHA256                               string
	fieldSnapshotJSON                                 []byte
	requiredBasePages                                 []int
	bases                                             []fittedBasePageV1
	baseReady                                         bool
	// Recovery forbids recomposition once any original final/index/certificate
	// body is reserved, including uploads with unknown outcomes. Its journal
	// bodies must be reused; fresh serialization can change their exact bytes.
	originalOutputsRequired bool
	journalRecoveryBound    bool
}

func (s *FittedFinalizationV1) OrgID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.orgID
}
func (s *FittedFinalizationV1) DocumentID() uuid.UUID {
	if s == nil {
		return uuid.Nil
	}
	return s.documentID
}
func (s *FittedFinalizationV1) CeremonyEpoch() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.ceremonyEpoch
}
func (s *FittedFinalizationV1) CompletionEffectiveAt() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.completionEffectiveAt
}
func (s *FittedFinalizationV1) RetainUntil() time.Time {
	if s == nil {
		return time.Time{}
	}
	return s.retainUntil
}
func (s *FittedFinalizationV1) Source() manualfit.SourceTupleV1 {
	if s == nil {
		return manualfit.SourceTupleV1{}
	}
	return s.source
}
func (s *FittedFinalizationV1) Geometry() sanitize.PDFManualGeometry {
	if s == nil {
		return sanitize.PDFManualGeometry{}
	}
	g := s.geometry
	g.Pages = append([]sanitize.PDFManualPage(nil), g.Pages...)
	return g
}
func (s *FittedFinalizationV1) Entries() []*FittedSignatureFinalizationV1 {
	if s == nil {
		return nil
	}
	return append([]*FittedSignatureFinalizationV1(nil), s.entries...)
}

// LegacySignatures exposes the frozen original adoption descriptors captured
// with this snapshot. Evidence export must not replace these with DSR row
// projections. A delegated kind records history, not grant authorization/QES.
func (s *FittedFinalizationV1) LegacySignatures() []manualfit.FitsIndexLegacySignatureV1 {
	if s == nil {
		return nil
	}
	return append([]manualfit.FitsIndexLegacySignatureV1(nil), s.legacySignatures...)
}
func (s *FittedFinalizationV1) LegacySpanBytes(signatureID uuid.UUID) ([]byte, error) {
	if s == nil {
		return nil, ErrFittedFinalizationV1
	}
	raw, ok := s.legacySpans[signatureID]
	if !ok {
		return nil, ErrFittedFinalizationV1
	}
	return bytes.Clone(raw), nil
}

// captureFittedLegacySignatureV1 is only the initial locked capture seam.
// Historical recovery must instead use an authenticated retained signed index
// or the scoped guarded migration86 journal's frozen payload/binding/SHA.
// Arbitrary caller metadata and redacted live rows are not original authority.
func captureFittedLegacySignatureV1(ctx context.Context, reader manualfit.BoundedReaderV1, documentID uuid.UUID, s *generated.Signature) (entry manualfit.FitsIndexLegacySignatureV1, span []byte, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			entry = manualfit.FitsIndexLegacySignatureV1{}
			span = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || reader == nil || s == nil || documentID == uuid.Nil {
		return entry, nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return entry, nil, fittedErrorV1(ctx, nil)
	}
	// Copy names/pins before any provider wait. This descriptor never retains a
	// generated row pointer; subsequent privacy projections cannot mutate it.
	entry = manualfit.FitsIndexLegacySignatureV1{DocumentID: s.DocumentID, SignatureID: s.ID, RecipientID: s.RecipientID, FieldID: s.FieldID, Kind: s.SignatureKind, SignedAt: s.SignedAt.Time.UTC().Round(0), Object: manualfit.ObjectPinV1{Key: s.ImageStorageKey, VersionID: s.ImageVersionID.String, SHA256: hex.EncodeToString(s.ImageSha256), ContentType: "text/html"}, OriginalName: s.TypedName, Font: s.Font, SpanSHA256: hex.EncodeToString(s.ImageSha256)}
	if entry.DocumentID != documentID || entry.SignatureID == uuid.Nil || entry.RecipientID == uuid.Nil || entry.FieldID == uuid.Nil || (entry.Kind != "manual" && entry.Kind != "delegated_grant_v1") || !finiteFittedTimeV1(s.SignedAt) || !s.ImageVersionPinRequired || !s.ImageVersionID.Valid || !manualfit.ValidObjectVersionV1(entry.Object.VersionID) || strings.TrimSpace(entry.Object.Key) == "" || len(entry.Object.Key) > 1024 || !utf8.ValidString(entry.Object.Key) || strings.TrimSpace(entry.Object.Key) != entry.Object.Key || !fittedDigestV1(entry.Object.SHA256) || !utf8.ValidString(entry.Font) || len(entry.Font) > 128 || render.ValidateSignatureName(entry.OriginalName) != nil {
		return manualfit.FitsIndexLegacySignatureV1{}, nil, ErrFittedFinalizationV1
	}
	digest, _ := hex.DecodeString(entry.Object.SHA256)
	// Historical rows do not store byte count. Enforce the frozen5056-byte format
	// cap while streaming; only then freeze the exact count in the journal/index.
	raw, err := reader.GetVerifiedVersionBounded(ctx, entry.Object.Key, entry.Object.VersionID, digest, int64(render.MaxArchivedSignatureSpanBytes))
	if err != nil {
		return manualfit.FitsIndexLegacySignatureV1{}, nil, fittedErrorV1(ctx, err)
	}
	if ctx.Err() != nil {
		return manualfit.FitsIndexLegacySignatureV1{}, nil, fittedErrorV1(ctx, nil)
	}
	if len(raw) < 1 || len(raw) > render.MaxArchivedSignatureSpanBytes || fittedSHA256V1(raw) != entry.Object.SHA256 {
		return manualfit.FitsIndexLegacySignatureV1{}, nil, ErrFittedFinalizationV1
	}
	if _, err = render.ValidateArchivedSignatureSpan(raw, entry.OriginalName, entry.Font); err != nil {
		return manualfit.FitsIndexLegacySignatureV1{}, nil, ErrFittedFinalizationV1
	}
	entry.Object.Bytes = int64(len(raw))
	return entry, bytes.Clone(raw), nil
}

func (s *FittedFinalizationV1) FieldSnapshotSHA256() string {
	if s == nil {
		return ""
	}
	return s.fieldSnapshotSHA256
}

// FieldSnapshotBytes are the exact canonical capture bytes committed by
// FieldSnapshotSHA256. The guarded86 journal must preserve them before effects.
func (s *FittedFinalizationV1) FieldSnapshotBytes() []byte {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.fieldSnapshotJSON)
}
func (s *FittedFinalizationV1) RequiredBasePages() []int {
	if s == nil {
		return nil
	}
	return append([]int(nil), s.requiredBasePages...)
}
func (s *FittedFinalizationV1) BasePages() []FittedBasePagePinV1 {
	if s == nil {
		return nil
	}
	out := make([]FittedBasePagePinV1, len(s.bases))
	for i, b := range s.bases {
		out[i] = b.descriptor
	}
	return out
}

func (s *FittedFinalizationV1) BasePDFBytes(page int) ([]byte, error) {
	if s == nil || !s.baseReady {
		return nil, ErrFittedBaseDurabilityRequiredV1
	}
	for _, b := range s.bases {
		if b.descriptor.Page == page {
			return bytes.Clone(b.pdf), nil
		}
	}
	return nil, ErrFittedFinalizationV1
}

func (e *Engine) LoadFittedFinalizationV1(ctx context.Context, doc *generated.Document) (*FittedFinalizationV1, error) {
	if e == nil || e.Queries == nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	reader, _ := e.Storage.(manualfit.BoundedReaderV1)
	return LoadFittedFinalizationV1(ctx, e.Queries, reader, doc)
}

// LoadFittedFinalizationV1 preserves the legacy path: with no fitted rows it
// returns nil without demanding a new storage capability. A fitted row must
// have its exact reciprocal companion, selected preparation and full inventory.
func LoadFittedFinalizationV1(ctx context.Context, q FittedFinalizationQueriesV1, reader manualfit.BoundedReaderV1, doc *generated.Document) (snapshot *FittedFinalizationV1, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			snapshot = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || q == nil || doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	fitted := 0
	for _, s := range signatures {
		if s == nil {
			return nil, ErrFittedFinalizationV1
		}
		if s.SignatureKind == manualfit.AuthoritySchemaV1 {
			fitted++
		}
	}
	if fitted == 0 {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		return nil, nil
	}
	if reader == nil || doc.SourceKind != "pdf" || !doc.RequiresSignature || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || doc.DeletedAt.Valid || (doc.Status != "finalizing" && doc.Status != "completed") || !doc.CompletionEffectiveAtBound || !doc.Article13NoticeEpochV61Committed || !finiteFittedTimeV1(doc.Article13NoticeEpochAt) {
		return nil, ErrFittedFinalizationV1
	}
	if _, err := canonicalCompletionEffectiveAt(doc.CompletionEffectiveAt); err != nil || !finiteFittedTimeV1(doc.CompletionEffectiveAt) {
		return nil, ErrFittedFinalizationV1
	}
	completion := doc.CompletionEffectiveAt.Time.UTC().Round(0)
	until, err := finalizationRetentionDeadline(doc)
	if err != nil || !finiteFittedTimeV1(doc.SentAt) || !finiteFittedTimeV1(doc.FinalizationRetainUntil) || !completion.After(doc.Article13NoticeEpochAt.Time) {
		return nil, ErrFittedFinalizationV1
	}
	fields, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	companions, err := q.ListDocumentSignatureFitCompanions(ctx, generated.ListDocumentSignatureFitCompanionsParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	if len(companions) != fitted || fitted > pdflayout.MaxParties || len(signatures) > pdflayout.MaxParties {
		return nil, ErrFittedFinalizationV1
	}
	companionByID := make(map[uuid.UUID]*generated.SignatureFitCompanion, len(companions))
	for _, c := range companions {
		if c == nil || c.SignatureID == uuid.Nil || c.OrgID != doc.OrgID || c.DocumentID != doc.ID || c.RecipientID == uuid.Nil || c.FieldID == uuid.Nil || c.SelectionID == uuid.Nil || companionByID[c.SignatureID] != nil || len(c.SpanSha256) != sha256.Size {
			return nil, ErrFittedFinalizationV1
		}
		companionByID[c.SignatureID] = c
	}
	out := &FittedFinalizationV1{orgID: doc.OrgID, documentID: doc.ID, ceremonyEpoch: doc.Article13NoticeEpochAt.Time.UTC().Round(0), completionEffectiveAt: completion, retainUntil: until}
	var archiveBytes int64
	seenSignatures := map[uuid.UUID]bool{}
	for _, s := range signatures {
		if s.ID == uuid.Nil || s.DocumentID != doc.ID || seenSignatures[s.ID] || !finiteFittedTimeV1(s.SignedAt) || s.SignedAt.Time.Before(out.ceremonyEpoch) || !s.SignedAt.Time.Before(completion) {
			return nil, ErrFittedFinalizationV1
		}
		seenSignatures[s.ID] = true
		if s.SignatureKind != manualfit.AuthoritySchemaV1 {
			if companionByID[s.ID] != nil {
				return nil, ErrFittedFinalizationV1
			}
			entry, raw, err := captureFittedLegacySignatureV1(ctx, reader, doc.ID, s)
			if err != nil {
				return nil, err
			}
			if out.legacySpans == nil {
				out.legacySpans = map[uuid.UUID][]byte{}
			}
			out.legacySignatures = append(out.legacySignatures, entry)
			out.legacySpans[entry.SignatureID] = raw
			continue
		}
		c := companionByID[s.ID]
		if c == nil || c.RecipientID != s.RecipientID || c.FieldID != s.FieldID || s.PresignExecutionID.Valid || !s.ImageVersionPinRequired || !s.ImageVersionID.Valid || len(s.ImageSha256) != sha256.Size || !bytes.Equal(c.SpanSha256, s.ImageSha256) {
			return nil, ErrFittedFinalizationV1
		}
		selected, err := q.GetSignatureFitSelection(ctx, generated.GetSignatureFitSelectionParams{DocumentID: doc.ID, RecipientID: s.RecipientID, CeremonyEpoch: doc.Article13NoticeEpochAt, OrgID: doc.OrgID})
		if err != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		if selected == nil || selected.ID != c.SelectionID || selected.PreparationID == uuid.Nil || selected.OrgID != doc.OrgID || selected.DocumentID != doc.ID || selected.RecipientID != s.RecipientID || !finiteFittedTimeV1(selected.CeremonyEpoch) || !selected.CeremonyEpoch.Time.Equal(out.ceremonyEpoch) || !finiteFittedTimeV1(selected.RetentionStartedAt) || !finiteFittedTimeV1(selected.RetentionCompletedAt) || selected.RetentionCompletedAt.Time.Before(selected.RetentionStartedAt.Time) || selected.RetentionCompletedAt.Time.After(s.SignedAt.Time) || !finiteFittedTimeV1(selected.RetainUntil) || !selected.RetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(out.ceremonyEpoch, article13.RetentionYearsV1)) || selected.SpanStorageKey != s.ImageStorageKey || selected.SpanVersionID != s.ImageVersionID.String || !bytes.Equal(selected.SpanSha256, s.ImageSha256) || len(selected.AuthoritySha256) != sha256.Size {
			return nil, ErrFittedFinalizationV1
		}
		pin := manualfit.ObjectPinV1{Key: selected.ManifestStorageKey, VersionID: selected.ManifestVersionID, SHA256: hex.EncodeToString(selected.ManifestSha256), Bytes: selected.ManifestBytes, ContentType: "application/json"}
		binding := manualfit.BindingV1{OperationID: selected.PreparationID, OrgID: doc.OrgID, DocumentID: doc.ID, RecipientID: s.RecipientID, CeremonyEpoch: out.ceremonyEpoch, AuthoritySHA256: hex.EncodeToString(selected.AuthoritySha256)}
		retained, err := manualfit.VerifyRetainedV1(ctx, reader, pin, binding)
		if err != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		m := retained.Manifest()
		prep, err := q.GetSignatureFitPreparation(ctx, generated.GetSignatureFitPreparationParams{ID: selected.PreparationID, OrgID: doc.OrgID})
		if err != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		objects, err := q.ListSignatureFitObjects(ctx, generated.ListSignatureFitObjectsParams{ID: selected.PreparationID, OrgID: doc.OrgID})
		if err != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		if validateFittedArchiveRebindV1(doc, s, selected, prep, fields, objects, m, pin) != nil {
			return nil, ErrFittedFinalizationV1
		}
		source, g := m.Authority().Input().Source, m.Authority().Geometry()
		if len(out.entries) == 0 {
			out.source = source
			out.geometry = g
		} else if out.source != source || !reflect.DeepEqual(out.geometry, g) {
			return nil, ErrFittedFinalizationV1
		}
		if m.AggregateBytes() > manualfit.MaxEvidenceBytesV1-archiveBytes {
			return nil, ErrFittedFinalizationV1
		}
		archiveBytes += m.AggregateBytes()
		out.entries = append(out.entries, &FittedSignatureFinalizationV1{signatureID: s.ID, selectionID: selected.ID, recipientID: s.RecipientID, fieldID: s.FieldID, signedAt: s.SignedAt.Time.UTC().Round(0), retentionFloor: selected.RetainUntil.Time.UTC(), retained: retained})
	}
	if archiveBytes > doc.SignatureFitReservedBytes || pdflayout.ValidateSignatureRows(doc, recipients, fields, signatures, len(out.geometry.Pages)) != nil {
		return nil, ErrFittedFinalizationV1
	}
	sort.Slice(out.entries, func(i, j int) bool {
		a, b := out.entries[i], out.entries[j]
		if !a.signedAt.Equal(b.signedAt) {
			return a.signedAt.Before(b.signedAt)
		}
		return bytes.Compare(a.signatureID[:], b.signatureID[:]) < 0
	})
	sort.Slice(out.legacySignatures, func(i, j int) bool {
		a, b := out.legacySignatures[i], out.legacySignatures[j]
		if !a.SignedAt.Equal(b.SignedAt) {
			return a.SignedAt.Before(b.SignedAt)
		}
		return bytes.Compare(a.SignatureID[:], b.SignatureID[:]) < 0
	})
	out.fieldSnapshotSHA256, out.requiredBasePages, out.fieldSnapshotJSON, err = fittedFieldSnapshotWithLegacyV1(doc.ID, fields, signatures, out.legacySignatures)
	if err != nil {
		return nil, ErrFittedFinalizationV1
	}
	out.baseReady = len(out.requiredBasePages) == 0
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	return out, nil
}

func validateFittedArchiveRebindV1(doc *generated.Document, s *generated.Signature, selected *generated.SignatureFitSelection, p *generated.SignatureFitPreparation, fields []*generated.DocumentField, objects []*generated.SignatureFitObject, m *manualfit.ManifestV1, pin manualfit.ObjectPinV1) error {
	if doc == nil || s == nil || selected == nil || p == nil || m == nil {
		return ErrFittedFinalizationV1
	}
	b, in, g := m.Binding(), m.Authority().Input(), m.Authority().Geometry()
	span := m.Span()
	if b.OrgID != doc.OrgID || b.DocumentID != doc.ID || b.RecipientID != s.RecipientID || b.OperationID != p.ID || !b.CeremonyEpoch.Equal(doc.Article13NoticeEpochAt.Time) || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String != in.Source.Key || !doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String != in.Source.VersionID || hex.EncodeToString(doc.PdfSha256) != in.Source.SHA256 || selected.SourceStorageKey != in.Source.Key || selected.SourceVersionID != in.Source.VersionID || hex.EncodeToString(selected.SourceSha256) != in.Source.SHA256 || selected.SourceBytes != in.Source.Bytes || hex.EncodeToString(selected.GeometrySha256) != g.GeometrySHA256 || selected.SpanStorageKey != span.Key || selected.SpanVersionID != span.VersionID || hex.EncodeToString(selected.SpanSha256) != span.SHA256 || selected.SpanBytes != span.Bytes || hex.EncodeToString(selected.AuthoritySha256) != b.AuthoritySHA256 {
		return ErrFittedFinalizationV1
	}
	if p.OrgID != b.OrgID || p.DocumentID != b.DocumentID || p.RecipientID != b.RecipientID || !finiteFittedTimeV1(p.CeremonyEpoch) || !p.CeremonyEpoch.Time.Equal(b.CeremonyEpoch) || p.Status != "prepared" || hex.EncodeToString(p.AuthoritySha256) != b.AuthoritySHA256 || p.SourceStorageKey != in.Source.Key || p.SourceVersionID != in.Source.VersionID || hex.EncodeToString(p.SourceSha256) != in.Source.SHA256 || p.SourceBytes != in.Source.Bytes || hex.EncodeToString(p.GeometrySha256) != g.GeometrySHA256 || hex.EncodeToString(p.SpanSha256) != in.SpanSHA256 || pin.Key != m.ManifestKey() || pin.SHA256 != m.SHA256() || pin.Bytes != int64(len(m.CanonicalJSON())) || pin.ContentType != "application/json" || p.ExpectedObjects != int32(len(m.Pages())+2) || p.ReservedBytes < m.AggregateBytes() || p.ReservedBytes > manualfit.MaxEvidenceBytesV1 {
		return ErrFittedFinalizationV1
	}
	if len(fields) < 1 || len(fields) > pdflayout.MaxFields {
		return ErrFittedFinalizationV1
	}
	targets := map[uuid.UUID]manualfit.TargetV1{}
	for _, t := range in.Targets {
		targets[t.ID] = t
	}
	seen := map[uuid.UUID]bool{}
	count := 0
	signatureFieldFound := false
	for _, f := range fields {
		if f == nil || f.ID == uuid.Nil || f.DocumentID != doc.ID || seen[f.ID] {
			return ErrFittedFinalizationV1
		}
		seen[f.ID] = true
		if f.Type != "signature" || !f.RecipientID.Valid || uuid.UUID(f.RecipientID.Bytes) != s.RecipientID {
			continue
		}
		t, ok := targets[f.ID]
		if !ok || !f.Required || t.Required != f.Required || t.Page != int(f.Page) || !pdflayout.ValidPlacement(f, len(g.Pages)) {
			return ErrFittedFinalizationV1
		}
		got := [4]string{}
		for i, n := range []pgtype.Numeric{f.XPct, f.YPct, f.WPct, f.HPct} {
			v, e := fittedDecimalV1(n)
			if e != nil {
				return ErrFittedFinalizationV1
			}
			got[i] = v
		}
		if got != [4]string{t.X, t.Y, t.W, t.H} {
			return ErrFittedFinalizationV1
		}
		if f.ID == s.FieldID {
			signatureFieldFound = true
		}
		count++
	}
	if !signatureFieldFound || count != len(in.Targets) {
		return ErrFittedFinalizationV1
	}
	expected := map[string]manualfit.ObjectPinV1{"span:0": span, "manifest:0": pin}
	for _, page := range m.Pages() {
		expected["page:"+strconv.Itoa(page.Page)] = page.Package
	}
	if len(objects) != len(expected) {
		return ErrFittedFinalizationV1
	}
	var total int64
	for _, o := range objects {
		if o == nil || o.PreparationID != b.OperationID || !finiteFittedTimeV1(o.UploadAttemptedAt) || !o.UploadOwnerID.Valid || uuid.UUID(o.UploadOwnerID.Bytes) == uuid.Nil || !o.VersionID.Valid || !finiteFittedTimeV1(o.ReadbackVerifiedAt) || o.ReadbackVerifiedAt.Time.Before(o.UploadAttemptedAt.Time) || o.CleanupCompletedAt.Valid {
			return ErrFittedFinalizationV1
		}
		id := o.Kind + ":" + strconv.Itoa(int(o.Page))
		want, ok := expected[id]
		if !ok || o.StorageKey != want.Key || o.VersionID.String != want.VersionID || hex.EncodeToString(o.Sha256) != want.SHA256 || o.Bytes != want.Bytes || o.ContentType != want.ContentType || o.Bytes < 1 || o.Bytes > manualfit.MaxEvidenceBytesV1-total {
			return ErrFittedFinalizationV1
		}
		total += o.Bytes
		delete(expected, id)
	}
	if len(expected) != 0 || total != m.AggregateBytes() || total > p.ReservedBytes {
		return ErrFittedFinalizationV1
	}
	return nil
}

// The V1 field basis is explicit: later generated-model additions must not
// silently change historical identities. All placement/value tuples and every
// legacy signature pin participate; fitted originals are committed by manifests.
type fittedFieldBasisV1 struct {
	ID             uuid.UUID
	RecipientID    uuid.UUID
	RecipientValid bool
	Type           string
	Page           int32
	Required       bool
	X, Y, W, H     string
	ValueValid     bool
	Value          string
}
type fittedLegacyBasisV1 struct {
	DocumentID, ID, RecipientID, FieldID uuid.UUID
	Kind                                 string
	SignedAt                             time.Time
	Object                               manualfit.ObjectPinV1
	Name, Font, SpanSHA256               string
}
type fittedFieldBasisDocumentV1 struct {
	Schema     string
	DocumentID uuid.UUID
	Fields     []fittedFieldBasisV1
	Legacy     []fittedLegacyBasisV1
}

func fittedFieldSnapshotV1(documentID uuid.UUID, fields []*generated.DocumentField, signatures []*generated.Signature) (string, []int, error) {
	sha, pages, _, err := fittedFieldSnapshotWithLegacyV1(documentID, fields, signatures, nil)
	return sha, pages, err
}
func fittedFieldSnapshotWithLegacyV1(documentID uuid.UUID, fields []*generated.DocumentField, signatures []*generated.Signature, frozen []manualfit.FitsIndexLegacySignatureV1) (string, []int, []byte, error) {
	basis := fittedFieldBasisDocumentV1{Schema: "hash-manual-finalization-field-basis-v1", DocumentID: documentID, Fields: make([]fittedFieldBasisV1, 0, len(fields)), Legacy: make([]fittedLegacyBasisV1, 0)}
	needed := map[int]bool{}
	fittedRecipients := map[uuid.UUID]bool{}
	captured := map[uuid.UUID]manualfit.FitsIndexLegacySignatureV1{}
	for _, entry := range frozen {
		if entry.SignatureID == uuid.Nil || captured[entry.SignatureID].SignatureID != uuid.Nil {
			return "", nil, nil, ErrFittedFinalizationV1
		}
		captured[entry.SignatureID] = entry
	}
	for _, s := range signatures {
		if s == nil {
			return "", nil, nil, ErrFittedFinalizationV1
		}
		if s.SignatureKind == manualfit.AuthoritySchemaV1 {
			fittedRecipients[s.RecipientID] = true
			continue
		}
		entry, ok := captured[s.ID]
		if !ok || entry.DocumentID != documentID || entry.SignatureID != s.ID || entry.RecipientID != s.RecipientID || entry.FieldID != s.FieldID || entry.Kind != s.SignatureKind || !entry.SignedAt.Equal(s.SignedAt.Time) || !s.ImageVersionPinRequired || !s.ImageVersionID.Valid || entry.Object.Key != s.ImageStorageKey || entry.Object.VersionID != s.ImageVersionID.String || entry.Object.SHA256 != hex.EncodeToString(s.ImageSha256) || entry.SpanSHA256 != entry.Object.SHA256 || !validFittedPinV1(entry.Object, int64(render.MaxArchivedSignatureSpanBytes)) || entry.Object.ContentType != "text/html" {
			return "", nil, nil, ErrFittedFinalizationV1
		}
		basis.Legacy = append(basis.Legacy, fittedLegacyBasisV1{DocumentID: entry.DocumentID, ID: entry.SignatureID, RecipientID: entry.RecipientID, FieldID: entry.FieldID, Kind: entry.Kind, SignedAt: entry.SignedAt, Object: entry.Object, Name: entry.OriginalName, Font: entry.Font, SpanSHA256: entry.SpanSHA256})
		delete(captured, s.ID)
	}
	if len(captured) != 0 {
		return "", nil, nil, ErrFittedFinalizationV1
	}
	seen := map[uuid.UUID]bool{}
	for _, f := range fields {
		if f == nil || f.ID == uuid.Nil || f.DocumentID != documentID || seen[f.ID] {
			return "", nil, nil, ErrFittedFinalizationV1
		}
		seen[f.ID] = true
		coords := [4]string{}
		for i, n := range []pgtype.Numeric{f.XPct, f.YPct, f.WPct, f.HPct} {
			v, e := fittedDecimalV1(n)
			if e != nil {
				return "", nil, nil, ErrFittedFinalizationV1
			}
			coords[i] = v
		}
		basis.Fields = append(basis.Fields, fittedFieldBasisV1{f.ID, uuid.UUID(f.RecipientID.Bytes), f.RecipientID.Valid, f.Type, f.Page, f.Required, coords[0], coords[1], coords[2], coords[3], f.Value.Valid, f.Value.String})
		if f.Type == "signature" {
			if f.RecipientID.Valid && !fittedRecipients[uuid.UUID(f.RecipientID.Bytes)] {
				needed[int(f.Page)] = true
			}
		} else if f.Value.Valid && strings.TrimSpace(f.Value.String) != "" && (f.Type != "checkbox" || isTruthy(f.Value.String)) {
			needed[int(f.Page)] = true
		}
	}
	sort.Slice(basis.Fields, func(i, j int) bool { return bytes.Compare(basis.Fields[i].ID[:], basis.Fields[j].ID[:]) < 0 })
	sort.Slice(basis.Legacy, func(i, j int) bool { return bytes.Compare(basis.Legacy[i].ID[:], basis.Legacy[j].ID[:]) < 0 })
	raw, err := json.Marshal(basis)
	if err != nil || len(raw) > manualfit.MaxAuthorityBytesV1 {
		return "", nil, nil, ErrFittedFinalizationV1
	}
	pages := make([]int, 0, len(needed))
	for p := range needed {
		pages = append(pages, p)
	}
	sort.Ints(pages)
	return fittedSHA256V1(raw), pages, bytes.Clone(raw), nil
}
func fittedDecimalV1(n pgtype.Numeric) (string, error) {
	if !n.Valid || n.Int == nil || n.NaN || n.InfinityModifier != pgtype.Finite || n.Exp < -32 || n.Exp > 32 || n.Int.BitLen() > 256 {
		return "", ErrFittedFinalizationV1
	}
	v, e := n.Value()
	s, ok := v.(string)
	if e != nil || !ok {
		return "", ErrFittedFinalizationV1
	}
	return s, nil
}
func finiteFittedTimeV1(t pgtype.Timestamptz) bool {
	return t.Valid && t.InfinityModifier == pgtype.Finite && !t.Time.IsZero() && t.Time.Year() >= 1 && t.Time.Year() <= 9999
}
func fittedSHA256V1(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func fittedDigestV1(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == sha256.Size && hex.EncodeToString(raw) == s
}

// LoadFittedBasePagesV1 consumes already committed migration86 descriptors.
// It neither renders nor writes. An absent required page remains explicitly
// unavailable; retries must recover the same reserved version, not regenerate.
func LoadFittedBasePagesV1(ctx context.Context, reader manualfit.BoundedReaderV1, snapshot *FittedFinalizationV1, pins []FittedBasePagePinV1) (resultSnapshot *FittedFinalizationV1, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			resultSnapshot = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || reader == nil || snapshot == nil || len(snapshot.entries) == 0 {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if len(pins) != len(snapshot.requiredBasePages) {
		return nil, ErrFittedBaseDurabilityRequiredV1
	}
	copied := append([]FittedBasePagePinV1(nil), pins...)
	sort.Slice(copied, func(i, j int) bool { return copied[i].Page < copied[j].Page })
	result := *snapshot
	result.bases = nil
	result.baseReady = false
	var operation uuid.UUID
	var total int64 = snapshot.source.Bytes
	for i, pin := range copied {
		if pin.Page != snapshot.requiredBasePages[i] || pin.Page < 1 || pin.Page > len(snapshot.geometry.Pages) || pin.SourceSHA256 != snapshot.source.SHA256 || pin.GeometrySHA256 != snapshot.geometry.GeometrySHA256 || pin.FieldSnapshotSHA256 != snapshot.fieldSnapshotSHA256 || pin.Object.ContentType != "application/pdf" || !validFittedPinV1(pin.Object, int64(sanitize.MaxPDFBytes)) {
			return nil, ErrFittedFinalizationV1
		}
		prefix := "org/" + snapshot.orgID.String() + "/documents/" + snapshot.documentID.String() + "/finalization/base/"
		suffix := "/page-" + strconv.Itoa(pin.Page) + ".pdf"
		if !strings.HasPrefix(pin.Object.Key, prefix) || !strings.HasSuffix(pin.Object.Key, suffix) {
			return nil, ErrFittedFinalizationV1
		}
		opText := strings.TrimSuffix(strings.TrimPrefix(pin.Object.Key, prefix), suffix)
		op, err := uuid.Parse(opText)
		if err != nil || op == uuid.Nil || op.String() != opText || (operation != uuid.Nil && operation != op) {
			return nil, ErrFittedFinalizationV1
		}
		operation = op
		if pin.Object.Bytes > int64(sanitize.MaxPDFBytes)-total {
			return nil, sanitize.ErrPDFTooLarge
		}
		total += pin.Object.Bytes
		pdf, err := readFittedPinV1(ctx, reader, pin.Object, int64(sanitize.MaxPDFBytes))
		if err != nil {
			return nil, err
		}
		result.bases = append(result.bases, fittedBasePageV1{pin, pdf})
	}
	result.baseReady = true
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	return &result, nil
}
func validFittedPinV1(pin manualfit.ObjectPinV1, max int64) bool {
	return strings.TrimSpace(pin.Key) == pin.Key && pin.Key != "" && manualfit.ValidObjectVersionV1(pin.VersionID) && fittedDigestV1(pin.SHA256) && pin.Bytes > 0 && pin.Bytes <= max
}
func readFittedPinV1(ctx context.Context, reader manualfit.BoundedReaderV1, pin manualfit.ObjectPinV1, max int64) ([]byte, error) {
	if ctx == nil || reader == nil || !validFittedPinV1(pin, max) {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	digest, _ := hex.DecodeString(pin.SHA256)
	raw, err := reader.GetVerifiedVersionBounded(ctx, pin.Key, pin.VersionID, digest, pin.Bytes)
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if int64(len(raw)) != pin.Bytes || fittedSHA256V1(raw) != pin.SHA256 {
		return nil, ErrFittedFinalizationV1
	}
	return bytes.Clone(raw), nil
}

// verifyFittedLegacySpansV1 rechecks original exact versions without consulting
// current name/font rows or a renderer. It cannot establish delegated authority.
func verifyFittedLegacySpansV1(ctx context.Context, reader manualfit.BoundedReaderV1, snapshot *FittedFinalizationV1) (map[uuid.UUID][]byte, error) {
	if ctx == nil || reader == nil || snapshot == nil {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if len(snapshot.legacySignatures) > pdflayout.MaxParties-len(snapshot.entries) {
		return nil, ErrFittedFinalizationV1
	}
	spans := make(map[uuid.UUID][]byte, len(snapshot.legacySignatures))
	for _, entry := range snapshot.legacySignatures {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if entry.DocumentID != snapshot.documentID || entry.SignatureID == uuid.Nil || spans[entry.SignatureID] != nil || entry.Object.ContentType != "text/html" || entry.SpanSHA256 != entry.Object.SHA256 || (entry.Kind != "manual" && entry.Kind != "delegated_grant_v1") {
			return nil, ErrFittedFinalizationV1
		}
		raw, err := readFittedPinV1(ctx, reader, entry.Object, int64(render.MaxArchivedSignatureSpanBytes))
		if err != nil {
			return nil, err
		}
		if _, err = render.ValidateArchivedSignatureSpan(raw, entry.OriginalName, entry.Font); err != nil {
			return nil, ErrFittedFinalizationV1
		}
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		spans[entry.SignatureID] = raw
	}
	return spans, nil
}

// FittedCompositionV1 preserves the isolated worker's exact ordered witness
// alongside final bytes, so the signed index cannot lose the composition proof.
type FittedCompositionV1 struct {
	pdf      []byte
	snapshot *FittedFinalizationV1
	witness  sanitize.PDFManualLayersManifest
}

func (c *FittedCompositionV1) PDFBytes() []byte {
	if c == nil {
		return nil
	}
	return bytes.Clone(c.pdf)
}
func (c *FittedCompositionV1) Snapshot() *FittedFinalizationV1 {
	if c == nil {
		return nil
	}
	return c.snapshot
}
func (c *FittedCompositionV1) Witness() sanitize.PDFManualLayersManifest {
	if c == nil {
		return sanitize.PDFManualLayersManifest{}
	}
	return c.witness
}

func (e *Engine) ComposeFittedPDFV1(ctx context.Context, snapshot *FittedFinalizationV1) (*FittedCompositionV1, error) {
	if e == nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if ctx == nil || ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	// The old hot-row constructor remains a capture/compatibility primitive.
	// Application dispatch must use the locked durable journal, whose reads
	// also fence existing original output reservations before composition.
	if snapshot == nil || !snapshot.journalRecoveryBound {
		return nil, ErrFittedJournalRecoveryRequiredV1
	}
	reader, _ := e.Storage.(manualfit.BoundedReaderV1)
	return ComposeFittedPDFV1(ctx, reader, snapshot)
}

// ComposeFittedPDFV1 has no renderer dependency. Source and bases are freshly
// fetched at their exact versions; fitted PDFs are freshly frozen-decoded from
// the retained manifests. Every party and source page participates. The worker
// enforces the complete 50 MiB source/layers/descriptor processing budget.
func ComposeFittedPDFV1(ctx context.Context, reader manualfit.BoundedReaderV1, snapshot *FittedFinalizationV1) (composition *FittedCompositionV1, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			composition = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || reader == nil || snapshot == nil || len(snapshot.entries) == 0 {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if snapshot.originalOutputsRequired {
		return nil, ErrFittedOriginalOutputsRequiredV1
	}
	if !snapshot.baseReady {
		return nil, ErrFittedBaseDurabilityRequiredV1
	}
	sourcePin := manualfit.ObjectPinV1{Key: snapshot.source.Key, VersionID: snapshot.source.VersionID, SHA256: snapshot.source.SHA256, Bytes: snapshot.source.Bytes, ContentType: "application/pdf"}
	source, err := readFittedPinV1(ctx, reader, sourcePin, int64(sanitize.MaxPDFBytes))
	if err != nil {
		return nil, err
	}
	fresh := *snapshot
	fresh.entries = nil
	fresh.bases = nil
	for _, entry := range snapshot.entries {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		m := entry.Manifest()
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if m == nil {
			return nil, ErrFittedFinalizationV1
		}
		r, err := manualfit.VerifyRetainedV1(ctx, reader, entry.ManifestObject(), m.Binding())
		if err != nil {
			return nil, fittedErrorV1(ctx, err)
		}
		recoveredManifest := r.Manifest()
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if recoveredManifest == nil {
			return nil, ErrFittedFinalizationV1
		}
		recoveredAuthority := recoveredManifest.Authority()
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if recoveredAuthority == nil || recoveredAuthority.Input().Source != snapshot.source || !reflect.DeepEqual(recoveredAuthority.Geometry(), snapshot.geometry) {
			return nil, ErrFittedFinalizationV1
		}
		copied := *entry
		copied.retained = r
		fresh.entries = append(fresh.entries, &copied)
	}
	if len(snapshot.bases) > 0 {
		loaded, err := LoadFittedBasePagesV1(ctx, reader, &fresh, snapshot.BasePages())
		if err != nil {
			return nil, err
		}
		fresh = *loaded
	}
	fresh.legacySpans, err = verifyFittedLegacySpansV1(ctx, reader, &fresh)
	if err != nil {
		return nil, err
	}
	layers, err := fittedOrderedLayersV1(ctx, &fresh)
	if err != nil {
		return nil, err
	}
	result, err := sanitize.ApplyManualPDFLayersWithContext(ctx, source, fresh.Geometry(), layers)
	if err != nil {
		return nil, fittedErrorV1(ctx, err)
	}
	if sanitize.ValidatePDFManualLayersResult(result) != nil || result.Layers.SourceSHA256 != fresh.source.SHA256 || result.Layers.SourceBytes != fresh.source.Bytes || result.Layers.GeometrySHA256 != fresh.geometry.GeometrySHA256 || result.Layers.Pages != len(fresh.geometry.Pages) || result.Layers.Layers != len(layers) {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	return &FittedCompositionV1{bytes.Clone(result.Bytes), &fresh, result.Layers}, nil
}

// fittedLayerAccessV1 names the expensive archive boundaries, so admission
// can count all fragments without copying their PDF sections. The production
// implementation reads only the immutable verified archive; the review tests
// observe decode/copy counts at these real boundaries.
type fittedLayerAccessV1 interface {
	Manifest(*FittedSignatureFinalizationV1) *manualfit.ManifestV1
	PDFByteCount(*FittedSignatureFinalizationV1, int) (int, error)
	PDFBytes(*FittedSignatureFinalizationV1, int) ([]byte, error)
}
type fittedArchivedLayerAccessV1 struct{}

func (fittedArchivedLayerAccessV1) Manifest(entry *FittedSignatureFinalizationV1) *manualfit.ManifestV1 {
	return entry.Manifest()
}
func (fittedArchivedLayerAccessV1) PDFByteCount(entry *FittedSignatureFinalizationV1, page int) (int, error) {
	if entry == nil || entry.retained == nil {
		return 0, ErrFittedFinalizationV1
	}
	return entry.retained.PDFByteCount(page)
}
func (fittedArchivedLayerAccessV1) PDFBytes(entry *FittedSignatureFinalizationV1, page int) ([]byte, error) {
	return entry.PDFBytes(page)
}

type fittedLayerCandidateV1 struct {
	page                   int
	kind, identity, sha256 string
	bytes                  int
	entry                  *FittedSignatureFinalizationV1
	base                   []byte
}

// These are the frozen V1 worker descriptor shapes. Admission includes their
// exact canonical JSON bytes before any PDF section is copied. The worker
// independently reconstructs and enforces this same frame at dispatch.
type fittedLayerDescriptorV1 struct {
	Page     int    `json:"page"`
	Order    int    `json:"order"`
	Kind     string `json:"kind"`
	Identity string `json:"identity"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}
type fittedLayersBatchV1 struct {
	SchemaVersion  int                       `json:"schema_version"`
	SourceSHA256   string                    `json:"source_sha256"`
	SourceBytes    int64                     `json:"source_bytes"`
	GeometrySHA256 string                    `json:"geometry_sha256"`
	Pages          int                       `json:"pages"`
	Layers         []fittedLayerDescriptorV1 `json:"layers"`
}

func fittedOrderedLayersV1(ctx context.Context, snapshot *FittedFinalizationV1) ([]sanitize.PDFManualLayerV1, error) {
	return fittedOrderedLayersWithAccessV1(ctx, snapshot, fittedArchivedLayerAccessV1{})
}

// Index occupied pages once. Work is bounded by parties plus actual retained
// fragments, never source pages multiplied by parties and full-manifest decode.
func fittedOrderedLayersWithAccessV1(ctx context.Context, snapshot *FittedFinalizationV1, access fittedLayerAccessV1) (layers []sanitize.PDFManualLayerV1, retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			layers = nil
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || access == nil {
		return nil, ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if snapshot == nil || !snapshot.baseReady {
		return nil, ErrFittedBaseDurabilityRequiredV1
	}
	if len(snapshot.geometry.Pages) < 1 || len(snapshot.geometry.Pages) > sanitize.MaxPDFPages || len(snapshot.entries) < 1 || len(snapshot.entries) > pdflayout.MaxParties || len(snapshot.bases) > sanitize.MaxPDFPages || len(snapshot.bases) != len(snapshot.requiredBasePages) || snapshot.source.Bytes < 1 || snapshot.source.Bytes > int64(sanitize.MaxPDFBytes) {
		return nil, ErrFittedFinalizationV1
	}
	byPage := map[int][]fittedLayerCandidateV1{}
	total := snapshot.source.Bytes
	count := 0
	add := func(c fittedLayerCandidateV1) error {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		if c.page < 1 || c.page > len(snapshot.geometry.Pages) || c.bytes < 1 || !fittedDigestV1(c.sha256) {
			return ErrFittedFinalizationV1
		}
		if count >= sanitize.MaxPDFManualLayersV1 || int64(c.bytes) > int64(sanitize.MaxPDFBytes)-total {
			return sanitize.ErrPDFTooLarge
		}
		total += int64(c.bytes)
		count++
		byPage[c.page] = append(byPage[c.page], c)
		return nil
	}
	// Bases are inserted before signatures. Only descriptors/references are
	// allocated in this phase; the complete source/layers/JSON gate comes first.
	seenBase := map[int]bool{}
	for i, b := range snapshot.bases {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		p := b.descriptor
		if p.Page != snapshot.requiredBasePages[i] || seenBase[p.Page] || p.SourceSHA256 != snapshot.source.SHA256 || p.GeometrySHA256 != snapshot.geometry.GeometrySHA256 || p.FieldSnapshotSHA256 != snapshot.fieldSnapshotSHA256 || !validFittedPinV1(p.Object, int64(sanitize.MaxPDFBytes)) || p.Object.ContentType != "application/pdf" || int64(len(b.pdf)) != p.Object.Bytes {
			return nil, ErrFittedFinalizationV1
		}
		seenBase[p.Page] = true
		if err := add(fittedLayerCandidateV1{page: p.Page, kind: sanitize.PDFManualLayerBaseV1, identity: "base-page-" + strconv.Itoa(p.Page), sha256: p.Object.SHA256, bytes: len(b.pdf), base: b.pdf}); err != nil {
			return nil, err
		}
	}
	seenSignature := map[uuid.UUID]bool{}
	var previous *FittedSignatureFinalizationV1
	for _, entry := range snapshot.entries {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if entry == nil || entry.signatureID == uuid.Nil || seenSignature[entry.signatureID] || (previous != nil && (entry.signedAt.Before(previous.signedAt) || (entry.signedAt.Equal(previous.signedAt) && bytes.Compare(entry.signatureID[:], previous.signatureID[:]) <= 0))) {
			return nil, ErrFittedFinalizationV1
		}
		seenSignature[entry.signatureID] = true
		previous = entry
		// Exactly one manifest decode and one page-array copy per party.
		manifest := access.Manifest(entry)
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if manifest == nil {
			return nil, ErrFittedFinalizationV1
		}
		pages := manifest.Pages()
		if len(pages) < 1 || len(pages) > sanitize.MaxPDFManualLayersV1-count {
			return nil, sanitize.ErrPDFTooLarge
		}
		previousPage := 0
		for _, p := range pages {
			if ctx.Err() != nil {
				return nil, fittedErrorV1(ctx, nil)
			}
			if p.Page <= previousPage {
				return nil, ErrFittedFinalizationV1
			}
			previousPage = p.Page
			n, err := access.PDFByteCount(entry, p.Page)
			if ctx.Err() != nil {
				return nil, fittedErrorV1(ctx, nil)
			}
			if err != nil || n < 1 || n > sanitize.MaxPDFManualSignatureFragmentBytes {
				return nil, ErrFittedFinalizationV1
			}
			if err := add(fittedLayerCandidateV1{page: p.Page, kind: sanitize.PDFManualLayerSignatureV1, identity: "signature:" + entry.signatureID.String(), sha256: p.PDFSHA256, bytes: n, entry: entry}); err != nil {
				return nil, err
			}
		}
	}
	if count < 1 {
		return nil, ErrFittedFinalizationV1
	}
	occupied := make([]int, 0, len(byPage))
	for p := range byPage {
		occupied = append(occupied, p)
	}
	sort.Ints(occupied)
	batch := fittedLayersBatchV1{SchemaVersion: 1, SourceSHA256: snapshot.source.SHA256, SourceBytes: snapshot.source.Bytes, GeometrySHA256: snapshot.geometry.GeometrySHA256, Pages: len(snapshot.geometry.Pages), Layers: make([]fittedLayerDescriptorV1, 0, count)}
	candidates := make([]fittedLayerCandidateV1, 0, count)
	for _, page := range occupied {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		for i, c := range byPage[page] {
			batch.Layers = append(batch.Layers, fittedLayerDescriptorV1{c.page, i + 1, c.kind, c.identity, c.bytes, c.sha256})
			candidates = append(candidates, c)
		}
	}
	metadata, err := json.Marshal(batch)
	if ctx.Err() != nil {
		return nil, fittedErrorV1(ctx, nil)
	}
	if err != nil || len(metadata) > 1<<20 || int64(len(metadata)) > int64(sanitize.MaxPDFBytes)-total {
		return nil, sanitize.ErrPDFTooLarge
	}
	// All aggregate and count admissions have succeeded. Copy each actual layer
	// once and recheck exact bytes immediately before handing them to the worker.
	layers = make([]sanitize.PDFManualLayerV1, 0, count)
	for i, c := range candidates {
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		var pdf []byte
		if c.entry != nil {
			pdf, err = access.PDFBytes(c.entry, c.page)
		} else {
			pdf = bytes.Clone(c.base)
		}
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		if err != nil || len(pdf) != c.bytes || fittedSHA256V1(pdf) != c.sha256 {
			return nil, ErrFittedFinalizationV1
		}
		if ctx.Err() != nil {
			return nil, fittedErrorV1(ctx, nil)
		}
		d := batch.Layers[i]
		layers = append(layers, sanitize.PDFManualLayerV1{Page: d.Page, Order: d.Order, Kind: d.Kind, Identity: d.Identity, PDF: pdf})
	}
	return layers, nil
}

// RetainFittedFinalizationV1 extends every exact span/page/manifest, source and
// staged base through the FINAL completion-effective target. It requires the
// already committed intent retention-start checkpoint before the first effect.
// A partial failure is irreversible and retryable; there is no compensation.
func RetainFittedFinalizationV1(ctx context.Context, q FittedFinalizationRetentionQueriesV1, reader manualfit.BoundedReaderV1, retainer manualfit.RetainerV1, doc *generated.Document, snapshot *FittedFinalizationV1) (retErr error) {
	defer func() {
		if ctx != nil && ctx.Err() != nil {
			retErr = fittedErrorV1(ctx, retErr)
		}
	}()
	if ctx == nil || q == nil || reader == nil || retainer == nil || doc == nil || snapshot == nil || doc.Status != "finalizing" || !doc.CompletionEffectiveAtBound || doc.ID != snapshot.documentID || doc.OrgID != snapshot.orgID || !doc.CompletionEffectiveAt.Time.Equal(snapshot.completionEffectiveAt) || !doc.FinalizationRetainUntil.Time.Equal(snapshot.retainUntil) {
		return ErrFittedFinalizationV1
	}
	if !snapshot.baseReady {
		return ErrFittedBaseDurabilityRequiredV1
	}
	if !finiteFittedTimeV1(doc.CompletionEffectiveAt) || !finiteFittedTimeV1(doc.FinalizationRetainUntil) || !finiteFittedTimeV1(doc.Article13NoticeEpochAt) || !doc.Article13NoticeEpochAt.Time.Equal(snapshot.ceremonyEpoch) || !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String != snapshot.source.Key || !doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String != snapshot.source.VersionID || hex.EncodeToString(doc.PdfSha256) != snapshot.source.SHA256 {
		return ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return fittedErrorV1(ctx, nil)
	}
	intent, err := q.GetDocumentFinalizationIntent(ctx, generated.GetDocumentFinalizationIntentParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return fittedErrorV1(ctx, err)
	}
	if intent == nil || intent.DocumentID != doc.ID || intent.OrgID != doc.OrgID || intent.Mode != "signature" || !finiteFittedTimeV1(intent.RetentionStartedAt) || !finiteFittedTimeV1(intent.CompletionEffectiveAt) || !finiteFittedTimeV1(intent.RetainUntil) || !intent.CompletionEffectiveAt.Time.Equal(snapshot.completionEffectiveAt) || !intent.RetainUntil.Time.Equal(snapshot.retainUntil) {
		return ErrFittedFinalizationV1
	}
	until, err := canonicalFinalizationRetainUntil(intent.CompletionEffectiveAt, intent.RetainUntil)
	if err != nil || validateFinalizationIntent(doc, intent) != nil {
		return ErrFittedFinalizationV1
	}
	if ctx.Err() != nil {
		return fittedErrorV1(ctx, nil)
	}
	sourcePin := manualfit.ObjectPinV1{Key: snapshot.source.Key, VersionID: snapshot.source.VersionID, SHA256: snapshot.source.SHA256, Bytes: snapshot.source.Bytes, ContentType: "application/pdf"}
	if _, err = readFittedPinV1(ctx, reader, sourcePin, int64(sanitize.MaxPDFBytes)); err != nil {
		return err
	}
	// Verify the complete input set before extending any one object.
	for _, entry := range snapshot.entries {
		m := entry.Manifest()
		if m == nil {
			return ErrFittedFinalizationV1
		}
		if _, err = manualfit.VerifyRetainedV1(ctx, reader, entry.ManifestObject(), m.Binding()); err != nil {
			return fittedErrorV1(ctx, err)
		}
	}
	if _, err = verifyFittedLegacySpansV1(ctx, reader, snapshot); err != nil {
		return err
	}
	if _, err = LoadFittedBasePagesV1(ctx, reader, snapshot, snapshot.BasePages()); err != nil {
		return err
	}
	digest, _ := hex.DecodeString(sourcePin.SHA256)
	if err = retainer.RetainEvidenceVersion(ctx, sourcePin.Key, sourcePin.VersionID, digest, until); err != nil {
		return fittedErrorV1(ctx, err)
	}
	if ctx.Err() != nil {
		return fittedErrorV1(ctx, nil)
	}
	for _, entry := range snapshot.entries {
		m := entry.Manifest()
		if _, err = manualfit.RetainVerifiedV1(ctx, reader, retainer, entry.ManifestObject(), m.Binding(), until); err != nil {
			return fittedErrorV1(ctx, err)
		}
	}
	for _, entry := range snapshot.legacySignatures {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		digest, _ := hex.DecodeString(entry.Object.SHA256)
		if err = retainer.RetainEvidenceVersion(ctx, entry.Object.Key, entry.Object.VersionID, digest, until); err != nil {
			return fittedErrorV1(ctx, err)
		}
	}
	for _, b := range snapshot.bases {
		if ctx.Err() != nil {
			return fittedErrorV1(ctx, nil)
		}
		digest, _ := hex.DecodeString(b.descriptor.Object.SHA256)
		if err = retainer.RetainEvidenceVersion(ctx, b.descriptor.Object.Key, b.descriptor.Object.VersionID, digest, until); err != nil {
			return fittedErrorV1(ctx, err)
		}
	}
	if _, err = readFittedPinV1(ctx, reader, sourcePin, int64(sanitize.MaxPDFBytes)); err != nil {
		return err
	}
	if _, err = LoadFittedBasePagesV1(ctx, reader, snapshot, snapshot.BasePages()); err != nil {
		return err
	}
	if _, err = verifyFittedLegacySpansV1(ctx, reader, snapshot); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return fittedErrorV1(ctx, nil)
	}
	return nil
}

// Never put private provider/SQL text or a custom cancellation cause into the
// printable error. Preserve cause identity for ownership and caller recovery.
type fittedContextErrorV1 struct{ causes []error }

func (e fittedContextErrorV1) Error() string   { return ErrFittedFinalizationV1.Error() }
func (e fittedContextErrorV1) Unwrap() []error { return append([]error(nil), e.causes...) }
func fittedErrorV1(ctx context.Context, cause error) error {
	causes := []error{ErrFittedFinalizationV1}
	if ctx != nil && ctx.Err() != nil {
		causes = append(causes, ctx.Err())
		if custom := context.Cause(ctx); custom != nil && custom != ctx.Err() {
			causes = append(causes, custom)
		}
	} else {
		for _, known := range []error{context.Canceled, context.DeadlineExceeded, ErrFittedBaseDurabilityRequiredV1, sanitize.ErrPDFTooLarge} {
			if errors.Is(cause, known) {
				causes = append(causes, known)
			}
		}
	}
	if len(causes) == 1 {
		return ErrFittedFinalizationV1
	}
	return fittedContextErrorV1{causes}
}

// retainFittedDocumentEvidenceV1 is the legacy-compatible publication fence.
// Migration86 base descriptors must be loaded before an ordinary-field/mixed
// fitted ceremony can pass; absent durable bases never trigger rendering.
func (e *Engine) retainFittedDocumentEvidenceV1(ctx context.Context, q *generated.Queries, doc *generated.Document) error {
	if e == nil || q == nil {
		return ErrFittedFinalizationV1
	}
	reader, _ := e.Storage.(manualfit.BoundedReaderV1)
	snapshot, err := LoadFittedFinalizationV1(ctx, q, reader, doc)
	if err != nil {
		return err
	}
	if snapshot == nil {
		return nil
	}
	return RetainFittedFinalizationV1(ctx, q, reader, e.Storage, doc, snapshot)
}
