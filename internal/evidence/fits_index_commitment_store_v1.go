// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// FitsIndexCommitmentQueriesV1 deliberately exposes only tenant-scoped reads.
// GetCompletedFittedFinalization is the SQL86 immutable published query: its
// retained/readback output and original46/document pairing predicates must stay
// intact. A hot-signature or unscoped document lookup is not a substitute.
type FitsIndexCommitmentQueriesV1 interface {
	GetDocument(context.Context, generated.GetDocumentParams) (*generated.Document, error)
	GetCompletedFittedFinalization(context.Context, generated.GetCompletedFittedFinalizationParams) (*generated.GetCompletedFittedFinalizationRow, error)
}

// PostgresFitsIndexCommitmentStoreV1 returns only the exact immutable index pin.
// It does not authenticate the signed index bytes; the existing archive reader
// must still read that version and verify its trusted issuer and full binding.
// Constructing this adapter does not activate fitted signing or export wiring.
type PostgresFitsIndexCommitmentStoreV1 struct {
	queries FitsIndexCommitmentQueriesV1
}

var _ FitsIndexCommitmentStoreV1 = (*PostgresFitsIndexCommitmentStoreV1)(nil)
var _ FitsIndexCommitmentQueriesV1 = (*generated.Queries)(nil)

func NewPostgresFitsIndexCommitmentStoreV1(q FitsIndexCommitmentQueriesV1) (*PostgresFitsIndexCommitmentStoreV1, error) {
	if fitsCommitmentQueriesNilV1(q) {
		return nil, fitsCommitmentStoreErrorV1(nil)
	}
	return &PostgresFitsIndexCommitmentStoreV1{queries: q}, nil
}

func fitsCommitmentQueriesNilV1(q FitsIndexCommitmentQueriesV1) bool {
	if q == nil {
		return true
	}
	// An interface holding a typed nil query must fail at construction instead
	// of deferring a panic or masquerading as historical evidence.
	value := reflect.ValueOf(q)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type fitsCommitmentStoreErrorTypeV1 struct{ cause error }

func (e fitsCommitmentStoreErrorTypeV1) Error() string {
	return "evidence: committed fitted index unavailable"
}
func (e fitsCommitmentStoreErrorTypeV1) Unwrap() []error {
	return []error{ErrArtifactIntegrity, e.cause}
}
func fitsCommitmentStoreErrorV1(cause error) error {
	return fitsCommitmentStoreErrorTypeV1{cause: cause}
}
func fitsCommitmentQueryErrorV1(ctx context.Context, cause error) error {
	if ctx.Err() != nil {
		return safeFitsEvidenceErrorV1(ctx, cause)
	}
	return fitsCommitmentStoreErrorV1(cause)
}

func fitsCommitmentFiniteTimeV1(value pgtype.Timestamptz) bool {
	return value.Valid && value.InfinityModifier == pgtype.Finite && !value.Time.IsZero() && value.Time.UTC().Year() >= 1 && value.Time.UTC().Year() <= 9999
}
func fitsCommitmentStorageKeyV1(value pgtype.Text, orgID, documentID uuid.UUID) bool {
	if !value.Valid || len(value.String) == 0 || len(value.String) > 1024 || !utf8.ValidString(value.String) || value.String != strings.TrimSpace(value.String) || !strings.HasPrefix(value.String, "org/"+orgID.String()+"/documents/"+documentID.String()+"/") {
		return false
	}
	for _, character := range value.String {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}
func fitsCommitmentArtifactPairV1(key, version pgtype.Text, digest []byte, journalKey, journalVersion pgtype.Text, journalDigest []byte, orgID, documentID uuid.UUID) bool {
	return fitsCommitmentStorageKeyV1(key, orgID, documentID) && fitsCommitmentStorageKeyV1(journalKey, orgID, documentID) &&
		version.Valid && journalVersion.Valid && manualfit.ValidObjectVersionV1(version.String) && manualfit.ValidObjectVersionV1(journalVersion.String) &&
		len(digest) == sha256.Size && len(journalDigest) == sha256.Size &&
		key.String == journalKey.String && version.String == journalVersion.String && bytes.Equal(digest, journalDigest)
}
func fitsCommitmentHistoricalMetadataEmptyV1(doc *generated.Document) bool {
	return !doc.FitsIndexPreparationID.Valid && uuid.UUID(doc.FitsIndexPreparationID.Bytes) == uuid.Nil &&
		!doc.FitsIndexStorageKey.Valid && doc.FitsIndexStorageKey.String == "" &&
		!doc.FitsIndexVersionID.Valid && doc.FitsIndexVersionID.String == "" &&
		len(doc.FitsIndexSha256) == 0 && !doc.FitsIndexBytes.Valid && doc.FitsIndexBytes.Int64 == 0
}

func (s *PostgresFitsIndexCommitmentStoreV1) LoadCommittedFitsIndexV1(ctx context.Context, orgID, documentID uuid.UUID) (manualfit.CommittedFitsIndexV1, error) {
	if ctx.Err() != nil {
		return manualfit.CommittedFitsIndexV1{}, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	if s == nil || fitsCommitmentQueriesNilV1(s.queries) || orgID == uuid.Nil || documentID == uuid.Nil {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	doc, err := s.queries.GetDocument(ctx, generated.GetDocumentParams{ID: documentID, OrgID: orgID})
	if err != nil || ctx.Err() != nil {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentQueryErrorV1(ctx, err)
	}
	if doc == nil || doc.ID != documentID || doc.OrgID != orgID || doc.Status != "completed" || doc.DeletedAt.Valid {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	if !doc.FitsIndexRequired {
		if !fitsCommitmentHistoricalMetadataEmptyV1(doc) {
			return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
		}
		return manualfit.CommittedFitsIndexV1{}, nil
	}
	if !doc.EvidenceVersionPinsRequired || !doc.CompletionEffectiveAtBound || !doc.FitsIndexPreparationID.Valid || uuid.UUID(doc.FitsIndexPreparationID.Bytes) == uuid.Nil ||
		!fitsCommitmentFiniteTimeV1(doc.SentAt) || !fitsCommitmentFiniteTimeV1(doc.CompletionEffectiveAt) || !fitsCommitmentFiniteTimeV1(doc.CompletedAt) || !fitsCommitmentFiniteTimeV1(doc.FinalizationRetainUntil) ||
		!doc.CompletionEffectiveAt.Time.After(doc.SentAt.Time) || !doc.CompletionEffectiveAt.Time.Equal(doc.CompletedAt.Time) ||
		!doc.FinalizationRetainUntil.Time.Equal(storage.EvidenceRetentionDeadline(doc.CompletionEffectiveAt.Time, article13.RetentionYearsV1)) {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	if !doc.FitsIndexBytes.Valid || !doc.FitsIndexStorageKey.Valid || !doc.FitsIndexVersionID.Valid || len(doc.FitsIndexSha256) != sha256.Size ||
		doc.FitsIndexStorageKey.String != manualfit.IndexStorageKeyV1(orgID, documentID, uuid.UUID(doc.FitsIndexPreparationID.Bytes)) {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	indexPin := manualfit.ObjectPinV1{
		Key: doc.FitsIndexStorageKey.String, VersionID: doc.FitsIndexVersionID.String,
		SHA256: hex.EncodeToString(doc.FitsIndexSha256), Bytes: doc.FitsIndexBytes.Int64,
		ContentType: "application/json",
	}
	// MIME comes from the fixed SQL86 fits_index kind/constraint, not from
	// unsigned caller metadata. The operation namespace is exact, not a prefix.
	if _, err := manualfit.ObjectPinSHA256V1(indexPin); err != nil {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(err)
	}
	if ctx.Err() != nil {
		return manualfit.CommittedFitsIndexV1{}, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	completed, err := s.queries.GetCompletedFittedFinalization(ctx, generated.GetCompletedFittedFinalizationParams{DocumentID: documentID, OrgID: orgID})
	if err != nil || ctx.Err() != nil {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentQueryErrorV1(ctx, err)
	}
	if completed == nil || completed.ID != documentID || completed.OrgID != orgID || !completed.FitsIndexRequired ||
		!completed.FitsIndexPreparationID.Valid || completed.FitsIndexPreparationID.Bytes != doc.FitsIndexPreparationID.Bytes ||
		!completed.FitsIndexStorageKey.Valid || !completed.FitsIndexVersionID.Valid || !completed.FitsIndexBytes.Valid ||
		completed.FitsIndexStorageKey.String != indexPin.Key || completed.FitsIndexVersionID.String != indexPin.VersionID ||
		len(completed.FitsIndexSha256) != sha256.Size || !bytes.Equal(completed.FitsIndexSha256, doc.FitsIndexSha256) || completed.FitsIndexBytes.Int64 != indexPin.Bytes ||
		!fitsCommitmentFiniteTimeV1(completed.CeremonyEpoch) || !completed.CeremonyEpoch.Time.Equal(doc.SentAt.Time) ||
		!fitsCommitmentFiniteTimeV1(completed.CompletionEffectiveAt) || !completed.CompletionEffectiveAt.Time.Equal(doc.CompletionEffectiveAt.Time) ||
		!fitsCommitmentFiniteTimeV1(completed.RetainUntil) || !completed.RetainUntil.Time.Equal(doc.FinalizationRetainUntil.Time) ||
		!fitsCommitmentFiniteTimeV1(completed.PublishedAt) || len(completed.FieldSnapshotSha256) != sha256.Size || len(completed.GeometrySha256) != sha256.Size ||
		len(completed.OriginalDocumentName) > 65536 || !utf8.ValidString(completed.OriginalDocumentName) || strings.TrimSpace(completed.OriginalDocumentName) == "" ||
		completed.FinalPdfBytes <= 0 || completed.FinalPdfBytes > manualfit.MaxFinalPDFBytesV1 {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	if !fitsCommitmentArtifactPairV1(doc.FinalPdfKey, doc.FinalPdfVersionID, doc.FinalPdfSha, completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha, orgID, documentID) ||
		!fitsCommitmentArtifactPairV1(doc.AuditCertKey, doc.AuditCertVersionID, doc.AuditCertSha256, completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256, orgID, documentID) ||
		!fitsCommitmentArtifactPairV1(doc.AuditPayloadKey, doc.AuditPayloadVersionID, doc.AuditPayloadSha256, completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256, orgID, documentID) ||
		!fitsCommitmentArtifactPairV1(doc.AuditSignatureKey, doc.AuditSignatureVersionID, doc.AuditSignatureSha256, completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256, orgID, documentID) {
		return manualfit.CommittedFitsIndexV1{}, fitsCommitmentStoreErrorV1(nil)
	}
	if ctx.Err() != nil {
		return manualfit.CommittedFitsIndexV1{}, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	// No current-name comparison: DSR projections may legitimately differ from
	// completed.OriginalDocumentName. Signature/field rows are never queried.
	return manualfit.CommittedFitsIndexV1{Required: true, Object: indexPin}, nil
}
