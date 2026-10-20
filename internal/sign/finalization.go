// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/storage"
)

// stagedDocumentFinalization is the complete cross-store publication unit.
// Every object is written atomically with Object Lock under its digest-addressed
// key. The exact returned versions are then committed to PostgreSQL; a crash
// before that commit reuses the same retained versions on retry rather than
// creating new WORM objects.
type stagedDocumentFinalization struct {
	Mode           string
	FinalKey       string
	FinalSHA256    [sha256.Size]byte
	FinalVersionID string
	Certificate    storedAuditCertificate
}

func (s stagedDocumentFinalization) validate(doc *generated.Document) error {
	if doc == nil || doc.ID == uuid.Nil || doc.OrgID == uuid.Nil || doc.Status != "finalizing" {
		return errors.New("stage finalization: document is not durably finalizing")
	}
	if !doc.CompletionEffectiveAtBound {
		return errors.New("stage finalization: completion-effective timestamp is not bound")
	}
	if _, err := canonicalCompletionEffectiveAt(doc.CompletionEffectiveAt); err != nil {
		return fmt.Errorf("stage finalization: %w", err)
	}
	if _, err := finalizationRetentionDeadline(doc); err != nil {
		return fmt.Errorf("stage finalization: %w", err)
	}
	if s.Mode != "signature" && s.Mode != "acknowledgement" {
		return errors.New("stage finalization: invalid mode")
	}
	if (s.Mode == "signature") != doc.RequiresSignature {
		return errors.New("stage finalization: mode does not match document")
	}
	artifacts := []struct {
		key, prefix, suffix, versionID string
		digest                         []byte
	}{
		{s.FinalKey, "final-", ".pdf", s.FinalVersionID, s.FinalSHA256[:]},
		{s.Certificate.CertKey, "audit-", ".pdf", s.Certificate.CertVersionID, s.Certificate.CertSHA256[:]},
		{s.Certificate.PayloadKey, "audit-payload-", ".txt", s.Certificate.PayloadVersionID, s.Certificate.PayloadSHA256[:]},
		{s.Certificate.SignatureKey, "audit-signature-", ".txt", s.Certificate.SignatureVersionID, s.Certificate.SignatureSHA256[:]},
	}
	seen := make(map[string]struct{}, len(artifacts))
	for _, artifact := range artifacts {
		if strings.TrimSpace(artifact.versionID) == "" {
			return errors.New("stage finalization: artifact VersionId is required")
		}
		if err := validateFinalizationArtifactIdentity(artifact.key, artifact.prefix, artifact.suffix, artifact.digest); err != nil {
			return err
		}
		if _, duplicate := seen[artifact.key]; duplicate {
			return fmt.Errorf("stage finalization: duplicate artifact key %q", artifact.key)
		}
		seen[artifact.key] = struct{}{}
	}
	return nil
}

func validateFinalizationArtifactIdentity(key, prefix, suffix string, digest []byte) error {
	if strings.TrimSpace(key) == "" || len(digest) != sha256.Size {
		return errors.New("stage finalization: artifact key and SHA-256 are required")
	}
	wantBase := prefix + hex.EncodeToString(digest) + suffix
	if path.Base(key) != wantBase {
		return fmt.Errorf("stage finalization: artifact %q is not content-addressed as %s", key, wantBase)
	}
	return nil
}

// claimDocumentFinalizing is the state-machine boundary that runs before any
// slow render, chain-head capture, or object write. It locks and rechecks the
// authoritative document/recipients, then commits the non-interactive
// finalizing state. Void, expiration, decline, request-changes, views,
// reminders, and field writes all take the same parent lock and accept only
// active states, so none can enter after this commit.
func (e *Engine) claimDocumentFinalizing(ctx context.Context, conn *pgxpool.Conn, orgID, docID uuid.UUID, mode string) (*generated.Document, error) {
	if conn == nil || e.Queries == nil {
		return nil, errors.New("claim finalization: lifecycle store unavailable")
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("claim finalization: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := e.Queries.WithTx(tx)
	locked, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{ID: docID, OrgID: orgID})
	if err != nil {
		return nil, fmt.Errorf("claim finalization: lock document: %w", err)
	}
	if err := requireHistoricalSigningAdmissionV1(locked); err != nil {
		return nil, err
	}
	if err := htmlsource.ValidateSigningPageState(ctx, q, locked, 0); err != nil {
		return nil, err
	}
	if locked.Status == "finalizing" {
		if err := validateFinalizationMode(locked, mode); err != nil {
			return nil, err
		}
		// Recovery must retain the independently declared contract parties even
		// when an earlier process already committed the finalizing state.
		parties, err := htmlsource.ContractParties(locked)
		if err != nil {
			return nil, err
		}
		if len(parties) != 0 {
			if _, err := e.requiredRolesForFinalization(ctx, q, locked, mode); err != nil {
				return nil, err
			}
		}
		if !locked.CompletionEffectiveAtBound {
			return nil, errors.New("claim finalization: completion-effective timestamp is not bound")
		}
		if _, err := canonicalCompletionEffectiveAt(locked.CompletionEffectiveAt); err != nil {
			return nil, fmt.Errorf("claim finalization: %w", err)
		}
		if _, err := finalizationRetentionDeadline(locked); err != nil {
			return nil, fmt.Errorf("claim finalization: %w", err)
		}
		return locked, nil
	}
	if locked.Status != "in_progress" {
		return nil, ErrDocumentRevisedDuringFinalize
	}
	if err := validateFinalizationMode(locked, mode); err != nil {
		return nil, err
	}
	if _, err := e.requiredRolesForFinalization(ctx, q, locked, mode); err != nil {
		return nil, err
	}
	// Envelope children are independently addressable documents. Lock them in a
	// deterministic order before allocating the family completion timestamp so a
	// child comment/lifecycle mutation either drains first (and is included in the
	// high-water scan) or waits until the child has become non-interactive.
	lockedChildren, err := e.lockEnvelopeChildrenForFinalization(ctx, q, locked)
	if err != nil {
		return nil, err
	}
	claimed, err := q.BeginDocumentFinalization(ctx, generated.BeginDocumentFinalizationParams{
		RetentionYears: article13.RetentionYearsV1,
		ID:             docID,
		OrgID:          orgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocumentRevisedDuringFinalize
	}
	if err != nil {
		return nil, fmt.Errorf("claim finalization: transition: %w", err)
	}
	if claimed == nil || claimed.Status != "finalizing" {
		return nil, errors.New("claim finalization: transition returned invalid state")
	}
	if !claimed.CompletionEffectiveAtBound {
		return nil, errors.New("claim finalization: completion-effective timestamp is not bound")
	}
	if _, err := canonicalCompletionEffectiveAt(claimed.CompletionEffectiveAt); err != nil {
		return nil, fmt.Errorf("claim finalization: %w", err)
	}
	if _, err := finalizationRetentionDeadline(claimed); err != nil {
		return nil, fmt.Errorf("claim finalization: %w", err)
	}
	if claimed.IsEnvelope {
		frozenChildren, err := q.BeginEnvelopeChildrenFinalization(ctx, generated.BeginEnvelopeChildrenFinalizationParams{
			ParentEnvelopeID: pgtype.UUID{Bytes: claimed.ID, Valid: true},
			OrgID:            claimed.OrgID,
		})
		if err != nil {
			return nil, fmt.Errorf("claim finalization: freeze envelope children: %w", err)
		}
		if err := validateEnvelopeChildrenFinalizationFreeze(claimed, lockedChildren, frozenChildren); err != nil {
			return nil, fmt.Errorf("claim finalization: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("claim finalization: commit: %w", err)
	}
	return claimed, nil
}

func (e *Engine) lockEnvelopeChildrenForFinalization(ctx context.Context, q *generated.Queries, envelope *generated.Document) ([]*generated.Document, error) {
	if envelope == nil || !envelope.IsEnvelope {
		return nil, nil
	}
	children, err := q.ListEnvelopeChildren(ctx, generated.ListEnvelopeChildrenParams{
		ParentEnvelopeID: pgtype.UUID{Bytes: envelope.ID, Valid: true},
		OrgID:            envelope.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("claim finalization: list envelope children: %w", err)
	}
	if len(children) == 0 {
		return nil, errors.New("claim finalization: envelope has no children")
	}
	sort.Slice(children, func(i, j int) bool {
		if children[i] == nil {
			return false
		}
		if children[j] == nil {
			return true
		}
		return children[i].ID.String() < children[j].ID.String()
	})
	locked := make([]*generated.Document, 0, len(children))
	seen := make(map[uuid.UUID]struct{}, len(children))
	for i, listed := range children {
		if listed == nil || listed.ID == uuid.Nil {
			return nil, fmt.Errorf("claim finalization: envelope child %d is invalid", i)
		}
		if _, duplicate := seen[listed.ID]; duplicate {
			return nil, fmt.Errorf("claim finalization: duplicate envelope child %s", listed.ID)
		}
		seen[listed.ID] = struct{}{}
		child, err := q.GetDocumentForUpdate(ctx, generated.GetDocumentForUpdateParams{
			ID: listed.ID, OrgID: envelope.OrgID,
		})
		if err != nil {
			return nil, fmt.Errorf("claim finalization: lock envelope child %s: %w", listed.ID, err)
		}
		if child.OrgID != envelope.OrgID || child.IsEnvelope || !child.ParentEnvelopeID.Valid ||
			uuid.UUID(child.ParentEnvelopeID.Bytes) != envelope.ID || child.DeletedAt.Valid ||
			(child.Status != "sent" && child.Status != "in_progress") {
			return nil, fmt.Errorf("claim finalization: envelope child %s is not an active attached document", listed.ID)
		}
		locked = append(locked, child)
	}
	return locked, nil
}

func validateEnvelopeChildrenFinalizationFreeze(parent *generated.Document, expected, frozen []*generated.Document) error {
	if parent == nil || !parent.IsEnvelope || parent.Status != "finalizing" ||
		!parent.CompletionEffectiveAtBound || !parent.CompletionEffectiveAt.Valid ||
		!parent.FinalizationRetainUntil.Valid {
		return errors.New("envelope parent has incomplete finalization commitments")
	}
	if len(expected) == 0 || len(frozen) != len(expected) {
		return fmt.Errorf("envelope child freeze updated %d of %d children", len(frozen), len(expected))
	}
	want := make(map[uuid.UUID]struct{}, len(expected))
	for _, child := range expected {
		if child == nil || child.ID == uuid.Nil {
			return errors.New("envelope child freeze expected an invalid child")
		}
		want[child.ID] = struct{}{}
	}
	for _, child := range frozen {
		if child == nil || child.Status != "finalizing" || child.OrgID != parent.OrgID ||
			!child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != parent.ID ||
			!child.CompletionEffectiveAtBound ||
			!completionEffectiveTimesEqual(child.CompletionEffectiveAt, parent.CompletionEffectiveAt) ||
			!retentionTimesEqual(child.FinalizationRetainUntil, parent.FinalizationRetainUntil) {
			return errors.New("envelope child freeze returned an invalid commitment")
		}
		if _, ok := want[child.ID]; !ok {
			return fmt.Errorf("envelope child freeze returned unexpected child %s", child.ID)
		}
		delete(want, child.ID)
	}
	if len(want) != 0 {
		return errors.New("envelope child freeze omitted an expected child")
	}
	return nil
}

func validateFinalizationMode(doc *generated.Document, mode string) error {
	if doc == nil {
		return errors.New("finalization: document unavailable")
	}
	if _, err := htmlsource.ContractParties(doc); err != nil {
		return err
	}
	switch mode {
	case "signature":
		if !doc.RequiresSignature {
			return ErrNotAcknowledgement
		}
	case "acknowledgement":
		if doc.RequiresSignature {
			return ErrNotAcknowledgement
		}
	default:
		return errors.New("finalization: invalid mode")
	}
	return nil
}

// ensureDocumentSourceVersions upgrades pre-migration active documents before
// finalization reads their source. This is required for ceremonies already in
// sent/in_progress when migration 47 lands; they never pass through the new
// send-sealing pin step.
func (e *Engine) ensureDocumentSourceVersions(ctx context.Context, doc *generated.Document) (*generated.Document, error) {
	if e == nil || e.Queries == nil || doc == nil {
		return nil, errors.New("finalization: source VersionId dependencies unavailable")
	}
	resolve := func(key pgtype.Text, digest []byte, current pgtype.Text) (pgtype.Text, error) {
		if !key.Valid || strings.TrimSpace(key.String) == "" {
			return pgtype.Text{}, nil
		}
		if e.Storage == nil || len(digest) != sha256.Size {
			return pgtype.Text{}, fmt.Errorf("finalization: source %q has no valid storage commitment", key.String)
		}
		if current.Valid && strings.TrimSpace(current.String) != "" {
			if _, err := e.Storage.GetVerifiedVersion(ctx, key.String, current.String, digest); err != nil {
				return pgtype.Text{}, fmt.Errorf("finalization: verify source %q VersionId: %w", key.String, err)
			}
			return current, nil
		}
		if doc.EvidenceVersionPinsRequired {
			return pgtype.Text{}, fmt.Errorf("finalization: source %q is missing its required VersionId", key.String)
		}
		_, stored, err := e.Storage.ResolveVerifiedLegacy(ctx, key.String, digest)
		if err != nil {
			return pgtype.Text{}, fmt.Errorf("finalization: resolve legacy source %q: %w", key.String, err)
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return pgtype.Text{}, fmt.Errorf("finalization: resolve legacy source %q returned no VersionId", key.String)
		}
		return pgtype.Text{String: stored.VersionID, Valid: true}, nil
	}
	pdfVersion, err := resolve(doc.PdfStorageKey, doc.PdfSha256, doc.PdfStorageVersionID)
	if err != nil {
		return nil, err
	}
	renderedVersion, err := resolve(doc.RenderedPdfKey, doc.RenderedPdfSha, doc.RenderedPdfVersionID)
	if err != nil {
		return nil, err
	}
	if doc.EvidenceVersionPinsRequired {
		return doc, nil
	}
	pinned, err := e.Queries.PinDocumentSendEvidenceVersions(ctx, generated.PinDocumentSendEvidenceVersionsParams{
		PdfStorageVersionID: pdfVersion, RenderedPdfVersionID: renderedVersion,
		ID: doc.ID, OrgID: doc.OrgID,
	})
	if err != nil {
		return nil, fmt.Errorf("finalization: persist source VersionIds: %w", err)
	}
	if pinned == nil || !pinned.EvidenceVersionPinsRequired ||
		(pinned.PdfStorageKey.Valid && !pinned.PdfStorageVersionID.Valid) ||
		(pinned.RenderedPdfKey.Valid && !pinned.RenderedPdfVersionID.Valid) {
		return nil, errors.New("finalization: persisted source VersionIds are incomplete")
	}
	return pinned, nil
}

// ensureSignatureVersions removes the last digest-history dependency from a
// pre-migration ceremony. New signatures are inserted with exact pins; legacy
// rows are resolved and atomically upgraded before terminal completion.
func (e *Engine) ensureSignatureVersions(ctx context.Context, documentID uuid.UUID) error {
	if e == nil || e.Queries == nil || e.Storage == nil {
		return errors.New("finalization: signature VersionId dependencies unavailable")
	}
	signatures, err := e.Queries.ListSignaturesByDocument(ctx, documentID)
	if err != nil {
		return fmt.Errorf("finalization: list signature evidence: %w", err)
	}
	for _, signature := range signatures {
		if signature == nil || strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size {
			return errors.New("finalization: signature evidence commitment is incomplete")
		}
		if signature.ImageVersionPinRequired {
			if !signature.ImageVersionID.Valid || strings.TrimSpace(signature.ImageVersionID.String) == "" {
				return errors.New("finalization: signature evidence is missing its required VersionId")
			}
			if _, err := e.Storage.GetVerifiedVersion(ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256); err != nil {
				return fmt.Errorf("finalization: verify signature evidence %s: %w", signature.ID, err)
			}
			continue
		}
		if signature.ImageVersionID.Valid {
			return errors.New("finalization: legacy signature evidence has a partial VersionId commitment")
		}
		_, stored, err := e.Storage.ResolveVerifiedLegacy(ctx, signature.ImageStorageKey, signature.ImageSha256)
		if err != nil {
			return fmt.Errorf("finalization: resolve legacy signature evidence %s: %w", signature.ID, err)
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return fmt.Errorf("finalization: resolve legacy signature evidence %s returned no VersionId", signature.ID)
		}
		pinned, err := e.Queries.PinLegacySignatureVersion(ctx, generated.PinLegacySignatureVersionParams{
			ImageVersionID: pgtype.Text{String: stored.VersionID, Valid: true},
			ID:             signature.ID, DocumentID: documentID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			refreshed, listErr := e.Queries.ListSignaturesByDocument(ctx, documentID)
			if listErr != nil {
				return fmt.Errorf("finalization: reload signature evidence: %w", listErr)
			}
			for _, candidate := range refreshed {
				if candidate != nil && candidate.ID == signature.ID {
					pinned = candidate
					break
				}
			}
			err = nil
		}
		if err != nil {
			return fmt.Errorf("finalization: persist signature VersionId %s: %w", signature.ID, err)
		}
		if pinned == nil || !pinned.ImageVersionPinRequired || !pinned.ImageVersionID.Valid || pinned.ImageVersionID.String != stored.VersionID {
			return fmt.Errorf("finalization: persisted signature VersionId %s does not match resolved object", signature.ID)
		}
		if _, err := e.Storage.GetVerifiedVersion(ctx, pinned.ImageStorageKey, pinned.ImageVersionID.String, pinned.ImageSha256); err != nil {
			return fmt.Errorf("finalization: verify pinned signature evidence %s: %w", signature.ID, err)
		}
	}
	return nil
}

// retainFinalizationSignatureEvidence extends every pinned signature-image
// version through the bundle's later completion deadline. Signature images are
// first retained from the immutable sent_at epoch when captured; finalization
// must not leave those inputs shorter-lived than the PDF/certificate they
// substantiate.
func (e *Engine) retainFinalizationSignatureEvidence(ctx context.Context, documents []*generated.Document, intent *generated.DocumentFinalizationIntent) error {
	if e == nil || e.Queries == nil || e.Storage == nil || intent == nil {
		return errors.New("resume finalization: signature retention dependencies unavailable")
	}
	retainUntil, err := canonicalFinalizationRetainUntil(intent.CompletionEffectiveAt, intent.RetainUntil)
	if err != nil {
		return fmt.Errorf("resume finalization: %w", err)
	}
	seen := make(map[uuid.UUID]struct{}, len(documents))
	for _, document := range documents {
		if document == nil || !document.RequiresSignature {
			continue
		}
		if _, duplicate := seen[document.ID]; duplicate {
			continue
		}
		seen[document.ID] = struct{}{}
		signatures, err := e.Queries.ListSignaturesByDocument(ctx, document.ID)
		if err != nil {
			return fmt.Errorf("resume finalization: list signature evidence for %s: %w", document.ID, err)
		}
		// A fitted signature owns span, every occupied page package and manifest.
		// A bare-span extension is insufficient for the completion commitment.
		if err := e.retainFittedDocumentEvidenceV1(ctx, e.Queries, document); err != nil {
			return err
		}
		legacy := make([]*generated.Signature, 0, len(signatures))
		for _, signature := range signatures {
			if signature == nil || signature.SignatureKind != "manual_pdf_fit_v1" {
				legacy = append(legacy, signature)
			}
		}
		if err := retainPinnedSignatureEvidence(ctx, e.Storage, document.ID, legacy, retainUntil); err != nil {
			return err
		}
	}
	return nil
}

func retainPinnedSignatureEvidence(ctx context.Context, store EvidenceStorage, documentID uuid.UUID, signatures []*generated.Signature, retainUntil time.Time) error {
	if store == nil || documentID == uuid.Nil || retainUntil.IsZero() || retainUntil.Nanosecond() != 0 {
		return errors.New("resume finalization: signature evidence retention input is invalid")
	}
	for _, signature := range signatures {
		if signature != nil && signature.SignatureKind == "manual_pdf_fit_v1" {
			return ErrFittedCompositionRequiredV1
		}
	}
	for _, signature := range signatures {
		if signature == nil || signature.DocumentID != documentID ||
			strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size ||
			!signature.ImageVersionPinRequired || !signature.ImageVersionID.Valid || strings.TrimSpace(signature.ImageVersionID.String) == "" {
			return fmt.Errorf("resume finalization: signature evidence for %s is incomplete", documentID)
		}
		if err := store.RetainEvidenceVersion(ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256, retainUntil); err != nil {
			return fmt.Errorf("resume finalization: retain signature evidence %s: %w", signature.ID, err)
		}
	}
	return nil
}

// ensureEnvelopeChildrenEvidenceVersions upgrades every pre-migration child
// before the envelope can publish a shared terminal artifact. Envelope
// children do not independently execute the root finalization state machine,
// so relying only on the root upgrade would leave their sources or captured
// signature spans dependent on bounded digest-history lookup after completion.
func (e *Engine) ensureEnvelopeChildrenEvidenceVersions(ctx context.Context, envelope *generated.Document) ([]*generated.Document, error) {
	if envelope == nil || !envelope.IsEnvelope {
		return nil, nil
	}
	if e.EnvelopeChildren == nil {
		return nil, errors.New("finalize envelope: children unavailable for VersionId pinning")
	}
	children, err := e.EnvelopeChildren(ctx, envelope)
	if err != nil {
		return nil, fmt.Errorf("finalize envelope: list children for VersionId pinning: %w", err)
	}
	if len(children) == 0 {
		return nil, errors.New("finalize envelope: no children available for VersionId pinning")
	}
	pinned := make([]*generated.Document, 0, len(children))
	for _, child := range children {
		if child == nil || child.OrgID != envelope.OrgID || !child.ParentEnvelopeID.Valid || child.ParentEnvelopeID.Bytes != envelope.ID ||
			!envelopeChildStatusMatchesParent(envelope.Status, child.Status) {
			return nil, errors.New("finalize envelope: invalid child while pinning evidence versions")
		}
		child, err = e.ensureDocumentSourceVersions(ctx, child)
		if err != nil {
			return nil, fmt.Errorf("finalize envelope: pin child %s source VersionIds: %w", child.ID, err)
		}
		if child.RequiresSignature {
			if err := e.ensureSignatureVersions(ctx, child.ID); err != nil {
				return nil, fmt.Errorf("finalize envelope: pin child %s signature VersionIds: %w", child.ID, err)
			}
		}
		pinned = append(pinned, child)
	}
	return pinned, nil
}

// requiredRolesForFinalization rechecks the legal-response predicate using a
// transaction-scoped recipient read. The returned role set is also the
// completion credential/notification policy.
func (e *Engine) requiredRolesForFinalization(ctx context.Context, q *generated.Queries, doc *generated.Document, mode string) (map[string]struct{}, error) {
	if q == nil {
		return nil, errors.New("finalization: recipient store unavailable")
	}
	if err := validateFinalizationMode(doc, mode); err != nil {
		return nil, err
	}
	recipients, err := q.ListRecipientsByDocument(ctx, doc.ID)
	if err != nil {
		return nil, fmt.Errorf("finalization: list recipients: %w", err)
	}
	if mode == "acknowledgement" {
		if !allRequiredAcceptorsAccepted(recipients) {
			return nil, ErrDocumentNotReadyToFinalize
		}
		return nil, nil
	}
	roles, err := e.signerRolesForDocumentTx(ctx, q, doc)
	if err != nil {
		return nil, err
	}
	if !allRequiredRecipientsSignedForRoles(roles, recipients) {
		return nil, ErrDocumentNotReadyToFinalize
	}
	if doc.SourceKind == "pdf" {
		fields, err := q.ListFieldsByDocument(ctx, doc.ID)
		if err != nil {
			return nil, err
		}
		signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
		if err != nil {
			return nil, err
		}
		if err := pdflayout.ValidateSignatureRows(doc, recipients, fields, signatures, 0); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDocumentNotReadyToFinalize, err)
		}
	}
	return signerRoleSet(roles), nil
}

// beginDocumentFinalization commits the exact staged tuple while the document
// is already non-interactive. A crash before this transaction is recoverable by
// rebuilding from finalizing; a crash after it is recoverable by resuming the
// immutable tuple without rendering a second legal artifact.
func (e *Engine) beginDocumentFinalization(ctx context.Context, conn *pgxpool.Conn, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1, staged stagedDocumentFinalization) error {
	if conn == nil || e.Queries == nil {
		return errors.New("stage finalization: lifecycle store unavailable")
	}
	return e.stageHistoricalFinalizationOwnedV1(ctx, reference, staged)
}

func finalizationIntentMatchesParams(intent *generated.DocumentFinalizationIntent, params generated.CreateDocumentFinalizationIntentParams) error {
	if intent == nil || intent.DocumentID != params.DocumentID || intent.OrgID != params.OrgID || intent.Mode != params.Mode ||
		!completionEffectiveTimesEqual(intent.CompletionEffectiveAt, params.CompletionEffectiveAt) ||
		!retentionTimesEqual(intent.RetainUntil, params.RetainUntil) ||
		intent.FinalPdfKey != params.FinalPdfKey || subtle.ConstantTimeCompare(intent.FinalPdfSha256, params.FinalPdfSha256) != 1 ||
		intent.FinalPdfVersionID != params.FinalPdfVersionID ||
		intent.AuditCertKey != params.AuditCertKey || subtle.ConstantTimeCompare(intent.AuditCertSha256, params.AuditCertSha256) != 1 ||
		intent.AuditCertVersionID != params.AuditCertVersionID ||
		intent.AuditPayloadKey != params.AuditPayloadKey || subtle.ConstantTimeCompare(intent.AuditPayloadSha256, params.AuditPayloadSha256) != 1 ||
		intent.AuditPayloadVersionID != params.AuditPayloadVersionID ||
		intent.AuditSignatureKey != params.AuditSignatureKey || subtle.ConstantTimeCompare(intent.AuditSignatureSha256, params.AuditSignatureSha256) != 1 ||
		intent.AuditSignatureVersionID != params.AuditSignatureVersionID || !intent.EvidenceVersionPinsRequired {
		return errors.New("stage finalization: existing intent does not match staged artifacts")
	}
	return nil
}

// ensureFinalizationIntentVersions is the one-time compatibility bridge for a
// finalizing row created before migration 47. It may perform bounded digest
// resolution only while the durable intent is explicitly marked legacy, then
// atomically flips it to exact pins. Every subsequent retry is exact-only.
func ensureFinalizationIntentVersions(ctx context.Context, q *generated.Queries, store EvidenceStorage, intent *generated.DocumentFinalizationIntent) (*generated.DocumentFinalizationIntent, error) {
	if q == nil || store == nil || intent == nil {
		return nil, errors.New("resume finalization: version pin dependencies unavailable")
	}
	if intent.EvidenceVersionPinsRequired {
		if !finalizationIntentHasPins(intent) {
			return nil, errors.New("resume finalization: pinned intent is missing an object VersionId")
		}
		return intent, nil
	}
	if intent.FinalPdfVersionID.Valid || intent.AuditCertVersionID.Valid ||
		intent.AuditPayloadVersionID.Valid || intent.AuditSignatureVersionID.Valid {
		return nil, errors.New("resume finalization: legacy intent has a partial VersionId set")
	}

	versions := make([]string, 0, 4)
	legacyArtifacts := []struct {
		key    string
		digest []byte
	}{
		{intent.FinalPdfKey, intent.FinalPdfSha256},
		{intent.AuditCertKey, intent.AuditCertSha256},
		{intent.AuditPayloadKey, intent.AuditPayloadSha256},
		{intent.AuditSignatureKey, intent.AuditSignatureSha256},
	}
	for _, artifact := range legacyArtifacts {
		_, stored, err := store.ResolveVerifiedLegacy(ctx, artifact.key, artifact.digest)
		if err != nil {
			return nil, fmt.Errorf("resume finalization: resolve legacy version for %q: %w", artifact.key, err)
		}
		if strings.TrimSpace(stored.VersionID) == "" {
			return nil, fmt.Errorf("resume finalization: resolve legacy version for %q returned no VersionId", artifact.key)
		}
		versions = append(versions, stored.VersionID)
	}
	pinned, err := q.PinLegacyDocumentFinalizationIntentVersions(ctx, generated.PinLegacyDocumentFinalizationIntentVersionsParams{
		FinalPdfVersionID:       pgtype.Text{String: versions[0], Valid: true},
		AuditCertVersionID:      pgtype.Text{String: versions[1], Valid: true},
		AuditPayloadVersionID:   pgtype.Text{String: versions[2], Valid: true},
		AuditSignatureVersionID: pgtype.Text{String: versions[3], Valid: true},
		DocumentID:              intent.DocumentID, OrgID: intent.OrgID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		pinned, err = q.GetDocumentFinalizationIntent(ctx, generated.GetDocumentFinalizationIntentParams{
			DocumentID: intent.DocumentID, OrgID: intent.OrgID,
		})
	}
	if err != nil {
		return nil, fmt.Errorf("resume finalization: persist legacy VersionIds: %w", err)
	}
	if !finalizationIntentHasPins(pinned) ||
		pinned.FinalPdfVersionID.String != versions[0] || pinned.AuditCertVersionID.String != versions[1] ||
		pinned.AuditPayloadVersionID.String != versions[2] || pinned.AuditSignatureVersionID.String != versions[3] {
		return nil, errors.New("resume finalization: persisted VersionIds do not match resolved artifacts")
	}
	return pinned, nil
}

func finalizationIntentHasPins(intent *generated.DocumentFinalizationIntent) bool {
	return intent != nil && intent.EvidenceVersionPinsRequired &&
		intent.FinalPdfVersionID.Valid && strings.TrimSpace(intent.FinalPdfVersionID.String) != "" &&
		intent.AuditCertVersionID.Valid && strings.TrimSpace(intent.AuditCertVersionID.String) != "" &&
		intent.AuditPayloadVersionID.Valid && strings.TrimSpace(intent.AuditPayloadVersionID.String) != "" &&
		intent.AuditSignatureVersionID.Valid && strings.TrimSpace(intent.AuditSignatureVersionID.String) != ""
}

// resumeDocumentFinalization is safe at every crash boundary: before
// retention, after any individual retain call, after the retention-complete
// checkpoint, and before/after the terminal SQL transaction.
func (e *Engine) resumeDocumentFinalization(ctx context.Context, conn *pgxpool.Conn, doc *generated.Document, capture *completionCredentialCapture) (*generated.Document, bool, error) {
	return e.resumeDocumentFinalizationAfterClaimOwnedV1(ctx, conn, doc, capture, nil)
}

func (e *Engine) resumeDocumentFinalizationAfterClaimOwnedV1(ctx context.Context, conn *pgxpool.Conn, doc *generated.Document, capture *completionCredentialCapture, prior *ownedHistoricalFinalizationClaimV1) (*generated.Document, bool, error) {
	if conn == nil || e.Queries == nil || e.Storage == nil || e.Audit == nil {
		return nil, false, errors.New("resume finalization: dependencies unavailable")
	}
	if doc == nil || doc.Status != "finalizing" {
		return nil, false, ErrDocumentRevisedDuringFinalize
	}
	return e.resumeDocumentFinalizationScopeOwnedV1(ctx, conn, doc.OrgID, doc.ID, capture, prior, nil)
}

func (e *Engine) resumeDocumentFinalizationScopeOwnedV1(ctx context.Context, conn *pgxpool.Conn, org, document uuid.UUID, capture *completionCredentialCapture, prior *ownedHistoricalFinalizationClaimV1, reference *pdfadmission.ApplicationHistoricalFinalizationStageReferenceV1) (*generated.Document, bool, error) {
	if conn == nil || e.Queries == nil || e.Storage == nil || e.Audit == nil {
		return nil, false, errors.New("resume finalization: dependencies unavailable")
	}
	next, intent, resumeOwner, err := e.loadHistoricalFinalizationResumeOwnedV1(ctx, org, document, reference)
	if err != nil {
		return nil, false, err
	}
	defer resumeOwner.closeV1()
	doc := next
	if prior != nil {
		if err = prior.retireAtResumeV1(e, doc, resumeOwner); err != nil {
			return nil, false, err
		}
	}
	if resumeOwner.frozenFailure != nil {
		return nil, false, fmt.Errorf("resume finalization: %w", resumeOwner.frozenFailure)
	}
	// Keep the one exact independently funded advisory witness. Every old real
	// source/CPU/intent consumer is dropped and retired before fresh Source24.
	publication := resumeOwner.publication
	if resumeOwner.publicationFailure != nil {
		return nil, false, blockSignatureFailureV1(resumeOwner.publicationFailure)
	}
	if publication == nil || !publication.MatchesOriginalIntentV1(resumeOwner.operation.native, intent) {
		return nil, false, errors.New("publish finalization: intent changed during resume")
	}
	originalEvidenceFailure := resumeOwner.evidenceFailure
	requiresSignature := doc.RequiresSignature
	next = nil
	doc = nil
	intent = nil
	resumeOwner.document = nil
	if resumeOwner.evidence != nil {
		resumeOwner.evidence.CloseConsumerV1()
		resumeOwner.evidence = nil
	}
	if err = resumeOwner.operation.closeV1(); err != nil {
		return nil, false, err
	}
	var sourceOwner *ownedHistoricalFinalizationSourceV1
	defer func() { retainHistoricalFinalizationInputV1(capture, sourceOwner) }()
	doc, sourceOwner, err = e.loadHistoricalFinalizationRootSourceOwnedV1(ctx, reference, requiresSignature)
	if err != nil {
		return nil, false, err
	}
	if doc.IsEnvelope {
		children, childErr := sourceOwner.ensureEnvelopeChildrenEvidenceVersionsV1(e)
		if childErr != nil {
			return nil, false, childErr
		}
		// Compatibility children have no remaining view/body consumer in Resume.
		children = nil
		_ = children
		if err = sourceOwner.retireResumeVersionFamilyV1(); err != nil {
			return nil, false, err
		}
	}
	doc, intent, publication, err = sourceOwner.resumeIntentVersionsV1(e)
	if err != nil {
		return nil, false, err
	}
	if sourceOwner.resumeIntentPolicyFailure != nil {
		return nil, false, sourceOwner.resumeIntentPolicyFailure
	}
	if err = validateFinalizationIntentAfterModeV1(doc, intent); err != nil {
		return nil, false, err
	}
	// Failures prepared under the original Resume callback retain their original
	// evidence-policy point; a fresh source cannot erase that refusal.
	if originalEvidenceFailure != nil {
		return nil, false, blockSignatureFailureV1(originalEvidenceFailure)
	}
	if sourceOwner.resumeEvidenceFailure != nil {
		return nil, false, blockSignatureFailureV1(sourceOwner.resumeEvidenceFailure)
	}
	artifacts := sourceOwner.resumeEvidence
	if artifacts == nil || !artifacts.MatchesIntentV1(intent) {
		return nil, false, errors.New("resume finalization: actual intent changed before artifact verification")
	}
	if err = artifacts.VerifyIntentArtifactsV1(); err != nil {
		e.markDocumentFinalizationFailed(intent, err)
		return nil, false, err
	}
	if !intent.RetentionCompletedAt.Valid {
		rows, checkpointErr := e.markHistoricalFinalizationCheckpointOwnedV1(ctx, intent, historicalRetentionStartedV1, "")
		if checkpointErr != nil || rows != 1 {
			return nil, false, fmt.Errorf("resume finalization: checkpoint retention start: rows=%d err=%w", rows, checkpointErr)
		}
		if err = sourceOwner.retainResumeSignatureInputsV1(e, publication); err != nil {
			e.markDocumentFinalizationFailed(intent, err)
			return nil, false, err
		}
		if err = artifacts.RetainIntentArtifactsV1(); err != nil {
			e.markDocumentFinalizationFailed(intent, err)
			return nil, false, err
		}
		rows, checkpointErr = e.markHistoricalFinalizationCheckpointOwnedV1(ctx, intent, historicalRetentionCompletedV1, "")
		if checkpointErr != nil || rows != 1 {
			return nil, false, fmt.Errorf("resume finalization: checkpoint retention completion: rows=%d err=%w", rows, checkpointErr)
		}
	}
	if !publication.MatchesIntentV1(intent) {
		return nil, false, errors.New("publish finalization: intent changed during resume")
	}
	// Only the independently funded exact witness crosses the real source last
	// use into fresh publication. Error paths retain Source24 to response lastuse.
	doc = nil
	intent = nil
	artifacts = nil
	if err = sourceOwner.closeV1(); err != nil {
		return nil, false, err
	}
	sourceOwner = nil
	return e.publishDocumentFinalizationFromReferenceV1(ctx, conn, publication, capture)
}

func validateFinalizationIntent(doc *generated.Document, intent *generated.DocumentFinalizationIntent) error {
	if doc == nil || intent == nil || doc.ID != intent.DocumentID || doc.OrgID != intent.OrgID || doc.Status != "finalizing" {
		return errors.New("resume finalization: intent/document identity or state mismatch")
	}
	if err := validateFinalizationMode(doc, intent.Mode); err != nil {
		return err
	}
	return validateFinalizationIntentAfterModeV1(doc, intent)
}

// Native publication has already run the SAME original mode/party policy
// through its genuine source owner; do not decode that full JSON a second time.
func validateFinalizationIntentAfterModeV1(doc *generated.Document, intent *generated.DocumentFinalizationIntent) error {
	if doc == nil || intent == nil || doc.ID != intent.DocumentID || doc.OrgID != intent.OrgID || doc.Status != "finalizing" {
		return errors.New("resume finalization: intent/document identity or state mismatch")
	}
	if !doc.CompletionEffectiveAtBound {
		return errors.New("resume finalization: completion-effective timestamp is not bound")
	}
	if !completionEffectiveTimesEqual(doc.CompletionEffectiveAt, intent.CompletionEffectiveAt) {
		return errors.New("resume finalization: completion-effective timestamp commitment mismatch")
	}
	if !retentionTimesEqual(doc.FinalizationRetainUntil, intent.RetainUntil) {
		return errors.New("resume finalization: retention deadline commitment mismatch")
	}
	staged := stagedDocumentFinalization{
		Mode: intent.Mode, FinalKey: intent.FinalPdfKey, FinalVersionID: intent.FinalPdfVersionID.String,
		Certificate: storedAuditCertificate{
			CertKey: intent.AuditCertKey, CertVersionID: intent.AuditCertVersionID.String,
			PayloadKey: intent.AuditPayloadKey, PayloadVersionID: intent.AuditPayloadVersionID.String,
			SignatureKey: intent.AuditSignatureKey, SignatureVersionID: intent.AuditSignatureVersionID.String,
		},
	}
	copy(staged.FinalSHA256[:], intent.FinalPdfSha256)
	copy(staged.Certificate.CertSHA256[:], intent.AuditCertSha256)
	copy(staged.Certificate.PayloadSHA256[:], intent.AuditPayloadSha256)
	copy(staged.Certificate.SignatureSHA256[:], intent.AuditSignatureSha256)
	return staged.validate(doc)
}

type committedFinalizationArtifact struct {
	key, versionID string
	digest         []byte
}

func finalizationIntentArtifacts(intent *generated.DocumentFinalizationIntent) []committedFinalizationArtifact {
	if intent == nil {
		return nil
	}
	return []committedFinalizationArtifact{
		{intent.FinalPdfKey, intent.FinalPdfVersionID.String, intent.FinalPdfSha256},
		{intent.AuditCertKey, intent.AuditCertVersionID.String, intent.AuditCertSha256},
		{intent.AuditPayloadKey, intent.AuditPayloadVersionID.String, intent.AuditPayloadSha256},
		{intent.AuditSignatureKey, intent.AuditSignatureVersionID.String, intent.AuditSignatureSha256},
	}
}

// retainFinalizationArtifacts is deliberately retryable. Each retain call is
// digest-verified by the storage capability and the complete tuple is verified
// again afterward; if a process exits after object N, a worker safely retries
// the whole list. Exact object-version pinning is handled by the storage/intent
// layer rather than inferred from a mutable latest-version lookup here.
func retainFinalizationArtifacts(ctx context.Context, store EvidenceStorage, intent *generated.DocumentFinalizationIntent) error {
	if store == nil || intent == nil {
		return errors.New("resume finalization: artifact store or intent unavailable")
	}
	retainUntil, err := canonicalFinalizationRetainUntil(intent.CompletionEffectiveAt, intent.RetainUntil)
	if err != nil {
		return fmt.Errorf("resume finalization: %w", err)
	}
	for _, artifact := range finalizationIntentArtifacts(intent) {
		if err := store.RetainEvidenceVersion(ctx, artifact.key, artifact.versionID, artifact.digest, retainUntil); err != nil {
			return fmt.Errorf("resume finalization: retain %q: %w", artifact.key, err)
		}
	}
	return verifyFinalizationArtifacts(ctx, store, intent)
}

func verifyFinalizationArtifacts(ctx context.Context, store EvidenceStorage, intent *generated.DocumentFinalizationIntent) error {
	if store == nil || intent == nil {
		return errors.New("resume finalization: artifact store or intent unavailable")
	}
	for _, artifact := range finalizationIntentArtifacts(intent) {
		if strings.TrimSpace(artifact.key) == "" || strings.TrimSpace(artifact.versionID) == "" || len(artifact.digest) != sha256.Size {
			return errors.New("resume finalization: artifact commitment is incomplete")
		}
		body, err := store.GetVerifiedVersion(ctx, artifact.key, artifact.versionID, artifact.digest)
		if err != nil {
			return fmt.Errorf("resume finalization: read %q: %w", artifact.key, err)
		}
		actual := sha256.Sum256(body)
		if subtle.ConstantTimeCompare(actual[:], artifact.digest) != 1 {
			return fmt.Errorf("resume finalization: artifact %q SHA-256 mismatch", artifact.key)
		}
	}
	return nil
}

func (e *Engine) markDocumentFinalizationFailed(intent *generated.DocumentFinalizationIntent, cause error) {
	if e == nil || e.Queries == nil || intent == nil || cause == nil {
		return
	}
	message := cause.Error()
	if len(message) > 2048 {
		message = message[:2048]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = e.markHistoricalFinalizationCheckpointOwnedV1(ctx, intent, historicalRetentionFailedV1, message)
}

func (e *Engine) publishDocumentFinalization(ctx context.Context, conn *pgxpool.Conn, prepared *generated.Document, stagedIntent *generated.DocumentFinalizationIntent, capture *completionCredentialCapture) (*generated.Document, bool, error) {
	if conn == nil || capture == nil || capture.publication != nil {
		return nil, false, ErrSigningAdmissionUnavailableV1
	}
	completed, did, owner, err := e.publishHistoricalFinalizationOwnedV1(ctx, prepared, stagedIntent, capture)
	capture.publication = owner
	return completed, did, err
}

func (e *Engine) publishDocumentFinalizationFromReferenceV1(ctx context.Context, conn *pgxpool.Conn, reference *pdfadmission.ApplicationHistoricalFinalizationPublicationReferenceV1, capture *completionCredentialCapture) (*generated.Document, bool, error) {
	if conn == nil || capture == nil || capture.publication != nil {
		return nil, false, ErrSigningAdmissionUnavailableV1
	}
	completed, did, owner, err := e.publishHistoricalFinalizationFromReferenceOwnedV1(ctx, reference, capture)
	capture.publication = owner
	return completed, did, err
}

// documentCompletionAuditPayload is the immutable ledger commitment for the
// complete evidence tuple. Keep keys and digests together: auditverify compares
// this payload_hashed body to the terminal document columns and fails a release
// when a completed root has no exact matching commitment.
func documentCompletionAuditPayload(intent *generated.DocumentFinalizationIntent) (map[string]any, error) {
	if intent == nil {
		return nil, errors.New("finalization intent is unavailable")
	}
	completionEffectiveAt, err := canonicalCompletionEffectiveAt(intent.CompletionEffectiveAt)
	if err != nil {
		return nil, err
	}
	retainUntil, err := canonicalFinalizationRetainUntil(intent.CompletionEffectiveAt, intent.RetainUntil)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"mode":                          intent.Mode,
		"completion_effective_at_bound": true,
		"completion_effective_at":       completionEffectiveAt,
		"retain_until":                  retainUntil.Format(time.RFC3339),
		"final_pdf_key":                 intent.FinalPdfKey,
		"final_pdf_sha256":              hex.EncodeToString(intent.FinalPdfSha256),
		"final_pdf_version_id":          intent.FinalPdfVersionID.String,
		"audit_cert_key":                intent.AuditCertKey,
		"audit_cert_sha256":             hex.EncodeToString(intent.AuditCertSha256),
		"audit_cert_version_id":         intent.AuditCertVersionID.String,
		"audit_payload_key":             intent.AuditPayloadKey,
		"audit_payload_sha256":          hex.EncodeToString(intent.AuditPayloadSha256),
		"audit_payload_version_id":      intent.AuditPayloadVersionID.String,
		"audit_signature_key":           intent.AuditSignatureKey,
		"audit_signature_sha256":        hex.EncodeToString(intent.AuditSignatureSha256),
		"audit_signature_version_id":    intent.AuditSignatureVersionID.String,
	}, nil
}

func finalizationIntentsEqual(left, right *generated.DocumentFinalizationIntent) bool {
	return left != nil && right != nil &&
		left.DocumentID == right.DocumentID && left.OrgID == right.OrgID && left.Mode == right.Mode &&
		completionEffectiveTimesEqual(left.CompletionEffectiveAt, right.CompletionEffectiveAt) &&
		retentionTimesEqual(left.RetainUntil, right.RetainUntil) &&
		left.FinalPdfKey == right.FinalPdfKey && subtle.ConstantTimeCompare(left.FinalPdfSha256, right.FinalPdfSha256) == 1 &&
		left.FinalPdfVersionID == right.FinalPdfVersionID &&
		left.AuditCertKey == right.AuditCertKey && subtle.ConstantTimeCompare(left.AuditCertSha256, right.AuditCertSha256) == 1 &&
		left.AuditCertVersionID == right.AuditCertVersionID &&
		left.AuditPayloadKey == right.AuditPayloadKey && subtle.ConstantTimeCompare(left.AuditPayloadSha256, right.AuditPayloadSha256) == 1 &&
		left.AuditPayloadVersionID == right.AuditPayloadVersionID &&
		left.AuditSignatureKey == right.AuditSignatureKey && subtle.ConstantTimeCompare(left.AuditSignatureSha256, right.AuditSignatureSha256) == 1 &&
		left.AuditSignatureVersionID == right.AuditSignatureVersionID &&
		left.EvidenceVersionPinsRequired == right.EvidenceVersionPinsRequired
}

func canonicalCompletionEffectiveAt(value pgtype.Timestamptz) (string, error) {
	if !value.Valid || value.Time.IsZero() {
		return "", errors.New("completion-effective timestamp is unavailable")
	}
	return value.Time.UTC().Format(time.RFC3339Nano), nil
}

func completionEffectiveTimesEqual(left, right pgtype.Timestamptz) bool {
	return left.Valid && right.Valid && !left.Time.IsZero() && !right.Time.IsZero() && left.Time.Equal(right.Time)
}

func finalizationRetentionDeadline(doc *generated.Document) (time.Time, error) {
	if doc == nil {
		return time.Time{}, errors.New("finalization retention deadline is unavailable")
	}
	if !doc.SentAt.Valid || doc.SentAt.Time.IsZero() {
		return time.Time{}, errors.New("authoritative sent timestamp is unavailable")
	}
	if !doc.CompletionEffectiveAt.Valid || doc.CompletionEffectiveAt.Time.IsZero() ||
		!doc.CompletionEffectiveAt.Time.After(doc.SentAt.Time) {
		return time.Time{}, errors.New("completion-effective timestamp must follow the authoritative sent timestamp")
	}
	return canonicalFinalizationRetainUntil(doc.CompletionEffectiveAt, doc.FinalizationRetainUntil)
}

func canonicalFinalizationRetainUntil(completionEffectiveAt, retainUntil pgtype.Timestamptz) (time.Time, error) {
	if !completionEffectiveAt.Valid || completionEffectiveAt.Time.IsZero() {
		return time.Time{}, errors.New("completion-effective timestamp is unavailable")
	}
	if !retainUntil.Valid || retainUntil.Time.IsZero() {
		return time.Time{}, errors.New("finalization retention deadline is unavailable")
	}
	canonical := retainUntil.Time.UTC()
	if canonical.Nanosecond() != 0 {
		return time.Time{}, errors.New("finalization retention deadline must use whole-second precision")
	}
	want := storage.EvidenceRetentionDeadline(completionEffectiveAt.Time, article13.RetentionYearsV1)
	if !canonical.Equal(want) {
		return time.Time{}, fmt.Errorf("finalization retention deadline %s does not match completion commitment %s", canonical.Format(time.RFC3339), want.Format(time.RFC3339))
	}
	return canonical, nil
}

func retentionTimesEqual(left, right pgtype.Timestamptz) bool {
	return left.Valid && right.Valid && !left.Time.IsZero() && !right.Time.IsZero() && left.Time.Equal(right.Time)
}
