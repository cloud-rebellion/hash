// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
)

// This private binding is created only after this actual Work has read and
// validated its own measured source/intent/recipient/field bodies. It carries no
// staff actor, authorization callback, caller model or original-operation loan.
type applicationPackageSendCompletionV1 struct {
	plan *applicationPackageSendRetentionPlanV1
}

// Caller holds the Work mutex. The current private queue slot, actual native
// operation and actual root Work must all agree; copied UUIDs prove none of it.
func (w *ApplicationHTMLSendWorkV1) packageCompletionScopeV1(call context.Context, p *applicationPackageSendRetentionPlanV1) bool {
	if !w.valid(call) || p == nil || p.batch == nil || !p.loaded || p.count < 1 || p.count > len(p.members) || w.stage == nil || w.stage.purpose != HTMLSendCompletionV1 || w.stage.operation == nil || w.state == nil || !w.packageRecoveryInspectionAttempted || p.observation.AttemptID != p.entry.attempt || p.current.AttemptID != p.entry.attempt || p.current.Outcome != HTMLSendPackageAttemptActiveV1 || !packageRetentionProgressV1(p.observation, p.current) || p.entry.document != w.state.ID || p.entry.org != w.state.OrgID || p.main.DocumentID != p.entry.document || p.members[0].document != p.entry.document {
		return false
	}
	p.batch.mu.Lock()
	bound := p.batch.retention == p
	p.batch.mu.Unlock()
	scope := applicationPackageSendRecoveryWorkScopeV1{batch: p.batch, operation: w.stage.operation, entry: p.entry}
	return bound && scope.validV1(w)
}

// The public ReadIntentV1 keeps refusing package intents. Only the genuine
// process-owned current slot can read this exact package intent through the same
// scalar-before-body accounting and exact RETURNING-string verification.
func (w *ApplicationHTMLSendWorkV1) readPackageSendCompletionIntentV1(call context.Context, p *applicationPackageSendRetentionPlanV1) (*generated.SendSealingIntent, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.packageCompletionScopeV1(call, p) {
		return nil, ErrHTMLSendWorkV1
	}
	if w.intentRead {
		if !packageCompletionIntentMatchesV1(w.sourceIntent, p) {
			return nil, ErrHTMLSendWorkV1
		}
		return w.sourceIntent, nil
	}
	w.intentRead = true
	s := w.session.state
	h, err := w.queries.GetHTMLSendIntentReadHeaderV1(call, generated.GetHTMLSendIntentReadHeaderV1Params{DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != p.entry.document || h.OrgID != p.entry.org || h.RawTextBytes < 0 || !h.PackageSendAttemptID.Valid || uuid.UUID(h.PackageSendAttemptID.Bytes) != p.entry.attempt {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	intent, err := w.queries.ReadHTMLSendIntentV1(call, generated.ReadHTMLSendIntentV1Params{DocumentID: s.document, OrgID: s.org, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if !packageCompletionIntentMatchesV1(intent, p) || intent.UpdatedAt != h.UpdatedAt || intent.PackageSendAttemptID != h.PackageSendAttemptID || int64(len(intent.ActorEmail)+len(intent.ActorIp)+len(intent.Via)+len(intent.Tool)+len(intent.LastError.String)) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	copy := *intent
	copy.ActorEmail = strings.Clone(intent.ActorEmail)
	copy.ActorIp = strings.Clone(intent.ActorIp)
	copy.Via = strings.Clone(intent.Via)
	copy.Tool = strings.Clone(intent.Tool)
	copy.LastError.String = strings.Clone(intent.LastError.String)
	w.sourceIntent = &copy
	return w.sourceIntent, nil
}

func packageCompletionIntentMatchesV1(intent *generated.SendSealingIntent, p *applicationPackageSendRetentionPlanV1) bool {
	if p == nil || intent == nil || intent.DocumentID != p.entry.document || intent.OrgID != p.entry.org || !intent.PackageSendAttemptID.Valid || uuid.UUID(intent.PackageSendAttemptID.Bytes) != p.entry.attempt || intent.PresignExecutionID.Valid || !intent.ActorUserID.Valid || uuid.UUID(intent.ActorUserID.Bytes) != p.current.Capture.CreatedBy || !applicationStampV1(intent.Article13NoticeEpochAt) || !intent.Article13NoticeEpochAt.Time.Equal(p.current.Article13NoticeEpochAt) || !applicationStampV1(intent.RetainUntil) || !intent.RetainUntil.Time.Equal(p.current.RetainUntil) || intent.RetentionStartedAt.Valid != !p.current.RetentionStartedAt.IsZero() || intent.RetentionCompletedAt.Valid != !p.current.RetentionCompletedAt.IsZero() {
		return false
	}
	return (!intent.RetentionStartedAt.Valid || (applicationStampV1(intent.RetentionStartedAt) && intent.RetentionStartedAt.Time.Equal(p.current.RetentionStartedAt))) && (!intent.RetentionCompletedAt.Valid || (applicationStampV1(intent.RetentionCompletedAt) && intent.RetentionCompletedAt.Time.Equal(p.current.RetentionCompletedAt)))
}

// Preparation is repeated on a new genuine Work before retention and again in
// the final transaction. Nothing from an earlier Work substitutes for fresh
// source policy, frozen branding, disclosure, recipient or field decisions.
func (w *ApplicationHTMLSendWorkV1) preparePackageSendCompletionV1(call context.Context, p *applicationPackageSendRetentionPlanV1) (*applicationPackageSendCompletionV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.packageCompletionScopeV1(call, p) || w.packageCompletion != nil || w.modelsRead || w.completedAttempted {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	fixed := 4096 + 8*int64(unsafe.Sizeof(applicationPackageSendCompletionV1{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		w.mu.Unlock()
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	w.mu.Unlock()
	if _, err = w.readPackageSendCompletionIntentV1(call, p); err != nil {
		return nil, err
	}
	models, err := w.ReadModelsV1(call)
	if err != nil {
		return nil, err
	}
	doc := models.Document
	if doc == nil || doc.ID != p.entry.document || doc.OrgID != p.entry.org || doc.DeletedAt.Valid || doc.Status != "sealing" || doc.SourceKind != "pdf" || doc.IsEnvelope || doc.ParentEnvelopeID.Valid || !doc.EvidenceVersionPinsRequired || eidas.Tier(doc.RoutingTier) != eidas.TierSES {
		return nil, ErrHTMLSendWorkV1
	}
	if !doc.RequiresSignature && (!doc.PdfStorageKey.Valid || strings.TrimSpace(doc.PdfStorageKey.String) == "" || len(doc.PdfSha256) != 32) {
		return nil, ErrHTMLSendWorkV1
	}
	confirmation, err := w.ReadConfirmationV1(call)
	if err != nil {
		return nil, err
	}
	if confirmation == nil || !applicationStampV1(confirmation.ConfirmedAt) || confirmation.DocumentID != doc.ID || confirmation.OrgID != doc.OrgID || strings.TrimSpace(confirmation.LawfulBasis) != strings.TrimSpace(doc.LawfulBasis) || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		return nil, ErrHTMLSendWorkV1
	}
	if _, err = article13.LegalBasisDisclosureV1(confirmation.LawfulBasis); err != nil {
		return nil, err
	}
	if err = article13.ValidateDisclosurePreflight(article13.DisclosurePreflight{DocumentName: doc.Name, Controller: confirmation.ControllerName, ControllerContact: confirmation.ControllerContact, LawfulBasis: confirmation.LawfulBasis}); err != nil {
		return nil, err
	}
	source, err := w.NewSourceV1(call)
	if err != nil {
		return nil, err
	}
	if err = source.ValidateReviewedV1(); err != nil {
		return nil, err
	}
	if err = source.ValidateCurrentV1(); err != nil {
		return nil, err
	}
	if err = w.ValidateSigningPageStateV1(call); err != nil {
		return nil, err
	}
	if err = w.readPackageCompletionBrandingV1(call); err != nil {
		return nil, err
	}
	if err = packageCompletionSourceMatchesV1(source, p); err != nil {
		return nil, err
	}
	rows, err := w.ReadRecipientsV1(call)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrHTMLSendWorkV1
	}
	if err = source.ValidatePartiesV1(doc, rows); err != nil {
		return nil, err
	}
	for _, row := range rows {
		if call.Err() != nil || row == nil || row.ID == uuid.Nil || row.DocumentID != doc.ID || (row.Status != "" && row.Status != "pending") || !recipients.CanRespond(row.Role) {
			return nil, ErrHTMLSendWorkV1
		}
		if err = recipients.ValidatePersisted(recipients.Values{Email: row.Email, Name: row.Name, Role: row.Role, OrderIndex: row.OrderIndex, Locale: row.Locale}); err != nil {
			return nil, err
		}
	}
	fields, err := w.ReadFieldsV1(call)
	if err != nil {
		return nil, err
	}
	if doc.RequiresSignature {
		if err = source.ValidatePDFRoleFieldsV1(doc, rows, fields, int(p.members[0].pages)); err != nil {
			return nil, err
		}
	} else if len(fields) != 0 {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.packageCompletionScopeV1(call, p) || w.packageCompletion != nil || w.sourceDocument == nil || w.sourceIntent == nil || w.completedAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.packageCompletion = &applicationPackageSendCompletionV1{plan: p}
	return w.packageCompletion, nil
}

// Plain imported PDFs have no HTML signing-page artifact to trigger the common
// signing-state branding read. Require the complete original frozen row for
// those documents too, without sampling today's organization defaults.
func (w *ApplicationHTMLSendWorkV1) readPackageCompletionBrandingV1(call context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceDocument == nil || w.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.queries.GetHTMLSendBrandingInputHeaderV1(call, generated.GetHTMLSendBrandingInputHeaderV1Params{DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || !h.HasDocumentBranding || h.DocumentBrandingRawBytes < 0 {
		return ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, h.DocumentBrandingRawBytes, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.GetDocumentBrandingOverride(call, s.document)
	if err != nil {
		return err
	}
	if row == nil || row.DocumentID != s.document {
		return ErrHTMLSendWorkV1
	}
	raw := int64(len(row.PrimaryHex.String) + len(row.AccentHex.String) + len(row.SurfaceHex.String) + len(row.TextHex.String) + len(row.MutedHex.String) + len(row.LogoUrl.String) + len(row.LogoAlt.String) + len(row.FontHeading.String) + len(row.FontBody.String) + len(row.SignatureColor.String))
	if raw != h.DocumentBrandingRawBytes {
		return ErrHTMLSendWorkV1
	}
	if err = branding.ValidateFrozenSnapshot(s.document, row); err != nil {
		return err
	}
	w.frozenBranding = htmlSendCloneBrandingV1(row)
	return nil
}

// The actual admitted source owns its validation/commitments while they are
// compared with the plan's separately retained canonical main member.
func packageCompletionSourceMatchesV1(source *ApplicationHTMLSendSourceV1, p *applicationPackageSendRetentionPlanV1) error {
	if source == nil || source.state == nil || p == nil || !source.state.lockV1() {
		return ErrHTMLSendWorkV1
	}
	state := source.state
	defer state.unlockV1()
	owner := state.owner
	if owner == nil || state.closeRequested.Load() || !state.attempted || state.failure != nil || !state.currentAttempted || state.currentFailure != nil {
		return ErrHTMLSendWorkV1
	}
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	owner.mu.Lock()
	if owner.processing || owner.snapshot == nil || owner.snapshot.document == nil || owner.validation == nil || !owner.currentValidated {
		owner.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	owner.processing = true
	doc, validation := owner.snapshot.document, owner.validation
	owner.mu.Unlock()
	defer func() { owner.mu.Lock(); owner.processing = false; owner.mu.Unlock() }()
	main, measured := p.main, &p.members[0]
	if main.DocumentID != doc.ID || main.Title != doc.Name || main.Category != "" || !doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || doc.PdfStorageKey.String != main.PDF.Key || doc.PdfStorageVersionID.String != main.PDF.VersionID || len(doc.PdfSha256) != 32 || hex.EncodeToString(doc.PdfSha256) != main.PDF.SHA256 || measured.document != doc.ID || measured.key != main.PDF.Key || measured.version != main.PDF.VersionID || !bytes.Equal(measured.digest[:], doc.PdfSha256) || measured.bytes != main.PDF.Bytes || measured.pages != main.PDF.Pages || measured.bytes < 1 || measured.bytes > documentpackage.MaxPDFBytesV1 || measured.pages < 1 || measured.pages > documentpackage.MaxPDFPagesV1 {
		return ErrHTMLSendWorkV1
	}
	if len(doc.HtmlSourceJson) == 0 {
		if main.Source.Kind != documentpackage.SourcePDFImportV1 || main.Source.CommitmentSHA256 != "" || main.Source.OriginCommitmentSHA256 != "" || main.Source.Materialization != nil {
			return ErrHTMLSendWorkV1
		}
		return nil
	}
	current, err := validation.CommitmentV1()
	if err != nil {
		return err
	}
	origin, err := validation.OriginCommitmentV1()
	if err != nil {
		return err
	}
	if current != main.Source.CommitmentSHA256 || origin != main.Source.OriginCommitmentSHA256 {
		return ErrHTMLSendWorkV1
	}
	if !doc.HtmlCurrentMaterializationID.Valid {
		if main.Source.Kind != documentpackage.SourceHTMLOriginV1 || main.Source.Materialization != nil || current != origin {
			return ErrHTMLSendWorkV1
		}
	} else if main.Source.Kind != documentpackage.SourceHTMLRevisionV1 || main.Source.Materialization == nil || main.Source.Materialization.ID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || !doc.HtmlCurrentMaterializationSequence.Valid || main.Source.Materialization.Sequence != doc.HtmlCurrentMaterializationSequence.Int32 {
		return ErrHTMLSendWorkV1
	}
	return nil
}

func (w *ApplicationHTMLSendWorkV1) completePackageDocumentSendV1(call context.Context, p *applicationPackageSendRetentionPlanV1) (*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.packageCompletionScopeV1(call, p) || w.packageCompletion == nil || w.packageCompletion.plan != p || w.sourceDocument == nil || w.sourceIntent == nil || w.completedAttempted || !applicationStampV1(w.sourceIntent.RetentionStartedAt) || !applicationStampV1(w.sourceIntent.RetentionCompletedAt) {
		return nil, ErrHTMLSendWorkV1
	}
	w.completedAttempted = true
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("sent")+len("hash-a13-2026-08-31")))
	if err != nil {
		return nil, err
	}
	c := p.observation.Capture
	row, err := w.queries.CompleteDocumentPackageSendSealingV1(call, generated.CompleteDocumentPackageSendSealingV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if err != nil {
		return nil, err
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "sent" {
		return nil, ErrHTMLSendWorkV1
	}
	before, after := *w.sourceDocument, *row
	before.Status = after.Status
	before.SentAt = after.SentAt
	before.Article13NoticeEpochAt = after.Article13NoticeEpochAt
	before.Article13NoticeSchema = after.Article13NoticeSchema
	before.Article13NoticeEpochV61Committed = after.Article13NoticeEpochV61Committed
	before.UpdatedAt = after.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&before, &after) || row.SentAt != w.sourceIntent.Article13NoticeEpochAt || row.Article13NoticeEpochAt != w.sourceIntent.Article13NoticeEpochAt || row.Article13NoticeSchema != "hash-a13-2026-08-31" || !row.Article13NoticeEpochV61Committed {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	w.models.Document = row
	w.completedDocument = row
	return row, nil
}
