// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"unsafe"
)

// This actual-recipient entry is allocated only under the completion producer
// loan. It is neither a caller's token nor a generic output-size declaration.
type htmlSendCompletionRecipientV1 struct {
	id                            uuid.UUID
	token                         string
	tokenHash                     [32]byte
	tokenExpiry                   pgtype.Timestamptz
	outboxID                      uuid.UUID
	attempted, rendered, enqueued bool
	message                       dispatch.Message
}
type htmlSendCompletionOutputsV1 struct {
	publicURL, orgName string
	recipients         []htmlSendCompletionRecipientV1
	packageOutbox      *applicationPackageSendOutboxBatchV1
}

// PrepareCompletionOutputsV1 binds real instance configuration and the SAME
// immutable recipient/document/intent rows. It owns the first URLs, token and
// result/container buffers before constructing them; actual per-locale render
// bounds are then acquired before the original renderer can run.
func (w *ApplicationHTMLSendWorkV1) PrepareCompletionOutputsV1(call context.Context, publicURL, orgName string) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.sourceDocument == nil || w.sourceIntent == nil || w.completionOutputs != nil || w.completionOutputsAttempted {
		return ErrHTMLSendWorkV1
	}
	w.completionOutputsAttempted = true
	n := int64(0)
	if w.packageCompletion != nil {
		if !w.packageCompletionScopeV1(call, w.packageCompletion.plan) {
			return ErrHTMLSendWorkV1
		}
		if err := htmlSendResolverAddV1(&n, 1, 8*int64(unsafe.Sizeof(applicationPackageSendOutboxBatchV1{}))); err != nil {
			return err
		}
	}
	if err := htmlSendResolverAddV1(&n, 1, int64(unsafe.Sizeof(htmlSendCompletionOutputsV1{}))); err != nil {
		return err
	}
	for _, x := range [][2]int64{{int64(len(publicURL)), 2}, {int64(len(orgName)), 1}, {int64(len(w.sourceRecipients)), int64(unsafe.Sizeof(htmlSendCompletionRecipientV1{})) + 12*int64(unsafe.Sizeof("")) + 2*int64(unsafe.Sizeof(uuid.UUID{})) + 2*(43+32+32) + 8 + int64(unsafe.Sizeof(audit.Entry{})) + 8*int64(unsafe.Sizeof("")+unsafe.Sizeof(any(nil))+2*unsafe.Sizeof(uintptr(0)))}} {
		if err := htmlSendResolverAddV1(&n, x[0], x[1]); err != nil {
			return err
		}
	}
	for _, r := range w.sourceRecipients {
		if r == nil || r.DocumentID != w.sourceDocument.ID {
			return ErrHTMLSendWorkV1
		}
		for _, x := range [][2]int64{{int64(len(publicURL)), 2}, {int64(len(r.Email)), 2}, {int64(len(r.Name)), 2}, {int64(len(r.Role)), 2}, {int64(len(r.Locale)), 2}, {1, int64(len("/sign/") + len("/e/o/") + 2*43)}} {
			if err := htmlSendResolverAddV1(&n, x[0], x[1]); err != nil {
				return err
			}
		}
	}
	closeInitial, err := w.actor.acquireOwnedRetainedBodyV1(call, n, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeInitial)
	// Tokens are always43 RawURLEncoding characters. Replacing those safe ASCII
	// characters with 'A' changes no HTML/text escaping or URL-output length.
	// This probe is actual fixed renderer input, never source/cost authority.
	signURL := publicURL + "/sign/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	beaconURL := publicURL + "/e/o/" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	output := int64(0)
	for _, r := range w.sourceRecipients {
		subject, html, text, err := dispatch.InviteNotificationComponentsV1(dispatch.TemplateContext{DocumentName: w.sourceDocument.Name, SenderName: w.sourceIntent.ActorEmail, SenderEmail: w.sourceIntent.ActorEmail, RecipientName: r.Name, OrgName: orgName, Locale: r.Locale, SignURL: signURL, BeaconURL: beaconURL, Acknowledgement: !w.sourceDocument.RequiresSignature})
		if err != nil {
			return err
		}
		// Each real branch renders once. Two retained output sets additionally
		// cover the private immutable queue binding plus its mutable dispatch view.
		for _, v := range []int64{subject, html, text} {
			if err := htmlSendResolverAddV1(&output, v, 2); err != nil {
				return err
			}
		}
	}
	closeOutput, err := w.actor.acquireOwnedRetainedBodyV1(call, output, 0)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeOutput)
	p := &htmlSendCompletionOutputsV1{publicURL: strings.Clone(publicURL), orgName: strings.Clone(orgName), recipients: make([]htmlSendCompletionRecipientV1, len(w.sourceRecipients))}
	for i, r := range w.sourceRecipients {
		p.recipients[i].id = r.ID
	}
	w.completionOutputs = p
	if w.packageCompletion != nil {
		return w.preparePackageSendOutboxBatchV1(call)
	}
	return nil
}
func (w *ApplicationHTMLSendWorkV1) RotateAndMarkRecipientV1(call context.Context, id uuid.UUID, exp pgtype.Timestamptz) (string, error) {
	if w == nil || w.self != w {
		return "", ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.completionOutputs == nil || w.completedAttempted {
		return "", ErrHTMLSendWorkV1
	}
	var item *htmlSendCompletionRecipientV1
	for i := range w.completionOutputs.recipients {
		if w.completionOutputs.recipients[i].id == id {
			item = &w.completionOutputs.recipients[i]
			break
		}
	}
	if item == nil || item.attempted {
		return "", ErrHTMLSendWorkV1
	}
	item.attempted = true
	tok, hash, err := auth.MintMagicToken()
	if err != nil {
		return "", fmt.Errorf("token mint: %w", err)
	}
	if len(tok) != 43 || len(hash) != 32 {
		return "", ErrHTMLSendWorkV1
	}
	item.token = tok
	if err = w.queries.RotateRecipientMagicToken(call, generated.RotateRecipientMagicTokenParams{ID: id, DocumentID: w.session.state.document, MagicTokenHash: hash, MagicTokenExpiresAt: exp}); err != nil {
		return "", fmt.Errorf("rotate token: %w", err)
	}
	rows, err := w.queries.MarkRecipientSent(call, generated.MarkRecipientSentParams{ID: id, DocumentID: w.session.state.document})
	if err != nil {
		return "", fmt.Errorf("complete send sealing: mark recipient sent: %w", err)
	}
	if rows != 1 {
		return "", fmt.Errorf("complete send sealing: mark recipient %s sent: updated %d rows", id, rows)
	}
	copy(item.tokenHash[:], hash)
	item.tokenExpiry = exp
	return tok, nil
}

// RenderInviteV1 repeats the unchanged fixed invite inputs; its caller supplies
// only the actual recipient ID, not a model/token/renderer callback or budget.
func (w *ApplicationHTMLSendWorkV1) RenderInviteV1(call context.Context, id uuid.UUID) (dispatch.Message, error) {
	if w == nil || w.self != w {
		return dispatch.Message{}, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.completionOutputs == nil || w.sourceIntent == nil || w.sourceDocument == nil {
		return dispatch.Message{}, ErrHTMLSendWorkV1
	}
	p := w.completionOutputs
	var item *htmlSendCompletionRecipientV1
	var rec *generated.Recipient
	for i := range p.recipients {
		if p.recipients[i].id == id {
			item = &p.recipients[i]
			rec = w.sourceRecipients[i]
			break
		}
	}
	if item == nil || rec == nil || item.token == "" || item.rendered {
		return dispatch.Message{}, ErrHTMLSendWorkV1
	}
	item.rendered = true
	subject, html, text, err := dispatch.Render(dispatch.KindInvite, dispatch.TemplateContext{DocumentName: w.sourceDocument.Name, SenderName: w.sourceIntent.ActorEmail, SenderEmail: w.sourceIntent.ActorEmail, RecipientName: rec.Name, OrgName: p.orgName, Locale: rec.Locale, SignURL: p.publicURL + "/sign/" + item.token, BeaconURL: p.publicURL + "/e/o/" + item.token, Acknowledgement: !w.sourceDocument.RequiresSignature})
	if err != nil {
		return dispatch.Message{}, err
	}
	msg := dispatch.Message{To: rec.Email, Subject: subject, HTML: html, Text: text, ReplyTo: w.sourceIntent.ActorEmail, FromName: p.orgName}
	item.message = dispatch.Message{To: strings.Clone(msg.To), Subject: strings.Clone(msg.Subject), HTML: strings.Clone(msg.HTML), Text: strings.Clone(msg.Text), ReplyTo: strings.Clone(msg.ReplyTo), FromName: strings.Clone(msg.FromName)}
	return msg, nil
}
func htmlSendInviteMessageEqualV1(a, b dispatch.Message) bool {
	return len(a.Headers) == 0 && len(b.Headers) == 0 && a.To == b.To && a.Subject == b.Subject && a.HTML == b.HTML && a.Text == b.Text && a.ReplyTo == b.ReplyTo && a.FromName == b.FromName
}
func (w *ApplicationHTMLSendWorkV1) EnqueueEmailDeliveryV1(call context.Context, msg dispatch.Message) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.completionOutputs == nil || !w.completedAttempted || w.sourceDocument == nil || w.sourceDocument.Status != "sent" {
		return ErrHTMLSendWorkV1
	}
	var item *htmlSendCompletionRecipientV1
	for i := range w.completionOutputs.recipients {
		candidate := &w.completionOutputs.recipients[i]
		if candidate.rendered && !candidate.enqueued && htmlSendInviteMessageEqualV1(candidate.message, msg) {
			item = candidate
			break
		}
	}
	if item == nil {
		return ErrHTMLSendWorkV1
	}
	item.enqueued = true
	raw, err := htmlAuthoringSumV1(int64(len(msg.To)), int64(len(msg.Subject)), int64(len(msg.HTML)), int64(len(msg.Text)), int64(len(msg.ReplyTo)), int64(len(msg.FromName)), int64(len("pending")))
	if err != nil {
		return err
	}
	// The ORIGINAL invite has no extra headers; the original outbox writes '{}'.
	// Its exact two-byteJSONB body and full actual RETURNING strings are charged
	// independently before QueryRow. No public output estimate enters admission.
	if w.packageCompletion != nil {
		if w.completionOutputs.packageOutbox == nil {
			return ErrHTMLSendWorkV1
		}
		if err := w.completionOutputs.packageOutbox.consumeV1(call, w, item, msg, raw); err != nil {
			return err
		}
	} else {
		closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 2)
		if err != nil {
			return errors.Join(ErrHTMLSendWorkV1, err)
		}
		w.closes = append(w.closes, closeBody)
	}
	row, err := w.queries.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text, ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: []byte("{}")})
	if err != nil {
		return fmt.Errorf("enqueue email to %s: %w", dispatch.MaskEmail(msg.To), err)
	}
	if row == nil {
		return fmt.Errorf("enqueue email to %s returned no delivery", dispatch.MaskEmail(msg.To))
	}
	if row.ID == uuid.Nil || row.ToEmail != msg.To || row.Subject != msg.Subject || row.HtmlBody != msg.HTML || row.TextBody != msg.Text || row.ReplyTo != msg.ReplyTo || row.FromName != msg.FromName || row.Status != "pending" || row.LastError != "" || string(row.HeadersJson) != "{}" {
		return ErrHTMLSendWorkV1
	}
	item.outboxID = row.ID
	return nil
}
func htmlSendDocumentExactTupleEqualV1(a, b *generated.Document) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.ID != b.ID {
		return false
	}
	if a.OrgID != b.OrgID {
		return false
	}
	if a.TemplateID != b.TemplateID {
		return false
	}
	if a.Name != b.Name {
		return false
	}
	if a.Status != b.Status {
		return false
	}
	if a.RoutingMode != b.RoutingMode {
		return false
	}
	if a.SourceKind != b.SourceKind {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.BlocksJson, b.BlocksJson) {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.VariablesJson, b.VariablesJson) {
		return false
	}
	if a.RenderedPdfKey != b.RenderedPdfKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.RenderedPdfSha, b.RenderedPdfSha) {
		return false
	}
	if a.PdfStorageKey != b.PdfStorageKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.PdfSha256, b.PdfSha256) {
		return false
	}
	if a.FinalPdfKey != b.FinalPdfKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.FinalPdfSha, b.FinalPdfSha) {
		return false
	}
	if a.AuditCertKey != b.AuditCertKey {
		return false
	}
	if a.ExpiresAt != b.ExpiresAt {
		return false
	}
	if a.SentAt != b.SentAt {
		return false
	}
	if a.CompletedAt != b.CompletedAt {
		return false
	}
	if a.SenderID != b.SenderID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.Metadata, b.Metadata) {
		return false
	}
	if a.CreatedAt != b.CreatedAt {
		return false
	}
	if a.UpdatedAt != b.UpdatedAt {
		return false
	}
	if a.ParentEnvelopeID != b.ParentEnvelopeID {
		return false
	}
	if a.EnvelopePosition != b.EnvelopePosition {
		return false
	}
	if a.IsEnvelope != b.IsEnvelope {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.MetadataRedactionReport, b.MetadataRedactionReport) {
		return false
	}
	if a.RoutingTier != b.RoutingTier {
		return false
	}
	if a.NegotiationEnabled != b.NegotiationEnabled {
		return false
	}
	if a.BilingualTargetLang != b.BilingualTargetLang {
		return false
	}
	if a.LawfulBasis != b.LawfulBasis {
		return false
	}
	if a.DeletedAt != b.DeletedAt {
		return false
	}
	if a.DefaultLocale != b.DefaultLocale {
		return false
	}
	if a.RequiresSignature != b.RequiresSignature {
		return false
	}
	if a.AuditPayloadKey != b.AuditPayloadKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditPayloadSha256, b.AuditPayloadSha256) {
		return false
	}
	if a.AuditSignatureKey != b.AuditSignatureKey {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditSignatureSha256, b.AuditSignatureSha256) {
		return false
	}
	if a.PdfStorageVersionID != b.PdfStorageVersionID {
		return false
	}
	if a.RenderedPdfVersionID != b.RenderedPdfVersionID {
		return false
	}
	if a.FinalPdfVersionID != b.FinalPdfVersionID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.AuditCertSha256, b.AuditCertSha256) {
		return false
	}
	if a.AuditCertVersionID != b.AuditCertVersionID {
		return false
	}
	if a.AuditPayloadVersionID != b.AuditPayloadVersionID {
		return false
	}
	if a.AuditSignatureVersionID != b.AuditSignatureVersionID {
		return false
	}
	if a.EvidenceVersionPinsRequired != b.EvidenceVersionPinsRequired {
		return false
	}
	if a.CompletionEffectiveAt != b.CompletionEffectiveAt {
		return false
	}
	if a.CompletionEffectiveAtBound != b.CompletionEffectiveAtBound {
		return false
	}
	if a.FinalizationRetainUntil != b.FinalizationRetainUntil {
		return false
	}
	if a.Article13NoticeEpochAt != b.Article13NoticeEpochAt {
		return false
	}
	if a.Article13NoticeSchema != b.Article13NoticeSchema {
		return false
	}
	if a.Article13NoticeEpochV61Committed != b.Article13NoticeEpochV61Committed {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlSourceJson, b.HtmlSourceJson) {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlReviewedPdfSha256, b.HtmlReviewedPdfSha256) {
		return false
	}
	if a.HtmlReviewedBy != b.HtmlReviewedBy {
		return false
	}
	if a.HtmlReviewedAt != b.HtmlReviewedAt {
		return false
	}
	if a.HtmlCurrentMaterializationID != b.HtmlCurrentMaterializationID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.HtmlCurrentSourceJson, b.HtmlCurrentSourceJson) {
		return false
	}
	if a.HtmlCurrentPageCount != b.HtmlCurrentPageCount {
		return false
	}
	if a.HtmlCurrentMaterializationSequence != b.HtmlCurrentMaterializationSequence {
		return false
	}
	if a.HtmlReviewedMaterializationID != b.HtmlReviewedMaterializationID {
		return false
	}
	if a.HtmlEffectiveSourceCommitment != b.HtmlEffectiveSourceCommitment {
		return false
	}
	if a.SignatureFitReservedBytes != b.SignatureFitReservedBytes {
		return false
	}
	if a.FitsIndexRequired != b.FitsIndexRequired {
		return false
	}
	if a.FitsIndexPreparationID != b.FitsIndexPreparationID {
		return false
	}
	if a.FitsIndexStorageKey != b.FitsIndexStorageKey {
		return false
	}
	if a.FitsIndexVersionID != b.FitsIndexVersionID {
		return false
	}
	if !htmlSendPinnedBytesEqualV1(a.FitsIndexSha256, b.FitsIndexSha256) {
		return false
	}
	if a.FitsIndexBytes != b.FitsIndexBytes {
		return false
	}
	if a.SignatureFitOriginalPayloadBytes != b.SignatureFitOriginalPayloadBytes {
		return false
	}
	if a.SignatureFitOriginalAuthorityBytes != b.SignatureFitOriginalAuthorityBytes {
		return false
	}
	if a.SignatureFitOriginalAuthorityCount != b.SignatureFitOriginalAuthorityCount {
		return false
	}
	if a.ParticipantReportSchema != b.ParticipantReportSchema {
		return false
	}
	if a.SigningAdmissionPolicy != b.SigningAdmissionPolicy {
		return false
	}
	if a.SigningAdmissionActiveID != b.SigningAdmissionActiveID {
		return false
	}
	if a.SigningAdmissionSealedID != b.SigningAdmissionSealedID {
		return false
	}
	if a.SigningAdmissionCount != b.SigningAdmissionCount {
		return false
	}
	if a.SigningAdmissionStaticBytes != b.SigningAdmissionStaticBytes {
		return false
	}
	if a.SigningAdmissionOrdinaryBytes != b.SigningAdmissionOrdinaryBytes {
		return false
	}
	if a.SigningAdmissionPlanBytes != b.SigningAdmissionPlanBytes {
		return false
	}
	if a.SignatureFitRequestBindingBytes != b.SignatureFitRequestBindingBytes {
		return false
	}
	if a.SignatureFitRequestBindingCount != b.SignatureFitRequestBindingCount {
		return false
	}
	return true
}

func (w *ApplicationHTMLSendWorkV1) CompleteDocumentSendV1(call context.Context) (*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || w.sourceDocument == nil || w.sourceIntent == nil || w.completedAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	w.completedAttempted = true
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("sent")+len("hash-a13-2026-08-31")))
	if err != nil {
		return nil, err
	}
	s := w.session.state
	row, err := w.queries.CompleteDocumentSendSealing(call, generated.CompleteDocumentSendSealingParams{ID: s.document, OrgID: s.org})
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
func (w *ApplicationHTMLSendWorkV1) ExpireCompletedSendV1(call context.Context) (*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLSendCompletionV1 || !w.completedAttempted || w.expiredAttempted || w.sourceDocument == nil || w.sourceDocument.Status != "sent" {
		return nil, ErrHTMLSendWorkV1
	}
	w.expiredAttempted = true
	raw, _, err := w.admitDocumentReturnV1(call, int64(len("expired")))
	if err != nil {
		return nil, err
	}
	s := w.session.state
	row, err := w.queries.ExpireDocumentIfActive(call, generated.ExpireDocumentIfActiveParams{ID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if !w.verifyDocumentReturnV1(row, raw) || row.Status != "expired" {
		return nil, ErrHTMLSendWorkV1
	}
	before, after := *w.sourceDocument, *row
	before.Status = after.Status
	before.UpdatedAt = after.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&before, &after) {
		return nil, ErrHTMLSendWorkV1
	}
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	w.models.Document = row
	return row, nil
}
