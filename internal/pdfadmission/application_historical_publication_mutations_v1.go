// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"unsafe"
)

var ErrHistoricalFittedPublicationV1 = errors.New("pdfadmission: fitted finalization requires its separate composition authority")

type applicationHistoricalPublicationV1 struct {
	completed                                                       *generated.Document
	children                                                        []*generated.Document
	completeAttempted, reminderCanceled, tokensInvalidated, deleted bool
	outputs                                                         *applicationHistoricalCompletionOutputsV1
	payloads                                                        []historicalCompletionPayloadV1
}

// The historical route supports no fitted-composition authority. Its exact
// original no-fit fast path is established using the real bounded signature
// inventory, before any terminal write. Actual fitted rows remain refused.
func (w *ApplicationHTMLSendWorkV1) CheckHistoricalPublicationCompatibilityV1(call context.Context) error {
	rows, err := w.ReadHistoricalFinalizationSignaturesV1(call)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		return err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationPublicationV1 {
		return ErrHTMLSendWorkV1
	}
	for _, row := range state.signatures {
		if row == nil {
			return ErrHTMLSendWorkV1
		}
		if row.SignatureKind == "manual_pdf_fit_v1" {
			return ErrHistoricalFittedPublicationV1
		}
	}
	if len(rows) != len(state.signatures) {
		return ErrHTMLSendWorkV1
	}
	state.compatibilityChecked = true
	return nil
}
func historicalPublicationDocumentTupleV1(before, row *generated.Document, intent *generated.DocumentFinalizationIntent) bool {
	// M67 advances each returned row independently. The persisted legal
	// completion/retention tuple remains exact; the actual row clock must advance.
	if before == nil || row == nil || intent == nil || row.Status != "completed" || !applicationStampV1(before.UpdatedAt) || !applicationStampV1(row.UpdatedAt) || !row.UpdatedAt.Time.After(before.UpdatedAt.Time) {
		return false
	}
	expected := *before
	expected.Status = "completed"
	expected.UpdatedAt = row.UpdatedAt
	expected.CompletedAt = before.CompletionEffectiveAt
	expected.FinalPdfKey = pgtype.Text{String: intent.FinalPdfKey, Valid: true}
	expected.FinalPdfSha = intent.FinalPdfSha256
	expected.FinalPdfVersionID = intent.FinalPdfVersionID
	expected.AuditCertKey = pgtype.Text{String: intent.AuditCertKey, Valid: true}
	expected.AuditCertSha256 = intent.AuditCertSha256
	expected.AuditCertVersionID = intent.AuditCertVersionID
	expected.AuditPayloadKey = pgtype.Text{String: intent.AuditPayloadKey, Valid: true}
	expected.AuditPayloadSha256 = intent.AuditPayloadSha256
	expected.AuditPayloadVersionID = intent.AuditPayloadVersionID
	expected.AuditSignatureKey = pgtype.Text{String: intent.AuditSignatureKey, Valid: true}
	expected.AuditSignatureSha256 = intent.AuditSignatureSha256
	expected.AuditSignatureVersionID = intent.AuditSignatureVersionID
	return htmlSendDocumentExactTupleEqualV1(&expected, row)
}

// All prospective full RETURNING bodies are owned before the first UPDATE,
// using only this actual root/member source and private locked intent. No
// caller Document, legal tuple, model count or byte estimate is admitted.
func (w *ApplicationHTMLSendWorkV1) CompleteHistoricalPublicationV1(call context.Context) (*generated.Document, []*generated.Document, error) {
	if w == nil || w.self != w {
		return nil, nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationPublicationV1 || w.familyRoot != nil || !state.ready || !state.compatibilityChecked || !state.intentRead || state.intent == nil || !state.intent.RetentionStartedAt.Valid || !state.intent.RetentionCompletedAt.Valid || state.publication != nil || w.sourceDocument.Status != "finalizing" {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	intent, before, members := state.intent, w.sourceDocument, w.familyMembers
	if before.IsEnvelope && (!w.familyMembersAttempted || len(members) == 0 || len(state.memberViews) != len(members)) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	extra, err := historicalFinalizationIntentRawV1(intent)
	if err == nil {
		extra, err = htmlAuthoringSumV1(extra, int64(len("completed")))
	}
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	raw, _, err := w.admitDocumentReturnV1(call, extra)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	bookkeeping := 2*int64(unsafe.Sizeof(applicationHistoricalPublicationV1{})) + 2*int64(unsafe.Sizeof(generated.CompleteDocumentFinalizationParams{})) + 2*int64(unsafe.Sizeof(generated.CompleteEnvelopeChildrenParams{}))
	if !htmlInputAddV1(&bookkeeping, int64(len(members)+1), 2*int64(unsafe.Sizeof(audit.PendingEvent{}))+2*int64(unsafe.Sizeof((*ApplicationHTMLAuditEventConsumerV1)(nil)))) || !htmlInputAddV1(&bookkeeping, int64(len(members)), 8*int64(unsafe.Sizeof((*generated.Document)(nil)))+8*int64(unsafe.Sizeof(uuid.UUID{}))+8*int64(unsafe.Sizeof(int64(0)))) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	closeBookkeeping, err := w.actor.acquireOwnedRetainedBodyV1(call, bookkeeping, 0)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	w.closes = append(w.closes, closeBookkeeping)
	state.publication = &applicationHistoricalPublicationV1{completeAttempted: true}
	w.sourceBorrowers++
	w.mu.Unlock()
	borrowed := make([]bool, len(members))
	defer func() {
		for i, member := range members {
			if !borrowed[i] {
				continue
			}
			member.mu.Lock()
			member.sourceBorrowers--
			closes, actor := member.retireSourcesLockedV1()
			member.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			member.releaseFamilyRootIfRetiredV1()
		}
		w.mu.Lock()
		w.sourceBorrowers--
		closes, actor := w.retireSourcesLockedV1()
		w.mu.Unlock()
		htmlSendCloseSourceResourcesV1(closes, actor)
		w.releaseFamilyRootIfRetiredV1()
	}()
	raws := make([]int64, len(members))
	seen := make([]bool, len(members))
	for i, member := range members {
		member.mu.Lock()
		d := member.sourceDocument
		final := member.finalization
		if !member.valid(call) || member.familyRoot != w || d == nil || final == nil || !final.compatibilityChecked || d.Status != "finalizing" || d.OrgID != before.OrgID || d.IsEnvelope || !d.ParentEnvelopeID.Valid || uuid.UUID(d.ParentEnvelopeID.Bytes) != before.ID || d.DeletedAt.Valid || d.CompletionEffectiveAt != before.CompletionEffectiveAt || d.FinalizationRetainUntil != before.FinalizationRetainUntil || !d.CompletionEffectiveAtBound {
			member.mu.Unlock()
			return nil, nil, ErrHTMLSendWorkV1
		}
		member.sourceBorrowers++
		borrowed[i] = true
		raws[i], _, err = member.admitDocumentReturnV1(call, extra)
		member.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
	}
	row, err := w.queries.CompleteDocumentFinalization(call, generated.CompleteDocumentFinalizationParams{ID: before.ID, OrgID: before.OrgID, FinalPdfKey: pgtype.Text{String: intent.FinalPdfKey, Valid: true}, FinalPdfSha256: intent.FinalPdfSha256, FinalPdfVersionID: intent.FinalPdfVersionID, AuditCertKey: pgtype.Text{String: intent.AuditCertKey, Valid: true}, AuditCertSha256: intent.AuditCertSha256, AuditCertVersionID: intent.AuditCertVersionID, AuditPayloadKey: pgtype.Text{String: intent.AuditPayloadKey, Valid: true}, AuditPayloadSha256: intent.AuditPayloadSha256, AuditPayloadVersionID: intent.AuditPayloadVersionID, AuditSignatureKey: pgtype.Text{String: intent.AuditSignatureKey, Valid: true}, AuditSignatureSha256: intent.AuditSignatureSha256, AuditSignatureVersionID: intent.AuditSignatureVersionID})
	if err != nil {
		return nil, nil, err
	}
	if !w.verifyDocumentReturnV1(row, raw) || !historicalPublicationDocumentTupleV1(before, row, intent) {
		return nil, nil, ErrHTMLSendWorkV1
	}
	var children []*generated.Document
	if before.IsEnvelope {
		children, err = w.queries.CompleteEnvelopeChildren(call, generated.CompleteEnvelopeChildrenParams{ParentEnvelopeID: pgtype.UUID{Bytes: before.ID, Valid: true}, OrgID: before.OrgID, FinalPdfKey: row.FinalPdfKey, FinalPdfSha: row.FinalPdfSha, FinalPdfVersionID: row.FinalPdfVersionID, AuditCertKey: row.AuditCertKey, AuditCertSha256: row.AuditCertSha256, AuditCertVersionID: row.AuditCertVersionID, AuditPayloadKey: row.AuditPayloadKey, AuditPayloadSha256: row.AuditPayloadSha256, AuditPayloadVersionID: row.AuditPayloadVersionID, AuditSignatureKey: row.AuditSignatureKey, AuditSignatureSha256: row.AuditSignatureSha256, AuditSignatureVersionID: row.AuditSignatureVersionID})
		if err != nil {
			return nil, nil, err
		}
		if len(children) != len(members) {
			return nil, nil, ErrHTMLSendWorkV1
		}
		for _, child := range children {
			index := blockSendFamilyReturnedIndexV1(members, child)
			if index < 0 || seen[index] {
				return nil, nil, ErrHTMLSendWorkV1
			}
			seen[index] = true
			member := members[index]
			member.mu.Lock()
			valid := member.verifyDocumentReturnV1(child, raws[index]) && historicalPublicationDocumentTupleV1(member.sourceDocument, child, intent)
			member.mu.Unlock()
			if !valid {
				return nil, nil, ErrHTMLSendWorkV1
			}
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.finalization != state {
		return nil, nil, ErrHTMLSendWorkV1
	}
	state.publication.completed = htmlSendCloneDocumentV1(row)
	state.publication.children = make([]*generated.Document, len(children))
	for i, child := range children {
		state.publication.children[i] = htmlSendCloneDocumentV1(child)
	}
	return row, children, nil
}
func (w *ApplicationHTMLSendWorkV1) historicalPublicationV1(call context.Context) (*applicationHistoricalFinalizationV1, *applicationHistoricalPublicationV1, error) {
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		return nil, nil, err
	}
	if w.stage.purpose != HTMLHistoricalFinalizationPublicationV1 || w.familyRoot != nil || state.publication == nil || state.publication.completed == nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	return state, state.publication, nil
}
func (w *ApplicationHTMLSendWorkV1) CancelHistoricalCompletionReminderV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	if p.reminderCanceled {
		return ErrHTMLSendWorkV1
	}
	p.reminderCanceled = true
	return w.queries.CancelReminder(call, p.completed.ID)
}
func (w *ApplicationHTMLSendWorkV1) InvalidateHistoricalCompletionTokensV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	if !p.reminderCanceled || p.tokensInvalidated {
		return ErrHTMLSendWorkV1
	}
	p.tokensInvalidated = true
	return w.queries.InvalidateRecipientTokens(call, p.completed.ID)
}
func (w *ApplicationHTMLSendWorkV1) DeletePublishedHistoricalIntentV1(call context.Context) (int64, error) {
	if w == nil || w.self != w {
		return 0, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return 0, err
	}
	if !p.tokensInvalidated || p.deleted || len(p.payloads) != len(p.children)+1 {
		return 0, ErrHTMLSendWorkV1
	}
	for _, event := range p.payloads {
		if event.owner == nil {
			return 0, ErrHTMLSendWorkV1
		}
	}
	if err := w.retirePublishedOrdinaryBodiesLockedV1(call); err != nil {
		return 0, err
	}
	p.deleted = true
	return w.queries.DeleteDocumentFinalizationIntent(call, generated.DeleteDocumentFinalizationIntentParams{DocumentID: state.intent.DocumentID, OrgID: state.intent.OrgID})
}
