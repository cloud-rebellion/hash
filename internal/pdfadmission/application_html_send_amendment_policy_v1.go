// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

// FreezePresentedAmendmentPolicyV1 consumes only the same native admitted,
// reviewed source used by ordinary Send. The insert shares its original SQL
// completion transaction and rolls back with its sent/outbox transition. Caller models, flags,
// costs and quoted policy bodies are deliberately absent from the interface.
func (w *ApplicationHTMLSendWorkV1) FreezePresentedAmendmentPolicyV1(call context.Context, h *ApplicationHTMLSendSourceV1) error {
	if w == nil || w.self != w || h == nil || h.state == nil || h.state.work != w || h.state.candidate {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || !s.attempted || s.failure != nil || !s.currentAttempted || s.currentFailure != nil || s.owner == nil {
		return ErrHTMLSendWorkV1
	}
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLSendCompletionV1 || w.sourceOwner != owner || w.sourceDocument == nil {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	doc := w.sourceDocument
	w.mu.Unlock()
	owner.mu.Lock()
	v := owner.validation
	owner.mu.Unlock()
	if v == nil {
		return ErrHTMLSendWorkV1
	}
	if !v.HasAmendmentPolicyV1() {
		return nil
	}
	w.mu.Lock()
	if !w.valid(call) || w.sourceIntent == nil || !w.sourceIntent.RetentionCompletedAt.Valid || !w.sourceIntent.ActorUserID.Valid || doc.Status != "sealing" || doc.IsEnvelope || doc.ParentEnvelopeID.Valid {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	actor := uuid.UUID(w.sourceIntent.ActorUserID.Bytes)
	w.mu.Unlock()
	user, err := w.ReadActorV1(call, actor)
	if err != nil {
		return err
	}
	if user == nil || user.ID != actor || user.OrgID != doc.OrgID || (user.Role != "owner" && user.Role != "sender") {
		return ErrHTMLSendWorkV1
	}
	if err := s.holdPolicyV1(); err != nil {
		return err
	}
	// Maximum escaped clause/reference/condition JSON, old+current marshal
	// buffers, returned body, hash scratch, bounded typed projection and SQL
	// arguments remain held through the original SQL/consumer retirement.
	const maxText = htmlmaster.MaxAmendmentClauseBytesV1 + htmlmaster.MaxAmendmentReferenceBytesV1 + htmlmaster.MaxAmendmentConditionBytesV1
	const projectionBytes = 4 * (6*maxText + 4096)
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, projectionBytes, 16384)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.mu.Lock()
	w.closes = append(w.closes, closeBody)
	w.mu.Unlock()
	presented, err := v.PresentedAmendmentPolicyV1()
	if err != nil {
		return err
	}
	if presented == nil {
		return ErrHTMLSendWorkV1
	}
	commitment, err := v.CommitmentV1()
	if err != nil {
		return err
	}
	sourceSHA, err := hex.DecodeString(commitment)
	if err != nil || len(sourceSHA) != 32 {
		return ErrHTMLSendWorkV1
	}
	if len(doc.PdfSha256) != 32 || !doc.PdfStorageVersionID.Valid || doc.PdfStorageVersionID.String == "" || actor == uuid.Nil {
		return ErrHTMLSendWorkV1
	}
	id := uuid.New()
	basis := amendments.BasisV1{Kind: "frozen_agreement_policy", FrozenPolicyID: &id, ClauseReference: presented.ClauseReference, ReviewedClause: presented.ReviewedClause, AllowedChannels: presented.AllowedChannels, EffectiveCondition: presented.EffectiveCondition}
	for _, m := range presented.AllowedModes {
		basis.AllowedModes = append(basis.AllowedModes, amendments.ModeV1(m))
	}
	raw, err := json.Marshal(basis)
	if err != nil || len(raw) > 16384 {
		return ErrHTMLSendWorkV1
	}
	digest, err := amendments.DigestV1("hash:later-amendment-basis:v1", basis)
	if err != nil {
		return err
	}
	basisSHA, err := hex.DecodeString(digest)
	if err != nil || len(basisSHA) != 32 {
		return ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	tag, err := db.Exec(call, `INSERT INTO document_amendment_policies_v1(id,org_id,document_id,basis,basis_sha256,presented_source_sha256,presented_pdf_sha256,presented_pdf_version_id,frozen_at,frozen_by)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, id, doc.OrgID, doc.ID, raw, basisSHA, sourceSHA, doc.PdfSha256, doc.PdfStorageVersionID.String, time.Now().UTC(), actor)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrHTMLSendWorkV1
	}
	return call.Err()
}
