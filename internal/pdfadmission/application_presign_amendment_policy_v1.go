// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/google/uuid"
)

// Only the fixed publication producer calls this with its internally loaded
// retained relation before token/invite/completion effects. It freezes the
// actual visible source clause; approved data is never labelled human review.
func (w *ApplicationHTMLSendWorkV1) freezePreSignAmendmentPolicyV1(call context.Context, r presignexecute.RetainedAssetsV1) error {
	x := r.Execution().Snapshot()
	w.mu.Lock()
	if !w.valid(call) || w.stage.purpose != HTMLPreSignPublicationV1 || w.sourceDocument == nil || w.sourceDocument.Status != "sealing" ||
		w.sourceIntent == nil || !w.sourceIntent.PresignExecutionID.Valid || uuid.UUID(w.sourceIntent.PresignExecutionID.Bytes) != x.ID ||
		!w.sourceIntent.RetentionCompletedAt.Valid || r.Publication().RetentionCompletedAt.IsZero() || x.Document.ID != w.logicalDocumentV1() {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	doc := w.sourceDocument
	w.mu.Unlock()
	source, err := w.NewSourceV1(call)
	if err != nil {
		return err
	}
	s := source.state
	if s == nil || !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.owner == nil || s.closeRequested.Load() {
		return ErrHTMLSendWorkV1
	}
	owner := s.owner
	if err = owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	v, err := s.prepareValidationV1()
	if err != nil {
		return err
	}
	if err = v.ValidateV1(false); err != nil {
		return err
	}
	if !v.HasAmendmentPolicyV1() {
		return nil
	}
	if err = s.holdPolicyV1(); err != nil {
		return err
	}
	const maxText = htmlmaster.MaxAmendmentClauseBytesV1 + htmlmaster.MaxAmendmentReferenceBytesV1 + htmlmaster.MaxAmendmentConditionBytesV1
	const projectionBytes = 4 * (6*maxText + 4096)
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, projectionBytes, 16384)
	if err != nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.mu.Lock()
	w.closes = append(w.closes, closeBody)
	w.mu.Unlock()
	var presented *htmlmaster.PresentedAmendmentPolicyV1
	if r.Policy().Snapshot().Rules.InputMode == presign.InputApprovedData {
		presented, err = v.PresentedApprovedDataAmendmentPolicyV1()
	} else {
		presented, err = v.PresentedAmendmentPolicyV1()
	}
	if err != nil || presented == nil {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	commitment, err := v.CommitmentV1()
	if err != nil || commitment != x.Document.Materialization.SourceCommitment {
		return ErrHTMLSendWorkV1
	}
	sourceSHA, err := hex.DecodeString(commitment)
	if err != nil || len(sourceSHA) != 32 {
		return ErrHTMLSendWorkV1
	}
	id := uuid.New()
	basis := amendments.BasisV1{Kind: "frozen_agreement_policy", FrozenPolicyID: &id, ClauseReference: presented.ClauseReference, ReviewedClause: presented.ReviewedClause, AllowedChannels: presented.AllowedChannels, EffectiveCondition: presented.EffectiveCondition}
	for _, mode := range presented.AllowedModes {
		basis.AllowedModes = append(basis.AllowedModes, amendments.ModeV1(mode))
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
  VALUES($1,$2,$3,$4,$5,$6,$7,$8,clock_timestamp(),$9)`, id, doc.OrgID, doc.ID, raw, basisSHA, sourceSHA, doc.PdfSha256, doc.PdfStorageVersionID.String, x.Executor.UserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrHTMLSendWorkV1
	}
	return call.Err()
}
