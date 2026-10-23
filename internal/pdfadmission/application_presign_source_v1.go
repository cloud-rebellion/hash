// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
)

// ValidatePreSignSourceV1 is solely the approved pre-sign policy point. The
// ordinary reviewed Send method and its human-review flag remain unchanged.
// Approved-data policy validates actual schema3 source without inventing a
// human review; EvaluateExecutionData and fresh locked commit remain mandatory.
func (h *ApplicationHTMLSendSourceV1) ValidatePreSignSourceV1(authority presignregistry.ExecutionAuthorityV1) error {
	if h == nil || h.state == nil || h.state.work == nil || h.state.work.stage == nil {
		return ErrHTMLSendWorkV1
	}
	purpose := h.state.work.stage.purpose
	if purpose != HTMLPreSignPreparationV1 && purpose != HTMLPreSignReadV1 && purpose != HTMLPreSignCommitV1 && purpose != HTMLPreSignReservationV1 {
		return ErrHTMLSendWorkV1
	}
	d := authority.Definition()
	p := authority.Policy()
	g := authority.Grant()
	if p.Snapshot().Operation != presign.OperationPreSignAndSend || d.PolicyID != p.Snapshot().ID || d.OrgID != h.state.work.session.state.org || g.Snapshot().Policy != p.Reference() {
		return ErrHTMLSendWorkV1
	}
	if d.Kind == presignregistry.KindReviewedDocument {
		return h.ValidateReviewedV1()
	}
	if d.Kind != presignregistry.KindApprovedData || p.Snapshot().Rules.InputMode != presign.InputApprovedData {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || s.owner.snapshot == nil || s.owner.snapshot.document == nil ||
		s.owner.snapshot.document.SenderID != g.Snapshot().Grantor.UserID {
		return ErrHTMLSendWorkV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if s.attempted {
		return s.failure
	}
	s.attempted = true
	s.failure = ErrHTMLSendWorkV1
	validation, err := s.prepareValidationV1()
	if err != nil {
		s.failure = err
		return err
	}
	s.failure = validation.ValidateV1(false)
	// Deliberately never set Work.reviewedOriginalValidated here. A caller
	// cannot reuse this explicit approved-data proof as a human-review receipt.
	return s.failure
}
