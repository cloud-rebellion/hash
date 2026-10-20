// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

type ownedSendCompletionSnapshotV1 struct {
	operation *ownedSendOperationV1
	reference *pdfadmission.ApplicationHTMLSendCompletionReferenceV1
	pageCount int
}

// Every retention/inspection/field/source consumer has returned here. Native
// capture takes a separately admitted exact body comparison witness before
// clearing all outer model/source/evidence aliases and closing only Fields13.
func (s *ownedSealedSendSnapshotV1) completionSnapshotV1(o *ownedSendOperationV1) (*ownedSendCompletionSnapshotV1, error) {
	if s == nil || s.operation != o || s.work == nil || s.evidence == nil || s.sealedSendSnapshot == nil || s.alreadyCompleted != nil {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	reference, err := s.evidence.CaptureCompletionReferenceV1()
	if err != nil {
		return nil, err
	}
	out := &ownedSendCompletionSnapshotV1{operation: o, reference: reference, pageCount: s.pageCount}
	work := s.work
	s.sealedSendSnapshot = nil
	s.source = nil
	s.evidence = nil
	s.members = nil
	s.work = nil
	if err = o.retireSnapshotForCompletionV1(work, reference); err != nil {
		return nil, err
	}
	return out, nil
}
