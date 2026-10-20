// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/blocks"
)

// This is the original signer frozenBlockDocument projection, without adding
// Send-only withdrawn-text or immutable-storage gates before their old points.
// Actual JSON and decimal work uses the private SAME-scope native source loan.
func (s *applicationHTMLSendSourceStateV1) blockSigningValuesV1() error {
	if s.work == nil || s.work.stage == nil || (s.work.stage.purpose != HTMLBlockSignPreparationV1 && s.work.stage.purpose != HTMLBlockSignMutationV1 && s.work.stage.purpose != HTMLHistoricalFinalizationClaimV1 && s.work.stage.purpose != HTMLHistoricalFinalizationResumeV1 && s.work.stage.purpose != HTMLHistoricalFinalizationPublicationV1 && s.work.stage.purpose != HTMLHistoricalFinalizationSourceV1) || s.owner == nil || s.owner.snapshot == nil || s.owner.snapshot.document.SourceKind != "blocks" {
		return ErrBlockSignatureRequestV1
	}
	if err := s.ensureBlockTreeV1(); err != nil {
		return fmt.Errorf("parse block tree: %w", err)
	}
	if s.blockValues != nil {
		return nil
	}
	was := s.blockProcessing
	s.blockProcessing = true
	defer func() { s.blockProcessing = was }()
	values, err := blocks.ValidateResolvedVariableValuesForSendV1(s.blockTree, s.owner.snapshot.document.VariablesJson, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		return fmt.Errorf("validate frozen variables: %w", err)
	}
	s.blockValues = values
	return nil
}
func (h *ApplicationHTMLSendSourceV1) SignatureFieldForSigningV1(role string) (string, error) {
	if h == nil || h.state == nil {
		return "", ErrBlockSignatureRequestV1
	}
	s := h.state
	if !s.lockV1() {
		return "", ErrBlockSignatureRequestV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return "", ErrBlockSignatureRequestV1
	}
	if err := s.owner.beginV1(); err != nil {
		return "", err
	}
	defer s.owner.finishV1()
	if err := s.blockSigningValuesV1(); err != nil {
		return "", err
	}
	s.blockProcessing = true
	defer func() { s.blockProcessing = false }()
	return blocks.SignatureFieldIDForVariablesForSigningV1(s.blockTree, role, s.blockValues, plainSendBlockDecimalAdmissionV1{source: s})
}
func (h *ApplicationHTMLSendSourceV1) BlockRolesForSigningV1() ([]string, error) {
	if h == nil || h.state == nil {
		return nil, ErrBlockSignatureRequestV1
	}
	s := h.state
	if !s.lockV1() {
		return nil, ErrBlockSignatureRequestV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil || s.blockRolesAttempted {
		return nil, ErrBlockSignatureRequestV1
	}
	if err := s.owner.beginV1(); err != nil {
		return nil, err
	}
	defer s.owner.finishV1()
	if err := s.blockSigningValuesV1(); err != nil {
		return nil, fmt.Errorf("resolve signer roles: %w", err)
	}
	s.blockRolesAttempted = true
	s.blockProcessing = true
	defer func() { s.blockProcessing = false }()
	roles, err := blocks.RequiredSignerRolesForVariablesForSendV1(s.blockTree, s.blockValues, plainSendBlockDecimalAdmissionV1{source: s})
	if err != nil {
		return nil, fmt.Errorf("resolve signer roles: project conditions: %w", err)
	}
	if len(roles) == 0 {
		return nil, errors.New("resolve signer roles: document contains no active signature fields")
	}
	s.blockRoles = roles
	return append([]string(nil), roles...), nil
}
