// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

// Original public policy errors are preserved; the private owner drives only
// the exact actual stored source and its fixed admitted block parser/evaluator.
func validateOwnedResolvedBlockVariablesV1(source *pdfadmission.ApplicationHTMLSendSourceV1) error {
	if source == nil {
		return pdfadmission.ErrHTMLSendWorkV1
	}
	if err := source.ValidateReviewedV1(); err != nil {
		return err
	}
	err := source.ValidateResolvedBlocksV1()
	switch {
	case errors.Is(err, pdfadmission.ErrPlainSendBlockTreeV1):
		return fmt.Errorf("%w: invalid block tree", ErrUnresolvedVariables)
	case errors.Is(err, pdfadmission.ErrPlainSendBlockLegalV1):
		return ErrUnsafeBuiltInLegalDraft
	case errors.Is(err, pdfadmission.ErrPlainSendBlockVariablesV1):
		return fmt.Errorf("%w: %v", ErrUnresolvedVariables, err)
	default:
		return err
	}
}
func requiredOwnedBlockRolesV1(source *pdfadmission.ApplicationHTMLSendSourceV1) ([]string, error) {
	if source == nil {
		return nil, pdfadmission.ErrHTMLSendWorkV1
	}
	roles, err := source.RequiredBlockRolesV1()
	if err == nil {
		return roles, nil
	}
	if errors.Is(err, pdfadmission.ErrPlainSendBlockEvidenceV1) {
		return nil, fmt.Errorf("send document: %w: %v", ErrUnsupportedBlockEvidence, err)
	}
	if errors.Is(err, pdfadmission.ErrPlainSendBlockVariablesV1) {
		return nil, fmt.Errorf("send document: signer roles: %w", err)
	}
	return nil, err
}
