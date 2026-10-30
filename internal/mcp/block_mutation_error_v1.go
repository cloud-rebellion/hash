// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

type blockMutationPublicErrorV1 struct {
	cause   error
	message string
}

func (e *blockMutationPublicErrorV1) Error() string { return e.message }
func (e *blockMutationPublicErrorV1) Unwrap() error { return e.cause }

// Native lock context is useful internally; the original typed domain refusal
// remains the public MCP contract. Preserve causes so the existing sanitizer
// still detects joined SQL/driver errors rather than exposing their messages.
func canonicalBlockMutationErrorV1(err error) error {
	if err == nil {
		return nil
	}
	for _, unavailable := range []error{context.Canceled, context.DeadlineExceeded,
		pdfadmission.ErrApplicationSessionV1, pdfadmission.ErrApplicationSessionUnknownV1,
		pdfadmission.ErrApplicationSessionCommitUnknownV1, pdfadmission.ErrApplicationAdmissionV1,
		pdfadmission.ErrHTMLRevisionReadV1, pdfadmission.ErrBlocksWriterV1} {
		if errors.Is(err, unavailable) {
			return err
		}
	}
	for _, safe := range []error{auth.ErrMutationCredentialExpired, auth.ErrMutationPermissionRevoked,
		authoring.ErrDocumentNotFound, authoring.ErrDocumentNotDraft, authoring.ErrDocumentHasEvidence,
		authoring.ErrPrivacyReviewChanging, authoring.ErrPendingPrivacyReview} {
		if errors.Is(err, safe) {
			return &blockMutationPublicErrorV1{cause: err, message: safe.Error()}
		}
	}
	return err
}
