// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestBlockMutationPublicDomainRefusalsPreserveCauseV1(t *testing.T) {
	for _, safe := range []error{auth.ErrMutationCredentialExpired, auth.ErrMutationPermissionRevoked,
		authoring.ErrDocumentNotFound, authoring.ErrDocumentNotDraft, authoring.ErrDocumentHasEvidence,
		authoring.ErrPrivacyReviewChanging, authoring.ErrPendingPrivacyReview} {
		original := fmt.Errorf("lock draft parent: %w", safe)
		public := canonicalBlockMutationErrorV1(original)
		if public.Error() != safe.Error() || !errors.Is(public, original) || !errors.Is(public, safe) || sanitizeToolError(public) != safe.Error() {
			t.Fatal("native context changed public domain contract or discarded its cause", safe)
		}
	}
	if canonicalBlockMutationErrorV1(nil) != nil {
		t.Fatal("success acquired an error")
	}
}

func TestBlockMutationPublicRefusalCannotConcealSQLOrUncertaintyV1(t *testing.T) {
	server := &pgconn.PgError{Code: "P0001", Message: "synthetic private SQL detail"}
	joined := errors.Join(authoring.ErrDocumentNotDraft, server)
	public := canonicalBlockMutationErrorV1(joined)
	var retained *pgconn.PgError
	if !errors.As(public, &retained) || retained != server || sanitizeToolError(public) != "internal error" {
		t.Fatal("public refusal concealed or exposed joined database failure")
	}
	for _, unknown := range []error{context.Canceled, context.DeadlineExceeded, pdfadmission.ErrApplicationSessionV1, pdfadmission.ErrApplicationSessionUnknownV1, pdfadmission.ErrApplicationSessionCommitUnknownV1, pdfadmission.ErrHTMLRevisionReadV1} {
		original := errors.Join(authoring.ErrDocumentNotDraft, unknown)
		if canonicalBlockMutationErrorV1(original) != original {
			t.Fatal("uncertain outcome became a canonical domain refusal", unknown)
		}
	}
	other := errors.New("unrecognized original validation message")
	if canonicalBlockMutationErrorV1(other) != other {
		t.Fatal("unrecognized error changed")
	}
}
