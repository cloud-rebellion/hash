//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// markHTMLReviewedHumanE2E reviews an HTML document the way the staff review
// path does: the exact-PDF review and the human reviewer-kind row. A bare
// MarkDocumentHTMLReviewed records no kind, which the signing-member gate
// (M124) refuses, so a fixture that intends a passing review must use this.
func markHTMLReviewedHumanE2E(t *testing.T, f lifecycleAuthorizationFixture, doc *generated.Document) *generated.Document {
	t.Helper()
	reviewed, err := f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, ExpectedPdfSha256: doc.PdfSha256, ReviewedBy: f.user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.InsertDocumentReviewKindV1(f.ctx, generated.InsertDocumentReviewKindV1Params{ID: uuid.New(), ReviewerKind: "human", DocumentID: doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return reviewed
}
