// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlsource"
)

func TestHTMLRevisionOwnedAppendPreservesOptionalEmptyAdditionV1(t *testing.T) {
	withHTMLRevisionConstructedWriterVariantV1(t, 1, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		if f.writer == nil || !f.writer.appended || !f.writer.fieldsWritten || f.writer.row == nil || f.writer.row.Sequence != 2 {
			t.Fatal("actual native writer did not append optional addition")
		}
		before, err := htmlsource.MaterializationDigest(f.document)
		if err != nil {
			t.Fatal(err)
		}
		after, err := htmlsource.MaterializationDigest(f.writer.updated)
		if err != nil || before != after {
			t.Fatal("fixture did not preserve actual same-content optional branch", err)
		}
		allowed, err := htmlsource.IsOptionalEmptyAddition(f.document, f.candidate.state.input)
		if err != nil || !allowed {
			t.Fatal("unchanged original optional-addition oracle disagreed", err)
		}
		if f.writer.updated.PdfStorageKey.String == f.document.PdfStorageKey.String || f.writer.updated.PdfStorageVersionID.String == f.document.PdfStorageVersionID.String {
			t.Fatal("optional addition reused original PDF tuple")
		}
		if f.writer.updated.HtmlEffectiveSourceCommitment.String == f.document.HtmlEffectiveSourceCommitment.String {
			t.Fatal("explicit optional value did not bind a distinct fresh source")
		}
		if f.writer.updated.HtmlReviewedBy.Valid || f.writer.updated.HtmlReviewedAt.Valid || len(f.writer.updated.HtmlReviewedPdfSha256) != 0 {
			t.Fatal("fresh revision retained old review")
		}
	})
}
func TestHTMLRevisionOwnedUnchangedInputRefusesBeforeCandidateOrWriteV1(t *testing.T) {
	withHTMLRevisionConstructedWriterVariantV1(t, 2, func(call context.Context, f *htmlRevisionWriterFixtureV1) {
		if f.writer != nil || f.candidate != nil || f.source == nil || f.source.state.prepared != nil || f.source.state.candidateAttempted {
			t.Fatal("unchanged declaration reached candidate or mutation")
		}
		if f.tx.calls != 8 || len(f.tx.rows) != 0 {
			t.Fatal("unchanged declaration dispatched beyond genuine bounded read/collection", f.tx.calls)
		}
		if f.coordinator.SnapshotV1(f.document.OrgID).Global.ParentBytes == 0 {
			t.Fatal("semantic refusal credited original unretired source/body")
		}
	})
}
