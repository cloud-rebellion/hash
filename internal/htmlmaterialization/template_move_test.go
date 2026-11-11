// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// A newer approved version may carry byte-identical content. The digest is then
// unchanged, but the version, approval and fresh PDF intake are a real revision.
func TestAppendAcceptsForwardTemplateVersionWithIdenticalDigestAndResetsReview(t *testing.T) {
	in, q := fixture(t)
	old := q.doc
	candidate := *old
	in.TemplateVersion++
	in.TemplateApprovedBy, in.TemplateApprovedAt = uuid.New(), time.Now().Add(-time.Minute)
	candidate.VariablesJson, _ = json.Marshal(in.Values)
	candidate.PdfStorageKey.String = "org/test/documents/moved.pdf"
	candidate.PdfStorageVersionID.String = "version-moved"
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	updated, row, err := Append(context.Background(), q, old, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New(), Summary: "Moved to newer approved design"})
	if err != nil {
		t.Fatalf("forward move with identical digests refused: %v", err)
	}
	if row.Sequence != 2 || !q.cleared || len(q.captures) != 1 || !q.captures[0].HtmlReviewedBy.Valid {
		t.Fatal("history, field reset or archived review lost")
	}
	if !bytes.Equal(updated.HtmlSourceJson, old.HtmlSourceJson) || !errors.Is(htmlsource.Validate(updated, true), htmlsource.ErrReviewRequired) {
		t.Fatal("origin changed or old review inherited")
	}
}

func TestAppendStillRefusesIdenticalDigestsWithoutVersionChange(t *testing.T) {
	in, q := fixture(t)
	old := q.doc
	candidate := *old
	candidate.PdfStorageKey.String = "org/test/documents/same.pdf"
	candidate.PdfStorageVersionID.String = "version-same"
	raw, err := htmlsource.New(in, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = Append(context.Background(), q, old, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New(), Summary: "no-op"}); err == nil {
		t.Fatal("no-op revision accepted")
	}
	if q.writes != 0 {
		t.Fatal("refusal wrote history")
	}
}
