// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"unicode/utf8"
)

// PrepareAppendValidationV1 performs only the original Append pre-write
// identity, plain-text summary and report checks, then builds the exact
// proposed current-source view for separate full htmlsource validation.
// It performs no SQL, source parse, Compile, work admission or mutation. The
// opaque temporary materialization UUID is only the original validation view;
// it is never an inserted row identity or authority to dispatch/replay.
//
// All inputs and the returned view must stay under the fixed native owner
// while consumed. Other than the two original cloned source JSON values, this
// deliberately preserves the original shallow view semantics. A subsequent
// immutable source validator captures its own complete detached document.
func PrepareAppendValidationV1(previous, candidate *generated.Document, in AppendInput) (*generated.Document, error) {
	if previous == nil || candidate == nil || in.ActorID == uuid.Nil || in.PageCount < 1 || in.PageCount > 500 ||
		!utf8.ValidString(in.Summary) || utf8.RuneCountInString(in.Summary) > 500 || bytes.IndexByte([]byte(in.Summary), 0) >= 0 ||
		previous.Status != "draft" || candidate.ID != previous.ID || candidate.OrgID != previous.OrgID || candidate.TemplateID != previous.TemplateID {
		return nil, ErrInvalid
	}
	if err := validateMaterializationReport(in.MetadataRedactionReport, candidate.PdfSha256, in.PageCount); err != nil {
		return nil, err
	}
	// Validate every proposed identity/input before writing history.
	check := *candidate
	check.HtmlSourceJson = bytes.Clone(previous.HtmlSourceJson)
	check.HtmlCurrentSourceJson = bytes.Clone(in.SourceJSON)
	check.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	check.HtmlCurrentPageCount = pgtype.Int4{Int32: in.PageCount, Valid: true}
	check.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	if previous.HtmlCurrentMaterializationSequence.Valid {
		check.HtmlCurrentMaterializationSequence.Int32 = previous.HtmlCurrentMaterializationSequence.Int32 + 1
	}
	return &check, nil
}
