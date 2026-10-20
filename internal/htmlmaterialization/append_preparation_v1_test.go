// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaterialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Existing fixture() uses original CanonicalTemplate/New, with explicitly
// synthetic PDF pins. These tests prove the pre-write/source view and original
// Append behavior; no renderer, worker measurement, native grant or SQL proof.
func TestPrepareAppendValidationMatchesOriginalSourceAndHistoryPathV1(t *testing.T) {
	input, q := fixture(t)
	original := q.doc
	candidate := *original
	input.Values["customer"] = "Negotiated preparatory view"
	candidate.VariablesJson, _ = json.Marshal(input.Values)
	candidate.PdfStorageKey.String = "org/test/documents/prepared.pdf"
	candidate.PdfStorageVersionID.String = "prepared-version"
	raw, err := htmlsource.New(input, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	in := AppendInput{SourceJSON: raw, PageCount: 2, PreviousPageCount: 1, ActorID: uuid.New(), Summary: "Preserve original reviewed text"}
	originalBytes := bytes.Clone(original.HtmlSourceJson)
	candidateBytes := bytes.Clone(candidate.HtmlSourceJson)
	sourceBytes := bytes.Clone(raw)
	prepared, err := PrepareAppendValidationV1(original, &candidate, in)
	if err != nil {
		t.Fatal(err)
	}
	if q.writes != 0 || len(q.rows) != 0 || len(q.captures) != 0 {
		t.Fatal("pure preparation performed history effects")
	}
	// Independent expected view reproduces the original explicit source/current
	// assignment contract. The one temporary UUID is intentionally not asserted
	// equal to a later operation's generated UUID; it is not a database identity.
	expected := candidate
	expected.HtmlSourceJson = originalBytes
	expected.HtmlCurrentSourceJson = sourceBytes
	expected.HtmlCurrentMaterializationID = prepared.HtmlCurrentMaterializationID
	expected.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	expected.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 2, Valid: true}
	if !reflect.DeepEqual(prepared, &expected) || !prepared.HtmlCurrentMaterializationID.Valid || uuid.UUID(prepared.HtmlCurrentMaterializationID.Bytes) == uuid.Nil {
		t.Fatal("preparation dropped or replaced an original candidate projection value")
	}
	if !bytes.Equal(original.HtmlSourceJson, originalBytes) || !bytes.Equal(candidate.HtmlSourceJson, candidateBytes) || !bytes.Equal(raw, sourceBytes) {
		t.Fatal("pure preparation mutated original/candidate/source input")
	}
	commitment, err := htmlsource.Commitment(prepared)
	if err != nil {
		t.Fatal("unchanged original full source validator rejected prepared view", err)
	}
	updated, row, err := Append(context.Background(), q, original, &candidate, in)
	if err != nil {
		t.Fatal("original full Append oracle refused prepared candidate", err)
	}
	actual, err := htmlsource.Commitment(updated)
	if err != nil || actual != commitment {
		t.Fatal("prepared and final immutable source commitments differ", err)
	}
	if !bytes.Equal(updated.HtmlSourceJson, originalBytes) || row.Sequence != 2 || len(q.captures) != 1 || !bytes.Equal(q.captures[0].HtmlSourceJson, originalBytes) || !q.cleared {
		t.Fatal("original complete capture/clear/chain path changed")
	}
}

func TestPrepareAppendValidationPreservesOriginalEarlyRefusalsV1(t *testing.T) {
	for _, kind := range []string{"nil-previous", "nil-candidate", "actor", "page-zero", "page-over", "summary-utf8", "summary-NUL", "summary-runes", "state", "document", "org", "template", "report"} {
		t.Run(kind, func(t *testing.T) {
			_, q := fixture(t)
			previous := q.doc
			candidate := *previous
			candidatePtr := &candidate
			in := AppendInput{SourceJSON: []byte("not parsed by preparation"), PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New(), Summary: "original"}
			switch kind {
			case "nil-previous":
				previous = nil
			case "nil-candidate":
				candidatePtr = nil
			case "actor":
				in.ActorID = uuid.Nil
			case "page-zero":
				in.PageCount = 0
			case "page-over":
				in.PageCount = 501
			case "summary-utf8":
				in.Summary = string([]byte{0xff})
			case "summary-NUL":
				in.Summary = "original\x00text"
			case "summary-runes":
				in.Summary = strings.Repeat("é", 501)
			case "state":
				previous.Status = "sent"
			case "document":
				candidate.ID = uuid.New()
			case "org":
				candidate.OrgID = uuid.New()
			case "template":
				candidate.TemplateID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			case "report":
				in.MetadataRedactionReport = []byte("{")
			}
			prepared, err := PrepareAppendValidationV1(previous, candidatePtr, in)
			_, _, legacy := Append(context.Background(), q, previous, candidatePtr, in)
			if prepared != nil || !errors.Is(err, ErrInvalid) || !errors.Is(legacy, ErrInvalid) {
				t.Fatal("preparation changed original early refusal", err, legacy)
			}
			if q.writes != 0 || len(q.captures) != 0 || len(q.rows) != 0 {
				t.Fatal("refused preparation reached immutable history effects")
			}
		})
	}
}

func TestPrepareAppendValidationKeepsReportBindingAndFullCandidateChecksV1(t *testing.T) {
	for _, kind := range []string{"valid-report", "wrong-report-digest", "wrong-report-pages", "invalid-source"} {
		t.Run(kind, func(t *testing.T) {
			input, q := fixture(t)
			candidate := *q.doc
			input.Values["customer"] = "Fresh candidate"
			candidate.VariablesJson, _ = json.Marshal(input.Values)
			candidate.PdfStorageKey.String = "org/test/documents/new-report.pdf"
			candidate.PdfStorageVersionID.String = "fresh-report-version"
			raw, err := htmlsource.New(input, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			in := AppendInput{SourceJSON: raw, PageCount: 2, PreviousPageCount: 1, ActorID: uuid.New(), MetadataRedactionReport: observedEnvelope(t, candidate.PdfSha256, 2)}
			if kind == "wrong-report-digest" {
				in.MetadataRedactionReport = observedEnvelope(t, bytes.Repeat([]byte{0xff}, 32), 2)
			}
			if kind == "wrong-report-pages" {
				in.MetadataRedactionReport = observedEnvelope(t, candidate.PdfSha256, 3)
			}
			if kind == "invalid-source" {
				in.SourceJSON = []byte("{}")
			}
			prepared, err := PrepareAppendValidationV1(q.doc, &candidate, in)
			_, _, legacy := Append(context.Background(), q, q.doc, &candidate, in)
			switch kind {
			case "valid-report":
				if err != nil || prepared == nil || legacy != nil || q.writes == 0 {
					t.Fatal("actual report-bound source path changed", err, legacy)
				}
			case "invalid-source":
				// Preparation grants no source legality: the original full validator
				// remains a separate mandatory stage before any history write.
				if err != nil || prepared == nil || !errors.Is(legacy, htmlsource.ErrInvalid) || q.writes != 0 {
					t.Fatal("preparation was substituted for full source validation", err, legacy, q.writes)
				}
			default:
				if prepared != nil || !errors.Is(err, ErrInvalid) || !errors.Is(legacy, ErrInvalid) || q.writes != 0 {
					t.Fatal("measured report mismatch lost its pre-effect refusal", err, legacy)
				}
			}
		})
	}
}
func TestPrepareAppendValidationPreservesNormalizedSequenceAndNilQueriesV1(t *testing.T) {
	_, q := fixture(t)
	candidate := *q.doc
	q.doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 27, Valid: true}
	in := AppendInput{SourceJSON: []byte("{}"), PageCount: 3, ActorID: uuid.New()}
	prepared, err := PrepareAppendValidationV1(q.doc, &candidate, in)
	if err != nil || prepared.HtmlCurrentMaterializationSequence.Int32 != 28 || prepared.HtmlCurrentPageCount.Int32 != 3 {
		t.Fatal("original normalized candidate projection changed", err)
	}
	if _, _, err := Append(context.Background(), nil, q.doc, &candidate, in); !errors.Is(err, ErrInvalid) {
		t.Fatal("legacy nil query refusal changed", err)
	}
	// This synthetic sequence fixture is only projection arithmetic. It is not a
	// valid normalized row, cache receipt, SQL identity or signing admission.
}
