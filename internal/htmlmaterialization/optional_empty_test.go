// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
)

// Synthetic source/report fixtures exercise append ordering and exact pins.
// They do not prove renderer measurements or actual database field recreation.
func emptyAdditionFixture(t *testing.T, schema int) (htmlsource.Input, *memoryQueries) {
	t.Helper()
	input, q := fixture(t)
	if schema > 1 {
		var doc *generated.Document
		input, doc, _ = testfixture.HTMLContract(t)
		if schema == 3 {
			input, doc, _ = testfixture.BrandedHTMLContract(t)
		}
		q = &memoryQueries{doc: doc, rows: map[uuid.UUID]*generated.HtmlDocumentMaterialization{}}
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.Values = append(master.Values, htmlmaster.Value{Name: "optional_note", MaxChars: 100})
	master.HTML += `<p><span data-hash-value="optional_note"></span></p>`
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	input.MasterJSON, input.DefaultVarsJSON, input.TemplateContentSHA256 = canonical.MasterJSON, canonical.DefaultsJSON, canonical.SHA256
	if input.SigningArtifact != nil {
		compiled, err := htmlmaster.Compile(master)
		if err != nil {
			t.Fatal(err)
		}
		input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, input.SigningArtifact.Composition)
		if err != nil {
			t.Fatal(err)
		}
	}
	q.doc.HtmlSourceJson, err = htmlsource.New(input, q.doc)
	if err != nil {
		t.Fatal(err)
	}
	input, err = htmlsource.InputForCurrent(q.doc)
	if err != nil {
		t.Fatal(err)
	}
	return input, q
}

type orderedEmptyAdditionQueries struct {
	*memoryQueries
	order []string
}

func (q *orderedEmptyAdditionQueries) InsertHTMLDocumentMaterialization(ctx context.Context, p generated.InsertHTMLDocumentMaterializationParams) (*generated.HtmlDocumentMaterialization, error) {
	q.order = append(q.order, "insert")
	return q.memoryQueries.InsertHTMLDocumentMaterialization(ctx, p)
}
func (q *orderedEmptyAdditionQueries) ProjectHTMLDocumentMaterialization(ctx context.Context, p generated.ProjectHTMLDocumentMaterializationParams) (*generated.Document, error) {
	q.order = append(q.order, "project")
	return q.memoryQueries.ProjectHTMLDocumentMaterialization(ctx, p)
}
func (q *orderedEmptyAdditionQueries) CaptureHTMLMaterializationSnapshot(ctx context.Context, p generated.CaptureHTMLMaterializationSnapshotParams) (*generated.HtmlDocumentMaterializationSnapshot, error) {
	q.order = append(q.order, "capture")
	return q.memoryQueries.CaptureHTMLMaterializationSnapshot(ctx, p)
}
func (q *orderedEmptyAdditionQueries) ClearUnsignedHTMLMaterializationFields(ctx context.Context, p generated.ClearUnsignedHTMLMaterializationFieldsParams) (int64, error) {
	q.order = append(q.order, "clear")
	return q.memoryQueries.ClearUnsignedHTMLMaterializationFields(ctx, p)
}

func TestHTMLMaterializationOptionalEmptyRunsCompleteRevisionPipeline(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		for _, registered := range []bool{false, true} {
			t.Run(fmt.Sprintf("schema%d/registered%t", schema, registered), func(t *testing.T) {
				input, memory := emptyAdditionFixture(t, schema)
				q := &orderedEmptyAdditionQueries{memoryQueries: memory}
				pages := int32(1)
				if schema == 3 {
					pages = 2
				}
				original := bytes.Clone(q.doc.HtmlSourceJson)
				if registered {
					if _, _, err := RegisterOrigin(context.Background(), q, q.doc, pages, uuid.New()); err != nil {
						t.Fatal(err)
					}
				}
				q.order, q.writes = nil, 0
				previous := q.doc
				beforeCommitment, err := htmlsource.Commitment(previous)
				if err != nil {
					t.Fatal(err)
				}
				beforeDigest, err := htmlsource.MaterializationDigest(previous)
				if err != nil {
					t.Fatal(err)
				}
				candidate := *previous
				input.Values["optional_note"] = ""
				candidate.VariablesJson, _ = json.Marshal(input.Values)
				candidate.PdfStorageKey.String = "org/test/documents/explicit-empty.pdf"
				candidate.PdfStorageVersionID.String = "fresh-explicit-empty-version"
				// Identical final PDF bytes are legitimate: raw input presence is
				// distinct provenance even though the rendered text is unchanged.
				if input.SigningArtifact != nil {
					master, err := htmlmaster.Decode(input.MasterJSON)
					if err != nil {
						t.Fatal(err)
					}
					compiled, err := htmlmaster.Compile(master)
					if err != nil {
						t.Fatal(err)
					}
					composition := input.SigningArtifact.Composition
					composition.BodySHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
					input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, composition)
					if err != nil {
						t.Fatal(err)
					}
				}
				raw, err := htmlsource.New(input, &candidate)
				if err != nil {
					t.Fatal(err)
				}
				freshReport := observedEnvelope(t, candidate.PdfSha256, int(pages))
				updated, row, err := Append(context.Background(), q, previous, &candidate, AppendInput{SourceJSON: raw, PageCount: pages, PreviousPageCount: pages, ActorID: uuid.New(), Summary: "Explicitly reviewed optional empty input", MetadataRedactionReport: freshReport})
				if err != nil {
					t.Fatal(err)
				}
				wantOrder := []string{"capture", "insert", "clear", "project"}
				if !registered {
					wantOrder = append([]string{"insert", "project"}, wantOrder...)
				}
				if !slices.Equal(q.order, wantOrder) || !q.cleared || len(q.captures) != 1 || !q.captures[0].HtmlReviewedBy.Valid {
					t.Fatalf("complete history/review/layout pipeline not retained: %v", q.order)
				}
				if row.Sequence != 2 || !bytes.Equal(updated.HtmlSourceJson, original) || !bytes.Equal(updated.PdfSha256, previous.PdfSha256) ||
					updated.PdfStorageVersionID.String != candidate.PdfStorageVersionID.String || !bytes.Equal(updated.MetadataRedactionReport, freshReport) {
					t.Fatal("exact origin/fresh artifact/report projection lost")
				}
				afterDigest, err := htmlsource.MaterializationDigest(updated)
				if err != nil || afterDigest != beforeDigest {
					t.Fatal("empty presence unexpectedly changed rendered content", err)
				}
				afterCommitment, err := htmlsource.Commitment(updated)
				if err != nil || beforeCommitment == afterCommitment {
					t.Fatal("new source presence lost", err)
				}
				if !errors.Is(htmlsource.Validate(updated, true), htmlsource.ErrReviewRequired) {
					t.Fatal("old same-SHA review survived revision")
				}
				var originRow *generated.HtmlDocumentMaterialization
				for _, old := range q.rows {
					if old.Sequence == 1 {
						originRow = old
					}
				}
				historical, err := HistoricalDocument(updated, originRow)
				if err != nil || !bytes.Equal(historical.VariablesJson, previous.VariablesJson) {
					t.Fatal("omitted historical value was rewritten", err)
				}
				fresh, err := htmlsource.InputForCurrent(updated)
				if err != nil {
					t.Fatal(err)
				}
				if value, present := fresh.Values["optional_note"]; !present || value != "" {
					t.Fatal("explicit empty was lost")
				}
				if schema > 1 && !slices.Equal(fresh.PartyBindings, input.PartyBindings) {
					t.Fatal("party IDs changed")
				}
				q.writes = 0
				if _, _, err := Append(context.Background(), q, updated, updated, AppendInput{SourceJSON: raw, PageCount: pages, ActorID: uuid.New(), MetadataRedactionReport: freshReport}); err == nil || q.writes != 0 {
					t.Fatal("repeated empty materialization bypassed no-op guard")
				}
			})
		}
	}
}

func TestHTMLMaterializationEqualContentRejectsOtherPresenceChangesBeforeWrites(t *testing.T) {
	for _, kind := range []string{"no_op", "same_effective_section", "drop_present_empty", "mixed_add_drop"} {
		t.Run(kind, func(t *testing.T) {
			input, q := emptyAdditionFixture(t, 1)
			if kind == "drop_present_empty" || kind == "mixed_add_drop" {
				input.Values["optional_note"] = ""
				q.doc.VariablesJson, _ = json.Marshal(input.Values)
				if kind == "mixed_add_drop" {
					master, _ := htmlmaster.Decode(input.MasterJSON)
					master.Values = append(master.Values, htmlmaster.Value{Name: "another", MaxChars: 100})
					master.HTML += `<p><span data-hash-value="another"></span></p>`
					raw, _ := json.Marshal(master)
					canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
					if err != nil {
						t.Fatal(err)
					}
					input.MasterJSON, input.DefaultVarsJSON, input.TemplateContentSHA256 = canonical.MasterJSON, canonical.DefaultsJSON, canonical.SHA256
				}
				var err error
				q.doc.HtmlSourceJson, err = htmlsource.New(input, q.doc)
				if err != nil {
					t.Fatal(err)
				}
				delete(input.Values, "optional_note")
				if kind == "mixed_add_drop" {
					input.Values["another"] = ""
				}
			}
			if kind == "same_effective_section" {
				input.Values["optional_note"] = ""
				input.Sections["scope"] = "Original prose"
			}
			candidate := *q.doc
			candidate.PdfStorageKey.String = "org/test/documents/equal-content-candidate.pdf"
			candidate.PdfStorageVersionID.String = "fresh-equal-content-version"
			candidate.VariablesJson, _ = json.Marshal(input.Values)
			raw, err := htmlsource.New(input, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := Append(context.Background(), q, q.doc, &candidate, AppendInput{SourceJSON: raw, PageCount: 1, PreviousPageCount: 1, ActorID: uuid.New()}); err == nil || q.writes != 0 {
				t.Fatalf("nonqualifying equal-content rewrite accepted: %v writes=%d", err, q.writes)
			}
		})
	}
}

func TestHTMLMaterializationOptionalEmptyStillValidatesArtifactReportAndHistory(t *testing.T) {
	for _, kind := range []string{"null_value", "changed_party", "bad_artifact", "missing_artifact", "unbound_report", "corrupt_history", "reused_artifact"} {
		t.Run(kind, func(t *testing.T) {
			input, q := emptyAdditionFixture(t, 3)
			previous, _, err := RegisterOrigin(context.Background(), q, q.doc, 2, uuid.New())
			if err != nil {
				t.Fatal(err)
			}
			candidate := *previous
			if kind != "reused_artifact" {
				candidate.PdfStorageKey.String = "org/test/documents/fresh-empty.pdf"
				candidate.PdfStorageVersionID.String = "fresh-empty-version"
			}
			input.Values["optional_note"] = ""
			candidate.VariablesJson, _ = json.Marshal(input.Values)
			if kind == "changed_party" {
				input.PartyBindings[0].RecipientID = uuid.New()
			}
			if kind == "changed_party" {
				master, _ := htmlmaster.Decode(input.MasterJSON)
				compiled, err := htmlmaster.Compile(master)
				if err != nil {
					t.Fatal(err)
				}
				input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, input.SigningArtifact.Composition)
				if err != nil {
					t.Fatal(err)
				}
			}
			raw, err := htmlsource.New(input, &candidate)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "null_value" {
				raw = bytes.Replace(raw, []byte(`"optional_note":""`), []byte(`"optional_note":null`), 1)
			}
			if kind == "bad_artifact" {
				raw = bytes.Replace(raw, []byte(`"x":100000`), []byte(`"x":100001`), 1)
			}
			if kind == "missing_artifact" {
				var fields map[string]json.RawMessage
				if err := json.Unmarshal(raw, &fields); err != nil {
					t.Fatal(err)
				}
				delete(fields, "signing_artifact")
				raw, err = json.Marshal(fields)
				if err != nil {
					t.Fatal(err)
				}
			}
			report := observedEnvelope(t, candidate.PdfSha256, 2)
			if kind == "unbound_report" {
				report = observedEnvelope(t, bytes.Repeat([]byte{0xff}, 32), 2)
			}
			if kind == "corrupt_history" {
				q.corrupt = true
			}
			q.writes = 0
			if _, _, err := Append(context.Background(), q, previous, &candidate, AppendInput{SourceJSON: raw, PageCount: 2, ActorID: uuid.New(), MetadataRedactionReport: report}); err == nil || q.writes != 0 {
				t.Fatalf("empty addition bypassed validation: %v writes=%d", err, q.writes)
			}
		})
	}
}
