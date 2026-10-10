// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlsource

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

func sourceFixture(t *testing.T) (Input, *generated.Document) {
	t.Helper()
	master, err := json.Marshal(htmlmaster.Master{
		SchemaVersion: 1, HTML: `<p>Customer: <span data-hash-value="customer_name"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer_name", Required: true, MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Deliver the approved service", MaxChars: 500}},
	})
	if err != nil {
		t.Fatal(err)
	}
	commitment, err := htmlmaster.CanonicalTemplate(master, []byte(`{"customer_name":"Default AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	input := Input{TemplateID: uuid.New(), TemplateVersion: 7, TemplateContentSHA256: commitment.SHA256,
		MasterJSON: commitment.MasterJSON, DefaultVarsJSON: commitment.DefaultsJSON,
		Values: map[string]string{"customer_name": "Recipient AB"}, Sections: map[string]string{},
		TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Date(2026, 10, 10, 8, 0, 0, 0, time.UTC),
	}
	sum := sha256.Sum256([]byte("synthetic already-rendered PDF fixture; not renderer acceptance"))
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SourceKind: "pdf", Status: "draft",
		TemplateID: pgtype.UUID{Bytes: input.TemplateID, Valid: true}, VariablesJson: []byte(`{"customer_name":"Recipient AB"}`),
		PdfStorageKey: pgtype.Text{String: "org/example/documents/source.pdf", Valid: true}, PdfSha256: sum[:],
		PdfStorageVersionID: pgtype.Text{String: "opaque-version-1", Valid: true}, EvidenceVersionPinsRequired: true,
	}
	return input, doc
}

func attachSource(t *testing.T, input Input, doc *generated.Document) {
	t.Helper()
	raw, err := New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = raw
}

func approveFixture(doc *generated.Document, input Input) {
	doc.HtmlReviewedPdfSha256 = bytes.Clone(doc.PdfSha256)
	doc.HtmlReviewedBy = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlReviewedAt = pgtype.Timestamptz{Time: input.TemplateApprovedAt.Add(time.Hour), Valid: true}
}

func TestHTMLSourcePreservesInputsAndRequiresExactHumanPDFReview(t *testing.T) {
	input, doc := sourceFixture(t)
	input.Sections["scope"] = "Human negotiated text with <literal markup>"
	attachSource(t, input, doc)
	if err := Validate(doc, false); err != nil {
		t.Fatal(err)
	}
	if err := Validate(doc, true); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("unreviewed send = %v", err)
	}
	approveFixture(doc, input)
	if err := Validate(doc, true); err != nil {
		t.Fatal(err)
	}
	var preserved source
	if err := decodeSource(doc.HtmlSourceJson, &preserved); err != nil {
		t.Fatal(err)
	}
	if preserved.TemplateVersion != 7 || preserved.Values["customer_name"] != "Recipient AB" || preserved.Sections["scope"] != input.Sections["scope"] {
		t.Fatal("lost approved template/input identity")
	}
	_, result, err := materialize(preserved)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChangedSections) != 1 || result.ChangedSections[0] != "scope" || !bytes.Contains([]byte(result.HTML), []byte("&lt;literal markup&gt;")) {
		t.Fatalf("editable text was not preserved inertly: %v", result.ChangedSections)
	}
	// Database JSONB transport formatting/order must not change commitments.
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, doc.HtmlSourceJson, "", "  "); err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = pretty.Bytes()
	if err := Validate(doc, true); err != nil {
		t.Fatalf("formatted JSON = %v", err)
	}
	input.Values["customer_name"] = "later caller mutation"
	if err := Validate(doc, true); err != nil {
		t.Fatalf("constructor retained mutable input aliases: %v", err)
	}
}

func TestHTMLSourceNewRefusesIncompleteOrMismatchedAuthority(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Input, *generated.Document)
	}{
		{"missing template", func(i *Input, d *generated.Document) { i.TemplateID = uuid.Nil }},
		{"template differs", func(i *Input, d *generated.Document) { d.TemplateID.Bytes = uuid.New() }},
		{"missing version", func(i *Input, d *generated.Document) { i.TemplateVersion = 0 }},
		{"wrong approval digest", func(i *Input, d *generated.Document) {
			i.TemplateContentSHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
		}},
		{"missing approver", func(i *Input, d *generated.Document) { i.TemplateApprovedBy = uuid.Nil }},
		{"missing approval time", func(i *Input, d *generated.Document) { i.TemplateApprovedAt = time.Time{} }},
		{"required blank", func(i *Input, d *generated.Document) {
			i.Values["customer_name"] = ""
			d.VariablesJson = []byte(`{"customer_name":""}`)
		}},
		{"unknown value", func(i *Input, d *generated.Document) { i.Values["other"] = "unapproved" }},
		{"unknown section", func(i *Input, d *generated.Document) { i.Sections["other"] = "unapproved" }},
		{"printed values differ", func(i *Input, d *generated.Document) { d.VariablesJson = []byte(`{"customer_name":"Stale AB"}`) }},
		{"missing PDF version", func(i *Input, d *generated.Document) { d.PdfStorageVersionID = pgtype.Text{} }},
		{"wrong source kind", func(i *Input, d *generated.Document) { d.SourceKind = "blocks" }},
		{"missing PDF digest", func(i *Input, d *generated.Document) { d.PdfSha256 = nil }},
		{"malformed defaults", func(i *Input, d *generated.Document) { i.DefaultVarsJSON = []byte(`{"customer_name":1}`) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, doc := sourceFixture(t)
			tc.mutate(&input, doc)
			if _, err := New(input, doc); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New = %v", err)
			}
		})
	}
}

func TestHTMLSourceValidateRefusesSourceAndPDFDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"master HTML tampering", func(d *generated.Document) {
			replaceSourceField(t, d, "master", []byte(`{"schema_version":1,"html":"<script>bad()</script>","css":"","values":[],"sections":[],"assets":[]}`))
		}},
		{"approved defaults tampering", func(d *generated.Document) {
			replaceSourceField(t, d, "default_values", []byte(`{"customer_name":"Different default"}`))
		}},
		{"value tampering", func(d *generated.Document) {
			replaceSourceField(t, d, "values", []byte(`{"customer_name":"Other AB"}`))
		}},
		{"section tampering", func(d *generated.Document) {
			replaceSourceField(t, d, "sections", []byte(`{"scope":"Different scope"}`))
		}},
		{"content commitment tampering", func(d *generated.Document) { replaceSourceField(t, d, "content_digest", []byte(`"forged"`)) }},
		{"source commitment tampering", func(d *generated.Document) { replaceSourceField(t, d, "commitment", []byte(`"forged"`)) }},
		{"document identity", func(d *generated.Document) { d.ID = uuid.New() }},
		{"tenant identity", func(d *generated.Document) { d.OrgID = uuid.New() }},
		{"template identity", func(d *generated.Document) { d.TemplateID.Bytes = uuid.New() }},
		{"PDF key", func(d *generated.Document) { d.PdfStorageKey.String += "-different" }},
		{"PDF hash", func(d *generated.Document) { d.PdfSha256 = bytes.Repeat([]byte{1}, 32) }},
		{"PDF version", func(d *generated.Document) { d.PdfStorageVersionID.String = "opaque-version-2" }},
		{"PDF version missing", func(d *generated.Document) { d.PdfStorageVersionID.Valid = false }},
		{"CRM freeze changed", func(d *generated.Document) { d.VariablesJson = []byte(`{"customer_name":"New CRM value"}`) }},
		{"variables duplicate", func(d *generated.Document) {
			d.VariablesJson = []byte(`{"customer_name":"ignored","customer_name":"Recipient AB"}`)
		}},
		{"variables malformed Unicode", func(d *generated.Document) { d.VariablesJson = []byte(`{"customer_name":"\ud800"}`) }},
		{"null source", func(d *generated.Document) { d.HtmlSourceJson = []byte(`null`) }},
		{"duplicate source schema", func(d *generated.Document) {
			d.HtmlSourceJson = append([]byte(`{"schema_version":1,`), d.HtmlSourceJson[1:]...)
		}},
		{"case alias source", func(d *generated.Document) {
			d.HtmlSourceJson = bytes.Replace(d.HtmlSourceJson, []byte(`"schema_version"`), []byte(`"SCHEMA_VERSION"`), 1)
		}},
		{"unknown source field", func(d *generated.Document) {
			d.HtmlSourceJson = append([]byte(`{"unknown":1,`), d.HtmlSourceJson[1:]...)
		}},
		{"trailing JSON", func(d *generated.Document) { d.HtmlSourceJson = append(d.HtmlSourceJson, []byte(` {}`)...) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, doc := sourceFixture(t)
			attachSource(t, input, doc)
			approveFixture(doc, input)
			tc.mutate(doc)
			if err := Validate(doc, true); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestHTMLSourceReviewCannotBeReusedForOtherPDFOrUnidentifiedHuman(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*generated.Document)
	}{
		{"other PDF digest", func(d *generated.Document) { d.HtmlReviewedPdfSha256 = bytes.Repeat([]byte{2}, 32) }},
		{"missing review digest", func(d *generated.Document) { d.HtmlReviewedPdfSha256 = nil }},
		{"missing reviewer", func(d *generated.Document) { d.HtmlReviewedBy.Valid = false }},
		{"zero reviewer", func(d *generated.Document) { d.HtmlReviewedBy.Bytes = uuid.Nil }},
		{"missing review time", func(d *generated.Document) { d.HtmlReviewedAt.Valid = false }},
		{"zero review time", func(d *generated.Document) { d.HtmlReviewedAt.Time = time.Time{} }},
		{"infinite review time", func(d *generated.Document) { d.HtmlReviewedAt.InfinityModifier = pgtype.Infinity }},
		{"review before template approval", func(d *generated.Document) { d.HtmlReviewedAt.Time = d.HtmlReviewedAt.Time.Add(-2 * time.Hour) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input, doc := sourceFixture(t)
			attachSource(t, input, doc)
			approveFixture(doc, input)
			tc.mutate(doc)
			if err := Validate(doc, true); !errors.Is(err, ErrReviewRequired) {
				t.Fatalf("Validate = %v", err)
			}
		})
	}
}

func TestHTMLSourceLegacyDocumentsRemainUnchanged(t *testing.T) {
	for _, kind := range []string{"blocks", "pdf"} {
		t.Run(kind, func(t *testing.T) {
			if err := Validate(&generated.Document{SourceKind: kind, VariablesJson: []byte(`legacy-invalid-for-html`)}, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHTMLSourceCommitmentStableAcrossJSONBTransport(t *testing.T) {
	input, doc := sourceFixture(t)
	attachSource(t, input, doc)
	original := bytes.Clone(doc.HtmlSourceJson)
	want, err := Commitment(doc)
	if err != nil || !validSHA256(want) {
		t.Fatalf("validated source commitment = %q, %v", want, err)
	}
	var preserved source
	if err := decodeSource(original, &preserved); err != nil {
		t.Fatal(err)
	}
	if want != preserved.Commitment {
		t.Fatal("accessor did not return the validated typed commitment")
	}
	// JSONB reorders object members and may change whitespace. That transport
	// differs from New's bytes, but both lifecycle audits must name one source.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(original, &fields); err != nil {
		t.Fatal(err)
	}
	reordered, err := json.MarshalIndent(fields, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(original, reordered) {
		t.Fatal("fixture did not change JSON transport representation")
	}
	doc.HtmlSourceJson = reordered
	got, err := Commitment(doc)
	if err != nil || got != want {
		t.Fatalf("JSONB roundtrip source commitment = %q, %v; want %q", got, err, want)
	}
	if err := Validate(doc, false); err != nil {
		t.Fatal(err)
	}
	if err := Validate(doc, true); !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("accessor unexpectedly approved the document: %v", err)
	}
}

func TestHTMLSourceCommitmentRefusesUnvalidatedMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *generated.Document)
	}{
		{"saved commitment", func(t *testing.T, d *generated.Document) { replaceSourceField(t, d, "commitment", []byte(`"forged"`)) }},
		{"saved values", func(t *testing.T, d *generated.Document) {
			replaceSourceField(t, d, "values", []byte(`{"customer_name":"Mutated AB"}`))
		}},
		{"saved sections", func(t *testing.T, d *generated.Document) {
			replaceSourceField(t, d, "sections", []byte(`{"scope":"Unreviewed prose"}`))
		}},
		{"document variables", func(_ *testing.T, d *generated.Document) {
			d.VariablesJson = []byte(`{"customer_name":"New CRM data"}`)
		}},
		{"PDF version", func(_ *testing.T, d *generated.Document) { d.PdfStorageVersionID.String = "replacement-version" }},
		{"PDF digest", func(_ *testing.T, d *generated.Document) { d.PdfSha256 = bytes.Repeat([]byte{4}, 32) }},
		{"tenant", func(_ *testing.T, d *generated.Document) { d.OrgID = uuid.New() }},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, doc := sourceFixture(t)
			attachSource(t, input, doc)
			test.mutate(t, doc)
			got, err := Commitment(doc)
			if !errors.Is(err, ErrInvalid) || got != "" {
				t.Fatalf("unvalidated source commitment exposed: %q, %v", got, err)
			}
		})
	}
}

func TestHTMLSourceCommitmentRejectsAbsentLegacySource(t *testing.T) {
	for _, kind := range []string{"blocks", "pdf"} {
		t.Run(kind, func(t *testing.T) {
			doc := &generated.Document{SourceKind: kind, VariablesJson: []byte(`legacy data`)}
			if err := Validate(doc, true); err != nil {
				t.Fatalf("legacy Validate semantics changed: %v", err)
			}
			if value, err := Commitment(doc); !errors.Is(err, ErrInvalid) || value != "" {
				t.Fatalf("absent source had commitment %q, %v", value, err)
			}
		})
	}
	if value, err := Commitment(nil); !errors.Is(err, ErrInvalid) || value != "" {
		t.Fatalf("missing document had commitment %q, %v", value, err)
	}
}

func TestHTMLSourceStrictStringMapsRejectNullInsteadOfEmptyString(t *testing.T) {
	for _, transport := range []string{"source value", "source section", "document variables"} {
		t.Run(transport, func(t *testing.T) {
			input, doc := sourceFixture(t)
			master, err := htmlmaster.Decode(input.MasterJSON)
			if err != nil {
				t.Fatal(err)
			}
			master.HTML += `<p><span data-hash-value="reference"></span></p>`
			master.Values = append(master.Values, htmlmaster.Value{Name: "reference", MaxChars: 100})
			raw, err := json.Marshal(master)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
			if err != nil {
				t.Fatal(err)
			}
			input.MasterJSON, input.TemplateContentSHA256 = canonical.MasterJSON, canonical.SHA256
			input.Values["reference"] = ""
			input.Sections["scope"] = ""
			doc.VariablesJson = []byte(`{"customer_name":"Recipient AB","reference":""}`)
			attachSource(t, input, doc)
			approveFixture(doc, input)
			if err := Validate(doc, true); err != nil {
				t.Fatal(err)
			}
			switch transport {
			case "source value":
				replaceSourceField(t, doc, "values", []byte(`{"customer_name":"Recipient AB","reference":null}`))
			case "source section":
				replaceSourceField(t, doc, "sections", []byte(`{"scope":null}`))
			case "document variables":
				doc.VariablesJson = []byte(`{"customer_name":"Recipient AB","reference":null}`)
			}
			if err := Validate(doc, true); !errors.Is(err, ErrInvalid) {
				t.Fatalf("null string alias accepted: %v", err)
			}
		})
	}
}

func replaceSourceField(t *testing.T, doc *generated.Document, key string, value json.RawMessage) {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(doc.HtmlSourceJson, &fields); err != nil {
		t.Fatal(err)
	}
	fields[key] = value
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson = raw
}
