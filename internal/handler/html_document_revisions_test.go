// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func htmlRevisionUnitDocument(t *testing.T) *generated.Document {
	t.Helper()
	master, _ := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML:     `<p><span data-hash-value="customer"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 120}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Original approved terms", MaxChars: 240}},
	})
	canonical, err := htmlmaster.CanonicalTemplate(master, []byte(`{"customer":"Original default AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("synthetic already-rendered artifact, not renderer proof"))
	id := uuid.New()
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), Status: "draft", SourceKind: "pdf",
		TemplateID: pgtype.UUID{Bytes: id, Valid: true}, VariablesJson: []byte(`{"customer":"Existing document AB"}`),
		PdfStorageKey: pgtype.Text{String: "org/example/documents/source.pdf", Valid: true}, PdfSha256: digest[:],
		PdfStorageVersionID: pgtype.Text{String: "opaque-version-1", Valid: true}, EvidenceVersionPinsRequired: true,
	}
	doc.HtmlSourceJson, err = htmlsource.New(htmlsource.Input{TemplateID: id, TemplateVersion: 7,
		TemplateContentSHA256: canonical.SHA256, MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON,
		Values: map[string]string{"customer": "Existing document AB"}, Sections: map[string]string{"scope": "Previously agreed text"},
		TemplateApprovedBy: uuid.New(), TemplateApprovedAt: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)}, doc)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestHTMLDocumentRevisionChangesDeclaredTextWithoutRewritingFrozenInputs(t *testing.T) {
	doc := htmlRevisionUnitDocument(t)
	origin, variables := bytes.Clone(doc.HtmlSourceJson), bytes.Clone(doc.VariablesJson)
	input, rendered, err := materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Sections: htmlStringMap{"scope": "Agreed <script>plain & text</script>"}})
	if err != nil {
		t.Fatal(err)
	}
	if input.TemplateVersion != 7 || input.Values["customer"] != "Existing document AB" ||
		!bytes.Contains(input.DefaultVarsJSON, []byte("Original default AB")) ||
		!strings.Contains(rendered.HTML, "Agreed &lt;script&gt;plain &amp; text&lt;/script&gt;") ||
		!strings.Contains(rendered.HTML, "Existing document AB") || !bytes.Equal(origin, doc.HtmlSourceJson) || !bytes.Equal(variables, doc.VariablesJson) {
		t.Fatal("revision changed approved defaults, origin or omitted values, or treated prose as markup")
	}
	input.Values["customer"] = "Later caller mutation"
	if _, err := htmlsource.InputForCurrent(doc); err != nil || !bytes.Equal(origin, doc.HtmlSourceJson) {
		t.Fatal("revision retained a mutable alias to the original source")
	}
	valueInput, valueResult, err := materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Values: htmlStringMap{"customer": "Changed AB"}})
	if err != nil || valueInput.Sections["scope"] != "Previously agreed text" || !strings.Contains(valueResult.HTML, "Previously agreed text") {
		t.Fatal("omitted sections reverted to template defaults")
	}
}

func TestHTMLDocumentRevisionRefusesNoOpUndeclaredOversizeAndCorruptSource(t *testing.T) {
	for name, request := range map[string]htmlDocumentRevisionInput{
		"omitted no-op":   {},
		"explicit no-op":  {Values: htmlStringMap{"customer": "Existing document AB"}, Sections: htmlStringMap{"scope": "Previously agreed text"}},
		"unknown value":   {Values: htmlStringMap{"undeclared": "Inserted"}},
		"unknown section": {Sections: htmlStringMap{"undeclared": "Inserted"}},
		"required blank":  {Values: htmlStringMap{"customer": ""}},
		"value limit":     {Values: htmlStringMap{"customer": strings.Repeat("界", 121)}},
		"section limit":   {Sections: htmlStringMap{"scope": strings.Repeat("界", 241)}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := materializeHTMLDocumentRevision(htmlRevisionUnitDocument(t), request); err == nil {
				t.Fatal("invalid or no-op revision accepted")
			}
		})
	}
	doc := htmlRevisionUnitDocument(t)
	doc.VariablesJson = []byte(`{"customer":"Uncommitted replacement"}`)
	if _, _, err := materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Values: htmlStringMap{"customer": "Changed AB"}}); !errors.Is(err, htmlsource.ErrInvalid) {
		t.Fatal("corrupt original bypassed revision source validation")
	}
}

func TestHTMLDocumentRevisionStrictWireInput(t *testing.T) {
	for _, body := range []string{
		`{"values":null}`, `{"sections":{"scope":null}}`, `{"values":{"customer":42}}`,
		`{"sections":{"scope":"a","scope":"b"}}`, `{"summary":"a","SUMMARY":"b"}`,
		`{"master":{}}`, `{"html":"<p>replacement</p>"}`, `{"template_id":"replacement"}`,
		`{"values":{}}{}`, `{"values":{"customer":"\ud800"}}`,
	} {
		var in htmlDocumentRevisionInput
		if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &in); err == nil {
			t.Fatal("ambiguous, mutable-master or coerced request accepted")
		}
	}
}
