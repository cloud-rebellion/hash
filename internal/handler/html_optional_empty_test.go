// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func htmlOptionalEmptyUnitDocument(t *testing.T) *generated.Document {
	t.Helper()
	doc := htmlRevisionUnitDocument(t)
	input, err := htmlsource.InputForCurrent(doc)
	if err != nil {
		t.Fatal(err)
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.HTML += `<p data-hash-value="currency"></p>`
	master.Values = append(master.Values, htmlmaster.Value{Name: "currency", MaxChars: 120})
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	input.MasterJSON, input.DefaultVarsJSON, input.TemplateContentSHA256 = canonical.MasterJSON, canonical.DefaultsJSON, canonical.SHA256
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestHTMLRevisionOptionalAbsentToEmptyRequiresFreshSourceTransition(t *testing.T) {
	doc := htmlOptionalEmptyUnitDocument(t)
	beforeSource, beforeVariables := bytes.Clone(doc.HtmlSourceJson), bytes.Clone(doc.VariablesJson)
	beforeDigest, err := htmlsource.MaterializationDigest(doc)
	if err != nil {
		t.Fatal(err)
	}
	input, rendered, err := materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Values: htmlStringMap{"currency": ""}})
	if err != nil {
		t.Fatal(err)
	}
	value, present := input.Values["currency"]
	if !present || value != "" || rendered.ContentDigest != beforeDigest || !bytes.Equal(beforeSource, doc.HtmlSourceJson) || !bytes.Equal(beforeVariables, doc.VariablesJson) {
		t.Fatal("optional presence transition changed original state or printed content")
	}
	// A repeated explicit empty is an ordinary no-op, not another revision.
	doc.VariablesJson, _ = json.Marshal(input.Values)
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Values: htmlStringMap{"currency": ""}}); !errors.Is(err, errHTMLDocumentRevisionConflict) {
		t.Fatal("repeated empty admitted", err)
	}
	if _, _, err = materializeHTMLDocumentRevision(doc, htmlDocumentRevisionInput{Values: htmlStringMap{"customer": ""}}); err == nil {
		t.Fatal("required field admitted empty")
	}
}
