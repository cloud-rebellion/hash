// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
)

// Actual unchanged producers are the output oracle. No native grant,
// allocation/RSS observation, real PDF, human approval or SQL is asserted.
func TestHTMLRevisionBodyAndSigningOutputOriginalOracleV1(t *testing.T) {
	input, doc, _ := testfixture.BrandedHTMLContract(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	canonicalOut, err := htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaults)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(input.MasterJSON, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	record, err := htmlRevisionRecordComponentsForV1(ctx, input, canonical, htmlsource.RevisionValidationRecordPinsV1{
		DocumentID: doc.ID, OrgID: doc.OrgID, PDFKey: doc.PdfStorageKey.String, PDFVersionID: doc.PdfStorageVersionID.String, PDFSHA256: doc.PdfSha256, VariablesJSON: doc.VariablesJson})
	if err != nil {
		t.Fatal(err)
	}
	bound, err := htmlRevisionBodyOutputComponentsForV1(master, input, canonicalOut, record)
	if err != nil {
		t.Fatal(err)
	}
	result, err := compiled.Materialize(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(result.HTML)) > bound.bodyHTMLBytes {
		t.Fatal("unchanged body producer exceeded derived output", len(result.HTML), bound)
	}
	// Original envelope populates all declared optional values and default text,
	// rather than treating only explicitly provided maps as complete wire input.
	values, sections := map[string]string{}, map[string]string{}
	for _, v := range master.Values {
		values[v.Name] = input.Values[v.Name]
	}
	for _, v := range master.Sections {
		text, ok := input.Sections[v.Name]
		if !ok {
			text = v.DefaultText
		}
		sections[v.Name] = text
	}
	envelope, err := json.Marshal(struct {
		Master     string            `json:"master_digest"`
		Values     map[string]string `json:"values"`
		Sections   map[string]string `json:"sections"`
		HTMLDigest string            `json:"html_digest"`
	}{result.MasterDigest, values, sections, strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(envelope)) > bound.contentEnvelopeJSONBytes {
		t.Fatalf("actual populated body envelope omitted: %d>%d", len(envelope), bound.contentEnvelopeJSONBytes)
	}
	signing, err := compiled.SigningPageHTML(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(signing)) > bound.signingHTMLBytes {
		t.Fatal("actual signing page omitted", len(signing), bound.signingHTMLBytes)
	}
	ready, err := compiled.ContractReadiness(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := json.Marshal(struct {
		Policy   *htmlmaster.SigningPagePolicy    `json:"policy"`
		Parties  []htmlmaster.ContractPartyValues `json:"parties"`
		Bindings []htmlsource.PartyBinding        `json:"bindings"`
	}{compiled.SigningPagePolicy(), ready.Parties, input.PartyBindings})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(plan)) > bound.planJSONBytes {
		t.Fatal("actual original typed signing plan omitted", len(plan), bound.planJSONBytes)
	}
	scratch, retained, err := htmlRevisionRecordStageComponentsV1(master, input, record, canonicalOut, 1)
	if err != nil || scratch <= bound.expressionBytes || retained < int64(cap(result.ChangedSections))*int64(unsafe.Sizeof("")) {
		t.Fatal("retained section result or actual expression work omitted", scratch, retained, err)
	}
	if _, _, err = htmlRevisionRecordStageComponentsV1(master, input, record, canonicalOut, math.MaxInt64); err == nil {
		t.Fatal("Record stage overflow accepted")
	}
}
func TestHTMLRevisionActual64DeclaredValuesExistingReplacementV1(t *testing.T) {
	var master htmlmaster.Master
	master.SchemaVersion = 1
	values := map[string]string{}
	sections := map[string]string{}
	for i := 0; i < htmlmaster.MaxDefinitions; i++ {
		name := fmt.Sprintf("value_%02d", i)
		master.HTML += fmt.Sprintf("<p data-hash-value=\"%s\"></p>", name)
		master.Values = append(master.Values, htmlmaster.Value{Name: name, Required: i != htmlmaster.MaxDefinitions-1, MaxChars: 32})
		values[name] = "original"
		section := fmt.Sprintf("section_%02d", i)
		master.HTML += fmt.Sprintf("<p data-hash-section=\"%s\"></p>", section)
		master.Sections = append(master.Sections, htmlmaster.Section{Name: section, DefaultText: "original", MaxChars: 32})
		sections[section] = "original"
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	clone := func(source map[string]string) map[string]string {
		out := map[string]string{}
		for key, value := range source {
			out[key] = value
		}
		return out
	}
	values63 := clone(values)
	delete(values63, "value_63") // A genuinely optional, previously omitted declaration.
	sections63 := clone(sections)
	delete(sections63, "section_63")
	unknown64 := map[string]string{}
	for i := 0; i < htmlmaster.MaxDefinitions; i++ {
		unknown64[fmt.Sprintf("unknown_%02d", i)] = "new"
	}
	for _, entry := range []struct {
		name                                 string
		base, baseSections, values, sections map[string]string
		want                                 error
		suffix                               string
	}{
		{"existing replacement at64", values, sections, map[string]string{"value_00": "changed"}, nil, nil, ""},
		{"65 merged values", values, sections, map[string]string{"unknown_65": "new"}, nil, htmlmaster.ErrLimit, "input values"},
		{"128 temporary values", values, sections, unknown64, nil, htmlmaster.ErrLimit, "input values"},
		{"65 sections", values, sections, nil, map[string]string{"unknown_65": "new"}, htmlmaster.ErrLimit, "input sections"},
		{"unknown value before section limit", values63, sections, map[string]string{"unknown_64": "new"}, map[string]string{"unknown_65": "new"}, htmlmaster.ErrInvalid, "unknown value name"},
		{"value text before section limit", values, sections, map[string]string{"value_00": strings.Repeat("x", 33)}, map[string]string{"unknown_65": "new"}, htmlmaster.ErrLimit, "value text: value_00"},
		{"value count before section count", values, sections, map[string]string{"unknown_65": "new"}, map[string]string{"unknown_65": "new"}, htmlmaster.ErrLimit, "input values"},
		{"unknown section", values, sections63, nil, map[string]string{"unknown": "new"}, htmlmaster.ErrInvalid, "unknown section name"},
	} {
		t.Run(entry.name, func(t *testing.T) {
			in := htmlsource.Input{Values: entry.base, Sections: entry.baseSections}
			if size, err := htmlRevisionNewMapCopiesV1(in, entry.values, entry.sections); err != nil || size <= 0 {
				t.Fatalf("copy pricing preempted original semantic validation: %d,%v", size, err)
			}
			merged := htmlsource.Input{Values: clone(entry.base), Sections: clone(entry.baseSections)}
			for key, value := range entry.values {
				merged.Values[key] = value
			}
			for key, value := range entry.sections {
				merged.Sections[key] = value
			}
			wire, err := htmlRevisionMergedValuesJSONBytesV1(merged.Values)
			if err != nil || wire < 2 {
				t.Fatalf("temporary actual map output not priced: %d,%v", wire, err)
			}
			if _, err = htmlRevisionBodyOutputComponentsForV1(master, merged, htmlRevisionCanonicalOutputComponentsV1{}, htmlRevisionRecordComponentsV1{valuesJSONBytes: wire}); err != nil {
				t.Fatal("body pricing preempted original validation", err)
			}
			if _, err = htmlRevisionContractReadinessComponentsForV1(master, htmlmaster.Input{Values: merged.Values, Sections: merged.Sections}); err != nil {
				t.Fatal("readiness pricing preempted original validation", err)
			}
			_, err = compiled.Materialize(htmlmaster.Input{Values: merged.Values, Sections: merged.Sections})
			if entry.want == nil {
				if err != nil {
					t.Fatal("original maximum valid replacement no longer succeeds", err)
				}
			} else if !errors.Is(err, entry.want) || !strings.HasSuffix(err.Error(), entry.suffix) {
				t.Fatalf("original refusal priority changed: got%v want%v/%s", err, entry.want, entry.suffix)
			}
		})
	}
	t.Run("contract readiness remains original", func(t *testing.T) {
		input, _, _ := testfixture.HTMLContract(t)
		contract, err := htmlmaster.Decode(input.MasterJSON)
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := htmlmaster.Compile(contract)
		if err != nil {
			t.Fatal(err)
		}
		name := contract.ContractProfile.Parties[0].CompanyName
		declaration := map[string]string{name: ""}
		if _, err = htmlRevisionNewMapCopiesV1(input, declaration, nil); err != nil {
			t.Fatal("copy pricing preempted original readiness", err)
		}
		merged := htmlsource.Input{Values: clone(input.Values), Sections: clone(input.Sections)}
		merged.Values[name] = ""
		wire, err := htmlRevisionMergedValuesJSONBytesV1(merged.Values)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = htmlRevisionBodyOutputComponentsForV1(contract, merged, htmlRevisionCanonicalOutputComponentsV1{}, htmlRevisionRecordComponentsV1{valuesJSONBytes: wire}); err != nil {
			t.Fatal("body pricing preempted original readiness", err)
		}
		if _, err = htmlRevisionContractReadinessComponentsForV1(contract, htmlmaster.Input{Values: merged.Values, Sections: merged.Sections}); err != nil {
			t.Fatal("readiness pricing preempted original validation", err)
		}
		if _, err = compiled.Materialize(htmlmaster.Input{Values: merged.Values, Sections: merged.Sections}); !errors.Is(err, htmlmaster.ErrContractIncomplete) {
			t.Fatal("original contract readiness no longer precedes required-values refusal", err)
		}
	})
	for count := 0; count <= htmlmaster.MaxDefinitions; count++ {
		old, err := htmlRevisionRetentionMapV1(count)
		next, nextErr := htmlRevisionMergedMapRetentionV1(count)
		if err != nil || nextErr != nil || old != next {
			t.Fatalf("accepted-map retention changed at%d: %d/%d,%v/%v", count, old, next, err, nextErr)
		}
	}
	if _, err := htmlRevisionMergedMapRetentionV1(2*htmlmaster.MaxDefinitions + 1); err == nil {
		t.Fatal("impossible temporary union accepted by pricing")
	}
}
