// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

func revisionComponentsContextV1(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}
func revisionComponentsShapeDominatesV1(t *testing.T, bound, actual htmlAuthoringInputShapeV1) {
	t.Helper()
	for _, part := range []struct {
		name          string
		bound, actual int64
	}{{"raw", bound.raw, actual.raw}, {"strings", bound.strings, actual.strings}, {"stringBytes", bound.stringBytes, actual.stringBytes}, {"scalars", bound.scalars, actual.scalars}, {"objects", bound.objects, actual.objects}, {"arrays", bound.arrays, actual.arrays}, {"tableSlots", bound.tableSlots, actual.tableSlots}, {"arraySlots", bound.arraySlots, actual.arraySlots}, {"depth", bound.depth, actual.depth}} {
		if part.bound < part.actual {
			t.Errorf("%s bound %d < actual %d", part.name, part.bound, part.actual)
		}
	}
}

func TestHTMLRevisionArtifactTypedOutputEnvelopeV1(t *testing.T) {
	ctx := revisionComponentsContextV1(t)
	// Missing typed members expand back to explicit zero/default fields; int64
	// bounds and HTML-sensitive strings exercise different expansion mechanisms.
	rawCases := [][]byte{[]byte("{}"), []byte("{\"policy\":\"" + strings.Repeat("&<>", 256) + "\",\"composition\":{\"merged_bytes\":-9223372036854775808,\"signing_page\":{\"boxes_milli_points\":[[-9223372036854775808,9223372036854775807,0,-1]],\"rotation\":-9223372036854775808,\"user_unit_milli\":9223372036854775807}},\"fields\":[{\"slot\":\"customer&\",\"x\":-9223372036854775808},{\"slot\":\"provider<>\",\"h\":9223372036854775807}]}")}
	for i, raw := range rawCases {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			original, err := htmlAuthoringInputRootShapeV1(ctx, htmlRevisionSigningArtifactNodeV1, raw)
			if err != nil {
				t.Fatal(err)
			}
			bound, err := htmlRevisionArtifactOutputShapeV1(original)
			if err != nil {
				t.Fatal(err)
			}
			var typed htmlsource.SigningArtifact
			if err = json.Unmarshal(raw, &typed); err != nil {
				t.Fatal(err)
			}
			canonical, err := json.Marshal(typed)
			if err != nil {
				t.Fatal(err)
			}
			actual, err := htmlAuthoringInputRootShapeV1(ctx, htmlRevisionSigningArtifactNodeV1, canonical)
			if err != nil {
				t.Fatal(err)
			}
			revisionComponentsShapeDominatesV1(t, bound, actual)
			if i == 0 && len(canonical) <= len(raw) {
				t.Fatal("typed defaults did not expand abbreviated input")
			}
			if bound.objects != 5 || bound.arrays != 7 || bound.strings != 43 || bound.scalars != 37 || bound.tableSlots != 96 || bound.arraySlots != 60 {
				t.Fatalf("unexpected fixed artifact topology: %+v", bound)
			}
		})
	}
	original := htmlAuthoringInputShapeV1{stringBytes: math.MaxInt64}
	if _, err := htmlRevisionArtifactOutputShapeV1(original); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestHTMLRevisionSourceComponentsKeepArtifactExpansionSeparateV1(t *testing.T) {
	ctx := revisionComponentsContextV1(t)
	raw := []byte("{\"master\":{\"schema_version\":1,\"html\":\"<p>Ready</p>\"},\"default_values\":{},\"signing_\\u0061rtifact\":{}}")
	components, err := htmlRevisionSourceDecodeComponentsForV1(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw[components.masterStart:components.masterEnd]) != "{\"schema_version\":1,\"html\":\"<p>Ready</p>\"}" {
		t.Fatal("master span did not retain original bytes")
	}
	if string(raw[components.defaultsStart:components.defaultsEnd]) != "{}" {
		t.Fatal("defaults span did not retain original bytes")
	}
	if components.sourceParserBytes <= 0 || components.retainedTypedSourceBytes <= 0 || components.artifactOriginalParserBytes <= 0 || components.artifactCanonicalParserBytes <= 0 || components.artifactEncodeBytes <= components.artifactJSONBytes || components.artifactJSONBytes <= 2 {
		t.Fatalf("missing separate expansion components: %+v", components)
	}
	duplicate := []byte("{\"master\":{\"schema_version\":1,\"html\":\"x\"},\"default_values\":{},\"signing_artifact\":{},\"signing_\\u0061rtifact\":{}}")
	if _, err = htmlRevisionSourceDecodeComponentsForV1(ctx, duplicate); err == nil {
		t.Fatal("duplicate exact artifact alias accepted")
	}
}

func TestHTMLRevisionCanonicalOutputEnvelopeEscapedSectionsV1(t *testing.T) {
	ctx := revisionComponentsContextV1(t)
	raw := []byte("{\"schema_version\":1,\"html\":\"<p data-hash-section=\\\"clause\\\"></p>\",\"sections\":[{\"name\":\"clause\",\"default_text\":\"" + strings.Repeat("&", 1024) + "\",\"max_chars\":2048}]}")
	master, err := htmlmaster.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	components, err := htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaults)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, canonical.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	revisionComponentsShapeDominatesV1(t, components.masterShape, actual)
	actualDefaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, canonical.DefaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	revisionComponentsShapeDominatesV1(t, components.defaultsShape, actualDefaults)
	if len(canonical.MasterJSON) <= 2*len(raw) {
		t.Fatal("fixture did not exercise expanded canonical output")
	}
	if components.masterParserBytes <= 0 || components.defaultsParserBytes <= 0 {
		t.Fatal("future parser components missing")
	}
	if len(canonical.SHA256) != 64 {
		t.Fatal("original canonical SHA missing")
	}
}

func TestHTMLRevisionCanonicalOutputEnvelopeAllTypedFieldsV1(t *testing.T) {
	ctx := revisionComponentsContextV1(t)
	text := strings.Repeat("&<>\"\n", 17)

	master := htmlmaster.Master{SchemaVersion: 3, HTML: "<p>Ready</p>", Values: []htmlmaster.Value{{Name: text, Required: true, MaxChars: math.MaxInt64}}, Sections: []htmlmaster.Section{{Name: text, DefaultText: text, MaxChars: math.MaxInt64}}, Assets: []htmlmaster.Asset{{Name: text, MediaType: text, DataBase64: text, SHA256: text}}, ContractProfile: &htmlmaster.ContractProfile{ID: text, Version: math.MaxInt64, Kind: text, Parties: []htmlmaster.ContractParty{{Slot: text, CompanyName: text, CompanyID: text, RepresentativeName: text, RepresentativeEmail: text, RepresentativeAuthority: text}, {Slot: text}}, Terms: []htmlmaster.ContractTerm{{Name: text, Value: text, Section: text}}}, SigningPage: &htmlmaster.SigningPagePolicy{Version: math.MaxInt64, Policy: text, LogoAsset: text, LogoSHA256: text, LogoAlt: text, FontSHA256: text, Branding: htmlmaster.SigningPageBranding{PrimaryHex: text, AccentHex: text, SurfaceHex: text, TextHex: text, MutedHex: text, LogoURL: text, LogoAlt: text, FontHeading: text, FontBody: text, SignatureColor: text}}}
	// This is intentionally typed-but-policy-invalid. These outputs can still be
	// formed in helper paths before their original semantic refusal. No test
	// treats this component calculation as validity, source approval or a grant.
	stats := htmlInputCanonicalStatsV1{tokens: 3, cssTokens: 1, maxTagOutput: 32}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, []byte("{\"name\":\"&&&&\"}"))
	if err != nil {
		t.Fatal(err)
	}
	components, err := htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaults)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, raw)
	if err != nil {
		t.Fatal(err)
	}
	revisionComponentsShapeDominatesV1(t, components.masterShape, actual)
	var defaultMap map[string]string
	if err = json.Unmarshal([]byte("{\"name\":\"&&&&\"}"), &defaultMap); err != nil {
		t.Fatal(err)
	}
	canonicalDefaults, err := json.Marshal(defaultMap)
	if err != nil {
		t.Fatal(err)
	}
	actualDefaultShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, canonicalDefaults)
	if err != nil {
		t.Fatal(err)
	}
	revisionComponentsShapeDominatesV1(t, components.defaultsShape, actualDefaultShape)
	// Inspection deliberately uses20001 as a bounded upper count for long CSS,
	// even when its actual scanner later accepts far fewer tokens.
	stats.cssTokens = 20001
	if _, err = htmlRevisionCanonicalOutputComponentsForV1(master, stats, defaults); err != nil {
		t.Fatalf("existing inspection ceiling refused: %v", err)
	}
}
