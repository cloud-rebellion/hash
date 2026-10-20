// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

var htmlRevisionRecordSourceKeysV1 = [...]string{"schema_version", "document_id", "org_id", "template_id", "template_version", "template_content_sha256", "template_approved_by", "template_approved_at", "master", "default_values", "values", "sections", "master_digest", "content_digest", "pdf_key", "pdf_sha256", "pdf_version_id", "commitment", "party_bindings", "signing_artifact"}
var htmlRevisionRecordArtifactKeysV1 = [...]string{"version", "policy", "plan_sha256", "composition", "fields"}
var htmlRevisionRecordCompositionKeysV1 = [...]string{"schema_version", "policy", "body_sha256", "signing_page_sha256", "merged_sha256", "merged_bytes", "output_sha256", "body_pages", "final_pages", "body_geometry_sha256", "geometry_sha256", "signing_page"}
var htmlRevisionRecordGeometryKeysV1 = [...]string{"boxes_milli_points", "rotation", "user_unit_milli"}
var htmlRevisionRecordRectangleKeysV1 = [...]string{"slot", "page", "x", "y", "w", "h"}
var htmlRevisionRecordBindingKeysV1 = [...]string{"slot", "recipient_id"}

// Actual typed record components only. A fixed native source owner derives
// these from its genuine staged builder Input/Canonical/RecordPins under the
// retained original-body borrower. This arithmetic grants no work or policy.
type htmlRevisionRecordComponentsV1 struct {
	sourceJSONBytes, valuesJSONBytes, sectionsJSONBytes, artifactJSONBytes, bindingsJSONBytes int64
	sourceCommitmentEncoderBytes, sourceNewEncoderBytes, originValuesEncoderBytes             int64
	variablesParserBytes, originVariablesParserBytes                                          int64
}

func htmlRevisionRecordAddV1(total *int64, n, factor int64) bool {
	return htmlInputAddV1(total, n, factor)
}

// RawMessage is embedded JSON, not a quoted string. encoding/json appendCompact
// can remove whitespace and escape literal <,>,&,U+2028/U+2029; it does not turn
// arbitrary JSON numeric exponents into expanded numbers. Count those ACTUAL
// bytes rather than applying an invented raw-JSON output multiplier.
func htmlRevisionRawMessageOutputV1(raw []byte) (int64, error) {
	n := int64(len(raw))
	for i := 0; i < len(raw); i++ {
		switch raw[i] {
		case '<', '>', '&':
			if !htmlRevisionRecordAddV1(&n, 1, 5) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
		if i+2 < len(raw) && raw[i] == 0xe2 && raw[i+1] == 0x80 && (raw[i+2] == 0xa8 || raw[i+2] == 0xa9) {
			if !htmlRevisionRecordAddV1(&n, 1, 3) {
				return 0, ErrHTMLAuthoringInputV1
			}
			i += 2
		}
	}
	return n, nil
}
func htmlRevisionQuotedOutputV1(s string) (int64, error) {
	n := int64(2)
	if !htmlRevisionRecordAddV1(&n, int64(len(s)), 6) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return n, nil
}
func htmlRevisionObjectOutputV1(keys []string, values int64) (int64, error) {
	n := int64(2)
	for _, key := range keys {
		if !htmlRevisionRecordAddV1(&n, int64(len(key))+6, 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	if !htmlRevisionRecordAddV1(&n, values, 1) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return n, nil
}
func htmlRevisionStringMapOutputV1(values map[string]string) (htmlAuthoringInputShapeV1, error) {
	var out htmlAuthoringInputShapeV1
	if values == nil || len(values) > htmlmaster.MaxDefinitions {
		return out, htmlsource.ErrInvalid
	}
	n := int64(2)
	text := int64(0)
	for key, value := range values {
		if !htmlRevisionRecordAddV1(&text, int64(len(key)), 1) || !htmlRevisionRecordAddV1(&text, int64(len(value)), 1) {
			return out, ErrHTMLAuthoringInputV1
		}
		if !htmlRevisionRecordAddV1(&n, int64(len(key)), 6) || !htmlRevisionRecordAddV1(&n, int64(len(value)), 6) || !htmlRevisionRecordAddV1(&n, 1, 8) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	// Future strict map parse sees the actual typed encoder's bounded output.
	// Raw output bytes also conservatively bound original escaped string bytes.
	out = htmlAuthoringInputShapeV1{raw: n, strings: 2 * int64(len(values)), stringBytes: n, objects: 1, depth: 1}
	if len(values) > 0 {
		out.tableSlots = 2 * htmlInputPowerV1(max(8, (int64(len(values))*8+6)/7))
	}
	return out, nil
}

func htmlRevisionArtifactTypedOutputV1(a *htmlsource.SigningArtifact) (int64, error) {
	if a == nil {
		return 4, nil
	}
	if len(a.Fields) > 2 {
		return 0, htmlsource.ErrInvalid
	}
	// Every actual artifact/Composition/Geometry field is priced even if the
	// original source omitted typed zero/default members. Exact successful schema
	// is5 objects,7 arrays,32 keys,37 integers and at most11 string values.
	text := int64(0)
	c := a.Composition
	for _, value := range []string{a.Policy, a.PlanSHA256, c.Policy, c.BodySHA256, c.SigningPageSHA256, c.MergedSHA256, c.OutputSHA256, c.BodyGeometrySHA256, c.GeometrySHA256} {
		if !htmlRevisionRecordAddV1(&text, int64(len(value)), 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, field := range a.Fields {
		if !htmlRevisionRecordAddV1(&text, int64(len(field.Slot)), 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	keyBytes := int64(0)
	for _, fields := range [][]string{htmlRevisionRecordArtifactKeysV1[:], htmlRevisionRecordCompositionKeysV1[:], htmlRevisionRecordGeometryKeysV1[:], htmlRevisionRecordRectangleKeysV1[:], htmlRevisionRecordRectangleKeysV1[:]} {
		for _, field := range fields {
			if !htmlRevisionRecordAddV1(&keyBytes, int64(len(field)), 1) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	n := int64(0)
	if !htmlRevisionRecordAddV1(&n, text, 6) || !htmlRevisionRecordAddV1(&n, keyBytes, 1) || !htmlRevisionRecordAddV1(&n, 37, 20) || !htmlRevisionRecordAddV1(&n, 43+37+5+7+32+27, 8) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return n, nil
}
func htmlRevisionTypedEncoderV1(output int64) (int64, error) {
	n := int64(0)
	// Same pinned encoder append/backing/result-copy/reflect-state class used by
	// existing admitted typed input producers. It is logical parent credit, not
	// a claim that GC or sync.Pool released any physical process memory.
	if !htmlRevisionRecordAddV1(&n, output, 18) || !htmlRevisionRecordAddV1(&n, 1, 4*4096) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return n, nil
}
func htmlRevisionTypedSourceEncodingForV1(ctx context.Context, input htmlsource.Input, canonical htmlmaster.TemplateCommitment, pdfKey, pdfVersion string) (htmlRevisionRecordComponentsV1, error) {
	var out htmlRevisionRecordComponentsV1
	if !applicationContextV1(ctx) || !htmlAuthoringInputRuntimeOKV1 {
		return out, ErrHTMLAuthoringInputV1
	}
	// Identity and legal/source validity remain the staged validator's job. These
	// are real bytes/models, never caller-reported size or resource declarations.
	values, err := htmlRevisionStringMapOutputV1(input.Values)
	if err != nil {
		return out, err
	}
	sections, err := htmlRevisionStringMapOutputV1(input.Sections)
	if err != nil {
		return out, err
	}
	out.valuesJSONBytes, out.sectionsJSONBytes = values.raw, sections.raw
	master, err := htmlRevisionRawMessageOutputV1(canonical.MasterJSON)
	if err != nil {
		return out, err
	}
	defaults, err := htmlRevisionRawMessageOutputV1(canonical.DefaultsJSON)
	if err != nil {
		return out, err
	}
	out.artifactJSONBytes, err = htmlRevisionArtifactTypedOutputV1(input.SigningArtifact)
	if err != nil {
		return out, err
	}
	if len(input.PartyBindings) > 2 {
		return out, htmlsource.ErrInvalid
	}
	out.bindingsJSONBytes = 2
	for _, binding := range input.PartyBindings {
		slot, err := htmlRevisionQuotedOutputV1(binding.Slot)
		if err != nil {
			return out, err
		}
		// recipient UUID is quoted36ASCII; fixed object+array separators included.
		row, err := htmlRevisionObjectOutputV1(htmlRevisionRecordBindingKeysV1[:], slot+38)
		if err != nil {
			return out, err
		}
		if !htmlRevisionRecordAddV1(&out.bindingsJSONBytes, row+2, 1) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	key, err := htmlRevisionQuotedOutputV1(pdfKey)
	if err != nil {
		return out, err
	}
	version, err := htmlRevisionQuotedOutputV1(pdfVersion)
	if err != nil {
		return out, err
	}
	// Root has20 fixed schema fields (18legacy+partybindings+artifact). Four
	// UUIDs,5SHA256 strings, one RFC3339 time,2bounded integers, actual PDF tuple,
	// canonical master/default RawMessages and actual Values/Sections follow.
	// Master/content digest strings reach encoding only after exact64-character
	// materialization digest matches. Commitment="" during hashing; bounding its
	// computed final64chars also covers New. Malformed oversized digest claims
	// are refused by those original checks BEFORE this encoding.
	valuesMass := int64(0)
	for _, part := range []int64{4 * 38, 5 * 66, 64, 2 * 20, key, version, master, defaults, values.raw, sections.raw, out.artifactJSONBytes, out.bindingsJSONBytes} {
		if !htmlRevisionRecordAddV1(&valuesMass, part, 1) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	out.sourceJSONBytes, err = htmlRevisionObjectOutputV1(htmlRevisionRecordSourceKeysV1[:], valuesMass)
	if err != nil {
		return out, err
	}
	out.sourceCommitmentEncoderBytes, err = htmlRevisionTypedEncoderV1(out.sourceJSONBytes)
	if err != nil {
		return out, err
	}
	// Original New makes sourceCommitment's Marshal then a final full-source
	// Marshal. Sum both ownership masses; no scratch/pool/GC alias credit.
	if !htmlRevisionRecordAddV1(&out.sourceNewEncoderBytes, out.sourceCommitmentEncoderBytes, 2) {
		return out, ErrHTMLAuthoringInputV1
	}
	out.originValuesEncoderBytes, err = htmlRevisionTypedEncoderV1(values.raw)
	if err != nil {
		return out, err
	}
	out.originVariablesParserBytes, err = htmlAuthoringInputParserArenaV1(values, 2)
	if err != nil {
		return out, err
	}
	return out, nil
}

// Original Record parser is the exact wrapper over the shared typed source
// encoder. Fresh native New uses the actual future Values parser derived above,
// without fabricating an origin flag or an existing VariablesJSON input.
func htmlRevisionRecordComponentsForV1(ctx context.Context, input htmlsource.Input, canonical htmlmaster.TemplateCommitment, pins htmlsource.RevisionValidationRecordPinsV1) (htmlRevisionRecordComponentsV1, error) {
	out, err := htmlRevisionTypedSourceEncodingForV1(ctx, input, canonical, pins.PDFKey, pins.PDFVersionID)
	if err != nil {
		return out, err
	}
	if !pins.Origin {
		shape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, pins.VariablesJSON)
		if err != nil {
			return out, errors.Join(htmlsource.ErrInvalid, err)
		}
		out.variablesParserBytes, err = htmlAuthoringInputParserArenaV1(shape, 2)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}
