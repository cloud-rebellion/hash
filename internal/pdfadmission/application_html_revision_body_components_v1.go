// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/base64"
	"unsafe"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// Fixed original SigningPageHTML function source: 4,438 UTF-8 bytes,
// SHA256 877a7b42ae2a6acf486b56c687cb598a91eb0397d88becaf1b7dc357a3030cfc.
// Every fixed literal byte is shorter than its source representation. At most
// ten identity rows repeat one literal site; all remaining literal sites repeat
// at most twice. This is a guarded source-derived syntax envelope, not a
// configurable output floor. Dynamic text, asset URLs and line spans follow.
const htmlRevisionSigningLiteralSyntaxBytesV1 int64 = 4438

type htmlRevisionBodyOutputComponentsV1 struct {
	contentEnvelopeJSONBytes, bodyHTMLBytes, signingHTMLBytes, planJSONBytes int64
	expressionBytes                                                          int64
}

func htmlRevisionBodyOutputComponentsForV1(master htmlmaster.Master, input htmlsource.Input, out htmlRevisionCanonicalOutputComponentsV1, record htmlRevisionRecordComponentsV1) (htmlRevisionBodyOutputComponentsV1, error) {
	var r htmlRevisionBodyOutputComponentsV1
	// Materialize checks this exact byte ceiling BEFORE every buffer write.
	// The original values/sections maps include ALL declared names, with omitted
	// optional values empty and omitted sections populated from actual defaults.
	r.bodyHTMLBytes = htmlmaster.MaxMaterializedBytes
	content := int64(len("{\"master_digest\":\"\",\"values\":{},\"sections\":{},\"html_digest\":\"\"}") + 2*64)
	for _, v := range master.Values {
		if !htmlInputAddV1(&content, int64(len(v.Name)+len(input.Values[v.Name])), 6) || !htmlInputAddV1(&content, 1, 8) {
			return r, ErrHTMLRevisionSourceV1
		}
	}
	for _, v := range master.Sections {
		text, overridden := input.Sections[v.Name]
		if !overridden {
			text = v.DefaultText
		}
		if !htmlInputAddV1(&content, int64(len(v.Name)+len(text)), 6) || !htmlInputAddV1(&content, 1, 8) {
			return r, ErrHTMLRevisionSourceV1
		}
	}
	r.contentEnvelopeJSONBytes = content
	// Both maps' original/current row and hash-table work is separately included,
	// even when every declared string is empty. Their strings alias the retained
	// original immutable Input/master and are never refunded by this helper.
	values, err := htmlRevisionRetentionMapV1(len(master.Values))
	if err != nil {
		return r, err
	}
	sections, err := htmlRevisionRetentionMapV1(len(master.Sections))
	if err != nil {
		return r, err
	}
	changed := int64(len(master.Sections)) * int64(unsafe.Sizeof(""))
	if !htmlInputAddV1(&r.expressionBytes, values, 1) || !htmlInputAddV1(&r.expressionBytes, sections, 1) ||
		!htmlInputAddV1(&r.expressionBytes, changed, 2) || !htmlInputAddV1(&r.expressionBytes, content, 18) ||
		!htmlInputAddV1(&r.expressionBytes, r.bodyHTMLBytes, 5) {
		return r, ErrHTMLRevisionSourceV1
	}
	if master.SchemaVersion != htmlmaster.SigningPageSchemaVersion {
		return r, nil
	}
	textBytes := int64(0)
	for _, text := range input.Values {
		if !htmlInputAddV1(&textBytes, int64(len(text)), 1) {
			return r, ErrHTMLRevisionSourceV1
		}
	}
	// A line can flush at most once per input rune; each emitted <span> wrapper
	// is 34 bytes, and html.EscapeString expands one input byte by at most six.
	// 40*N therefore covers all per-character line/escape output even before the
	// existing printable identity checks refuse invalid text. Fixed wrappers for
	// all ten identity fields are included beside the original literal syntax.
	signing := 10*htmlRevisionSigningLiteralSyntaxBytesV1 + 10*34
	if !htmlInputAddV1(&signing, textBytes, 40) {
		return r, ErrHTMLRevisionSourceV1
	}
	if master.SigningPage != nil {
		policy := master.SigningPage
		if !htmlInputAddV1(&signing, int64(len(policy.LogoAlt)), 6) {
			return r, ErrHTMLRevisionSourceV1
		}
		for _, asset := range master.Assets {
			if asset.Name != policy.LogoAsset {
				continue
			}
			url := int64(len("data:") + len(asset.MediaType) + len(";base64,") + base64.StdEncoding.EncodedLen(base64.StdEncoding.DecodedLen(len(asset.DataBase64))))
			if !htmlInputAddV1(&signing, url, 6) {
				return r, ErrHTMLRevisionSourceV1
			}
		}
		b := policy.Branding
		for _, color := range [...]string{b.SurfaceHex, b.TextHex, b.AccentHex, b.PrimaryHex, b.PrimaryHex, b.MutedHex, b.SignatureColor, b.MutedHex, b.MutedHex} {
			if !htmlInputAddV1(&signing, int64(len(color)), 1) {
				return r, ErrHTMLRevisionSourceV1
			}
		}
	}
	r.signingHTMLBytes = signing
	// The complete canonical Master output envelope includes its entire policy
	// object. Party values are unique compiled profile references; the full typed
	// Values map envelope covers all selected value bytes. Fixed party output
	// names, two slots and root keys are explicit; bindings use their real typed
	// source component. This does not Marshal any unpriced value.
	plan := int64(len("{\"policy\":{},\"parties\":[],\"bindings\":[]}"))
	for _, key := range [...]string{"slot", "company_name", "company_id", "representative_name", "representative_email", "representative_authority"} {
		if !htmlInputAddV1(&plan, int64(len(key)+4), 2) {
			return r, ErrHTMLRevisionSourceV1
		}
	}
	for _, n := range []int64{out.masterJSONBytes, record.valuesJSONBytes, record.bindingsJSONBytes, 2 * int64(len("provider")+len("customer")+8)} {
		if !htmlInputAddV1(&plan, n, 1) {
			return r, ErrHTMLRevisionSourceV1
		}
	}
	r.planJSONBytes = plan
	// One signingPlanDigest performs ONE SigningPageHTML and one typed plan
	// Marshal. Builder growth/old-new/result strings, line buffers, escaping and
	// format output all remain logical expression debt through that call.
	if !htmlInputAddV1(&r.expressionBytes, signing, 10) || !htmlInputAddV1(&r.expressionBytes, plan, 18) {
		return r, ErrHTMLRevisionSourceV1
	}
	return r, nil
}

// One concrete Record stage: one unchanged Materialize, plus schema3's exact
// SigningPageHTML -> readiness -> typed plan, plus the original source and
// variables encoders/parsers. No Compile is dispatched in this stage.
// canonicalScratch is the actual already-inspected canonical model's logical
// DOM/parser class, reused serially, not a measured executor/RSS translation.
func htmlRevisionRecordStageComponentsV1(master htmlmaster.Master, input htmlsource.Input, record htmlRevisionRecordComponentsV1, out htmlRevisionCanonicalOutputComponentsV1, canonicalScratch int64) (scratch, retained int64, failure error) {
	if canonicalScratch < 0 {
		return 0, 0, ErrHTMLRevisionSourceV1
	}
	readiness, err := htmlRevisionContractReadinessComponentsForV1(master, htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		return 0, 0, err
	}
	outputs, err := htmlRevisionBodyOutputComponentsForV1(master, input, out, record)
	if err != nil {
		return 0, 0, err
	}
	calls := int64(1)
	if master.SchemaVersion == htmlmaster.SigningPageSchemaVersion {
		calls = 4
	}
	scratch = canonicalScratch
	if !htmlInputAddV1(&scratch, readiness.parentBytes, calls) {
		return 0, 0, ErrHTMLRevisionSourceV1
	}
	for _, n := range []int64{outputs.expressionBytes, record.sourceCommitmentEncoderBytes, record.originValuesEncoderBytes,
		record.variablesParserBytes, record.originVariablesParserBytes} {
		if !htmlInputAddV1(&scratch, n, 1) {
			return 0, 0, ErrHTMLRevisionSourceV1
		}
	}
	retained = record.valuesJSONBytes
	// Finish retains an independent changed-section header slice after Record
	// scratch is reused. Names alias the separately retained compiled design.
	if !htmlRevisionRetentionAllocV1(&retained, int64(len(master.Sections))*int64(unsafe.Sizeof(""))) {
		return 0, 0, ErrHTMLRevisionSourceV1
	}
	if !htmlInputAddV1(&retained, 64, 2) {
		return 0, 0, ErrHTMLRevisionSourceV1
	}
	return scratch, retained, nil
}
