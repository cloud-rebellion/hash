// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"math"
	"runtime"
	"runtime/debug"
	"strconv"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

var errHTMLAuthoringJSONShapeV1 = errors.New("invalid HTML command JSON structure")

type htmlInputNodeV1 uint8

const (
	htmlInputScalarV1 htmlInputNodeV1 = iota
	htmlInputMasterInputV1
	htmlInputApprovalV1
	htmlInputPreviewV1
	htmlInputDocumentV1
	htmlInputCloseV1
	htmlInputMasterV1
	htmlInputValueV1
	htmlInputSectionV1
	htmlInputAssetV1
	htmlInputContractV1
	htmlInputPartyV1
	htmlInputTermV1
	htmlInputSigningV1
	htmlInputBrandingV1
	htmlInputCandidateV1
	htmlInputMappingV1
	htmlInputSearchV1
	htmlInputObservationV1
	htmlInputPopulationV1
	htmlInputStringMapV1
	htmlInputValuesV1
	htmlInputSectionsV1
	htmlInputAssetsV1
	htmlInputPartiesV1
	htmlInputTermsV1
	htmlInputMappingsV1
	htmlInputRevisionV1
)

type htmlInputFieldV1 struct {
	name string
	node htmlInputNodeV1
}

var htmlInputMasterInputV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"html_master_json", htmlInputMasterV1},
	{"variables_json", htmlInputStringMapV1},
	{"expected_version", htmlInputScalarV1},
}
var htmlInputRevisionV1Fields = [...]htmlInputFieldV1{{"expected_updated_at", htmlInputScalarV1}, {"expected_html_source_commitment", htmlInputScalarV1}, {"values", htmlInputStringMapV1}, {"sections", htmlInputStringMapV1}, {"summary", htmlInputScalarV1}}
var htmlInputApprovalV1Fields = [...]htmlInputFieldV1{
	{"expected_version", htmlInputScalarV1},
	{"expected_content_sha256", htmlInputScalarV1},
	{"preview_receipt", htmlInputScalarV1},
	{"expected_preview_pdf_sha256", htmlInputScalarV1},
}
var htmlInputPreviewV1Fields = [...]htmlInputFieldV1{
	{"expected_version", htmlInputScalarV1},
	{"expected_content_sha256", htmlInputScalarV1},
	{"values", htmlInputStringMapV1},
	{"sections", htmlInputStringMapV1},
}
var htmlInputDocumentV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"expected_template_version", htmlInputScalarV1},
	{"expected_template_content_sha256", htmlInputScalarV1},
	{"values", htmlInputStringMapV1},
	{"sections", htmlInputStringMapV1},
	{"expires_at", htmlInputScalarV1},
	{"request_id", htmlInputScalarV1},
	{"expected_org_id", htmlInputScalarV1},
	{"expected_user_id", htmlInputScalarV1},
	{"crm_population", htmlInputPopulationV1},
}
var htmlInputCloseV1Fields = [...]htmlInputFieldV1{
	{"expected_org_id", htmlInputScalarV1},
	{"expected_user_id", htmlInputScalarV1},
	{"confirmed", htmlInputScalarV1},
}
var htmlInputMasterV1Fields = [...]htmlInputFieldV1{
	{"schema_version", htmlInputScalarV1},
	{"html", htmlInputScalarV1},
	{"css", htmlInputScalarV1},
	{"values", htmlInputValuesV1},
	{"sections", htmlInputSectionsV1},
	{"assets", htmlInputAssetsV1},
	{"contract_profile", htmlInputContractV1},
	{"signing_page", htmlInputSigningV1},
}
var htmlInputValueV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"required", htmlInputScalarV1},
	{"max_chars", htmlInputScalarV1},
}
var htmlInputSectionV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"default_text", htmlInputScalarV1},
	{"max_chars", htmlInputScalarV1},
}
var htmlInputAssetV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"media_type", htmlInputScalarV1},
	{"data_base64", htmlInputScalarV1},
	{"sha256", htmlInputScalarV1},
}
var htmlInputContractV1Fields = [...]htmlInputFieldV1{
	{"id", htmlInputScalarV1},
	{"version", htmlInputScalarV1},
	{"kind", htmlInputScalarV1},
	{"parties", htmlInputPartiesV1},
	{"terms", htmlInputTermsV1},
}
var htmlInputPartyV1Fields = [...]htmlInputFieldV1{
	{"slot", htmlInputScalarV1},
	{"company_name", htmlInputScalarV1},
	{"company_id", htmlInputScalarV1},
	{"representative_name", htmlInputScalarV1},
	{"representative_email", htmlInputScalarV1},
	{"representative_authority", htmlInputScalarV1},
}
var htmlInputTermV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"value", htmlInputScalarV1},
	{"section", htmlInputScalarV1},
}
var htmlInputSigningV1Fields = [...]htmlInputFieldV1{
	{"version", htmlInputScalarV1},
	{"policy", htmlInputScalarV1},
	{"branding", htmlInputBrandingV1},
	{"logo_asset", htmlInputScalarV1},
	{"logo_sha256", htmlInputScalarV1},
	{"logo_alt", htmlInputScalarV1},
	{"font_sha256", htmlInputScalarV1},
}
var htmlInputBrandingV1Fields = [...]htmlInputFieldV1{
	{"primary_hex", htmlInputScalarV1},
	{"accent_hex", htmlInputScalarV1},
	{"surface_hex", htmlInputScalarV1},
	{"text_hex", htmlInputScalarV1},
	{"muted_hex", htmlInputScalarV1},
	{"logo_url", htmlInputScalarV1},
	{"logo_alt", htmlInputScalarV1},
	{"font_heading", htmlInputScalarV1},
	{"font_body", htmlInputScalarV1},
	{"signature_color", htmlInputScalarV1},
}
var htmlInputCandidateV1Fields = [...]htmlInputFieldV1{
	{"name", htmlInputScalarV1},
	{"values", htmlInputStringMapV1},
	{"sections", htmlInputStringMapV1},
	{"expires_at", htmlInputScalarV1},
}
var htmlInputMappingV1Fields = [...]htmlInputFieldV1{
	{"variable", htmlInputScalarV1},
	{"source_kind", htmlInputScalarV1},
	{"source_ref", htmlInputScalarV1},
	{"source_path", htmlInputScalarV1},
}
var htmlInputSearchV1Fields = [...]htmlInputFieldV1{
	{"expected_org_id", htmlInputScalarV1},
	{"expected_user_id", htmlInputScalarV1},
	{"expected_template_version", htmlInputScalarV1},
	{"expected_template_content_sha256", htmlInputScalarV1},
	{"expected_template_approved_by", htmlInputScalarV1},
	{"expected_template_approved_at", htmlInputScalarV1},
	{"expected_connection_id", htmlInputScalarV1},
	{"expected_connection_generation", htmlInputScalarV1},
	{"kind", htmlInputScalarV1},
	{"query", htmlInputScalarV1},
	{"offset", htmlInputScalarV1},
}
var htmlInputObservationV1Fields = [...]htmlInputFieldV1{
	{"expected_org_id", htmlInputScalarV1},
	{"expected_user_id", htmlInputScalarV1},
	{"expected_template_version", htmlInputScalarV1},
	{"expected_template_content_sha256", htmlInputScalarV1},
	{"expected_template_approved_by", htmlInputScalarV1},
	{"expected_template_approved_at", htmlInputScalarV1},
	{"expected_connection_id", htmlInputScalarV1},
	{"expected_connection_generation", htmlInputScalarV1},
	{"candidate", htmlInputCandidateV1},
	{"mappings", htmlInputMappingsV1},
}
var htmlInputPopulationV1Fields = [...]htmlInputFieldV1{
	{"expected_org_id", htmlInputScalarV1},
	{"expected_user_id", htmlInputScalarV1},
	{"expected_template_version", htmlInputScalarV1},
	{"expected_template_content_sha256", htmlInputScalarV1},
	{"expected_template_approved_by", htmlInputScalarV1},
	{"expected_template_approved_at", htmlInputScalarV1},
	{"expected_connection_id", htmlInputScalarV1},
	{"expected_connection_generation", htmlInputScalarV1},
	{"mappings", htmlInputMappingsV1},
	{"reviewed_digest", htmlInputScalarV1},
	{"review_receipt", htmlInputScalarV1},
	{"confirmed", htmlInputScalarV1},
}

func htmlInputFieldsV1(n htmlInputNodeV1) []htmlInputFieldV1 {
	if fields := htmlRevisionCanonicalFieldsV1(n); fields != nil {
		return fields
	}
	switch n {
	case htmlInputRevisionV1:
		return htmlInputRevisionV1Fields[:]
	case htmlInputMasterInputV1:
		return htmlInputMasterInputV1Fields[:]
	case htmlInputApprovalV1:
		return htmlInputApprovalV1Fields[:]
	case htmlInputPreviewV1:
		return htmlInputPreviewV1Fields[:]
	case htmlInputDocumentV1:
		return htmlInputDocumentV1Fields[:]
	case htmlInputCloseV1:
		return htmlInputCloseV1Fields[:]
	case htmlInputMasterV1:
		return htmlInputMasterV1Fields[:]
	case htmlInputValueV1:
		return htmlInputValueV1Fields[:]
	case htmlInputSectionV1:
		return htmlInputSectionV1Fields[:]
	case htmlInputAssetV1:
		return htmlInputAssetV1Fields[:]
	case htmlInputContractV1:
		return htmlInputContractV1Fields[:]
	case htmlInputPartyV1:
		return htmlInputPartyV1Fields[:]
	case htmlInputTermV1:
		return htmlInputTermV1Fields[:]
	case htmlInputSigningV1:
		return htmlInputSigningV1Fields[:]
	case htmlInputBrandingV1:
		return htmlInputBrandingV1Fields[:]
	case htmlInputCandidateV1:
		return htmlInputCandidateV1Fields[:]
	case htmlInputMappingV1:
		return htmlInputMappingV1Fields[:]
	case htmlInputSearchV1:
		return htmlInputSearchV1Fields[:]
	case htmlInputObservationV1:
		return htmlInputObservationV1Fields[:]
	case htmlInputPopulationV1:
		return htmlInputPopulationV1Fields[:]
	}
	return nil
}
func htmlInputArrayV1(n htmlInputNodeV1) (htmlInputNodeV1, int) {
	if child, bound := htmlRevisionCanonicalArrayV1(n); bound != 0 {
		return child, bound
	}
	switch n {
	case htmlInputValuesV1:
		return htmlInputValueV1, htmlmaster.MaxDefinitions
	case htmlInputSectionsV1:
		return htmlInputSectionV1, htmlmaster.MaxDefinitions
	case htmlInputAssetsV1:
		return htmlInputAssetV1, htmlmaster.MaxAssets
	case htmlInputPartiesV1:
		return htmlInputPartyV1, 2
	case htmlInputTermsV1:
		return htmlInputTermV1, 16
	case htmlInputMappingsV1:
		return htmlInputMappingV1, crmconnection.MaxRecordReferences
	}
	return htmlInputScalarV1, 0
}
func htmlAuthoringInputLimitV1(p HTMLAuthoringInputProfileV1) (int64, error) {
	switch p {
	case HTMLTemplateMasterInputV1:
		return htmlmaster.MaxMasterJSONBytes + (2 << 20), nil
	case HTMLTemplateApprovalInputV1, HTMLTemplatePreviewInputV1, HTMLDocumentCreationInputV1, HTMLDocumentRevisionInputV1:
		return 1 << 20, nil
	case HTMLCRMTemplateSearchInputV1:
		return 16 << 10, nil
	case HTMLCRMTemplateObservationInputV1:
		return 256 << 10, nil
	case HTMLCreationClosureInputV1:
		return 2 << 10, nil
	}
	return 0, ErrHTMLAuthoringInputV1
}
func htmlInputRootV1(p HTMLAuthoringInputProfileV1) htmlInputNodeV1 {
	switch p {
	case HTMLTemplateMasterInputV1:
		return htmlInputMasterInputV1
	case HTMLTemplateApprovalInputV1:
		return htmlInputApprovalV1
	case HTMLTemplatePreviewInputV1:
		return htmlInputPreviewV1
	case HTMLDocumentCreationInputV1:
		return htmlInputDocumentV1
	case HTMLCRMTemplateSearchInputV1:
		return htmlInputSearchV1
	case HTMLCRMTemplateObservationInputV1:
		return htmlInputObservationV1
	case HTMLDocumentRevisionInputV1:
		return htmlInputRevisionV1
	case HTMLCreationClosureInputV1:
		return htmlInputCloseV1
	}
	return htmlInputScalarV1
}

type htmlAuthoringInputShapeV1 struct {
	raw, strings, stringBytes, scalars, objects, arrays, tableSlots, arraySlots, depth int64
	masterStart, masterEnd, defaultsStart, defaultsEnd                                 int
}
type htmlInputScanV1 struct {
	ctx        context.Context
	raw        []byte
	pos, check int
	shape      htmlAuthoringInputShapeV1
}

// Finite route-specific schema paths are a pre-allocation refusal filter only.
// All accepted bytes still cross the original duplicate/exact-name/typed/null
// decoders. No arbitrary metadata schema or generic member ceiling is added.
func htmlAuthoringInputShapeForV1(ctx context.Context, profile HTMLAuthoringInputProfileV1, raw []byte) (htmlAuthoringInputShapeV1, error) {
	return htmlAuthoringInputRootShapeV1(ctx, htmlInputRootV1(profile), raw)
}
func htmlAuthoringInputRootShapeV1(ctx context.Context, root htmlInputNodeV1, raw []byte) (htmlAuthoringInputShapeV1, error) {
	if root == htmlInputScalarV1 || !utf8.Valid(raw) {
		return htmlAuthoringInputShapeV1{}, errHTMLAuthoringJSONShapeV1
	}
	p := htmlInputScanV1{ctx: ctx, raw: raw, shape: htmlAuthoringInputShapeV1{raw: int64(len(raw))}}
	p.space()
	if p.pos == len(raw) || raw[p.pos] != '{' {
		return p.shape, errHTMLAuthoringJSONShapeV1
	}
	if err := p.value(root, 0); err != nil {
		return p.shape, err
	}
	p.space()
	if p.pos != len(raw) {
		return p.shape, errHTMLAuthoringJSONShapeV1
	}
	return p.shape, nil
}
func (p *htmlInputScanV1) poll() error {
	if p.pos >= p.check {
		p.check = p.pos + 4096
		if err := p.ctx.Err(); err != nil {
			return errors.Join(ErrHTMLAuthoringInputV1, err)
		}
	}
	return nil
}
func (p *htmlInputScanV1) space() {
	for p.pos < len(p.raw) {
		b := p.raw[p.pos]
		if b != ' ' && b != '\n' && b != '\r' && b != '\t' {
			return
		}
		p.pos++
	}
}
func (p *htmlInputScanV1) str() (int, int, error) {
	start := p.pos
	p.pos++
	p.shape.strings++
	for p.pos < len(p.raw) {
		if err := p.poll(); err != nil {
			return 0, 0, err
		}
		b := p.raw[p.pos]
		p.pos++
		if b == '"' {
			p.shape.stringBytes += int64(p.pos - start - 2)
			return start, p.pos, nil
		}
		if b < 0x20 {
			return 0, 0, errHTMLAuthoringJSONShapeV1
		}
		if b == '\\' {
			if p.pos == len(p.raw) {
				return 0, 0, errHTMLAuthoringJSONShapeV1
			}
			b = p.raw[p.pos]
			p.pos++
			if b == 'u' {
				for i := 0; i < 4; i++ {
					if p.pos == len(p.raw) || htmlInputHexV1(p.raw[p.pos]) < 0 {
						return 0, 0, errHTMLAuthoringJSONShapeV1
					}
					p.pos++
				}
			} else if b != '"' && b != '\\' && b != '/' && b != 'b' && b != 'f' && b != 'n' && b != 'r' && b != 't' {
				return 0, 0, errHTMLAuthoringJSONShapeV1
			}
		}
	}
	return 0, 0, errHTMLAuthoringJSONShapeV1
}
func htmlInputHexV1(b byte) int {
	switch {
	case b >= '0' && b <= '9':
		return int(b - '0')
	case b >= 'a' && b <= 'f':
		return int(b-'a') + 10
	case b >= 'A' && b <= 'F':
		return int(b-'A') + 10
	}
	return -1
}
func htmlInputKeyEqualV1(raw []byte, start, end int, want string) bool {
	at := 0
	for i := start + 1; i < end-1; {
		b := raw[i]
		i++
		if b == '\\' {
			b = raw[i]
			i++
			switch b {
			case 'u':
				v := 0
				for j := 0; j < 4; j++ {
					v = 16*v + htmlInputHexV1(raw[i])
					i++
				}
				if v > 127 {
					return false
				}
				b = byte(v)
			case 'b':
				b = '\b'
			case 'f':
				b = '\f'
			case 'n':
				b = '\n'
			case 'r':
				b = '\r'
			case 't':
				b = '\t'
			}
		}
		if at == len(want) || b != want[at] {
			return false
		}
		at++
	}
	return at == len(want)
}
func htmlInputPowerV1(n int64) int64 {
	p := int64(1)
	for p < n {
		p *= 2
	}
	return p
}
func (p *htmlInputScanV1) value(node htmlInputNodeV1, depth int) error {
	// The acyclic typed request schemas have maximum container depth five.
	// Eight frames leave room for the outer master/CRM wrappers, not new content.
	if depth > 8 {
		return errHTMLAuthoringJSONShapeV1
	}
	if int64(depth) > p.shape.depth {
		p.shape.depth = int64(depth)
	}
	p.space()
	if err := p.poll(); err != nil {
		return err
	}
	if p.pos == len(p.raw) {
		return errHTMLAuthoringJSONShapeV1
	}
	b := p.raw[p.pos]
	if b == '{' {
		fields := htmlInputFieldsV1(node)
		bound := len(fields)
		if node == htmlInputStringMapV1 {
			bound = htmlmaster.MaxDefinitions
		} else if bound == 0 {
			return errHTMLAuthoringJSONShapeV1
		}
		p.pos++
		p.shape.objects++
		p.space()
		members := 0
		if p.pos < len(p.raw) && p.raw[p.pos] == '}' {
			p.pos++
			p.shape.tableSlots += 16
			return nil
		}
		for {
			p.space()
			if p.pos == len(p.raw) || p.raw[p.pos] != '"' {
				return errHTMLAuthoringJSONShapeV1
			}
			start, end, err := p.str()
			if err != nil {
				return err
			}
			child := htmlInputScalarV1
			if node != htmlInputStringMapV1 {
				found := false
				for _, f := range fields {
					if htmlInputKeyEqualV1(p.raw, start, end, f.name) {
						child = f.node
						found = true
						break
					}
				}
				if !found {
					return errHTMLAuthoringJSONShapeV1
				}
			}
			members++
			if members > bound {
				return errHTMLAuthoringJSONShapeV1
			}
			p.space()
			if p.pos == len(p.raw) || p.raw[p.pos] != ':' {
				return errHTMLAuthoringJSONShapeV1
			}
			p.pos++
			at := p.pos
			if err := p.value(child, depth+1); err != nil {
				return err
			}
			if node == htmlRevisionSourceNodeV1 && depth == 0 {
				if htmlInputKeyEqualV1(p.raw, start, end, "master") {
					p.shape.masterStart = at
					p.shape.masterEnd = p.pos
				}
				if htmlInputKeyEqualV1(p.raw, start, end, "default_values") {
					p.shape.defaultsStart = at
					p.shape.defaultsEnd = p.pos
				}
			}
			if node == htmlInputMasterInputV1 && depth == 0 {
				if htmlInputKeyEqualV1(p.raw, start, end, "html_master_json") {
					p.shape.masterStart = at
					p.shape.masterEnd = p.pos
				}
				if htmlInputKeyEqualV1(p.raw, start, end, "variables_json") {
					p.shape.defaultsStart = at
					p.shape.defaultsEnd = p.pos
				}
			}
			p.space()
			if p.pos == len(p.raw) {
				return errHTMLAuthoringJSONShapeV1
			}
			b = p.raw[p.pos]
			p.pos++
			if b == '}' {
				p.shape.tableSlots += 2 * htmlInputPowerV1(max(8, (int64(members)*8+6)/7))
				return nil
			}
			if b != ',' {
				return errHTMLAuthoringJSONShapeV1
			}
		}
	}
	if b == '[' {
		child, bound := htmlInputArrayV1(node)
		if bound == 0 {
			return errHTMLAuthoringJSONShapeV1
		}
		p.pos++
		p.shape.arrays++
		p.space()
		items := 0
		if p.pos < len(p.raw) && p.raw[p.pos] == ']' {
			p.pos++
			return nil
		}
		for {
			items++
			if items > bound {
				return errHTMLAuthoringJSONShapeV1
			}
			if err := p.value(child, depth+1); err != nil {
				return err
			}
			p.space()
			if p.pos == len(p.raw) {
				return errHTMLAuthoringJSONShapeV1
			}
			b = p.raw[p.pos]
			p.pos++
			if b == ']' {
				p.shape.arraySlots += 2 * htmlInputPowerV1(int64(items))
				return nil
			}
			if b != ',' {
				return errHTMLAuthoringJSONShapeV1
			}
		}
	}
	if b == '"' {
		_, _, err := p.str()
		return err
	}
	p.shape.scalars++
	for _, lit := range [...]string{"true", "false", "null"} {
		if len(p.raw)-p.pos < len(lit) {
			continue
		}
		equal := true
		for i := 0; i < len(lit); i++ {
			if p.raw[p.pos+i] != lit[i] {
				equal = false
				break
			}
		}
		if equal {
			p.pos += len(lit)
			return nil
		}
	}
	if b == '-' {
		p.pos++
		if p.pos == len(p.raw) {
			return errHTMLAuthoringJSONShapeV1
		}
	}
	if p.raw[p.pos] == '0' {
		p.pos++
	} else {
		if p.raw[p.pos] < '1' || p.raw[p.pos] > '9' {
			return errHTMLAuthoringJSONShapeV1
		}
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
			if err := p.poll(); err != nil {
				return err
			}
		}
	}
	if p.pos < len(p.raw) && p.raw[p.pos] == '.' {
		p.pos++
		at := p.pos
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
			if err := p.poll(); err != nil {
				return err
			}
		}
		if p.pos == at {
			return errHTMLAuthoringJSONShapeV1
		}
	}
	if p.pos < len(p.raw) && (p.raw[p.pos] == 'e' || p.raw[p.pos] == 'E') {
		p.pos++
		if p.pos < len(p.raw) && (p.raw[p.pos] == '+' || p.raw[p.pos] == '-') {
			p.pos++
		}
		at := p.pos
		for p.pos < len(p.raw) && p.raw[p.pos] >= '0' && p.raw[p.pos] <= '9' {
			p.pos++
			if err := p.poll(); err != nil {
				return err
			}
		}
		if p.pos == at {
			return errHTMLAuthoringJSONShapeV1
		}
	}
	return nil
}

// Pinned 64-bit Go1.26.9 model: decoder buffers grow 2*cap+512; strings
// unquote into encodedLen+8 then at most one copied string. Each bounded map
// stays below a 1024-slot table split (largest request map64 entries); growth
// slots include all old groups. Typed element/header maxima are from the fixed
// request structs, not arbitrary any/RawMessage producer declarations.
func htmlInputAddV1(total *int64, count, unit int64) bool {
	if count < 0 || unit < 0 || count > math.MaxInt64/max(1, unit) || *total > math.MaxInt64-count*unit {
		return false
	}
	*total += count * unit
	return true
}

var htmlAuthoringInputRuntimeOKV1 = func() bool {
	if runtime.Version() != "go1.26.9" || strconv.IntSize != 64 {
		return false
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOEXPERIMENT" && setting.Value != "" {
			return false
		}
	}
	return true
}()

func htmlAuthoringInputReadResourcesV1(limit int64) (int64, error) {
	if !htmlAuthoringInputRuntimeOKV1 {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	buffer := ((limit + 1 + 8191) / 8192) * 8192
	if !htmlInputAddV1(&n, 1, buffer) || !htmlInputAddV1(&n, 2*9, 512) || !htmlInputAddV1(&n, 1, 4096) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return n, nil
}
func htmlAuthoringInputParserArenaV1(s htmlAuthoringInputShapeV1, passes int64) (int64, error) {
	n := int64(0)
	// Map slot includes string key16B plus largest typed value64B; class rounding
	// and old growth slots explicit. Each source is scanned before its decoders.
	for _, part := range [][2]int64{{s.raw, 8}, {s.stringBytes, 2}, {s.strings, 64}, {s.scalars, 8192}, {s.tableSlots, 2 * (80 + 1)}, {s.objects, 2 * 16 * 256}, {s.arraySlots, 2 * 256}, {s.depth + 1, 2 * 512}, {1, 4096}} {
		if !htmlInputAddV1(&n, part[0], part[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	total := int64(0)
	if !htmlInputAddV1(&total, n, passes) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return total, nil
}
func htmlAuthoringInputParseResourcesV1(profile HTMLAuthoringInputProfileV1, s htmlAuthoringInputShapeV1) (int64, error) {
	passes := int64(8)
	if profile == HTMLTemplateMasterInputV1 {
		passes = 15
	}
	total, err := htmlAuthoringInputParserArenaV1(s, passes)
	if err != nil {
		return 0, err
	}
	// Four typed command outputs:6xHTMLescape*(2encoderbacking+1resultcopy).
	// Command clones and input-sized errors are separately priced. No arbitrary
	// RawMessage numeric-exponent factor supplies a serialization allowance.
	if profile != HTMLTemplateMasterInputV1 {
		for _, part := range [][2]int64{{s.stringBytes, 72}, {s.strings, 32}, {s.scalars, 80}, {s.arraySlots, 2048}, {s.raw, 12}, {1, 4096}} {
			if !htmlInputAddV1(&total, part[0], part[1]) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	return total, nil
}
