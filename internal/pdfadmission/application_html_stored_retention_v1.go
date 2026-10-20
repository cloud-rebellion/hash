// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"unsafe"
)

// Retained components are independent of the serialized canonical scratch peak.
// The fixed native producer derives all inputs from its private admitted source.
// No resource declaration, callback, external source or allocator/RSS refund.
type htmlStoredCanonicalOutputV1 struct{ masterJSONBytes, defaultsJSONBytes int64 }

func htmlStoredRetentionAllocV1(total *int64, n int64) bool {
	if n < 0 {
		return false
	}
	if n == 0 {
		return true
	}
	// Pinned Go64 allocator classes: <=2*n plus a tiny-allocation16B allowance.
	// Large-page rounding is below2*n; tiny string/byte copies need the explicit
	// constant even when n==1. No universal2xsmall-string assumption is made.
	return htmlInputAddV1(total, n, 2) && htmlInputAddV1(total, 1, 16)
}
func htmlStoredRetentionFinishV1(n int64) (int64, error) {
	if !htmlAuthoringInputRuntimeOKV1 || n < 0 {
		return 0, ErrHTMLAuthoringInputV1
	}
	rounded := n
	if !htmlInputAddV1(&rounded, 1, 8191) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return rounded / 8192 * 8192, nil
}
func htmlStoredRetentionMasterShapeV1(m htmlmaster.Master) bool {
	return len(m.Values) <= htmlmaster.MaxDefinitions && len(m.Sections) <= htmlmaster.MaxDefinitions && len(m.Assets) <= htmlmaster.MaxAssets && (m.ContractProfile == nil || (len(m.ContractProfile.Parties) <= 2 && len(m.ContractProfile.Terms) <= 16))
}

// The fixed typed clone code copies these headers/arrays/profile/policy, but
// shares immutable string backing with the privately retained source model.
// Parser-created master string storage is priced separately below.
func htmlStoredPreparedMasterProjectionV1(m htmlmaster.Master) (int64, error) {
	if !htmlStoredRetentionMasterShapeV1(m) {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	for _, size := range []int64{int64(unsafe.Sizeof(htmlmaster.Master{})), int64(len(m.Values)) * int64(unsafe.Sizeof(htmlmaster.Value{})), int64(len(m.Sections)) * int64(unsafe.Sizeof(htmlmaster.Section{})), int64(len(m.Assets)) * int64(unsafe.Sizeof(htmlmaster.Asset{}))} {
		if !htmlStoredRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	if p := m.ContractProfile; p != nil {
		for _, size := range []int64{int64(unsafe.Sizeof(*p)), int64(len(p.Parties)) * int64(unsafe.Sizeof(htmlmaster.ContractParty{})), int64(len(p.Terms)) * int64(unsafe.Sizeof(htmlmaster.ContractTerm{}))} {
			if !htmlStoredRetentionAllocV1(&n, size) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	if p := m.SigningPage; p != nil {
		if !htmlStoredRetentionAllocV1(&n, int64(unsafe.Sizeof(*p))) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlStoredRetentionFinishV1(n)
}

// A parser-created raw/canonical typed Master retains each decoded string in
// addition to its typed projection. Use it for the private builder model, then
// add MasterProjection for any simultaneous MasterV1 inspection-copy arrays.
func htmlStoredPreparedMasterRetentionV1(m htmlmaster.Master) (int64, error) {
	n, err := htmlStoredPreparedMasterProjectionV1(m)
	if err != nil {
		return 0, err
	}
	text := func(value string) bool { return htmlStoredRetentionAllocV1(&n, int64(len(value))) }
	if !text(m.HTML) || !text(m.CSS) {
		return 0, ErrHTMLAuthoringInputV1
	}
	for _, value := range m.Values {
		if !text(value.Name) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, section := range m.Sections {
		if !text(section.Name) || !text(section.DefaultText) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, asset := range m.Assets {
		if !text(asset.Name) || !text(asset.MediaType) || !text(asset.DataBase64) || !text(asset.SHA256) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	if p := m.ContractProfile; p != nil {
		if !text(p.ID) || !text(p.Kind) {
			return 0, ErrHTMLAuthoringInputV1
		}
		for _, party := range p.Parties {
			for _, value := range [...]string{party.Slot, party.CompanyName, party.CompanyID, party.RepresentativeName, party.RepresentativeEmail, party.RepresentativeAuthority} {
				if !text(value) {
					return 0, ErrHTMLAuthoringInputV1
				}
			}
		}
		for _, term := range p.Terms {
			if !text(term.Name) || !text(term.Value) || !text(term.Section) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	if p := m.SigningPage; p != nil {
		for _, value := range [...]string{p.Policy, p.LogoAsset, p.LogoSHA256, p.LogoAlt, p.FontSHA256, p.Branding.PrimaryHex, p.Branding.AccentHex, p.Branding.SurfaceHex, p.Branding.TextHex, p.Branding.MutedHex, p.Branding.LogoURL, p.Branding.LogoAlt, p.Branding.FontHeading, p.Branding.FontBody, p.Branding.SignatureColor} {
			if !text(value) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	return htmlStoredRetentionFinishV1(n)
}

// Same pinned Swiss-map bounded-object/old-growth groups as the reviewed input
// parser model. The slot unit includes key16 plus largest typed value64 and
// control byte; it dominates Value32,Section40,resolvedAsset24 and string16.
// No map here can exceed64 entries or trigger the1024-entry table split.
func htmlStoredRetentionMapV1(n int) (int64, error) {
	if n < 0 || n > htmlmaster.MaxDefinitions {
		return 0, ErrHTMLAuthoringInputV1
	}
	slots := int64(16)
	if n != 0 {
		slots = 2 * htmlInputPowerV1(max(8, (int64(n)*8+6)/7))
	}
	bytes := int64(0)
	for _, part := range [][2]int64{{slots, 2 * (80 + 1)}, {1, 2 * 16 * 256}} {
		if !htmlInputAddV1(&bytes, part[0], part[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return bytes, nil
}

// Compiled retains typed clone arrays, maps, normalized HTML/CSS, renderedCSS,
// canonical bytes/digest, normalized base64 and dataURL strings. It does NOT
// retain decoded image pixels, the HTML parse tree or regex working queues.
// Actual raw and actual canonical models are priced independently; no compiler
// equivalence or caller-supplied geometry/cost becomes authority.
func htmlStoredPreparedCompiledRetentionV1(m htmlmaster.Master, s htmlInputCanonicalStatsV1, out htmlStoredCanonicalOutputV1) (int64, error) {
	if !htmlStoredRetentionMasterShapeV1(m) || s.tokens < 0 || s.tokens > 20000 || s.formatStarts < 0 || s.formatStarts > s.tokens || s.formatEnds < 0 || s.formatEnds > s.tokens || s.cssTokens < 0 || s.cssTokens > 20001 || s.cssURIs < 0 || s.maxAssetURL < 0 || s.maxTagOutput < 0 || out.masterJSONBytes < 0 {
		return 0, ErrHTMLAuthoringInputV1
	}
	n, err := htmlStoredPreparedMasterProjectionV1(m)
	if err != nil {
		return 0, err
	}
	if !htmlStoredRetentionAllocV1(&n, int64(unsafe.Sizeof(htmlmaster.Compiled{}))) || !htmlStoredRetentionAllocV1(&n, 64) || !htmlStoredRetentionAllocV1(&n, out.masterJSONBytes) {
		return 0, ErrHTMLAuthoringInputV1
	}
	for _, count := range [...]int{len(m.Values), len(m.Sections), len(m.Assets)} {
		storage, err := htmlStoredRetentionMapV1(count)
		if err != nil || !htmlInputAddV1(&n, storage, 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	clones := (s.tokens+1)*min(s.formatStarts, int64(513)) + 32*s.formatEnds
	htmlBytes := int64(0)
	if !htmlInputAddV1(&htmlBytes, int64(len(m.HTML)), 6) || !htmlInputAddV1(&htmlBytes, s.tokens+1, 32) || !htmlInputAddV1(&htmlBytes, clones, s.maxTagOutput) || !htmlInputAddV1(&htmlBytes, 1, 512) {
		return 0, ErrHTMLAuthoringInputV1
	}
	htmlBytes = min(htmlBytes, int64(htmlmaster.MaxHTMLBytes))
	cssBase := int64(0)
	if !htmlInputAddV1(&cssBase, int64(len(m.CSS)), 12) || !htmlInputAddV1(&cssBase, s.cssTokens+1, 32) {
		return 0, ErrHTMLAuthoringInputV1
	}
	cssBytes := min(cssBase, int64(htmlmaster.MaxCSSBytes))
	renderedCSS := cssBase
	assetURL := s.maxAssetURL
	if !htmlInputAddV1(&assetURL, 1, 7) || !htmlInputAddV1(&renderedCSS, s.cssURIs, assetURL) {
		return 0, ErrHTMLAuthoringInputV1
	}
	renderedCSS = min(renderedCSS, int64(htmlmaster.MaxMaterializedBytes/2))
	// These caps apply to SUCCESSFUL retained Compiled results only; unchanged
	// full CanonicalResources prices failure-path render/encoder allocations.
	for _, size := range [...]int64{htmlBytes, cssBytes, renderedCSS} {
		if !htmlStoredRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, asset := range m.Assets {
		// Strict StdEncoding may discard CR/LF; canonical base64 never grows beyond
		// the actual original spelling. dataURL prefix/normalized payload are ASCII.
		normalized := int64(len(asset.DataBase64))
		url := normalized
		if !htmlInputAddV1(&url, int64(len("data:")+len(asset.MediaType)+len(";base64,")), 1) || !htmlStoredRetentionAllocV1(&n, normalized) || !htmlStoredRetentionAllocV1(&n, url) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlStoredRetentionFinishV1(n)
}

// Private TemplateCommitment retained after CanonicalTemplate, including its
// produced default map encoding even if larger than a future strict-input cap.
func htmlStoredPreparedTemplateRetentionV1(out htmlStoredCanonicalOutputV1) (int64, error) {
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(htmlmaster.TemplateCommitment{})), out.masterJSONBytes, out.defaultsJSONBytes, 64} {
		if !htmlStoredRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlStoredRetentionFinishV1(n)
}

// Bound successful canonical Master bytes using the same actual tokens/typed
// input envelope already priced by CanonicalResources. This is not JSONB or an
// unrestricted RawMessage multiplier; only the fixed Master serializer emits it.
func htmlStoredCanonicalOutputUpperV1(master, defaults []byte, m htmlmaster.Master, s htmlInputCanonicalStatsV1) (htmlStoredCanonicalOutputV1, error) {
	var out htmlStoredCanonicalOutputV1
	clones := (s.tokens+1)*min(s.formatStarts, int64(513)) + 32*s.formatEnds
	htmlOut := int64(0)
	for _, p := range [][2]int64{{int64(len(m.HTML)), 6}, {s.tokens + 1, 32}, {clones, s.maxTagOutput}, {1, 512}} {
		if !htmlInputAddV1(&htmlOut, p[0], p[1]) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	htmlOut = min(htmlOut, int64(htmlmaster.MaxMaterializedBytes))
	cssBase := int64(0)
	if !htmlInputAddV1(&cssBase, int64(len(m.CSS)), 12) || !htmlInputAddV1(&cssBase, s.cssTokens+1, 32) {
		return out, ErrHTMLAuthoringInputV1
	}
	jsonOut := int64(4096)
	for _, n := range []int64{int64(len(master)), int64(len(defaults)), htmlOut, cssBase} {
		if !htmlInputAddV1(&jsonOut, n, 6) {
			return out, ErrHTMLAuthoringInputV1
		}
	}
	out.masterJSONBytes = min(jsonOut, int64(htmlmaster.MaxMasterJSONBytes))
	// This upper is used only for Compiled. Actual TemplateCommitment retention
	// below uses exact produced defaults bytes, including expanded escaping.
	return out, nil
}

func htmlStoredTemplateResultRetentionV1(content htmlmaster.TemplateCommitment) (int64, error) {
	out := htmlStoredCanonicalOutputV1{masterJSONBytes: int64(len(content.MasterJSON)), defaultsJSONBytes: int64(len(content.DefaultsJSON))}
	one, err := htmlStoredPreparedTemplateRetentionV1(out)
	if err != nil {
		return 0, err
	}
	total := int64(0)
	if !htmlInputAddV1(&total, one, 2) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return total, nil
}

// Actual later values are not fetched yet. The only expanding parser is
// net/mail, whose original guard refuses >254 bytes BEFORE parsing. Price the
// accepted maximum for each actual compiled party; no fake values or new limit
// is passed to a validator. This is a fixed logical ceiling, not RSS proof.
func htmlStoredTemplateReadinessCeilingV1(m htmlmaster.Master) (int64, error) {
	base, err := htmlRevisionContractReadinessComponentsForV1(m, htmlmaster.Input{})
	if err != nil {
		return 0, err
	}
	if m.ContractProfile == nil {
		return base.parentBytes, nil
	}
	maxMail, err := htmlRevisionReadinessMailBytesV1(254)
	if err != nil {
		return 0, err
	}
	total := base.parentBytes - base.mailBytes
	if total < 0 || !htmlInputAddV1(&total, maxMail, int64(len(m.ContractProfile.Parties))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return total, nil
}

// The preparation call graph is fixed and synchronous: up to three readiness
// calls (initial observation, post-population observation, body Materialize)
// plus two signing-page calls. Those calls retain party/issue/digest results,
// not each mail parser's entire scratch arena. The existing full ONE-call
// ceiling remains unchanged and is held continuously as a scratch MAX.
// Recheck cannot materialize and grants none of this future readiness work.
func htmlStoredTemplateFutureReadinessResourcesV1(purpose htmlStoredTemplatePurposeV1, m htmlmaster.Master) (scratch, retained int64, failure error) {
	if purpose != htmlStoredTemplateRecheckV1 && purpose != htmlStoredTemplatePreparationV1 {
		return 0, 0, errHTMLCanonicalModelWorkV1
	}
	if purpose == htmlStoredTemplateRecheckV1 {
		return 0, 0, nil
	}
	one, err := htmlStoredTemplateReadinessCeilingV1(m)
	if err != nil {
		return 0, 0, err
	}
	result, err := htmlRevisionContractReadinessComponentsForV1(m, htmlmaster.Input{})
	if err != nil {
		return 0, 0, err
	}
	calls := int64(3)
	if m.SigningPage != nil {
		calls += 2
	}
	if !htmlInputAddV1(&retained, result.retainedResultBytes, calls) {
		return 0, 0, errHTMLCanonicalModelWorkV1
	}
	// one already includes one result; retaining all results separately is a
	// deliberate conservative overlap, not a subtraction/refund of live work.
	return one, retained, nil
}
