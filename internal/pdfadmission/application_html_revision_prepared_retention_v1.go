// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// Private retained/projection components, not an admission or lifetime proof.
// Only the fixed source owner may derive these from its actual private builder
// projections and immutable source snapshot. Existing full CanonicalResources
// prices actual raw/canonical scratch; retained resources are separate so that
// no pixels/DOM/regex arena is refunded while a live compiled result uses it.
// The native owner still joins actual CPU/route/body/SQL consumers before release.
func htmlRevisionRetentionAllocV1(total *int64, n int64) bool {
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
func htmlRevisionRetentionFinishV1(n int64) (int64, error) {
	if !htmlAuthoringInputRuntimeOKV1 || n < 0 {
		return 0, ErrHTMLAuthoringInputV1
	}
	rounded := n
	if !htmlInputAddV1(&rounded, 1, 8191) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return rounded / 8192 * 8192, nil
}
func htmlRevisionRetentionMasterShapeV1(m htmlmaster.Master) bool {
	return len(m.Values) <= htmlmaster.MaxDefinitions && len(m.Sections) <= htmlmaster.MaxDefinitions && len(m.Assets) <= htmlmaster.MaxAssets && (m.ContractProfile == nil || (len(m.ContractProfile.Parties) <= 2 && len(m.ContractProfile.Terms) <= 16 && htmlmaster.AmendmentPolicyShapeV1(m.ContractProfile.AmendmentPolicy)))
}

// The fixed typed clone code copies these headers/arrays/profile/policy, but
// shares immutable string backing with the privately retained source model.
// Parser-created master string storage is priced separately below.
func htmlRevisionPreparedMasterProjectionV1(m htmlmaster.Master) (int64, error) {
	if !htmlRevisionRetentionMasterShapeV1(m) {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	for _, size := range []int64{int64(unsafe.Sizeof(htmlmaster.Master{})), int64(len(m.Values)) * int64(unsafe.Sizeof(htmlmaster.Value{})), int64(len(m.Sections)) * int64(unsafe.Sizeof(htmlmaster.Section{})), int64(len(m.Assets)) * int64(unsafe.Sizeof(htmlmaster.Asset{}))} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	if p := m.ContractProfile; p != nil {
		for _, size := range []int64{int64(unsafe.Sizeof(*p)), int64(len(p.Parties)) * int64(unsafe.Sizeof(htmlmaster.ContractParty{})), int64(len(p.Terms)) * int64(unsafe.Sizeof(htmlmaster.ContractTerm{}))} {
			if !htmlRevisionRetentionAllocV1(&n, size) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	if p := m.ContractProfile; p != nil && p.AmendmentPolicy != nil {
		a := p.AmendmentPolicy
		for _, size := range []int64{int64(unsafe.Sizeof(*a)), int64(len(a.AllowedModes)+len(a.AllowedChannels)) * 16} {
			if !htmlRevisionRetentionAllocV1(&n, size) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	if p := m.SigningPage; p != nil {
		if !htmlRevisionRetentionAllocV1(&n, int64(unsafe.Sizeof(*p))) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}

// A parser-created raw/canonical typed Master retains each decoded string in
// addition to its typed projection. Use it for the private builder model, then
// add MasterProjection for any simultaneous MasterV1 inspection-copy arrays.
func htmlRevisionPreparedMasterRetentionV1(m htmlmaster.Master) (int64, error) {
	n, err := htmlRevisionPreparedMasterProjectionV1(m)
	if err != nil {
		return 0, err
	}
	text := func(value string) bool { return htmlRevisionRetentionAllocV1(&n, int64(len(value))) }
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
	if p := m.ContractProfile; p != nil && p.AmendmentPolicy != nil {
		a := p.AmendmentPolicy
		for _, value := range []string{a.Term, a.ClauseReference, a.EffectiveCondition} {
			if !text(value) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
		for _, value := range a.AllowedModes {
			if !text(value) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
		for _, value := range a.AllowedChannels {
			if !text(value) {
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
	return htmlRevisionRetentionFinishV1(n)
}

// Same pinned Swiss-map bounded-object/old-growth groups as the reviewed input
// parser model. The slot unit includes key16 plus largest typed value64 and
// control byte; it dominates Value32,Section40,resolvedAsset24 and string16.
// No map here can exceed64 entries or trigger the1024-entry table split.
func htmlRevisionRetentionMapV1(n int) (int64, error) {
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
func htmlRevisionPreparedCompiledRetentionV1(m htmlmaster.Master, s htmlInputCanonicalStatsV1, out htmlRevisionCanonicalOutputComponentsV1) (int64, error) {
	if !htmlRevisionRetentionMasterShapeV1(m) || s.tokens < 0 || s.tokens > 20000 || s.formatStarts < 0 || s.formatStarts > s.tokens || s.formatEnds < 0 || s.formatEnds > s.tokens || s.cssTokens < 0 || s.cssTokens > 20001 || s.cssURIs < 0 || s.maxAssetURL < 0 || s.maxTagOutput < 0 || out.masterJSONBytes < 0 {
		return 0, ErrHTMLAuthoringInputV1
	}
	n, err := htmlRevisionPreparedMasterProjectionV1(m)
	if err != nil {
		return 0, err
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(unsafe.Sizeof(htmlmaster.Compiled{}))) || !htmlRevisionRetentionAllocV1(&n, 64) || !htmlRevisionRetentionAllocV1(&n, out.masterJSONBytes) {
		return 0, ErrHTMLAuthoringInputV1
	}
	for _, count := range [...]int{len(m.Values), len(m.Sections), len(m.Assets)} {
		storage, err := htmlRevisionRetentionMapV1(count)
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
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, asset := range m.Assets {
		// Strict StdEncoding may discard CR/LF; canonical base64 never grows beyond
		// the actual original spelling. dataURL prefix/normalized payload are ASCII.
		normalized := int64(len(asset.DataBase64))
		url := normalized
		if !htmlInputAddV1(&url, int64(len("data:")+len(asset.MediaType)+len(";base64,")), 1) || !htmlRevisionRetentionAllocV1(&n, normalized) || !htmlRevisionRetentionAllocV1(&n, url) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}

// Private TemplateCommitment retained after CanonicalTemplate, including its
// produced default map encoding even if larger than a future strict-input cap.
func htmlRevisionPreparedTemplateRetentionV1(out htmlRevisionCanonicalOutputComponentsV1) (int64, error) {
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(htmlmaster.TemplateCommitment{})), out.masterJSONBytes, out.defaultsJSONBytes, 64} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}

// InputV1 and InputForCurrentV1 clone raw messages/maps/bindings/artifact.Fields;
// immutable string backing remains owned by the private decoded source model.
func htmlRevisionPreparedInputProjectionV1(input htmlsource.Input) (int64, error) {
	if len(input.Values) > htmlmaster.MaxDefinitions || len(input.Sections) > htmlmaster.MaxDefinitions || len(input.PartyBindings) > 2 || (input.SigningArtifact != nil && len(input.SigningArtifact.Fields) > 2) {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(htmlsource.Input{})), int64(len(input.MasterJSON)), int64(len(input.DefaultVarsJSON)), int64(len(input.PartyBindings)) * int64(unsafe.Sizeof(htmlsource.PartyBinding{}))} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, count := range [...]int{len(input.Values), len(input.Sections)} {
		storage, err := htmlRevisionRetentionMapV1(count)
		if err != nil || !htmlInputAddV1(&n, storage, 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	if a := input.SigningArtifact; a != nil {
		for _, size := range [...]int64{int64(unsafe.Sizeof(*a)), int64(len(a.Fields)) * int64(unsafe.Sizeof(htmlsource.SigningRectangle{}))} {
			if !htmlRevisionRetentionAllocV1(&n, size) {
				return 0, ErrHTMLAuthoringInputV1
			}
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}
func htmlRevisionPreparedRecordPinsProjectionV1(p htmlsource.RevisionValidationRecordPinsV1) (int64, error) {
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(p)), int64(len(p.PDFSHA256)), int64(len(p.VariablesJSON))} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}

// Exact same40 variable fields as the pure operation Document clone.
func htmlRevisionPreparedDocumentCloneV1(doc *generated.Document) (int64, error) {
	if doc == nil {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	if !htmlRevisionRetentionAllocV1(&n, int64(unsafe.Sizeof(*doc))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.Name))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.Status))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.RoutingMode))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.SourceKind))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.BlocksJson))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.VariablesJson))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.RenderedPdfKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.RenderedPdfSha))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.PdfStorageKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.PdfSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FinalPdfKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FinalPdfSha))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditCertKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.Metadata))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.MetadataRedactionReport))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.RoutingTier))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.BilingualTargetLang))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.LawfulBasis))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.DefaultLocale))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditPayloadKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditPayloadSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditSignatureKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditSignatureSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.PdfStorageVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.RenderedPdfVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FinalPdfVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditCertSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditCertVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditPayloadVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.AuditSignatureVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.Article13NoticeSchema))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.HtmlSourceJson))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.HtmlReviewedPdfSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.HtmlCurrentSourceJson))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.HtmlEffectiveSourceCommitment.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FitsIndexStorageKey.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FitsIndexVersionID.String))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.FitsIndexSha256))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.ParticipantReportSchema))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	if !htmlRevisionRetentionAllocV1(&n, int64(len(doc.SigningAdmissionPolicy))) {
		return 0, ErrHTMLAuthoringInputV1
	}
	return htmlRevisionRetentionFinishV1(n)
}

// This fixed existing-schema ceiling can be acquired BEFORE MasterV1 creates
// its inspection copy. It includes no strings: the getter shares only immutable
// backing retained by the source operation. It is an existing typed topology,
// never a caller count or an operator-configured capacity.
func htmlRevisionPreparedMasterProjectionCeilingV1() (int64, error) {
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(htmlmaster.Master{})), htmlmaster.MaxDefinitions * int64(unsafe.Sizeof(htmlmaster.Value{})), htmlmaster.MaxDefinitions * int64(unsafe.Sizeof(htmlmaster.Section{})), htmlmaster.MaxAssets * int64(unsafe.Sizeof(htmlmaster.Asset{})), int64(unsafe.Sizeof(htmlmaster.ContractProfile{})), 2 * int64(unsafe.Sizeof(htmlmaster.ContractParty{})), 16 * int64(unsafe.Sizeof(htmlmaster.ContractTerm{})), int64(unsafe.Sizeof(htmlmaster.SigningPagePolicy{})), int64(unsafe.Sizeof(htmlmaster.AmendmentPolicyV1{})), 4 * 16} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}

// The source owner uses its ACTUAL original source bytes and the matching
// allocation-free source span result BEFORE InputV1 clones Master/Defaults.
// Fixed existing map/binding/artifact maxima price the remaining projection;
// this helper neither validates source semantics nor authorizes native work.
func htmlRevisionPreparedInputProjectionFromSourceV1(raw []byte, parts htmlRevisionSourceDecodeComponentsV1) (int64, error) {
	if parts.masterStart < 0 || parts.masterEnd < parts.masterStart || parts.masterEnd > len(raw) || parts.defaultsStart < 0 || parts.defaultsEnd < parts.defaultsStart || parts.defaultsEnd > len(raw) {
		return 0, ErrHTMLAuthoringInputV1
	}
	n := int64(0)
	for _, size := range [...]int64{int64(unsafe.Sizeof(htmlsource.Input{})), int64(parts.masterEnd - parts.masterStart), int64(parts.defaultsEnd - parts.defaultsStart), 2 * int64(unsafe.Sizeof(htmlsource.PartyBinding{})), int64(unsafe.Sizeof(htmlsource.SigningArtifact{})), 2 * int64(unsafe.Sizeof(htmlsource.SigningRectangle{}))} {
		if !htmlRevisionRetentionAllocV1(&n, size) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for range 2 {
		storage, err := htmlRevisionRetentionMapV1(htmlmaster.MaxDefinitions)
		if err != nil || !htmlInputAddV1(&n, storage, 1) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return htmlRevisionRetentionFinishV1(n)
}
