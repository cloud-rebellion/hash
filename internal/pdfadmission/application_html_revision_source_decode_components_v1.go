// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

// These are private component bounds, not an admission, a source validation or
// authority to call an arbitrary callback. The revision owner must derive them
// from its actual retained source snapshot under the original body borrower,
// acquire its fixed native source grants, and retain every real output through
// last use. In particular, this file does not sum the full revision live set.
type htmlRevisionSourceDecodeComponentsV1 struct {
	sourceShape                                                                  htmlAuthoringInputShapeV1
	masterStart, masterEnd, defaultsStart, defaultsEnd                           int
	sourceParserBytes, artifactOriginalParserBytes, artifactCanonicalParserBytes int64
	artifactEncodeBytes, artifactJSONBytes, retainedTypedSourceBytes             int64
}

// Source decoding has four original-input operations: the strict token pass,
// typed source Decode, source fields RawMessage map, and party binding maps.
// The signing-artifact any parses and its expanded typed Marshal are separate.
// RawMessage is never assigned an arbitrary raw-to-output multiplier.
func htmlRevisionSourceDecodeComponentsForV1(ctx context.Context, raw []byte) (htmlRevisionSourceDecodeComponentsV1, error) {
	var out htmlRevisionSourceDecodeComponentsV1
	if !htmlAuthoringInputRuntimeOKV1 {
		return out, ErrHTMLAuthoringInputV1
	}
	shape, err := htmlRevisionSourceShapeV1(ctx, raw)
	if err != nil {
		return out, err
	}
	out.sourceShape = shape
	out.masterStart, out.masterEnd = shape.masterStart, shape.masterEnd
	out.defaultsStart, out.defaultsEnd = shape.defaultsStart, shape.defaultsEnd
	out.sourceParserBytes, err = htmlAuthoringInputParserArenaV1(shape, 4)
	if err != nil {
		return out, err
	}
	// A separate retained typed-source allowance remains after synchronous parser
	// scratch is no longer used. It is conservative to retain one full arena;
	// no GC/RSS reclamation or physical SQL retirement is inferred here.
	out.retainedTypedSourceBytes, err = htmlAuthoringInputParserArenaV1(shape, 1)
	if err != nil {
		return out, err
	}
	start, end, present, err := htmlRevisionSourceArtifactSpanV1(ctx, raw)
	if err != nil {
		return out, err
	}
	if !present {
		return out, nil
	}
	original, err := htmlAuthoringInputRootShapeV1(ctx, htmlRevisionSigningArtifactNodeV1, raw[start:end])
	if err != nil {
		return out, errors.Join(htmlsource.ErrInvalid, err)
	}
	out.artifactOriginalParserBytes, err = htmlAuthoringInputParserArenaV1(original, 1)
	if err != nil {
		return out, err
	}
	canonical, err := htmlRevisionArtifactOutputShapeV1(original)
	if err != nil {
		return out, err
	}
	out.artifactJSONBytes = canonical.raw
	out.artifactCanonicalParserBytes, err = htmlAuthoringInputParserArenaV1(canonical, 1)
	if err != nil {
		return out, err
	}
	// Pinned encoder append growth, old/new backing, result copy, reflect/number
	// scratch and fixed state. This applies to the derived concrete typed output,
	// never to unrestricted raw JSON or to arbitrary caller size declarations.
	if !htmlInputAddV1(&out.artifactEncodeBytes, canonical.raw, 18) || !htmlInputAddV1(&out.artifactEncodeBytes, 1, 4*4096) {
		return out, ErrHTMLAuthoringInputV1
	}
	return out, nil
}

// Called only after the complete allocation-free source shape has accepted the
// original bytes. Duplicate artifact keys are already invalid to strictDecode;
// refusing them here cannot reject a formerly valid source. Escaped exact names
// use the same scanner comparison as the unchanged source grammar.
func htmlRevisionSourceArtifactSpanV1(ctx context.Context, raw []byte) (start, end int, present bool, err error) {
	p := htmlInputScanV1{ctx: ctx, raw: raw}
	p.space()
	if p.pos == len(raw) || raw[p.pos] != '{' {
		return 0, 0, false, htmlsource.ErrInvalid
	}
	p.pos++
	p.space()
	if p.pos < len(raw) && raw[p.pos] == '}' {
		return 0, 0, false, nil
	}
	for {
		p.space()
		if p.pos == len(raw) || raw[p.pos] != '"' {
			return 0, 0, false, htmlsource.ErrInvalid
		}
		keyStart, keyEnd, e := p.str()
		if e != nil {
			return 0, 0, false, e
		}
		child := htmlInputScalarV1
		found := false
		for _, field := range htmlRevisionSourceFieldsV1 {
			if htmlInputKeyEqualV1(raw, keyStart, keyEnd, field.name) {
				child = field.node
				found = true
				break
			}
		}
		if !found {
			return 0, 0, false, htmlsource.ErrInvalid
		}
		p.space()
		if p.pos == len(raw) || raw[p.pos] != ':' {
			return 0, 0, false, htmlsource.ErrInvalid
		}
		p.pos++
		p.space()
		valueStart := p.pos
		if e = p.value(child, 1); e != nil {
			return 0, 0, false, e
		}
		if htmlInputKeyEqualV1(raw, keyStart, keyEnd, "signing_artifact") {
			if present {
				return 0, 0, false, htmlsource.ErrInvalid
			}
			start, end, present = valueStart, p.pos, true
		}
		p.space()
		if p.pos == len(raw) {
			return 0, 0, false, htmlsource.ErrInvalid
		}
		delimiter := raw[p.pos]
		p.pos++
		if delimiter == '}' {
			p.space()
			if p.pos != len(raw) {
				return 0, 0, false, htmlsource.ErrInvalid
			}
			return start, end, present, nil
		}
		if delimiter != ',' {
			return 0, 0, false, htmlsource.ErrInvalid
		}
	}
}

// Actual fixed SigningArtifact serialization topology (rectangles have SIX
// fields each): at most5 objects,7 arrays,32 keys,43 quoted strings,37 bounded
// integer scalars and27 array items. Omitted input struct members can reappear
// as typed zero/default fields. All source string bytes plus all fixed key names
// therefore remain priced even for an empty or abbreviated artifact input.
func htmlRevisionArtifactOutputShapeV1(original htmlAuthoringInputShapeV1) (htmlAuthoringInputShapeV1, error) {
	var out htmlAuthoringInputShapeV1
	keyBytes := int64(0)
	for _, fields := range [][]htmlInputFieldV1{htmlRevisionSigningArtifactFieldsV1[:], htmlRevisionCompositionFieldsV1[:], htmlRevisionPageGeometryFieldsV1[:], htmlRevisionRectangleFieldsV1[:], htmlRevisionRectangleFieldsV1[:]} {
		for _, field := range fields {
			keyBytes += int64(len(field.name))
		}
	}
	decodedStrings := int64(0)
	if !htmlInputAddV1(&decodedStrings, original.stringBytes, 1) || !htmlInputAddV1(&decodedStrings, keyBytes, 1) {
		return out, ErrHTMLAuthoringInputV1
	}
	// UTF8 string values can expand to at most six ASCII bytes per input byte;
	// int/int32/int64 decimal spelling uses at most twenty bytes, including '-'.
	escapedStrings := int64(0)
	if !htmlInputAddV1(&escapedStrings, decodedStrings, 6) {
		return out, ErrHTMLAuthoringInputV1
	}
	raw := escapedStrings
	if !htmlInputAddV1(&raw, 37, 20) || !htmlInputAddV1(&raw, 43+37+5+7+32+27, 8) {
		return out, ErrHTMLAuthoringInputV1
	}
	out = htmlAuthoringInputShapeV1{raw: raw, strings: 43, stringBytes: escapedStrings, scalars: 37, objects: 5, arrays: 7, tableSlots: 96, arraySlots: 60, depth: 5}
	return out, nil
}

// Canonical master output is a concrete typed serialization. Compile changes
// only HTML/CSS, clones/sorts the typed declarations, and emits their actual
// fields. This bound includes absent input zero fields, JSON string escaping and
// the future Decode's five parser operations. It is not a second Compile.
type htmlRevisionCanonicalOutputComponentsV1 struct {
	masterShape, defaultsShape             htmlAuthoringInputShapeV1
	masterParserBytes, defaultsParserBytes int64
	masterJSONBytes, defaultsJSONBytes     int64
}
type htmlRevisionTypedOutputV1 struct {
	shape                          htmlAuthoringInputShapeV1
	decodedStrings, members, items int64
	failed                         bool
}

func (b *htmlRevisionTypedOutputV1) add(n, u int64) {
	if !htmlInputAddV1(&b.decodedStrings, n, u) {
		b.failed = true
	}
}
func (b *htmlRevisionTypedOutputV1) object(fields []htmlInputFieldV1) {
	b.shape.objects++
	b.members += int64(len(fields))
	b.shape.strings += int64(len(fields))
	b.shape.tableSlots += 2 * htmlInputPowerV1(max(8, (int64(len(fields))*8+6)/7))
	for _, field := range fields {
		b.add(int64(len(field.name)), 1)
	}
}
func (b *htmlRevisionTypedOutputV1) array(n int) {
	b.shape.arrays++
	b.items += int64(n)
	if n != 0 {
		b.shape.arraySlots += 2 * htmlInputPowerV1(int64(n))
	}
}
func (b *htmlRevisionTypedOutputV1) text(s string)     { b.shape.strings++; b.add(int64(len(s)), 1) }
func (b *htmlRevisionTypedOutputV1) textBound(n int64) { b.shape.strings++; b.add(n, 1) }
func (b *htmlRevisionTypedOutputV1) scalar()           { b.shape.scalars++ }
func (b *htmlRevisionTypedOutputV1) finish(limit int64) (htmlAuthoringInputShapeV1, error) {
	if b.failed {
		return htmlAuthoringInputShapeV1{}, ErrHTMLAuthoringInputV1
	}
	escaped := int64(0)
	if !htmlInputAddV1(&escaped, b.decodedStrings, 6) {
		return htmlAuthoringInputShapeV1{}, ErrHTMLAuthoringInputV1
	}
	raw := escaped
	if !htmlInputAddV1(&raw, b.shape.scalars, 20) || !htmlInputAddV1(&raw, b.shape.strings+b.shape.scalars+b.shape.objects+b.shape.arrays+b.members+b.items, 8) {
		return htmlAuthoringInputShapeV1{}, ErrHTMLAuthoringInputV1
	}
	b.shape.raw = min(raw, limit)
	b.shape.stringBytes = min(escaped, b.shape.raw)
	b.shape.depth = 5
	return b.shape, nil
}
func htmlRevisionCanonicalOutputComponentsForV1(master htmlmaster.Master, stats htmlInputCanonicalStatsV1, defaults htmlAuthoringInputShapeV1) (htmlRevisionCanonicalOutputComponentsV1, error) {
	var out htmlRevisionCanonicalOutputComponentsV1
	if !htmlAuthoringInputRuntimeOKV1 {
		return out, ErrHTMLAuthoringInputV1
	}
	if len(master.Values) > htmlmaster.MaxDefinitions || len(master.Sections) > htmlmaster.MaxDefinitions || len(master.Assets) > htmlmaster.MaxAssets {
		return out, htmlsource.ErrInvalid
	}
	if master.ContractProfile != nil && (len(master.ContractProfile.Parties) > 2 || len(master.ContractProfile.Terms) > 16) {
		return out, htmlsource.ErrInvalid
	}
	if master.ContractProfile != nil && !htmlmaster.AmendmentPolicyShapeV1(master.ContractProfile.AmendmentPolicy) {
		return out, ErrHTMLAuthoringInputV1
	}
	// All arithmetic inputs below are either existing typed maxima or derived by
	// the private canonical inspection of this SAME actual owned typed master.
	if stats.tokens < 0 || stats.tokens > 20000 || stats.formatStarts < 0 || stats.formatStarts > stats.tokens || stats.formatEnds < 0 || stats.formatEnds > stats.tokens || stats.cssTokens < 0 || stats.cssTokens > 20001 || stats.maxTagOutput < 0 {
		return out, ErrHTMLAuthoringInputV1
	}
	clones := (stats.tokens+1)*min(stats.formatStarts, int64(513)) + 32*stats.formatEnds
	htmlBound := int64(0)
	if !htmlInputAddV1(&htmlBound, int64(len(master.HTML)), 6) || !htmlInputAddV1(&htmlBound, stats.tokens+1, 32) || !htmlInputAddV1(&htmlBound, clones, stats.maxTagOutput) || !htmlInputAddV1(&htmlBound, 1, 512) {
		return out, ErrHTMLAuthoringInputV1
	}
	cssBound := int64(0)
	if !htmlInputAddV1(&cssBound, int64(len(master.CSS)), 12) || !htmlInputAddV1(&cssBound, stats.cssTokens+1, 32) {
		return out, ErrHTMLAuthoringInputV1
	}
	// Future Decode runs only after the original Compile has passed these exact
	// successful-output limits. Its original failure/normalization is untouched.
	htmlBound = min(htmlBound, int64(htmlmaster.MaxHTMLBytes))
	cssBound = min(cssBound, int64(htmlmaster.MaxCSSBytes))
	b := htmlRevisionTypedOutputV1{}
	b.object(htmlInputMasterV1Fields[:])
	b.scalar()
	b.textBound(htmlBound)
	b.textBound(cssBound)
	b.array(len(master.Values))
	for _, value := range master.Values {
		b.object(htmlInputValueV1Fields[:])
		b.text(value.Name)
		b.scalar()
		b.scalar()
	}
	b.array(len(master.Sections))
	for _, section := range master.Sections {
		b.object(htmlInputSectionV1Fields[:])
		b.text(section.Name)
		b.text(section.DefaultText)
		b.scalar()
	}
	b.array(len(master.Assets))
	for _, asset := range master.Assets {
		b.object(htmlInputAssetV1Fields[:])
		b.text(asset.Name)
		b.text(asset.MediaType)
		b.text(asset.DataBase64)
		b.text(asset.SHA256)
	}
	if p := master.ContractProfile; p != nil {
		b.object(htmlInputContractV1Fields[:])
		b.text(p.ID)
		b.scalar()
		b.text(p.Kind)
		b.array(len(p.Parties))
		for _, party := range p.Parties {
			b.object(htmlInputPartyV1Fields[:])
			for _, text := range [...]string{party.Slot, party.CompanyName, party.CompanyID, party.RepresentativeName, party.RepresentativeEmail, party.RepresentativeAuthority} {
				b.text(text)
			}
		}
		b.array(len(p.Terms))
		for _, term := range p.Terms {
			b.object(htmlInputTermV1Fields[:])
			b.text(term.Name)
			b.text(term.Value)
			b.text(term.Section)
		}
		if a := p.AmendmentPolicy; a != nil {
			b.object(htmlInputAmendmentPolicyV1Fields[:])
			b.text(a.Term)
			b.text(a.ClauseReference)
			b.array(len(a.AllowedModes))
			for _, m := range a.AllowedModes {
				b.text(m)
			}
			b.array(len(a.AllowedChannels))
			for _, c := range a.AllowedChannels {
				b.text(c)
			}
			b.text(a.EffectiveCondition)
		}
	}
	if p := master.SigningPage; p != nil {
		b.object(htmlInputSigningV1Fields[:])
		b.scalar()
		b.text(p.Policy)
		b.text(p.LogoAsset)
		b.text(p.LogoSHA256)
		b.text(p.LogoAlt)
		b.text(p.FontSHA256)
		b.object(htmlInputBrandingV1Fields[:])
		for _, text := range [...]string{p.Branding.PrimaryHex, p.Branding.AccentHex, p.Branding.SurfaceHex, p.Branding.TextHex, p.Branding.MutedHex, p.Branding.LogoURL, p.Branding.LogoAlt, p.Branding.FontHeading, p.Branding.FontBody, p.Branding.SignatureColor} {
			b.text(text)
		}
	}
	var err error
	out.masterShape, err = b.finish(int64(htmlmaster.MaxMasterJSONBytes))
	if err != nil {
		return out, err
	}
	out.masterJSONBytes = out.masterShape.raw
	out.masterParserBytes, err = htmlAuthoringInputParserArenaV1(out.masterShape, 5)
	if err != nil {
		return out, err
	}
	// Defaults are a concrete map[string]string. The original strict default
	// parser must succeed before any Marshal. Original string spellings bound the
	// decoded keys/values even when canonical escaping expands them sixfold.
	if defaults.objects != 1 || defaults.arrays != 0 || defaults.strings < 0 || defaults.strings > 2*htmlmaster.MaxDefinitions || defaults.stringBytes < 0 {
		return out, htmlsource.ErrInvalid
	}
	raw := int64(0)
	if !htmlInputAddV1(&raw, defaults.stringBytes, 6) || !htmlInputAddV1(&raw, defaults.strings+htmlmaster.MaxDefinitions+1, 8) {
		return out, ErrHTMLAuthoringInputV1
	}
	out.defaultsJSONBytes = raw
	out.defaultsShape = htmlAuthoringInputShapeV1{raw: min(raw, int64(htmlmaster.MaxDefinitions*htmlmaster.MaxValueChars*4+4096)), strings: defaults.strings, stringBytes: min(raw, int64(htmlmaster.MaxDefinitions*htmlmaster.MaxValueChars*4+4096)), objects: 1, tableSlots: defaults.tableSlots, depth: 1}
	out.defaultsParserBytes, err = htmlAuthoringInputParserArenaV1(out.defaultsShape, 2)
	if err != nil {
		return out, err
	}
	return out, nil
}

// This fixed adapter is the only snapshot entry point. Its caller is the native
// source owner after borrowHTMLRevisionSourceV1 has minted its actual borrower;
// that borrower MUST remain held through inspection, grants and actual CPU use.
// These checked components do not themselves mint a grant or run source checks.
type htmlRevisionSourceSnapshotDecodeComponentsV1 struct {
	snapshot *applicationHTMLRevisionSourceSnapshotV1
	records  [3]htmlRevisionSourceDecodeComponentsV1 // origin, projected current, row current
	present  [3]bool
}

func htmlRevisionSourceDecodeSnapshotV1(ctx context.Context, snapshot *applicationHTMLRevisionSourceSnapshotV1) (htmlRevisionSourceSnapshotDecodeComponentsV1, error) {
	var out htmlRevisionSourceSnapshotDecodeComponentsV1
	if !applicationContextV1(ctx) || snapshot == nil || snapshot.owner == nil {
		return out, ErrHTMLRevisionReadV1
	}
	reader := snapshot.owner
	if reader.self != reader {
		return out, ErrHTMLRevisionReadV1
	}
	reader.mu.Lock()
	if reader.snapshot != snapshot || reader.resourcesClosed || reader.sourceBorrowers < 1 || reader.session == nil || reader.session.state == nil || snapshot.document == nil {
		reader.mu.Unlock()
		return out, ErrHTMLRevisionReadV1
	}
	state := reader.session.state
	if snapshot.document.ID != state.document || snapshot.document.OrgID != state.org || state.factory == nil || state.factory.work == nil || state.admission == nil || state.fence == nil || !state.admission.valid() || state.admission.fence != state.fence || state.admission.cleanupDone != state.fence.clientDone {
		reader.mu.Unlock()
		return out, ErrHTMLRevisionReadV1
	}
	origin, current := snapshot.document.HtmlSourceJson, snapshot.document.HtmlCurrentSourceJson
	var row []byte
	if snapshot.current != nil {
		row = snapshot.current.SourceJson
	}
	reader.mu.Unlock()
	out.snapshot = snapshot
	for i, raw := range [3][]byte{origin, current, row} {
		if len(raw) == 0 {
			if i == 0 {
				return out, htmlsource.ErrInvalid
			}
			continue
		}
		record, err := htmlRevisionSourceDecodeComponentsForV1(ctx, raw)
		if err != nil {
			return out, err
		}
		out.records[i] = record
		out.present[i] = true
	}
	return out, nil
}
