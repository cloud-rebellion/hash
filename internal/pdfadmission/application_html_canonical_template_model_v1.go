// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"fmt"
	"github.com/bright-interaction/hash/internal/htmlmaster"
)

// This private producer receives only the reader's actual scoped loaded model.
// There is no public raw-message, size, callback or multiplicity authority.
// The canonicalizer still decides validity and the exact approved SHA bytes.
func (c *applicationHTMLCanonicalModelConsumerV1) canonicalTemplateV1(ctx context.Context, masterRaw, defaultsRaw []byte, expectedDigest [32]byte, digestValid bool, purpose htmlStoredTemplatePurposeV1) (htmlmaster.TemplateCommitment, error) {
	var empty htmlmaster.TemplateCommitment
	if purpose > htmlStoredTemplatePreparationV1 {
		return empty, ErrHTMLAuthoringReadV1
	}
	if !digestValid {
		return empty, fmt.Errorf("%w: stored template content commitment", htmlmaster.ErrInvalid)
	}
	shape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, masterRaw)
	if err != nil {
		return empty, err
	}
	parse, err := htmlAuthoringInputParserArenaV1(shape, 10)
	if err != nil {
		return empty, err
	}
	defaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, defaultsRaw)
	if err != nil {
		return empty, err
	}
	defaultsParse, err := htmlAuthoringInputParserArenaV1(defaults, 2)
	if err != nil || !htmlInputAddV1(&parse, defaultsParse, 1) {
		return empty, errHTMLCanonicalModelWorkV1
	}
	if err = c.holdV1(ctx, parse); err != nil {
		return empty, err
	}
	// The first Decode is inspection; the unchanged CanonicalTemplate performs
	// the second. Both are charged before either typed parser allocation.
	m, err := htmlmaster.Decode(masterRaw)
	if err != nil {
		return empty, err
	}
	if len(m.HTML) == 0 || len(m.HTML) > htmlmaster.MaxHTMLBytes || len(m.CSS) > htmlmaster.MaxCSSBytes || len(m.Assets) > htmlmaster.MaxAssets {
		return empty, htmlInputCanonicalInvalidV1()
	}
	inspection, err := htmlInputCanonicalInspectionResourcesV1(m)
	if err != nil {
		return empty, err
	}
	if err = c.holdV1(ctx, inspection); err != nil {
		return empty, err
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, m)
	if err != nil {
		return empty, err
	}
	canonical, err := htmlInputCanonicalResourcesV1(masterRaw, defaultsRaw, m, stats)
	if err != nil {
		return empty, err
	}
	if err = c.holdScratchV1(ctx, canonical); err != nil {
		return empty, err
	}
	content, err := htmlmaster.CanonicalTemplate(masterRaw, defaultsRaw)
	if err != nil {
		return empty, err
	}
	if content.SHA256 != hex.EncodeToString(expectedDigest[:]) {
		return empty, fmt.Errorf("%w: stored template content commitment", htmlmaster.ErrInvalid)
	}
	retainedContent, err := htmlStoredTemplateResultRetentionV1(content)
	if err != nil {
		return empty, err
	}
	if err = c.holdV1(ctx, retainedContent); err != nil {
		return empty, err
	}
	if purpose == htmlStoredTemplateCurrentV1 {
		return content, nil
	}
	// Preparation reserves the actual later Compile/materialization paths. A
	// fixed recheck reserves only inspection plus PreparedRetainedTemplate
	// Decode/Compile/defaults: its result is never materialized by those callers.
	// Both use ACTUAL canonical output rather than the original JSON spelling.
	output, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, content.MasterJSON)
	if err != nil {
		return empty, err
	}
	masterPasses, defaultsPasses := int64(20), int64(4)
	if purpose == htmlStoredTemplateRecheckV1 {
		masterPasses, defaultsPasses = 10, 2
	}
	outputParse, err := htmlAuthoringInputParserArenaV1(output, masterPasses)
	if err != nil {
		return empty, err
	}
	outputDefaults, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, content.DefaultsJSON)
	if err != nil {
		return empty, err
	}
	outputDefaultsParse, err := htmlAuthoringInputParserArenaV1(outputDefaults, defaultsPasses)
	if err != nil || !htmlInputAddV1(&outputParse, outputDefaultsParse, 1) {
		return empty, errHTMLCanonicalModelWorkV1
	}
	if err = c.holdV1(ctx, outputParse); err != nil {
		return empty, err
	}
	future, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return empty, err
	}
	futureInspection, err := htmlInputCanonicalInspectionResourcesV1(future)
	if err != nil {
		return empty, err
	}
	if err = c.holdV1(ctx, futureInspection); err != nil {
		return empty, err
	}
	futureStats, err := htmlInputCanonicalInspectV1(ctx, future)
	if err != nil {
		return empty, err
	}
	futureCanonical, err := htmlInputCanonicalResourcesV1(content.MasterJSON, content.DefaultsJSON, future, futureStats)
	if err != nil {
		return empty, err
	}
	if err = c.holdScratchV1(ctx, futureCanonical); err != nil {
		return empty, err
	}
	// Readiness calls finish synchronously before the next Compile, body or
	// signing-page materialization. Keep the complete conservative ONE-call
	// arena in the same continuously retained scratch peak, and price every
	// retained result independently below. No cancellation/GC credit is given.
	readinessScratch, _, err := htmlStoredTemplateFutureReadinessResourcesV1(purpose, future)
	if err != nil {
		return empty, err
	}
	if err = c.holdScratchV1(ctx, readinessScratch); err != nil {
		return empty, err
	}
	futureCost, err := htmlStoredTemplateFutureResourcesV1(purpose, content.MasterJSON, content.DefaultsJSON, future, futureStats)
	if err != nil {
		return empty, err
	}
	if err = c.holdV1(ctx, futureCost); err != nil {
		return empty, err
	}
	return content, nil
}

func htmlStoredTemplateMaterializationResourcesV1(m htmlmaster.Master, s htmlInputCanonicalStatsV1) (int64, error) {
	// Input lengths remain bounded by the unchanged declaration MaxChars and
	// strict text validation. Markers can repeat; every source token is charged.
	// This prices first body HTML and CRM readiness's discarded trial HTML;
	// provider/PDF/composition allocations are separate held runtime gates.
	maxText := int64(0)
	for _, v := range m.Values {
		if v.MaxChars < 1 || v.MaxChars > htmlmaster.MaxValueChars {
			return 0, htmlInputCanonicalInvalidV1()
		}
		maxText = max(maxText, 4*int64(v.MaxChars))
	}
	for _, v := range m.Sections {
		if v.MaxChars < 1 || v.MaxChars > htmlmaster.MaxSectionChars {
			return 0, htmlInputCanonicalInvalidV1()
		}
		maxText = max(maxText, 4*int64(v.MaxChars), int64(len(v.DefaultText)))
	}
	cssBase := 12*int64(len(m.CSS)) + 32*(s.cssTokens+1)
	cssOut := min(cssBase+s.cssURIs*(s.maxAssetURL+7), int64(htmlmaster.MaxMaterializedBytes)+4096+cssBase)
	output := min(int64(htmlmaster.MaxMaterializedBytes), int64(len(m.HTML))+cssOut+(s.tokens+1)*(6*maxText+s.maxAssetURL)+8192)
	clones := (s.tokens+1)*min(s.formatStarts, int64(513)) + 32*s.formatEnds
	nodes := clones + 5*(s.tokens+1) + 8
	n := int64(0)
	// Repeated parsing of accepted immutable canonical HTML, replacement text
	// nodes and output buffer growth/copies; no image decode occurs Materialize.
	for _, v := range [][2]int64{{nodes, 2 * (112 + 14*48)}, {int64(len(m.HTML)), 32}, {output, 16}, {int64(len(m.Values) + len(m.Sections)), 2 * 256 * 128}, {1, 4 * 4096}} {
		if !htmlInputAddV1(&n, v[0], v[1]) {
			return 0, errHTMLCanonicalModelWorkV1
		}
	}
	return n, nil
}

// Fixed later call graph. Recheck has no body/signing-page materialization path.
func htmlStoredTemplateFutureResourcesV1(purpose htmlStoredTemplatePurposeV1, masterRaw, defaultsRaw []byte, future htmlmaster.Master, futureStats htmlInputCanonicalStatsV1) (int64, error) {
	if purpose != htmlStoredTemplateRecheckV1 && purpose != htmlStoredTemplatePreparationV1 {
		return 0, errHTMLCanonicalModelWorkV1
	}
	output, err := htmlStoredCanonicalOutputUpperV1(masterRaw, defaultsRaw, future, futureStats)
	if err != nil {
		return 0, err
	}
	compiled, err := htmlStoredPreparedCompiledRetentionV1(future, futureStats, output)
	if err != nil {
		return 0, err
	}
	typed, err := htmlStoredPreparedMasterRetentionV1(future)
	if err != nil {
		return 0, err
	}
	futureCost, futureCompiles := int64(0), int64(2)
	if purpose == htmlStoredTemplateRecheckV1 {
		futureCompiles = 1
	}
	if !htmlInputAddV1(&futureCost, compiled, futureCompiles) || !htmlInputAddV1(&futureCost, typed, futureCompiles) {
		return 0, errHTMLCanonicalModelWorkV1
	}
	if purpose == htmlStoredTemplatePreparationV1 {
		_, readinessRetained, e := htmlStoredTemplateFutureReadinessResourcesV1(purpose, future)
		if e != nil || !htmlInputAddV1(&futureCost, readinessRetained, 1) {
			return 0, errHTMLCanonicalModelWorkV1
		}
		materialization, e := htmlStoredTemplateMaterializationResourcesV1(future, futureStats)
		if e != nil || !htmlInputAddV1(&futureCost, materialization, 2) {
			return 0, errHTMLCanonicalModelWorkV1
		}
		if future.SigningPage != nil && !htmlInputAddV1(&futureCost, materialization, 1) {
			return 0, errHTMLCanonicalModelWorkV1
		}
	}
	return futureCost, nil
}
