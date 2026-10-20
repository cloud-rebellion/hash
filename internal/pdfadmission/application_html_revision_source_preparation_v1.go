// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

var ErrHTMLRevisionNoChangeV1 = errors.New("pdfadmission: revision has no changed declared text")

// This data borrow never selects source/design/work authority. The native
// owner keeps a separate immutable input and every actual result consumer.
// The returned once-release joins the real render/source user; cancellation or
// route Close cannot pretend that a still-used HTML/input buffer has retired.
type HTMLRevisionPreparedModelsV1 struct {
	Input    htmlsource.Input
	Rendered htmlmaster.Result
}
type applicationHTMLRevisionPreparedV1 struct {
	input    htmlsource.Input
	rendered htmlmaster.Result
	borrowed bool
}

func htmlRevisionCopyInputV1(in htmlsource.Input) htmlsource.Input {
	out := in
	out.MasterJSON = bytes.Clone(in.MasterJSON)
	out.DefaultVarsJSON = bytes.Clone(in.DefaultVarsJSON)
	out.Values = maps.Clone(in.Values)
	out.Sections = maps.Clone(in.Sections)
	out.PartyBindings = slices.Clone(in.PartyBindings)
	if in.SigningArtifact != nil {
		artifact := *in.SigningArtifact
		artifact.Fields = slices.Clone(in.SigningArtifact.Fields)
		out.SigningArtifact = &artifact
	}
	return out
}
func htmlRevisionNewMapCopiesV1(in htmlsource.Input, values, sections map[string]string) (int64, error) {
	n, err := htmlRevisionPreparedInputProjectionV1(in)
	if err != nil {
		return 0, err
	}
	// One actual merged cost-inspection map plus the original helper's copied
	// result maps. Newly declared strings are cloned by the unchanged helper.
	for _, pair := range [][2]map[string]string{{in.Values, values}, {in.Sections, sections}} {
		count := len(pair[0])
		for key := range pair[1] {
			if _, exists := pair[0][key]; !exists {
				count++
			}
		}
		rows, err := htmlRevisionMergedMapRetentionV1(count)
		if err != nil || !htmlInputAddV1(&n, rows, 2) {
			return 0, ErrHTMLRevisionSourceV1
		}
		for key, value := range pair[1] {
			for _, text := range [...]string{key, value} {
				if !htmlRevisionRetentionAllocV1(&n, int64(len(text))) {
					return 0, ErrHTMLRevisionSourceV1
				}
			}
		}
	}
	if !htmlInputAddV1(&n, n, 1) {
		return 0, ErrHTMLRevisionSourceV1
	}
	return n, nil
}

// These are temporary-copy/output envelopes, not accepted input limits. The
// immutable validated source and actual revision declaration each have at most
// MaxDefinitions entries. The unchanged Materialize remains the sole semantic
// authority for their merged values/sections and their exact error priority.
func htmlRevisionMergedMapRetentionV1(n int) (int64, error) {
	if n < 0 || n > 2*htmlmaster.MaxDefinitions {
		return 0, ErrHTMLRevisionSourceV1
	}
	slots := int64(16)
	if n != 0 {
		slots = 2 * htmlInputPowerV1(max(8, (int64(n)*8+6)/7))
	}
	bytes := int64(0)
	for _, part := range [][2]int64{{slots, 2 * (80 + 1)}, {1, 2 * 16 * 256}} {
		if !htmlInputAddV1(&bytes, part[0], part[1]) {
			return 0, ErrHTMLRevisionSourceV1
		}
	}
	return bytes, nil
}

func htmlRevisionMergedValuesJSONBytesV1(values map[string]string) (int64, error) {
	if values == nil || len(values) > 2*htmlmaster.MaxDefinitions {
		return 0, ErrHTMLRevisionSourceV1
	}
	n := int64(2)
	for key, value := range values {
		if !htmlRevisionRecordAddV1(&n, int64(len(key)), 6) || !htmlRevisionRecordAddV1(&n, int64(len(value)), 6) || !htmlRevisionRecordAddV1(&n, 1, 8) {
			return 0, ErrHTMLRevisionSourceV1
		}
	}
	return n, nil
}

// Only the immutable declaration captured from this ORIGINAL real revision
// request is merged. No public map, Master, Compiled or digest argument exists.
func (h *ApplicationHTMLRevisionSourceV1) MaterializeRevisionV1() error {
	if h == nil || h.state == nil || h.state.purpose != htmlRevisionSourcePurposeV1 || h.state.operation == nil {
		return ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return err
	}
	defer s.finishV1()
	s.mu.Lock()
	if s.processing || s.prepareAttempted || s.validation == nil || !s.currentValidated || s.prepared != nil {
		s.mu.Unlock()
		return ErrHTMLRevisionSourceV1
	}
	s.processing = true
	s.prepareAttempted = true
	v := s.validation
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	declaration := s.operation.declaration
	copies, err := htmlRevisionNewMapCopiesV1(s.effectiveInput, declaration.Values, declaration.Sections)
	if err != nil {
		return err
	}
	if err = s.holdV1(htmlRevisionSourcePrepareV1, 0, copies); err != nil {
		return err
	}
	merged := s.effectiveInput
	merged.Values = maps.Clone(merged.Values)
	merged.Sections = maps.Clone(merged.Sections)
	if merged.Values == nil {
		merged.Values = map[string]string{}
	}
	if merged.Sections == nil {
		merged.Sections = map[string]string{}
	}
	for key, value := range declaration.Values {
		merged.Values[key] = value
	}
	for key, value := range declaration.Sections {
		merged.Sections[key] = value
	}
	// Price the temporary union without deciding validity. Existing and declared
	// maps each have at most64 names, but their union can have128 before the
	// unchanged Materialize applies its original readiness/value/section order.
	valuesJSONBytes, err := htmlRevisionMergedValuesJSONBytesV1(merged.Values)
	if err != nil {
		return err
	}
	bindings, err := htmlRevisionObjectOutputV1([]string{"slot", "recipient_id"}, 2*int64(len("customer")+len("provider")+36+8))
	if err != nil {
		return err
	}
	record := htmlRevisionRecordComponentsV1{valuesJSONBytes: valuesJSONBytes, bindingsJSONBytes: bindings}
	outputs, err := htmlRevisionBodyOutputComponentsForV1(s.effectiveRawMaster, merged, s.effectiveOutput, record)
	if err != nil {
		return err
	}
	readiness, err := htmlRevisionContractReadinessComponentsForV1(s.effectiveRawMaster, htmlmaster.Input{Values: merged.Values, Sections: merged.Sections})
	if err != nil {
		return err
	}
	scratch, err := htmlAuthoringSumV1(s.effectiveRawScratch, outputs.expressionBytes, readiness.parentBytes)
	if err != nil {
		return err
	}
	retained := int64(htmlmaster.MaxMaterializedBytes)
	if !htmlRevisionRetentionAllocV1(&retained, int64(len(s.effectiveRawMaster.Sections))*16) || !htmlRevisionRetentionAllocV1(&retained, int64(len(s.effectiveRawMaster.Sections))*16) {
		return ErrHTMLRevisionSourceV1
	}
	// Original MaterializeRevision returns a cloned input and result; one later
	// actual render borrow returns a separate input/changed-section projection.
	if err = s.holdV1(htmlRevisionSourcePrepareV1, scratch, retained); err != nil {
		return err
	}
	input, result, changed, err := v.MaterializeRevisionV1(declaration.Values, declaration.Sections)
	if err != nil {
		return err
	}
	if !changed {
		return ErrHTMLRevisionNoChangeV1
	}
	if !applicationContextV1(s.binding.ctx) {
		return ErrHTMLRevisionSourceV1
	}
	s.mu.Lock()
	s.prepared = &applicationHTMLRevisionPreparedV1{input: input, rendered: result}
	s.mu.Unlock()
	return nil
}
func (h *ApplicationHTMLRevisionSourceV1) BorrowPreparedV1() (*HTMLRevisionPreparedModelsV1, func(), error) {
	if h == nil || h.state == nil || h.state.purpose != htmlRevisionSourcePurposeV1 || h.state.operation == nil {
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	if s.processing || s.prepared == nil || s.prepared.borrowed {
		s.mu.Unlock()
		s.finishV1()
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	s.prepared.borrowed = true
	input, rendered := s.prepared.input, s.prepared.rendered
	s.mu.Unlock()
	input = htmlRevisionCopyInputV1(input)
	rendered.ChangedSections = slices.Clone(rendered.ChangedSections)
	// Ensure the result's externally visible scalar strings remain values; no
	// caller can mutate the separately retained native input/maps/artifact.
	rendered.MasterDigest = strings.Clone(rendered.MasterDigest)
	rendered.ContentDigest = strings.Clone(rendered.ContentDigest)
	if !applicationContextV1(s.binding.ctx) {
		s.finishV1()
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	models := &HTMLRevisionPreparedModelsV1{Input: input, Rendered: rendered}
	var once sync.Once
	release := func() { once.Do(s.finishV1) }
	return models, release, nil
}
