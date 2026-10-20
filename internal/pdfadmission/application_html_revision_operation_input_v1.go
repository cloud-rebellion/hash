// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"

	"github.com/google/uuid"
)

type htmlRevisionDeclarationV1 struct {
	ExpectedUpdatedAt            string            `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment string            `json:"expected_html_source_commitment"`
	Values                       map[string]string `json:"values"`
	Sections                     map[string]string `json:"sections"`
	Summary                      string            `json:"summary"`
}

// The authenticated route runs its unchanged strict decoder and parameter
// checks first. This fixed producer then snapshots the SAME real admitted body;
// no later caller map, replacement raw JSON or cost declaration becomes source.
// One typed parse/copy consumes the installed input profile's existing fixed
// parser/output ledger; the native operation retains its actual producer use.
func (f *ApplicationSessionFactoryV1) revisionDeclarationV1(ctx context.Context, org uuid.UUID, h *ApplicationHTMLAuthoringInputV1) (htmlRevisionDeclarationV1, func(), error) {
	var out htmlRevisionDeclarationV1
	if f == nil || f.state == nil || h == nil || h.state == nil || !applicationContextV1(ctx) {
		return out, nil, ErrHTMLRevisionOperationV1
	}
	state := h.state
	p := f.state
	p.mu.Lock()
	state.mu.Lock()
	_, registered := p.htmlInputProducers[state]
	if !registered || p.closing || state.factory != p || state.org != org || state.profile != HTMLDocumentRevisionInputV1 ||
		state.consumerClosed || state.retired || !state.ready || len(state.raw) == 0 {
		state.mu.Unlock()
		p.mu.Unlock()
		return out, nil, ErrHTMLRevisionOperationV1
	}
	state.active++
	raw := state.raw
	state.mu.Unlock()
	p.mu.Unlock()
	owned := bytes.Clone(raw)
	if err := json.Unmarshal(owned, &out); err != nil {
		state.finishV1()
		return htmlRevisionDeclarationV1{}, nil, err
	}
	var once sync.Once
	release := func() { once.Do(state.finishV1) }
	return out, release, nil
}
func (o *applicationHTMLRevisionOperationV1) releaseSourceInputV1() {
	o.mu.Lock()
	o.sourceUses--
	release := o.releaseInputIfCompleteLockedV1()
	o.mu.Unlock()
	if release != nil {
		release()
	}
}
func (o *applicationHTMLRevisionOperationV1) releaseInputIfCompleteLockedV1() func() {
	if !o.closed || o.sourceUses != 0 || o.releaseInput == nil {
		return nil
	}
	o.declaration = htmlRevisionDeclarationV1{}
	release := o.releaseInput
	o.releaseInput = nil
	return release
}
