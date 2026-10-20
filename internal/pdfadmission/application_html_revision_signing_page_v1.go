// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"sync"
)

// This render borrow derives its HTML solely from the original immutable
// prepared declaration and raw-design result. It owns the source/body loan
// until the renderer has actually finished using HTML and policy.
type HTMLRevisionSigningPageV1 struct {
	HTML   string
	Policy *htmlmaster.SigningPagePolicy
}

func (h *ApplicationHTMLRevisionSourceV1) BorrowSigningPageV1() (*HTMLRevisionSigningPageV1, func(), error) {
	if h == nil || h.state == nil || h.state.purpose != htmlRevisionSourcePurposeV1 || h.state.operation == nil {
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	s := h.state
	if err := s.beginV1(); err != nil {
		return nil, nil, err
	}
	keep := false
	defer func() {
		if !keep {
			s.finishV1()
		}
	}()
	s.mu.Lock()
	if s.processing || s.prepared == nil || s.validation == nil {
		s.mu.Unlock()
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	s.processing = true
	input, v := s.prepared.input, s.validation
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.processing = false; s.mu.Unlock() }()
	// Policy is a defensive fixed-schema getter of the already-owned design.
	policy, _, err := v.SigningPageV1()
	if err != nil {
		return nil, nil, err
	}
	if policy == nil {
		keep = true
		var once sync.Once
		return &HTMLRevisionSigningPageV1{}, func() { once.Do(s.finishV1) }, nil
	}
	record, err := htmlRevisionTypedSourceEncodingForV1(s.binding.ctx, input, s.effectiveCanonical, s.snapshot.document.PdfStorageKey.String, s.snapshot.document.PdfStorageVersionID.String)
	if err != nil {
		return nil, nil, err
	}
	outputs, err := htmlRevisionBodyOutputComponentsForV1(s.effectiveRawMaster, input, s.effectiveOutput, record)
	if err != nil {
		return nil, nil, err
	}
	readiness, err := htmlRevisionContractReadinessComponentsForV1(s.effectiveRawMaster, htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil {
		return nil, nil, err
	}
	scratch, err := htmlAuthoringSumV1(s.effectiveRawScratch, outputs.expressionBytes, readiness.parentBytes, readiness.parentBytes)
	if err != nil {
		return nil, nil, err
	}
	if err = s.holdV1(htmlRevisionSourcePrepareV1, scratch, outputs.signingHTMLBytes); err != nil {
		return nil, nil, err
	}
	html, err := v.SigningPageHTMLV1(input.Values, input.Sections)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(html)) > outputs.signingHTMLBytes || !applicationContextV1(s.binding.ctx) {
		return nil, nil, ErrHTMLRevisionSourceV1
	}
	keep = true
	var once sync.Once
	return &HTMLRevisionSigningPageV1{HTML: html, Policy: policy}, func() { once.Do(s.finishV1) }, nil
}
