// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"strings"
)

func htmlSendCloneBrandingV1(in *generated.DocumentBrandingOverride) *generated.DocumentBrandingOverride {
	if in == nil {
		return nil
	}
	out := *in
	out.PrimaryHex.String = strings.Clone(in.PrimaryHex.String)
	out.AccentHex.String = strings.Clone(in.AccentHex.String)
	out.SurfaceHex.String = strings.Clone(in.SurfaceHex.String)
	out.TextHex.String = strings.Clone(in.TextHex.String)
	out.MutedHex.String = strings.Clone(in.MutedHex.String)
	out.LogoUrl.String = strings.Clone(in.LogoUrl.String)
	out.LogoAlt.String = strings.Clone(in.LogoAlt.String)
	out.FontHeading.String = strings.Clone(in.FontHeading.String)
	out.FontBody.String = strings.Clone(in.FontBody.String)
	out.SignatureColor.String = strings.Clone(in.SignatureColor.String)
	return &out
}

// The original Freeze query's private result, rather than its mutable returned
// view, owns this policy input. Current-source validation remains pinned to the
// original locked tuple; lawful-basis confirmation does not substitute a new
// immutable source or require another Compile.
func (w *ApplicationHTMLSendWorkV1) ValidateFrozenBrandingV1(call context.Context, h *ApplicationHTMLSendSourceV1) error {
	if w == nil || w.self != w || h == nil || h.state == nil || h.state.work != w || h.state.candidate {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || !s.attempted || s.failure != nil || s.owner == nil {
		return ErrHTMLSendWorkV1
	}
	owner := s.owner
	if err := owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	w.mu.Lock()
	if !w.valid(call) || w.sourceOwner != owner || w.frozenBranding == nil {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	row := w.frozenBranding
	w.mu.Unlock()
	if err := s.holdPolicyV1(); err != nil {
		return err
	}
	owner.mu.Lock()
	v := owner.validation
	owner.mu.Unlock()
	if v == nil {
		return ErrHTMLSendWorkV1
	}
	return v.ValidateSigningBrandingV1(row)
}
