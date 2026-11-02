// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

// WithPDFBodyV1 derives the exact provider pin from this genuine native source,
// never from the exported response model. The original SQL session has ended;
// its retained source consumer remains live through provider work, a fresh
// authorization/source recheck and the synchronous HTTP writer callback.
func (h *ApplicationPDFTemplateSourceV1) WithPDFBodyV1(ctx context.Context, client *storage.Client, consume func([]byte) error) error {
	if h == nil || h.state == nil || client == nil || consume == nil || !applicationContextV1(ctx) {
		return ErrPDFTemplateSourceV1
	}
	s := h.state
	// CloseConsumer waits for this real borrower instead of refunding its source
	// loan during provider IO or a blocked HTTP write. No copied close can bypass it.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.template == nil || s.session == nil || s.session.state == nil || s.session.state.factory == nil {
		return ErrPDFTemplateSourceV1
	}
	// The public ReadV1 facade must have ended and positively retired the
	// original physical SQL session before this distinct provider operation.
	session := s.session.state
	session.mu.Lock()
	sqlRetired := session.closed && session.retired && !session.unknown && session.active == 0 && !session.callbackActive && !session.sqlActive
	session.mu.Unlock()
	if !sqlRetired {
		return ErrPDFTemplateSourceV1
	}
	t := s.template
	if t.SourceKind != "pdf" || t.ArchivedAt.Valid || !t.PdfStorageKey.Valid || !t.PdfStorageVersionID.Valid || !t.EvidenceVersionPinRequired || len(t.PdfSha256) != sha256.Size {
		return ErrPDFTemplateSourceV1
	}
	p := s.session.state.factory
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return ErrPDFTemplateSourceV1
	}
	body, _, err := client.ReadTemplatePDFLocalOwnedV1(ctx, t.PdfStorageKey.String, t.PdfStorageVersionID.String, t.PdfSha256, coordinator, t.OrgID)
	if body != nil {
		defer body.CloseConsumerV1()
	}
	if err != nil {
		return errors.Join(ErrPDFTemplateSourceV1, err)
	}
	return body.WithPDFV1(consume)
}
