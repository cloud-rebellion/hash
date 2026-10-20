// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/jackc/pgx/v5/pgtype"
)

func htmlSendRecipientsEqualV1(a, b []*generated.Recipient) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x == nil || y == nil {
			if x != y {
				return false
			}
			continue
		}
		if x.ID != y.ID || x.DocumentID != y.DocumentID || x.Role != y.Role || x.Email != y.Email || x.Name != y.Name || x.OrderIndex != y.OrderIndex || x.Status != y.Status || x.SentAt != y.SentAt || x.FirstViewedAt != y.FirstViewedAt || x.SignedAt != y.SignedAt || x.DeclinedReason != y.DeclinedReason || x.CreatedAt != y.CreatedAt || x.MagicTokenExpiresAt != y.MagicTokenExpiresAt || x.Locale != y.Locale || !bytes.Equal(x.MagicTokenHash, y.MagicTokenHash) {
			return false
		}
	}
	return true
}
func htmlSendNumericEqualV1(a, b pgtype.Numeric) bool {
	ai, bi := a.Int, b.Int
	a.Int = nil
	b.Int = nil
	if a != b || (ai == nil) != (bi == nil) {
		return false
	}
	return ai == nil || ai.Cmp(bi) == 0
}
func htmlSendFieldsEqualV1(a, b []*generated.DocumentField) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		y := b[i]
		if x == nil || y == nil {
			if x != y {
				return false
			}
			continue
		}
		if x.ID != y.ID || x.DocumentID != y.DocumentID || x.RecipientID != y.RecipientID || x.Type != y.Type || x.Page != y.Page || x.Required != y.Required || x.Label != y.Label || x.Value != y.Value || x.CompletedAt != y.CompletedAt || x.CreatedAt != y.CreatedAt || !bytes.Equal(x.OptionsJson, y.OptionsJson) || !htmlSendNumericEqualV1(x.XPct, y.XPct) || !htmlSendNumericEqualV1(x.YPct, y.YPct) || !htmlSendNumericEqualV1(x.WPct, y.WPct) || !htmlSendNumericEqualV1(x.HPct, y.HPct) {
			return false
		}
	}
	return true
}
func (s *applicationHTMLSendSourceStateV1) policyV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, withFields bool) (*htmlsource.RevisionValidationV1, error) {
	if s.work == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s.work.mu.Lock()
	defer s.work.mu.Unlock()
	if !s.work.recipientsRead || (withFields && !s.work.fieldsRead) || s.closeRequested.Load() || !s.attempted || s.failure != nil || s.owner == nil || s.owner.validation == nil || s.work == nil || !s.owner.validation.MatchesDocumentV1(doc) || !htmlSendRecipientsEqualV1(rows, s.work.sourceRecipients) || (withFields && !htmlSendFieldsEqualV1(fields, s.work.sourceFields)) {
		return nil, ErrHTMLSendWorkV1
	}
	return s.owner.validation, nil
}
func (s *applicationHTMLSendSourceStateV1) holdPolicyV1() error {
	owner := s.owner
	n, retained := int64(0), int64(0)
	if owner.effectiveRawMaster.SchemaVersion == htmlmaster.ContractSchemaVersion || owner.effectiveRawMaster.SchemaVersion == htmlmaster.SigningPageSchemaVersion {
		r, err := htmlRevisionContractReadinessComponentsForV1(owner.effectiveRawMaster, htmlmaster.Input{Values: owner.effectiveInput.Values, Sections: owner.effectiveInput.Sections})
		if err != nil {
			return err
		}
		n = r.parentBytes
		retained = r.retainedResultBytes
	}
	// Every original party/role/object/option result and local roles
	// slice is separately retained. Fixed role maps are bounded by the ORIGINAL
	// pdflayout100 parties/1000 fields gate, not a new customer restriction.
	rows := int64(min(len(s.work.sourceRecipients), pdflayout.MaxParties))
	maps := rows * 4
	if !htmlInputAddV1(&n, maps, int64(unsafe.Sizeof("")+unsafe.Sizeof([16]byte{})+unsafe.Sizeof(uintptr(0)))) || !htmlInputAddV1(&retained, rows, 4*int64(unsafe.Sizeof(""))) || !htmlInputAddV1(&retained, 4, int64(unsafe.Sizeof(htmlsource.ContractParty{}))) || !htmlInputAddV1(&retained, 2, int64(unsafe.Sizeof(htmlsource.SigningArtifact{}))+2*int64(unsafe.Sizeof(htmlsource.SigningRectangle{}))) {
		return ErrHTMLSendWorkV1
	}
	if err := owner.holdV1(htmlRevisionSourceStateV1, n, retained); err != nil {
		return err
	}
	owner.stateScratchBase = n
	return nil
}

// ValidatePartiesV1 compares the caller view only to reject tampering. Actual
// validation consumes the owner's immutable admitted rows and source tuple.
func (h *ApplicationHTMLSendSourceV1) ValidatePartiesV1(doc *generated.Document, rows []*generated.Recipient) error {
	if h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	v, err := s.policyV1(doc, rows, nil, false)
	if err != nil {
		return err
	}
	if s.partiesAttempted {
		return s.partiesFailure
	}
	s.partiesAttempted = true
	s.partiesFailure = ErrHTMLSendWorkV1
	if err = s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if err = s.holdPolicyV1(); err != nil {
		s.partiesFailure = err
		return err
	}
	s.partiesFailure = v.ValidateContractPartiesV1(s.work.sourceRecipients)
	return s.partiesFailure
}
func (h *ApplicationHTMLSendSourceV1) ValidatePDFRoleFieldsV1(doc *generated.Document, rows []*generated.Recipient, fields []*generated.DocumentField, pages int) error {
	if h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	v, err := s.policyV1(doc, rows, fields, true)
	if err != nil {
		return err
	}
	if s.rolesAttempted {
		if s.rolesPages != pages {
			return ErrHTMLSendWorkV1
		}
		return s.rolesFailure
	}
	s.rolesAttempted = true
	s.rolesPages = pages
	s.rolesFailure = ErrHTMLSendWorkV1
	if err = s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	if err = s.holdPolicyV1(); err != nil {
		s.rolesFailure = err
		return err
	}
	if err = s.owner.fieldOptionsComponentsV1(s.work.sourceFields); err != nil {
		s.rolesFailure = err
		return err
	}
	_, s.rolesFailure = pdflayout.RequiredRolesPreparedHTMLV1(s.owner.snapshot.document, s.work.sourceRecipients, s.work.sourceFields, pages, v)
	return s.rolesFailure
}
