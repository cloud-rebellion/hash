// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"unsafe"
)

type applicationHistoricalSourceMemberV1 struct {
	document uuid.UUID
	evidence *ApplicationHistoricalFinalizationSourceEvidenceV1
}

// Only this fixed historical family continuation keeps private, genuinely
// captured child sources. Public views cannot replace the selector inventory.
// Its real Work/member source grants remain owned by the existing operation.
type ApplicationHistoricalFinalizationSourceFamilyV1 struct {
	self    *ApplicationHistoricalFinalizationSourceFamilyV1
	work    *ApplicationHTMLSendWorkV1
	members []applicationHistoricalSourceMemberV1
	views   []*generated.Document
}

// ContinueEnvelopeSourceVersionsV1 runs at the ORIGINAL post-deadline/branding
// child gate in a fresh actual callback. It never reuses an ended call context
// or rereads/clones the root JSON. The same private Source24 root body is lent
// only while its evidence mutex retains the original source borrower/grant.
// A fresh FOR UPDATE scalar State and M67's every-writer row clock bind that
// body to the actual new transaction. All child bodies/headers remain fresh.
func (e *ApplicationHistoricalFinalizationSourceEvidenceV1) ContinueEnvelopeSourceVersionsV1(call context.Context, w *ApplicationHTMLSendWorkV1) (family *ApplicationHistoricalFinalizationSourceFamilyV1, failure error) {
	if e == nil || e.self != e || w == nil || w.self != w {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer e.unlockV1()
	if !e.validV1() || !e.sourceChecked || e.familyAttempted || e.document == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !e.document.IsEnvelope {
		return nil, nil
	}
	e.familyAttempted = true
	old := e.work
	old.mu.Lock()
	sourceVersion := old.sourceServerVersion
	operation := old.stage.operation
	sourceLive := !old.closed && !old.resourcesClosed && old.historicalSourceEvidence == e && old.sourceDocument == e.document && old.sourceBorrowers > 0
	old.mu.Unlock()
	if !sourceLive || sourceVersion <= 0 {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	// No caller row, body size, cache insertion, alternate source or SQL authority
	// can construct this borrowing window. The private old source is still live.
	if old == w || !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationSourceV1 || w.stage.operation == nil || old.stage == nil || old.stage.operation == nil || w.stage.operation != operation || w.stage.operation.factory != operation.factory || w.familyRoot != nil || w.sourceDocument != nil || w.models != nil || w.modelsRead || w.familyMembersAttempted || w.sourceBorrowers != 0 || !historicalSourceContinuationStateMatchesV1(e.document, w.state) {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	// This is fixed native scalar/model shell work, never a replacement body
	// estimate or a reduced authoring-header allowance. No DB body is expanded.
	fixed := 2*int64(unsafe.Sizeof(HTMLSendModelsV1{})) + 2*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationSourceFamilyV1{})) + 2*int64(unsafe.Sizeof(generated.GetBlockSendFamilyMemberCountV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetHTMLSendDocumentStateHeaderV1Row{})) + 16*int64(unsafe.Sizeof(uintptr(0)))
	closeFixed, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		w.mu.Unlock()
		return nil, err
	}
	w.closes = append(w.closes, closeFixed)
	w.sourceBorrowers++
	w.sourceDocument = e.document
	w.models = &HTMLSendModelsV1{Document: e.document}
	w.modelsRead = true
	w.sourceServerVersion = sourceVersion
	w.mu.Unlock()
	// Clear every borrowed root view before the old evidence mutex can release
	// its source borrower. Independently retained children use only their own
	// private source bodies after this callback and keep the root registry loan.
	defer func() {
		w.mu.Lock()
		w.sourceDocument = nil
		w.models = nil
		w.sourceServerVersion = 0
		w.sourceBorrowers--
		closes, actor := w.retireSourcesLockedV1()
		w.mu.Unlock()
		htmlSendCloseSourceResourcesV1(closes, actor)
		w.releaseFamilyRootIfRetiredV1()
	}()
	listed, err := w.HistoricalFinalizationMembersV1(call)
	if err != nil {
		return nil, fmt.Errorf("finalize envelope: list children for VersionId pinning: %w", err)
	}
	if len(listed) == 0 {
		return nil, errors.New("finalize envelope: no children available for VersionId pinning")
	}
	// Both returned and private arrays are funded from THIS actual captured list
	// before allocation. The existing count producer has already funded its list.
	raw := 2 * int64(unsafe.Sizeof(ApplicationHistoricalFinalizationSourceFamilyV1{}))
	if !htmlInputAddV1(&raw, int64(len(listed)), 4*int64(unsafe.Sizeof(applicationHistoricalSourceMemberV1{}))+4*int64(unsafe.Sizeof((*generated.Document)(nil)))) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	if !w.valid(call) {
		w.mu.Unlock()
		return nil, ErrHistoricalFinalizationSourceV1
	}
	closeMembers, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err == nil {
		w.closes = append(w.closes, closeMembers)
	}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	family = &ApplicationHistoricalFinalizationSourceFamilyV1{work: w, members: make([]applicationHistoricalSourceMemberV1, 0, len(listed)), views: make([]*generated.Document, 0, len(listed))}
	family.self = family
	for _, child := range listed {
		if child == nil || child.OrgID != e.document.OrgID || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != e.document.ID || !historicalSourceChildStatusMatchesV1(e.document.Status, child.Status) {
			return family, errors.New("finalize envelope: invalid child while pinning evidence versions")
		}
		member := w.EnvelopeMemberForAuditV1(call, child.ID)
		if member == nil {
			return family, ErrHistoricalFinalizationSourceV1
		}
		evidence, err := member.NewHistoricalFinalizationSourceEvidenceV1(call, e.client)
		if err != nil {
			return family, err
		}
		family.members = append(family.members, applicationHistoricalSourceMemberV1{document: child.ID, evidence: evidence})
		pinned, err := evidence.EnsureSourceVersionsV1(call)
		if err != nil {
			return family, fmt.Errorf("finalize envelope: pin child %s source VersionIds: %w", child.ID, err)
		}
		if pinned.RequiresSignature {
			if err = evidence.EnsureSignatureVersionsV1(call); err != nil {
				return family, fmt.Errorf("finalize envelope: pin child %s signature VersionIds: %w", child.ID, err)
			}
		}
		family.views = append(family.views, pinned)
	}
	return family, nil
}
func historicalSourceContinuationStateMatchesV1(d *generated.Document, h *generated.GetHTMLSendDocumentStateHeaderV1Row) bool {
	return d != nil && h != nil && (d.SourceKind == "pdf" || d.SourceKind == "blocks") && d.ID == h.ID && d.OrgID == h.OrgID && d.Status == "finalizing" && h.BoundedStatus == d.Status && d.IsEnvelope && h.IsEnvelope && !d.ParentEnvelopeID.Valid && !h.ParentEnvelopeID.Valid && d.RequiresSignature == h.RequiresSignature && (d.SourceKind == "pdf") == h.IsPdfSource && applicationStampV1(d.UpdatedAt) && applicationStampV1(h.UpdatedAt) && d.UpdatedAt == h.UpdatedAt && d.EvidenceVersionPinsRequired == h.EvidenceVersionPinsRequired
}
func historicalSourceChildStatusMatchesV1(parent, child string) bool {
	switch parent {
	case "finalizing":
		return child == "finalizing"
	case "sent", "in_progress", "changes_requested":
		return child == "sent" || child == "in_progress"
	}
	return false
}
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) DocumentsV1() ([]*generated.Document, error) {
	if f == nil || f.self != f || f.work == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	f.work.mu.Lock()
	valid := !f.work.closed && !f.work.resourcesClosed
	f.work.mu.Unlock()
	if !valid {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	return f.views, nil
}
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) memberV1(document uuid.UUID) (*ApplicationHistoricalFinalizationSourceEvidenceV1, error) {
	if f == nil || f.self != f || f.work == nil {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	for _, member := range f.members {
		if member.document == document && member.evidence != nil {
			return member.evidence, nil
		}
	}
	return nil, ErrHistoricalFinalizationSourceV1
}
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) WithSourcePDFV1(document uuid.UUID, consume func([]byte) error) error {
	e, err := f.memberV1(document)
	if err != nil {
		return err
	}
	return e.WithSourcePDFV1(consume)
}
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) SignatureRowsV1(document uuid.UUID) ([]*generated.Signature, error) {
	e, err := f.memberV1(document)
	if err != nil {
		return nil, err
	}
	return e.SignatureRowsV1()
}
func (f *ApplicationHistoricalFinalizationSourceFamilyV1) WithSignatureBodyV1(document, signature uuid.UUID, consume func([]byte) error) error {
	e, err := f.memberV1(document)
	if err != nil {
		return err
	}
	return e.WithSignatureBodyV1(signature, consume)
}
