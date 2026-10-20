// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"unsafe"
)

// Only a genuine same-operation private Source24 family issues this manifest.
// Its independent immutable output keeps no child/body/SQL owner after the
// actual native parse/hash/formatter consumer and COMMIT have joined.
type ApplicationHistoricalTerminalManifestV1 struct {
	self    *ApplicationHistoricalTerminalManifestV1
	html    *ApplicationHistoricalFinalizationHTMLV1
	updated pgtype.Timestamptz
}

func (m *ApplicationHistoricalTerminalManifestV1) CloseConsumerV1() {
	if m != nil && m.self == m && m.html != nil {
		m.html.CloseConsumerV1()
	}
}
func (m *ApplicationHistoricalTerminalManifestV1) borrowForCertificateV1(source *ApplicationHistoricalFinalizationSourceEvidenceV1) (string, func(), error) {
	if m == nil || m.self != m || m.html == nil || source == nil || source.document == nil || source.work == nil || source.work.stage == nil || source.work.stage.operation == nil {
		return "", nil, ErrHistoricalFinalizationSourceV1
	}
	// Borrow first under the actual HTML mutex: its copied Close may request
	// retirement, but cannot clear scope or bytes while this borrower exists.
	section, finish, err := m.html.BorrowHTMLV1()
	if err != nil {
		return "", nil, err
	}
	m.html.mu.Lock()
	valid := m.html.factory == source.work.stage.operation.factory && m.html.org == source.document.OrgID && m.html.document == source.document.ID && m.updated == source.document.UpdatedAt
	m.html.mu.Unlock()
	if !valid {
		finish()
		return "", nil, ErrHistoricalFinalizationSourceV1
	}
	return section, finish, nil
}
func (w *ApplicationHTMLSendWorkV1) NewHistoricalTerminalManifestV1(call context.Context, source *ApplicationHistoricalFinalizationSourceEvidenceV1, family *ApplicationHistoricalFinalizationSourceFamilyV1) (*ApplicationHistoricalTerminalManifestV1, error) {
	if w == nil || w.self != w || source == nil || family == nil || family.self != family {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	if !source.lockV1() {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	defer source.unlockV1()
	if !source.validV1() || !source.sourceChecked || source.document == nil || !source.document.IsEnvelope || family.work == nil || family.work.stage.operation != source.work.stage.operation {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && w.stage.purpose == HTMLHistoricalFinalizationSourceV1 && w.stage.operation == source.work.stage.operation && w.sourceDocument == source.document && w.familyRoot == nil
	doc := w.sourceDocument
	w.mu.Unlock()
	if !valid {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	members, err := w.ReadEnvelopeMembersV1(call)
	if err != nil {
		return nil, err
	}
	resource := int64(65536) + 8*int64(unsafe.Sizeof(ApplicationHistoricalTerminalManifestV1{}))
	if !htmlInputAddV1(&resource, int64(len(members)), 8192+8*int64(unsafe.Sizeof((*generated.Document)(nil)))+8*int64(unsafe.Sizeof(""))) || !htmlInputAddV1(&resource, int64(len(doc.Name)), 64) {
		return nil, ErrHistoricalFinalizationSourceV1
	}
	output, err := w.newHistoricalHTMLV1(call, resource)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			output.CloseConsumerV1()
		}
	}()
	children := make([]*generated.Document, len(members))
	for i, member := range members {
		if member == nil {
			return nil, fmt.Errorf("manifest: child %d is nil", i+1)
		}
		if _, err = family.NewHistoricalRenderMemberContinuationV1(call, member); err != nil {
			return nil, err
		}
		member.mu.Lock()
		children[i] = member.sourceDocument
		member.mu.Unlock()
	}
	// All original topology/status decisions precede the first child parse/hash.
	if err = envelopes.ValidateTerminalManifestFamilyV1(doc, children); err != nil {
		return nil, err
	}
	snapshots := make([]string, len(children))
	for i, child := range children {
		if child.OrgID != doc.OrgID || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != doc.ID {
			return nil, ErrHistoricalFinalizationSourceV1
		}
		if child.SourceKind != "blocks" {
			return nil, fmt.Errorf("manifest: child %s: unsupported source kind %q", child.ID, child.SourceKind)
		}
		native, err := members[i].historicalFinalizationSourceV1(call)
		if err != nil {
			return nil, err
		}
		if err = native.prepareHistoricalManifestTreeV1(); err != nil {
			return nil, fmt.Errorf("manifest: child %s: parse blocks: %w", child.ID, err)
		}
		if err = output.grant.TryGrowParentV1(w.stage.operation.original, 64*int64(len(child.Name))+8192); err != nil {
			return nil, err
		}
		snapshots[i] = envelopes.FrozenContentSnapshotDigestV1(child)
	}
	manifest, err := envelopes.BuildTerminalManifestFromSnapshotsV1(doc, children, snapshots)
	if err != nil {
		return nil, err
	}
	output.html = manifest.HTMLSection()
	if output.html == "" {
		return nil, errors.New("finalize envelope: terminal manifest is empty")
	}
	result := &ApplicationHistoricalTerminalManifestV1{html: output, updated: doc.UpdatedAt}
	result.self = result
	keep = true
	return result, nil
}
func (h *ApplicationHTMLSendSourceV1) prepareHistoricalManifestTreeV1() error {
	if h == nil || h.state == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	s := h.state
	if !s.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if err := s.owner.beginV1(); err != nil {
		return err
	}
	defer s.owner.finishV1()
	return s.ensureBlockTreeV1()
}
