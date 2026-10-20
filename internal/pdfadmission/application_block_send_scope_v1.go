// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/google/uuid"
)

// A member ID is minted only by the same root Work's actual ordered membership
// read. The physical session and every body/SQL admission keep the root UUID.
// This private logical selector adopts no caller row, UUID or membership claim.
// Callers hold w.mu; the root mutex is distinct for genuine member Works.
func (w *ApplicationHTMLSendWorkV1) logicalDocumentV1() uuid.UUID {
	if w == nil || w.self != w || w.session == nil || w.session.state == nil || w.stage == nil || w.stage.operation == nil {
		return uuid.Nil
	}
	physical := w.session.state
	if w.familyRoot == nil {
		if w.memberDocument != uuid.Nil || w.familyPin != nil || w.stage.operation.document != physical.document {
			return uuid.Nil
		}
		return physical.document
	}
	root := w.familyRoot
	if root == w || root.self != root || root.familyRoot != nil || root.stage != w.stage || root.session != w.session || w.memberDocument == uuid.Nil || w.familyPin == nil || w.familyPin.ID != w.memberDocument || w.familyPin.OrgID != physical.org || !w.familyPin.ParentEnvelopeID.Valid || uuid.UUID(w.familyPin.ParentEnvelopeID.Bytes) != physical.document {
		return uuid.Nil
	}
	root.mu.Lock()
	defer root.mu.Unlock()
	for _, member := range root.familyMembers {
		if member == w {
			return w.memberDocument
		}
	}
	return uuid.Nil
}

// Child block documents inherit the root's signing parties. This proof consumes
// the actual same-phase root recipient observation; it fabricates no child rows.
func (w *ApplicationHTMLSendWorkV1) memberRootPartiesReadyV1() bool {
	if w == nil || w.self != w {
		return false
	}
	w.mu.Lock()
	root := w.familyRoot
	live := !w.closed && !w.resourcesClosed && root != nil && w.stage != nil
	w.mu.Unlock()
	if !live || root == w {
		return false
	}
	root.mu.Lock()
	registered := false
	for _, member := range root.familyMembers {
		if member == w {
			registered = true
			break
		}
	}
	source := root.sourceState
	ready := registered && !root.closed && !root.resourcesClosed && root.stage == w.stage && root.recipientsRead && source != nil
	root.mu.Unlock()
	if !ready {
		return false
	}
	if !source.lockV1() {
		return false
	}
	defer source.unlockV1()
	return !source.closeRequested.Load() && source.work == root && source.owner != nil && source.partiesAttempted && source.partiesFailure == nil
}
