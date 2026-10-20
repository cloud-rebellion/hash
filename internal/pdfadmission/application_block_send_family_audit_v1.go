// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// The only extra logical audit scope is an ACTUAL registered envelope member.
// Native SQL/admission stays on its root; WithPrepared still locks the exact
// child identity, chains the original payload and measures ONLY the new event.
func (w *ApplicationHTMLSendWorkV1) memberAuditScopeMatchesV1(call context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID) bool {
	if w == nil || w.self != w {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.familyRoot == nil || w.logicalDocumentV1() != document || w.session.state.org != org || w.sourceDocument == nil || w.sourceDocument.ID != document {
		return false
	}
	if purpose == HTMLAuditCRMObservedV1 {
		return w.stage.purpose == HTMLSendAdmissionV1 && w.observationsAttempted
	}
	if purpose == HTMLAuditHistoricalCompletedV1 && w.stage.purpose == HTMLHistoricalFinalizationPublicationV1 {
		root := w.familyRoot
		root.mu.Lock()
		defer root.mu.Unlock()
		if root.finalization == nil || root.finalization.publication == nil || root.finalization.publication.completed == nil {
			return false
		}
		for _, child := range root.finalization.publication.children {
			if child != nil && child.ID == document && child.OrgID == org && child.Status == "completed" {
				return true
			}
		}
		return false
	}
	if w.stage.purpose != HTMLSendCompletionV1 {
		return false
	}
	root := w.familyRoot
	root.mu.Lock()
	defer root.mu.Unlock()
	state := root.familyMutations
	if state == nil || state.root != root || !state.completeDone {
		return false
	}
	switch purpose {
	case HTMLAuditDocumentSentV1:
		return true
	case HTMLAuditDocumentExpiredV1:
		return state.expireDone
	default:
		return false
	}
}
func (w *ApplicationHTMLSendWorkV1) NewEnvelopeMemberAuditV1(call context.Context, purpose HTMLAuditPurposeV1, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLAuditEventV1
	}
	w.mu.Lock()
	if w.session == nil || w.session.state == nil {
		w.mu.Unlock()
		return nil, ErrHTMLAuditEventV1
	}
	session := w.session
	org, document := session.state.org, w.logicalDocumentV1()
	w.mu.Unlock()
	if document == uuid.Nil || !w.memberAuditScopeMatchesV1(call, purpose, org, document) {
		return nil, ErrHTMLAuditEventV1
	}
	return session.newHTMLAuditEventV1(call, purpose, org, document, recipient, actor, kind, ip, ua, payload, w)
}

// Lookup only an already registered native member; an arbitrary UUID never
// creates membership, source work, another session or an audit grant.
func (w *ApplicationHTMLSendWorkV1) EnvelopeMemberForAuditV1(call context.Context, document uuid.UUID) *ApplicationHTMLSendWorkV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.familyRoot != nil || !w.familyMembersAttempted {
		return nil
	}
	for _, member := range w.familyMembers {
		if member != nil && member.memberDocument == document {
			return member
		}
	}
	return nil
}
