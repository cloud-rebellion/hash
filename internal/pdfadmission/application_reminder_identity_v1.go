// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// This original subject-scoped native scalar phase takes NO document lock.
// Its result is only a hint. The returned mutation operation privately retains
// the original requested subject and must re-establish actual membership under
// root-first locks before it can issue a reminder producer.
func (w *ApplicationHTMLSendWorkV1) NewReminderRootOperationV1(call context.Context) (*ApplicationHTMLSendOperationV1, uuid.UUID, error) {
	if w == nil || w.self != w {
		return nil, uuid.Nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLReminderIdentityV1 || w.reminderIdentityAttempted || w.state != nil || w.modelsRead || w.familyRoot != nil {
		return nil, uuid.Nil, ErrHTMLSendWorkV1
	}
	w.reminderIdentityAttempted = true
	s := w.session.state
	row, err := w.queries.ResolveReminderRootIdentityV1(call, generated.ResolveReminderRootIdentityV1Params{DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, uuid.Nil, err
	}
	if row == nil || row.DocumentID != s.document || row.OrgID != s.org || row.RootDocumentID == uuid.Nil {
		return nil, uuid.Nil, ErrHTMLSendWorkV1
	}
	op, err := w.stage.operation.factory.NewHTMLSendOperationV1(w.stage.operation.callerContext, s.org, row.RootDocumentID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	op.reminderSubject = s.document
	return op, row.RootDocumentID, nil
}

// Only the private original request selects the subject. A mutable UUID or
// preflight full row cannot select a different family member here.
func (w *ApplicationHTMLSendWorkV1) ReminderSubjectV1(call context.Context) (*ApplicationHTMLSendWorkV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLReminderManualV1 && w.stage.purpose != HTMLReminderScheduledV1) || w.stage.operation.reminderSubject == uuid.Nil || w.familyRoot != nil || w.sourceDocument == nil || w.sourceDocument.ParentEnvelopeID.Valid || (w.sourceDocument.Status != "sent" && w.sourceDocument.Status != "in_progress") {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	subject := w.stage.operation.reminderSubject
	if subject == w.sourceDocument.ID {
		w.mu.Unlock()
		return w, nil
	}
	if !w.sourceDocument.IsEnvelope {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Unlock()
	members, err := w.ReadEnvelopeMembersV1(call)
	if err != nil {
		return nil, err
	}
	for _, member := range members {
		if member == nil {
			return nil, ErrHTMLSendWorkV1
		}
		member.mu.Lock()
		matched := member.valid(call) && member.familyRoot == w && member.logicalDocumentV1() == subject
		member.mu.Unlock()
		if matched {
			if _, err = member.ReadModelsV1(call); err != nil {
				return nil, err
			}
			return member, nil
		}
	}
	return nil, ErrHTMLSendWorkV1
}

// Returns only the already-owned original view, never re-expands a model or
// replaces private document/source authority from a caller row.
func (w *ApplicationHTMLSendWorkV1) ReminderModelsV1(call context.Context) (*HTMLSendModelsV1, error) {
	if w == nil || w.self != w {
		return nil, ErrReminderV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLReminderManualV1 && w.stage.purpose != HTMLReminderScheduledV1) || w.sourceDocument == nil || w.models == nil || !w.modelsRead || w.stage.operation.reminderSubject != w.sourceDocument.ID {
		return nil, ErrReminderV1
	}
	return w.models, nil
}
