// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/remindercadence"
)

// This is a fixed native completion producer, not a public policy/SQL grant.
// The document and sent epoch are the actual private completed return. All
// controls precede scalar SQL; all schedule expansion precedes allocation.
func (w *ApplicationHTMLSendWorkV1) InstallReminderPolicyV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.installReminderPolicyLockedV1(call)
}
func (w *ApplicationHTMLSendWorkV1) installReminderPolicyLockedV1(call context.Context) error {
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLSendCompletionV1 && w.stage.purpose != HTMLPreSignPublicationV1) || w.familyRoot != nil || w.sourceDocument == nil || w.completedDocument == nil || !w.completedAttempted || w.reminderPolicyAttempted || w.sourceDocument.Status != "sent" || w.completedDocument.ID != w.sourceDocument.ID || w.completedDocument.OrgID != w.sourceDocument.OrgID || !applicationStampV1(w.sourceDocument.SentAt) || !applicationStampEqualV1(w.completedDocument.SentAt, w.sourceDocument.SentAt) {
		return ErrHTMLSendWorkV1
	}
	w.reminderPolicyAttempted = true
	controls, err := w.actor.acquireOwnedRetainedBodyV1(call, 32<<10, 8<<10)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, controls)
	w.sourceBorrowers++
	defer func() { w.sourceBorrowers-- }()
	_, err = remindercadence.FreezeAndInstallV1(call, w.queries, w.sourceDocument, func(p remindercadence.PolicyV1) error {
		if p.ValidateV1() != nil {
			return ErrHTMLSendWorkV1
		}
		// Count is native scalar policy <=365. Price schedule entries plus JSON,
		// expanded controls and driver copies before Offsets/Marshal/RETURNING.
		size := int64(512 + p.MaxFires*32)
		close, err := w.actor.acquireOwnedRetainedBodyV1(call, size*64, size*16)
		if err != nil {
			return err
		}
		w.closes = append(w.closes, close)
		return nil
	})
	return err
}
