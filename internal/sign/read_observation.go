// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"crypto/subtle"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/amendments"
)

// ValidateRecipientReadCredential retains the exact public magic-link
// admission through a read's database and external storage waits. Fresh data
// must have been looked up using the originally captured token; an extended
// deadline or a replacement identity cannot revive the earlier admission.
//
// This grants read access only. It neither checks response-role permission nor
// authorizes a mutation, and does not acquire the locks required for one.
// Callers must separately validate the observed document source and notice
// before publishing any response headers or body.
func ValidateRecipientReadCredential(original, fresh *RecipientContext, now time.Time) error {
	if original == nil || fresh == nil || original.Recipient == nil || fresh.Recipient == nil ||
		original.Document == nil || fresh.Document == nil {
		return ErrMagicLinkExpired
	}
	if original.AmendmentContext.ValidateV1(original.Document.ID, original.Document.RequiresSignature) != nil ||
		fresh.AmendmentContext.ValidateV1(fresh.Document.ID, fresh.Document.RequiresSignature) != nil ||
		!amendments.EqualSignerContextV1(original.AmendmentContext, fresh.AmendmentContext) {
		return ErrMagicLinkExpired
	}
	oldRecipient, newRecipient := original.Recipient, fresh.Recipient
	oldDocument, newDocument := original.Document, fresh.Document
	if oldRecipient.ID == uuid.Nil || oldDocument.ID == uuid.Nil || oldDocument.OrgID == uuid.Nil ||
		newRecipient.ID != oldRecipient.ID || oldRecipient.DocumentID != oldDocument.ID ||
		newRecipient.DocumentID != newDocument.ID || newDocument.ID != oldDocument.ID ||
		newDocument.OrgID != oldDocument.OrgID || oldRecipient.DocOrgID != oldDocument.OrgID ||
		newRecipient.DocOrgID != newDocument.OrgID ||
		len(oldRecipient.MagicTokenHash) == 0 ||
		subtle.ConstantTimeCompare(oldRecipient.MagicTokenHash, newRecipient.MagicTokenHash) != 1 ||
		oldRecipient.Name != newRecipient.Name || oldRecipient.Email != newRecipient.Email ||
		oldRecipient.Role != newRecipient.Role || oldRecipient.Locale != newRecipient.Locale ||
		oldRecipient.OrderIndex != newRecipient.OrderIndex {
		return ErrMagicLinkExpired
	}
	if err := checkMagicLinkExpiry(oldRecipient, oldDocument, now); err != nil {
		return err
	}
	if err := checkMagicLinkExpiry(newRecipient, newDocument, now); err != nil {
		return err
	}
	// Lookup reads the joined token row and then its parent. A state change
	// between those queries must fail this observation, rather than combine
	// routing admission from one state with a parent from another.
	if oldDocument.DeletedAt.Valid || newDocument.DeletedAt.Valid ||
		oldRecipient.DocStatus != oldDocument.Status || newRecipient.DocStatus != newDocument.Status {
		return ErrDocumentNotSignable
	}
	if err := checkActiveCeremonyAccess(oldDocument); err != nil {
		return err
	}
	return checkActiveCeremonyAccess(newDocument)
}
