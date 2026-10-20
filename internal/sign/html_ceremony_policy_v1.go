// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This value contains real policy fields from either the legacy full row or
// the native separately admitted actual policy projection. It is never a
// generated.Document shell, a source/model authority or a replacement identity.
type htmlCeremonyDocumentPinsV1 struct {
	present                         bool
	document, org                   uuid.UUID
	name, lawfulBasis, noticeSchema string
	sentAt, noticeEpoch, expiresAt  pgtype.Timestamptz
	noticeCommitted                 bool
}

func htmlCeremonyDocumentPinsForV1(document *generated.Document) htmlCeremonyDocumentPinsV1 {
	if document == nil {
		return htmlCeremonyDocumentPinsV1{}
	}
	return htmlCeremonyDocumentPinsV1{present: true, document: document.ID, org: document.OrgID, name: document.Name, lawfulBasis: document.LawfulBasis,
		noticeSchema: document.Article13NoticeSchema, sentAt: document.SentAt, noticeEpoch: document.Article13NoticeEpochAt,
		expiresAt: document.ExpiresAt, noticeCommitted: document.Article13NoticeEpochV61Committed}
}
func validateHTMLCeremonyNoticePinsV1(pins htmlCeremonyDocumentPinsV1, recipient uuid.UUID, notice article13.Evidence) error {
	if !pins.present {
		return ErrInvalidNoticeEvidence
	}
	if err := notice.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNoticeEvidence, err)
	}
	snapshot := notice.Snapshot
	if snapshot.OrgID != pins.org || snapshot.DocumentID != pins.document || snapshot.RecipientID != recipient || !pins.sentAt.Valid ||
		!pins.noticeEpoch.Valid || !pins.noticeEpoch.Time.Equal(pins.sentAt.Time) || snapshot.Schema != pins.noticeSchema ||
		snapshot.SentAt != pins.sentAt.Time.UTC().Format(time.RFC3339Nano) {
		return ErrInvalidNoticeEvidence
	}
	return nil
}
func (p *presentedCredentialV1) validateLockedPinsV1(rc *RecipientContext, recipient *generated.Recipient, pins htmlCeremonyDocumentPinsV1, now time.Time) error {
	if err := p.validateLockedIdentityV1(rc, recipient, pins); err != nil {
		return err
	}
	if err := p.originalLiveV1(now); err != nil {
		return err
	}
	if !presentedStampEqualV1(pins.sentAt, p.sentAt) || !presentedStampEqualV1(pins.noticeEpoch, p.noticeEpoch) || pins.noticeSchema != p.noticeSchema ||
		pins.noticeCommitted != p.noticeCommitted || pins.name != p.documentName || pins.lawfulBasis != p.lawfulBasis {
		return ErrInvalidNoticeEvidence
	}
	return checkSignerReadExpiryV1(recipient.MagicTokenExpiresAt, pins.expiresAt, now)
}
func validateLockedRecipientPinsV1(rc *RecipientContext, fresh *generated.Recipient, pins htmlCeremonyDocumentPinsV1, now time.Time) error {
	if rc != nil && rc.presentedCredential != nil {
		if err := rc.presentedCredential.validateLockedPinsV1(rc, fresh, pins, now); err != nil {
			return err
		}
	}
	if rc == nil || rc.Recipient == nil || rc.Document == nil || fresh == nil || !pins.present ||
		fresh.ID != rc.Recipient.ID || fresh.DocumentID != pins.document || pins.document != rc.Document.ID || pins.org != rc.Document.OrgID ||
		len(rc.Recipient.MagicTokenHash) == 0 || subtle.ConstantTimeCompare(rc.Recipient.MagicTokenHash, fresh.MagicTokenHash) != 1 {
		return ErrMagicLinkExpired
	}
	if err := checkMagicLinkExpiry(rc.Recipient, rc.Document, now); err != nil {
		return err
	}
	return checkSignerReadExpiryV1(fresh.MagicTokenExpiresAt, pins.expiresAt, now)
}

func (p *presentedCredentialV1) validateLockedIdentityV1(rc *RecipientContext, recipient *generated.Recipient, pins htmlCeremonyDocumentPinsV1) error {
	if !p.matchesContextV1(rc) || recipient == nil || !pins.present || recipient.ID != p.recipientID || recipient.DocumentID != p.documentID || pins.document != p.documentID || pins.org != p.orgID ||
		len(recipient.MagicTokenHash) != sha256.Size || subtle.ConstantTimeCompare(p.tokenHash[:], recipient.MagicTokenHash) != 1 || recipient.Role != p.role {
		return ErrMagicLinkExpired
	}
	return nil
}

// The fixed actual document/recipient identity and old receipt liveness precede
// variable policy text in the original private credential decision. This uses
// real scalar pins only; it never substitutes a partial Document for that text.
func validateLockedRecipientPrefixV1(rc *RecipientContext, fresh *generated.Recipient, pins htmlCeremonyDocumentPinsV1, now time.Time) error {
	if rc != nil && rc.presentedCredential != nil {
		p := rc.presentedCredential
		if err := p.validateLockedIdentityV1(rc, fresh, pins); err != nil {
			return err
		}
		return p.originalLiveV1(now)
	}
	if rc == nil || rc.Recipient == nil || rc.Document == nil || fresh == nil || !pins.present ||
		fresh.ID != rc.Recipient.ID || fresh.DocumentID != pins.document || pins.document != rc.Document.ID || pins.org != rc.Document.OrgID ||
		len(rc.Recipient.MagicTokenHash) == 0 || subtle.ConstantTimeCompare(rc.Recipient.MagicTokenHash, fresh.MagicTokenHash) != 1 {
		return ErrMagicLinkExpired
	}
	return checkMagicLinkExpiry(rc.Recipient, rc.Document, now)
}
