// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func readCredentialFixture(now time.Time) *RecipientContext {
	docID, orgID := uuid.New(), uuid.New()
	return &RecipientContext{
		Recipient: &generated.GetRecipientByTokenHashRow{
			ID: uuid.New(), DocumentID: docID, DocOrgID: orgID, DocStatus: "sent",
			Name: "Printed representative", Email: "Signer@company.example", Role: "customer",
			Locale: "en", OrderIndex: 2, Status: "sent", MagicTokenHash: bytes.Repeat([]byte{0x42}, 32),
			MagicTokenExpiresAt: ts(now.Add(time.Hour)),
		},
		Document: &generated.Document{ID: docID, OrgID: orgID, Status: "sent", ExpiresAt: ts(now.Add(2 * time.Hour))},
	}
}

func cloneReadCredential(rc *RecipientContext) *RecipientContext {
	recipient, document := *rc.Recipient, *rc.Document
	recipient.MagicTokenHash = append([]byte(nil), recipient.MagicTokenHash...)
	return &RecipientContext{Recipient: &recipient, Document: &document}
}

func TestRecipientReadCredentialRetainsExactOriginalAdmission(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name   string
		change func(*RecipientContext, *RecipientContext)
		want   error
	}{
		{"same admission", func(_, _ *RecipientContext) {}, nil},
		{"original recipient naturally expired", func(old, _ *RecipientContext) { old.Recipient.MagicTokenExpiresAt = ts(now.Add(-time.Nanosecond)) }, ErrMagicLinkExpired},
		{"original document naturally expired", func(old, _ *RecipientContext) { old.Document.ExpiresAt = ts(now.Add(-time.Nanosecond)) }, ErrMagicLinkExpired},
		{"fresh recipient expired", func(_, next *RecipientContext) { next.Recipient.MagicTokenExpiresAt = ts(now.Add(-time.Nanosecond)) }, ErrMagicLinkExpired},
		{"fresh document expired", func(_, next *RecipientContext) { next.Document.ExpiresAt = ts(now.Add(-time.Nanosecond)) }, ErrMagicLinkExpired},
		{"same hash extension cannot revive recipient admission", func(old, next *RecipientContext) {
			old.Recipient.MagicTokenExpiresAt = ts(now.Add(-time.Nanosecond))
			next.Recipient.MagicTokenExpiresAt = ts(now.Add(time.Hour))
		}, ErrMagicLinkExpired},
		{"document extension cannot revive original admission", func(old, next *RecipientContext) {
			old.Document.ExpiresAt = ts(now.Add(-time.Nanosecond))
			next.Document.ExpiresAt = ts(now.Add(time.Hour))
		}, ErrMagicLinkExpired},
		{"revoked token", func(_, next *RecipientContext) { next.Recipient.MagicTokenHash = nil }, ErrMagicLinkExpired},
		{"rotated token", func(_, next *RecipientContext) { next.Recipient.MagicTokenHash[0] ^= 1 }, ErrMagicLinkExpired},
		{"credentialless admission", func(old, next *RecipientContext) {
			old.Recipient.MagicTokenHash = nil
			next.Recipient.MagicTokenHash = nil
		}, ErrMagicLinkExpired},
		{"replacement recipient", func(_, next *RecipientContext) { next.Recipient.ID = uuid.New() }, ErrMagicLinkExpired},
		{"different document", func(_, next *RecipientContext) {
			next.Document.ID = uuid.New()
			next.Recipient.DocumentID = next.Document.ID
		}, ErrMagicLinkExpired},
		{"different organization", func(_, next *RecipientContext) {
			next.Document.OrgID = uuid.New()
			next.Recipient.DocOrgID = next.Document.OrgID
		}, ErrMagicLinkExpired},
		{"incoherent original organization", func(old, _ *RecipientContext) { old.Recipient.DocOrgID = uuid.New() }, ErrMagicLinkExpired},
		{"incoherent fresh document", func(_, next *RecipientContext) { next.Recipient.DocumentID = uuid.New() }, ErrMagicLinkExpired},
		{"nil original recipient ID", func(old, _ *RecipientContext) { old.Recipient.ID = uuid.Nil }, ErrMagicLinkExpired},
		{"nil original document ID", func(old, _ *RecipientContext) { old.Document.ID = uuid.Nil; old.Recipient.DocumentID = uuid.Nil }, ErrMagicLinkExpired},
		{"nil original organization ID", func(old, _ *RecipientContext) { old.Document.OrgID = uuid.Nil; old.Recipient.DocOrgID = uuid.Nil }, ErrMagicLinkExpired},
		{"printed name changed", func(_, next *RecipientContext) { next.Recipient.Name += " changed" }, ErrMagicLinkExpired},
		{"mailbox case changed", func(_, next *RecipientContext) { next.Recipient.Email = "signer@company.example" }, ErrMagicLinkExpired},
		{"role escalated", func(_, next *RecipientContext) { next.Recipient.Role = "provider" }, ErrMagicLinkExpired},
		{"routing order changed", func(_, next *RecipientContext) { next.Recipient.OrderIndex++ }, ErrMagicLinkExpired},
		{"routing locale changed", func(_, next *RecipientContext) { next.Recipient.Locale = "sv" }, ErrMagicLinkExpired},
		{"original document deleted", func(old, _ *RecipientContext) { old.Document.DeletedAt = ts(now) }, ErrDocumentNotSignable},
		{"fresh document deleted", func(_, next *RecipientContext) { next.Document.DeletedAt = ts(now) }, ErrDocumentNotSignable},
		{"incoherent fresh status", func(_, next *RecipientContext) { next.Recipient.DocStatus = "completed" }, ErrDocumentNotSignable},
		{"incoherent original status", func(old, _ *RecipientContext) { old.Recipient.DocStatus = "draft" }, ErrDocumentNotSignable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := readCredentialFixture(now)
			next := cloneReadCredential(old)
			tc.change(old, next)
			if err := ValidateRecipientReadCredential(old, next, now); !errors.Is(err, tc.want) {
				t.Fatalf("read admission error=%v want=%v", err, tc.want)
			}
		})
	}
}

func TestRecipientReadCredentialAllowsFreshAdmissionAndActiveReadProgression(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, status := range []string{"sent", "in_progress", "changes_requested"} {
		t.Run(status, func(t *testing.T) {
			old := readCredentialFixture(now)
			next := cloneReadCredential(old)
			next.Document.Status, next.Recipient.DocStatus = status, status
			next.Recipient.Status = "signed"
			if err := ValidateRecipientReadCredential(old, next, now); err != nil {
				t.Fatalf("active read progression rejected: %v", err)
			}
		})
	}
	for _, status := range []string{"pending", "sent", "viewed", "signed", "accepted", "declined"} {
		t.Run("recipient "+status, func(t *testing.T) {
			old := readCredentialFixture(now)
			next := cloneReadCredential(old)
			next.Recipient.Status = status
			if err := ValidateRecipientReadCredential(old, next, now); err != nil {
				t.Fatalf("read-only recipient status semantics changed: %v", err)
			}
		})
	}
	old := readCredentialFixture(now)
	old.Recipient.MagicTokenExpiresAt = ts(now.Add(-time.Hour))
	next := cloneReadCredential(old)
	next.Recipient.MagicTokenExpiresAt = ts(now.Add(time.Hour))
	if err := ValidateRecipientReadCredential(next, cloneReadCredential(next), now); err != nil {
		t.Fatalf("new admission under extended deadline rejected: %v", err)
	}
	// Keep the existing equality-at-deadline and null-expiry policy. This helper
	// retains a read admission; it does not redefine magic-link issuance.
	next.Recipient.MagicTokenExpiresAt = ts(now)
	next.Document.ExpiresAt = ts(now)
	if err := ValidateRecipientReadCredential(next, cloneReadCredential(next), now); err != nil {
		t.Fatalf("existing exact-deadline semantics changed: %v", err)
	}
}

func TestRecipientReadCredentialNeverAdmitsDraftTerminalOrIncompleteContexts(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, status := range []string{"", "draft", "completed", "finalizing", "voided", "declined", "expired"} {
		t.Run(status, func(t *testing.T) {
			old := readCredentialFixture(now)
			next := cloneReadCredential(old)
			next.Document.Status, next.Recipient.DocStatus = status, status
			if err := ValidateRecipientReadCredential(old, next, now); !errors.Is(err, ErrDocumentNotSignable) {
				t.Fatalf("terminal read error=%v", err)
			}
			if err := ValidateRecipientReadCredential(next, old, now); !errors.Is(err, ErrDocumentNotSignable) {
				t.Fatalf("terminal original admission error=%v", err)
			}
		})
	}
	valid := readCredentialFixture(now)
	for _, rc := range []*RecipientContext{nil, {}, {Document: valid.Document}, {Recipient: valid.Recipient}} {
		if err := ValidateRecipientReadCredential(rc, valid, now); !errors.Is(err, ErrMagicLinkExpired) {
			t.Fatalf("incomplete original read error=%v", err)
		}
		if err := ValidateRecipientReadCredential(valid, rc, now); !errors.Is(err, ErrMagicLinkExpired) {
			t.Fatalf("incomplete fresh read error=%v", err)
		}
	}
}
