// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func TestHTMLCeremonyOwnedResultsKeepOriginalConsumerOnCopiedCloseV1(t *testing.T) {
	// Result-shell/consumer semantics only. This does not manufacture a native
	// admission or establish PostgreSQL physical retirement.
	t.Run("resolved change", func(t *testing.T) {
		id := uuid.New()
		calls := 0
		var result *ChangeResolutionResultV1
		result = newChangeResolutionResultV1(&generated.ChangeRequest{ID: id, Message: "retained original"}, func() {
			calls++
			if result.ChangeRequest != nil {
				t.Error("model remained reachable during original consumer release")
			}
		})
		copied := *result
		copied.CloseConsumerV1()
		if calls != 0 || result.ChangeRequest == nil || result.ID != id || result.Message != "retained original" {
			t.Fatal("copied result released the original response consumer")
		}
		result.CloseConsumerV1()
		result.CloseConsumerV1()
		if calls != 1 || result.ChangeRequest != nil {
			t.Fatal("actual last-use signal did not clear and release exactly once")
		}
	})
	t.Run("reopened document", func(t *testing.T) {
		id := uuid.New()
		calls := 0
		var result *CeremonyRevisionResultV1
		result = newCeremonyRevisionResultV1(&generated.Document{ID: id, Name: "retained original"}, func() {
			calls++
			if result.Document != nil {
				t.Error("model remained reachable during original consumer release")
			}
		})
		copied := *result
		copied.CloseConsumerV1()
		if calls != 0 || result.Document == nil || result.ID != id || result.Name != "retained original" {
			t.Fatal("copied result released the original response consumer")
		}
		result.CloseConsumerV1()
		result.CloseConsumerV1()
		if calls != 1 || result.Document != nil {
			t.Fatal("actual last-use signal did not clear and release exactly once")
		}
	})
	var change ChangeResolutionResultV1
	change.CloseConsumerV1()
	var document CeremonyRevisionResultV1
	document.CloseConsumerV1()
}

func TestHTMLCeremonyCredentialPrefixPreservesRotationBeforePolicyTextV1(t *testing.T) {
	for _, name := range []string{"rotated token", "changed role", "expired original receipt", "valid prefix then changed policy"} {
		t.Run(name, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			rc := f.lookup(t)
			fresh := presentedFreshRecipientTestV1(rc)
			document := *rc.Document
			now := f.now
			// Every fixture also has a later real notice-policy mismatch. Original
			// private identity/receipt failures must win before that later text stage.
			document.Name = "changed current notice purpose"
			switch name {
			case "rotated token":
				fresh.MagicTokenHash[0] ^= 1
			case "changed role":
				fresh.Role = "observer"
			case "expired original receipt":
				now = rc.Recipient.MagicTokenExpiresAt.Time.Add(1)
			}
			want := htmlCeremonyOriginalCredentialOracleV1(rc, fresh, &document, now)
			actual := validateLockedRecipientPrefixV1(rc, fresh, htmlCeremonyDocumentPinsV1{present: true, document: document.ID, org: document.OrgID}, now)
			if name == "valid prefix then changed policy" {
				if actual != nil || !errors.Is(want, ErrInvalidNoticeEvidence) {
					t.Fatalf("prefix consumed a later policy decision: prefix=%v original=%v", actual, want)
				}
				actual = validateLockedRecipientPinsV1(rc, fresh, htmlCeremonyDocumentPinsForV1(&document), now)
			}
			htmlCeremonyAssertSameErrorV1(t, want, actual)
		})
	}
}
