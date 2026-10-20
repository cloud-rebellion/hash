// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/fitselect"
)

// Use the actual token lookup, private issuance, generated current-policy reads
// and exported historical validator over the existing explicitly synthetic SQL
// fixture. These regressions prove deadline semantics, not runtime readiness.
func TestFittedIntentV1OriginalExpiryHasExclusiveBoundary(t *testing.T) {
	for _, deadline := range []string{"recipient", "document"} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			t.Run(deadline+"/"+delta.String(), func(t *testing.T) {
				f := newPresentedCredentialTestFixtureV1(t)
				expiry := f.now.Add(time.Minute)
				f.db.recipient.MagicTokenExpiresAt.Time = f.now.Add(2 * time.Hour)
				f.db.document.ExpiresAt.Time = f.now.Add(2 * time.Hour)
				if deadline == "recipient" {
					f.db.recipient.MagicTokenExpiresAt.Time = expiry
				} else {
					f.db.document.ExpiresAt.Time = expiry
				}
				rc := f.lookup(t)
				in := presentedCredentialTestInputV1(t, rc)
				f.now = expiry.Add(delta)
				_, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in)
				if delta < 0 {
					if err != nil {
						t.Fatalf("live original deadline refused: %v", err)
					}
				} else if !errors.Is(err, ErrMagicLinkExpired) {
					t.Fatalf("original deadline accepted at or after expiry: %v", err)
				}
			})
		}
	}
}

func TestFittedPolicyV1OriginalAndCurrentExpiryHaveExclusiveBoundary(t *testing.T) {
	for _, deadline := range []string{"original recipient", "original document", "current recipient", "current document"} {
		for _, delta := range []time.Duration{-time.Nanosecond, 0, time.Nanosecond} {
			t.Run(deadline+"/"+delta.String(), func(t *testing.T) {
				f := newPresentedCredentialTestFixtureV1(t)
				expiry := f.now.Add(time.Minute)
				f.db.recipient.MagicTokenExpiresAt.Time = f.now.Add(2 * time.Hour)
				f.db.document.ExpiresAt.Time = f.now.Add(2 * time.Hour)
				if deadline == "original recipient" {
					f.db.recipient.MagicTokenExpiresAt.Time = expiry
				}
				if deadline == "original document" {
					f.db.document.ExpiresAt.Time = expiry
				}
				rc := f.lookup(t)
				in := presentedCredentialTestInputV1(t, rc)
				locked := *rc.Document
				fresh := presentedFreshRecipientTestV1(rc)
				if deadline == "current recipient" {
					fresh.MagicTokenExpiresAt.Time = expiry
				}
				if deadline == "current document" {
					locked.ExpiresAt.Time = expiry
				}
				// Keep the current deadline later in the original cases: extending
				// current rows must not revive the original admitted credential.
				if deadline == "original recipient" {
					fresh.MagicTokenExpiresAt.Time = expiry.Add(time.Hour)
				}
				if deadline == "original document" {
					locked.ExpiresAt.Time = expiry.Add(time.Hour)
				}
				f.db.policyCollections = true
				f.db.calls = 0
				f.now = expiry.Add(delta)
				state := fitselect.LockedStateV1{Document: &locked, Recipient: fresh, Queries: f.engine.Queries}
				err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state)
				if delta < 0 {
					if err != nil || f.db.calls == 0 {
						t.Fatalf("live policy did not reach current SQL: calls=%d err=%v", f.db.calls, err)
					}
				} else {
					if !errors.Is(err, ErrMagicLinkExpired) {
						t.Fatalf("policy admitted at or after expiry: %v", err)
					}
					if f.db.calls != 0 {
						t.Fatal("expired policy reached SQL")
					}
				}
			})
		}
	}
}

func TestFittedPolicyV1RechecksExclusiveExpiryAfterFinalSQLWait(t *testing.T) {
	for _, deadline := range []string{"original recipient", "original document", "current recipient", "current document"} {
		t.Run(deadline, func(t *testing.T) {
			f := newPresentedCredentialTestFixtureV1(t)
			expiry := f.now.Add(time.Minute)
			f.db.recipient.MagicTokenExpiresAt.Time = f.now.Add(2 * time.Hour)
			f.db.document.ExpiresAt.Time = f.now.Add(2 * time.Hour)
			if deadline == "original recipient" {
				f.db.recipient.MagicTokenExpiresAt.Time = expiry
			}
			if deadline == "original document" {
				f.db.document.ExpiresAt.Time = expiry
			}
			rc := f.lookup(t)
			in := presentedCredentialTestInputV1(t, rc)
			locked := *rc.Document
			fresh := presentedFreshRecipientTestV1(rc)
			if deadline == "current recipient" {
				fresh.MagicTokenExpiresAt.Time = expiry
			}
			if deadline == "current document" {
				locked.ExpiresAt.Time = expiry
			}
			if deadline == "original recipient" {
				fresh.MagicTokenExpiresAt.Time = expiry.Add(time.Hour)
			}
			if deadline == "original document" {
				locked.ExpiresAt.Time = expiry.Add(time.Hour)
			}
			f.db.policyCollections = true
			countReached := false
			f.db.beforeQuery = func(name string) {
				if strings.Contains(name, "-- name: CountUnfilledRequiredForRecipient ") {
					countReached = true
					f.now = expiry
				}
			}
			state := fitselect.LockedStateV1{Document: &locked, Recipient: fresh, Queries: f.engine.Queries}
			if err := f.engine.validateFittedSigningPolicyV1(context.Background(), rc, in, state); !errors.Is(err, ErrMagicLinkExpired) {
				t.Fatalf("SQL wait admitted exact-expiry credential: %v", err)
			}
			if !countReached {
				t.Fatal("fixture did not exercise final successful SQL wait")
			}
		})
	}
}

func TestFittedExpiryV1PreservesHistoricalExactBoundary(t *testing.T) {
	f := newPresentedCredentialTestFixtureV1(t)
	rc := f.lookup(t)
	in := presentedCredentialTestInputV1(t, rc)
	f.now = rc.Recipient.MagicTokenExpiresAt.Time
	fresh := presentedFreshRecipientTestV1(rc)
	locked := *rc.Document
	if err := checkMagicLinkExpiry(rc.Recipient, &locked, f.now); err != nil {
		t.Fatalf("historical lookup boundary changed: %v", err)
	}
	if err := ValidateLockedRecipientCredential(rc, fresh, &locked, f.now); err != nil {
		t.Fatalf("historical locked boundary changed: %v", err)
	}
	if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), rc, in); !errors.Is(err, ErrMagicLinkExpired) {
		t.Fatal("fitted boundary reused historical equality")
	}
	// ID/QES-style contexts have no private presented receipt and retain the
	// same exported exact-boundary check. They cannot mint a fitted request.
	legacy := &RecipientContext{Recipient: rc.Recipient, Document: rc.Document}
	if err := ValidateLockedRecipientCredential(legacy, fresh, &locked, f.now); err != nil {
		t.Fatalf("ID/QES-style boundary changed: %v", err)
	}
	if _, err := f.engine.issueFittedSigningIntentV1(context.Background(), legacy, in); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("ID context minted fitted request")
	}
}
