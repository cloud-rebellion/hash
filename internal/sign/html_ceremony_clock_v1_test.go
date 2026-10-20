// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/actiontoken"
)

func TestHTMLCeremonyActionTokenClockKeepsOriginalDistinctCallsV1(t *testing.T) {
	for _, secret := range []string{"", "local-test-secret"} {
		t.Run(secret, func(t *testing.T) {
			// Exact second-boundary inputs distinguish the two actual token expiries.
			// This is the original clock/token recipe oracle, not native SQL authority.
			times := []time.Time{time.Unix(2_000_000_000, 999_999_999), time.Unix(2_000_000_001, 0), time.Unix(2_000_000_002, 0)}
			calls := 0
			engine := &Engine{ActionSecret: secret, Now: func() time.Time { at := times[calls]; calls++; return at }}
			approveAt, denyAt := engine.changeNotificationTimesV1()
			if secret == "" {
				if calls != 0 || !approveAt.IsZero() || !denyAt.IsZero() {
					t.Fatal("disabled action links consumed a credential clock observation")
				}
			} else {
				if calls != 2 || approveAt != times[0] || denyAt != times[1] {
					t.Fatal("approve and deny did not preserve distinct original engine clocks")
				}
				base := actiontoken.Claims{Kind: "cr", OrgID: "org", DocID: "document", TargetID: "request"}
				approve, deny := base, base
				approve.Action = "approve"
				deny.Action = "deny"
				gotApprove := actiontoken.Mint(secret, approve, approveAt, 14*24*time.Hour)
				gotDeny := actiontoken.Mint(secret, deny, denyAt, 14*24*time.Hour)
				if gotApprove != actiontoken.Mint(secret, approve, times[0], 14*24*time.Hour) || gotDeny != actiontoken.Mint(secret, deny, times[1], 14*24*time.Hour) {
					t.Fatal("token claims/expiry changed from the original separate-clock recipe")
				}
				if gotDeny == actiontoken.Mint(secret, deny, approveAt, 14*24*time.Hour) {
					t.Fatal("one captured timestamp would hide the deny token boundary")
				}
			}
			final := engine.now()
			want := times[0]
			if secret != "" {
				want = times[2]
			}
			if final != want {
				t.Fatal("token preparation displaced the original later credential check clock")
			}
		})
	}
}
