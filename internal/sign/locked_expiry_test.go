// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestDeadlineRecheckedAfterWaitingForDocumentLock(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	for _, tokenDeadline := range []bool{false, true} {
		doc := &generated.Document{}
		rec := &generated.Recipient{}
		deadline := pgtype.Timestamptz{Time: now.Add(time.Second), Valid: true}
		if tokenDeadline {
			rec.MagicTokenExpiresAt = deadline
		} else {
			doc.ExpiresAt = deadline
		}
		if err := checkLockedMagicLinkExpiry(rec, doc, now); err != nil {
			t.Fatal(err)
		}
		if err := checkLockedMagicLinkExpiry(rec, doc, now.Add(2*time.Second)); !errors.Is(err, ErrMagicLinkExpired) {
			t.Fatalf("expired locked ceremony authorized: %v", err)
		}
	}
}
