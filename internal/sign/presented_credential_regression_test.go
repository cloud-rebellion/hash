// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Use the real LookupByToken and public locked-credential validator. This row
// fixture supplies the exact fields omitted by the older controller-only fake;
// it does not manufacture the implementation's private receipt.
type originalCredentialRegressionDB struct {
	*controllerLookupTestDB
	tokenHash                               []byte
	recipientExpiry, documentExpiry, sentAt pgtype.Timestamptz
}

func (db *originalCredentialRegressionDB) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	row := db.controllerLookupTestDB.QueryRow(ctx, query, args...)
	v, ok := row.(controllerLookupTestRow)
	if !ok || v.err != nil {
		return row
	}
	switch {
	case strings.Contains(query, "-- name: GetRecipientByTokenHash"):
		if len(args) != 1 {
			return controllerLookupTestRow{err: errors.New("wrong token query arity")}
		}
		presented, ok := args[0].([]byte)
		if !ok || !bytes.Equal(presented, db.tokenHash) {
			return controllerLookupTestRow{err: pgx.ErrNoRows}
		}
		v.values[7] = bytes.Clone(db.tokenHash)
		v.values[8] = db.sentAt
		v.values[13] = db.recipientExpiry
	case strings.Contains(query, "-- name: GetDocument "):
		v.values[16] = db.documentExpiry
		v.values[17] = db.sentAt
	}
	return v
}

func TestPresentedCredentialCannotBeRewrittenAfterLookup(t *testing.T) {
	for _, scenario := range []string{"token rotation", "recipient deadline extension", "document deadline extension", "parent identity replacement"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			engine, rows := newControllerLookupEngine(uuid.New(), "Credential Test AB")
			digest := sha256.Sum256([]byte("owned-native-regression-magic-link"))
			db := &originalCredentialRegressionDB{controllerLookupTestDB: rows, tokenHash: digest[:],
				recipientExpiry: pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
				documentExpiry:  pgtype.Timestamptz{Time: now.Add(time.Hour), Valid: true},
				sentAt:          pgtype.Timestamptz{Time: now.Add(-time.Minute), Valid: true}}
			if scenario == "recipient deadline extension" {
				db.recipientExpiry.Time = now.Add(5 * time.Minute)
			}
			if scenario == "document deadline extension" {
				db.documentExpiry.Time = now.Add(5 * time.Minute)
			}
			engine.Queries = generated.New(db)
			engine.Now = func() time.Time { return now }
			rc, err := engine.lookupByTokenQueriesV1(context.Background(), digest[:], engine.Queries)
			if err != nil {
				t.Fatalf("actual lookup: %v", err)
			}
			lockedDoc := *rc.Document
			fresh := &generated.Recipient{ID: rc.Recipient.ID, DocumentID: rc.Document.ID, Role: rc.Recipient.Role,
				MagicTokenHash: bytes.Clone(rc.Recipient.MagicTokenHash), MagicTokenExpiresAt: rc.Recipient.MagicTokenExpiresAt}
			checkAt := now.Add(time.Minute)
			if err := ValidateLockedRecipientCredential(rc, fresh, &lockedDoc, checkAt); err != nil {
				t.Fatalf("unchanged original credential refused: %v", err)
			}
			switch scenario {
			case "token rotation":
				rc.Recipient.MagicTokenHash = bytes.Repeat([]byte{0x44}, sha256.Size)
				fresh.MagicTokenHash = bytes.Clone(rc.Recipient.MagicTokenHash)
			case "recipient deadline extension":
				rc.Recipient.MagicTokenExpiresAt.Time = now.Add(time.Hour)
				fresh.MagicTokenExpiresAt = rc.Recipient.MagicTokenExpiresAt
				checkAt = now.Add(6 * time.Minute)
			case "document deadline extension":
				rc.Document.ExpiresAt.Time = now.Add(time.Hour)
				lockedDoc.ExpiresAt = rc.Document.ExpiresAt
				checkAt = now.Add(6 * time.Minute)
			case "parent identity replacement":
				replacement := uuid.New()
				rc.Document.ID = replacement
				rc.Recipient.DocumentID = replacement
				lockedDoc.ID = replacement
				fresh.DocumentID = replacement
			}
			if err := ValidateLockedRecipientCredential(rc, fresh, &lockedDoc, checkAt); !errors.Is(err, ErrMagicLinkExpired) {
				t.Fatalf("rewritten admitted credential accepted; error=%v", err)
			}
		})
	}
}
