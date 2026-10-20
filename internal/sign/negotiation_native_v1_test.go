// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// A deliberately absent Pool makes any attempted pooled fallback fail this
// test, instead of pretending a caller's mutable models supply native work.
// These synthetic rows test refusal/input order only, not a legal ceremony.
func TestOrdinaryNegotiationRequiresNativeOwnershipBeforeSQLV1(t *testing.T) {
	ctx := context.Background()
	engine := &Engine{}
	org, doc := uuid.New(), uuid.New()
	if row, err := engine.ResolveChange(ctx, org, doc, uuid.New(), true); row != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("missing native resolution owner reached alternate SQL", err)
	}
	if row, err := engine.Revise(ctx, org, doc); row != nil || !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
		t.Fatal("missing native revision owner reached alternate SQL", err)
	}
	for _, kind := range []string{"blocks", "pdf"} {
		t.Run(kind, func(t *testing.T) {
			rc := &RecipientContext{
				Document:  &generated.Document{ID: doc, OrgID: org, SourceKind: kind, Status: "sent", SentAt: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}},
				Recipient: &generated.GetRecipientByTokenHashRow{ID: uuid.New(), DocumentID: doc, Role: "signer", Status: "sent"},
			}
			notice := testArticle13NoticeEvidence(t, rc)
			if err := engine.RequestChanges(ctx, rc, ChangeRequestInput{Message: "Actual unowned input must refuse", Notice: notice}); !errors.Is(err, ErrSigningAdmissionUnavailableV1) {
				t.Fatal("unowned ordinary recipient selected alternate SQL", err)
			}
			if err := engine.RequestChanges(ctx, rc, ChangeRequestInput{Message: "Invalid notice remains first"}); !errors.Is(err, ErrInvalidNoticeEvidence) {
				t.Fatal("unowned ordinary pure notice refusal order changed", err)
			}
			if err := engine.RequestChanges(ctx, rc, ChangeRequestInput{Notice: notice}); err == nil || err.Error() != "describe the change you need" {
				t.Fatal("unowned ordinary empty-change refusal order changed", err)
			}
		})
	}
}
