// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestReminderPurposesAreDistinctAndDoNotAliasExistingStagesV1(t *testing.T) {
	if HTMLReminderIdentityV1 <= HTMLSignerPackageReadV1 || HTMLReminderManualV1 != HTMLReminderIdentityV1+1 || HTMLReminderScheduledV1 != HTMLReminderManualV1+1 {
		t.Fatal("reminder identity/manual/scheduled stages must be distinct forward purposes")
	}
}

func TestReminderPreservesExistingRecipientPredicateV1(t *testing.T) {
	for _, role := range []string{"signer", "approver", "cc", "viewer", "legacy-role"} {
		for _, status := range []string{"pending", "sent", "viewed", "signed", "accepted", "declined"} {
			got := reminderEligibleV1(&generated.Recipient{Role: role, Status: status})
			want := status == "pending" || status == "sent" || status == "viewed"
			if got != want {
				t.Fatalf("role=%q status=%q eligible=%v", role, status, got)
			}
		}
	}
	if reminderEligibleV1(nil) {
		t.Fatal("nil recipient eligible")
	}
}
func TestReminderUnissuedNativeOwnersRefuseV1(t *testing.T) {
	ctx := context.Background()
	work := &ApplicationHTMLSendWorkV1{}
	work.self = work
	for _, w := range []*ApplicationHTMLSendWorkV1{nil, {}, work, {self: work}} {
		if op, _, err := w.NewReminderRootOperationV1(ctx); op != nil || !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatalf("unissued identity: %v", err)
		}
		if subject, err := w.ReminderSubjectV1(ctx); subject != nil || !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatalf("unissued subject: %v", err)
		}
		if r, _, err := w.StartReminderV1(ctx, time.Now()); r != nil || !errors.Is(err, ErrReminderV1) {
			t.Fatalf("unissued producer: %v", err)
		}
	}
	for _, r := range []*ApplicationReminderV1{nil, {}, {state: &applicationReminderStateV1{}}} {
		if _, err := r.CountV1(ctx); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
		if err := r.RotateV1(ctx, 0); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
		if _, err := r.RenderV1(ctx, 0); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
		if err := r.EnqueueV1(ctx, 0); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
		if _, err := r.NewNextAuditV1(ctx); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
		if err := r.FinishV1(ctx, time.Now()); !errors.Is(err, ErrReminderV1) {
			t.Fatal(err)
		}
	}
}

func TestReminderAuditPurposeHasOnlyOriginalClosedModeShapeV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tc := range []struct {
		p          HTMLAuditPurposeV1
		key, other string
	}{{HTMLAuditReminderManualV1, "manual", "automatic"}, {HTMLAuditReminderAutomaticV1, "automatic", "manual"}} {
		if tc.p.KindV1() != "reminder.sent" {
			t.Fatal("reminder kind changed")
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, tc.p, map[string]any{tc.key: true, "via": "mcp", "tool": "remind_recipient"}); err != nil {
			t.Fatal(err)
		}
		if _, err := htmlAuditPayloadShapeV1(ctx, tc.p, map[string]any{tc.other: true}); err == nil {
			t.Fatal("cross-mode payload accepted")
		}
	}
}
