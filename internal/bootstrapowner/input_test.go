// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package bootstrapowner

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func testInput() Input {
	return Input{OrgID: uuid.MustParse("10101010-1010-4010-8010-101010101010"), Company: "Example Company", OwnerName: "Example Owner", OwnerEmail: "owner@example.test", ReviewRef: "review-first-owner"}
}

func TestBootstrapOwnerInputUsesNativeIdentityPolicy(t *testing.T) {
	in := testInput()
	in.Company, in.OwnerName, in.OwnerEmail, in.ReviewRef = " Example Company ", " Example Owner ", " OWNER@EXAMPLE.TEST ", " review-first-owner "
	got, err := Normalize(in)
	if err != nil || got != testInput() {
		t.Fatal("valid identity was not normalized consistently with native login")
	}
	for _, change := range []func(*Input){
		func(v *Input) { v.OrgID = uuid.Nil },
		func(v *Input) { v.Company = "\t\n" },
		func(v *Input) { v.Company = "Company\nInjected" },
		func(v *Input) { v.Company = strings.Repeat("a", 201) },
		func(v *Input) { v.OwnerName = string([]byte{0xff}) },
		func(v *Input) { v.OwnerEmail = "Name <owner@example.test>" },
		func(v *Input) { v.OwnerEmail = "a@example.test, b@example.test" },
		func(v *Input) { v.OwnerEmail = "owner@example.test\r\nBcc:other@example.test" },
		func(v *Input) { v.OwnerEmail = string([]byte{0xff}) + "@example.test" },
		func(v *Input) { v.ReviewRef = strings.Repeat("a", 257) },
		func(v *Input) { v.ReviewRef = "review\x00suffix" },
	} {
		in := testInput()
		change(&in)
		if _, err := Normalize(in); err != ErrInput || strings.Contains(err.Error(), in.OwnerEmail) {
			t.Fatal("invalid identity was accepted or its value escaped the fixed error")
		}
	}
}

func originalEvent(t *testing.T, in Input, userID uuid.UUID) *generated.Event {
	t.Helper()
	payload, err := json.Marshal(bootstrapPayload(in, userID))
	if err != nil {
		t.Fatal("marshal fixture payload")
	}
	row := &generated.Event{ID: uuid.New(), OrgID: in.OrgID, Kind: audit.KindMemberCreated,
		CreatedAt:     pgtype.Timestamptz{Time: time.Now().UTC().Truncate(time.Microsecond), Valid: true},
		PayloadHashed: payload, PayloadJson: append([]byte(nil), payload...)}
	row.RowHash, err = audit.RecomputeEventRowHash(row)
	if err != nil {
		t.Fatal("hash fixture event")
	}
	return row
}

func TestBootstrapOwnerRetryRequiresOriginalGenesisEvidence(t *testing.T) {
	in, user := testInput(), uuid.New()
	row := originalEvent(t, in, user)
	if !matchesOriginal(row, in, user) {
		t.Fatal("genuine original event was refused")
	}
	for _, change := range []func(*generated.Event){
		func(v *generated.Event) { v.ActorUserID = pgtype.UUID{Bytes: user, Valid: true} },
		func(v *generated.Event) { v.DocumentID = pgtype.UUID{Bytes: uuid.New(), Valid: true} },
		func(v *generated.Event) { v.PrevHash = bytes.Repeat([]byte{1}, 32) },
		func(v *generated.Event) { v.RowHash = bytes.Repeat([]byte{2}, 32) },
		func(v *generated.Event) { v.PayloadJson = json.RawMessage(`{"bootstrap":true}`) },
		func(v *generated.Event) { v.PayloadHashed = nil },
		func(v *generated.Event) { v.Kind = "member.password_verified" },
		func(v *generated.Event) { v.OrgID = uuid.New() },
	} {
		row := originalEvent(t, in, user)
		change(row)
		if matchesOriginal(row, in, user) {
			t.Fatal("changed or nongenuine bootstrap proof was accepted")
		}
	}
	changed := in
	changed.ReviewRef = "different-review"
	if matchesOriginal(row, changed, user) || matchesOriginal(row, in, uuid.New()) {
		t.Fatal("retry was not bound to original inputs and member")
	}
}
