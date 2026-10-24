// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"bytes"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestStaffAuthMailIsSealedAndBoundToDelivery(t *testing.T) {
	box, err := NewStaffAuthMailBox(strings.Repeat("1a", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	msg := Message{To: "staff@example.test", Subject: "Set password", HTML: "<a>#token=private-bearer</a>", Text: "/reset-password#token=private-bearer"}
	sealed, err := SealStaffAuthEmail(box, id, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("private-bearer")) {
		t.Fatal("raw auth token persisted in outbox")
	}
	opened, err := OpenStaffAuthEmail(box, id, msg.To, msg.Subject, sealed)
	if err != nil || opened.HTML != msg.HTML || opened.Text != msg.Text {
		t.Fatal("sealed mail unavailable", err)
	}
	for _, other := range []struct {
		id             uuid.UUID
		email, subject string
	}{
		{uuid.New(), msg.To, msg.Subject}, {id, "other@example.test", msg.Subject}, {id, msg.To, "other subject"},
	} {
		if _, err := OpenStaffAuthEmail(box, other.id, other.email, other.subject, sealed); err == nil {
			t.Fatal("auth mail envelope moved between identities")
		}
	}
	rotated, err := NewStaffAuthMailBox(strings.Repeat("2b", 32), strings.Repeat("1a", 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStaffAuthEmail(rotated, id, msg.To, msg.Subject, sealed); err != nil {
		t.Fatal("previous encryption key cannot deliver queued mail", err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := OpenStaffAuthEmail(box, id, msg.To, msg.Subject, sealed); err == nil {
		t.Fatal("tampered mail was opened")
	}
}
