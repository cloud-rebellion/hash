// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type smtpRouteRecording730 struct{ calls int }

func (m *smtpRouteRecording730) Send(context.Context, dispatch.Message) error { m.calls++; return nil }
func TestWorkerWorkspaceSMTPNeverInfersOrFallsBack730(t *testing.T) {
	org := uuid.New()
	old := &smtpRouteRecording730{}
	called := 0
	w := worker{emailSender: old, workspaceSMTPSend: func(_ context.Context, d *generated.EmailDelivery, _ dispatch.Message, legacy dispatch.Mailer) error {
		if d.SmtpOrgID.Bytes != [16]byte(org) || legacy != old {
			t.Fatal("wrong scoped route")
		}
		called++
		return nil
	}}
	for _, purpose := range []string{"workspace", "workspace_test"} {
		d := &generated.EmailDelivery{SmtpPurpose: purpose, SmtpOrgID: pgtype.UUID{Bytes: org, Valid: true}}
		if e := w.sendEmailTransport(context.Background(), d, dispatch.Message{}); e != nil {
			t.Fatal(e)
		}
	}
	if called != 2 || old.calls != 0 {
		t.Fatal("workspace transport used installation sender")
	}
	for _, d := range []*generated.EmailDelivery{nil, {SmtpPurpose: ""}, {SmtpPurpose: "workspace"}, {SmtpPurpose: "workspace", SmtpOrgID: pgtype.UUID{Valid: true}}, {SmtpPurpose: "workspace", SmtpOrgID: pgtype.UUID{Bytes: org, Valid: true}, StaffAuthCiphertext: []byte("invalid")}, {SmtpPurpose: "installation_legacy", SmtpOrgID: pgtype.UUID{Bytes: org, Valid: true}}} {
		if e := w.sendEmailTransport(context.Background(), d, dispatch.Message{}); e == nil {
			t.Fatal("unattributed or contradictory mail route accepted")
		}
	}
	if called != 2 || old.calls != 0 {
		t.Fatal("refused row reached a transport")
	}
	if e := w.sendEmailTransport(context.Background(), &generated.EmailDelivery{SmtpPurpose: "installation_legacy"}, dispatch.Message{}); e != nil || old.calls != 1 {
		t.Fatal("migration-classified retained mail changed")
	}
}
func TestWorkerStaffAuthExplicitlyRetainsInstallationSMTP730(t *testing.T) {
	box, e := dispatch.NewStaffAuthMailBox("7777777777777777777777777777777777777777777777777777777777777777", "")
	if e != nil {
		t.Fatal(e)
	}
	id := uuid.New()
	message := dispatch.Message{To: "owner@example.invalid", Subject: "Synthetic recovery", Text: "Synthetic sealed authentication content"}
	sealed, e := dispatch.SealStaffAuthEmail(box, id, message)
	if e != nil {
		t.Fatal(e)
	}
	old := &smtpRouteRecording730{}
	w := worker{emailSender: old, staffAuthMailBox: box, workspaceSMTPSend: func(context.Context, *generated.EmailDelivery, dispatch.Message, dispatch.Mailer) error {
		t.Fatal("auth mail entered workspace transport")
		return nil
	}}
	d := &generated.EmailDelivery{ID: id, ToEmail: message.To, Subject: message.Subject, StaffAuthCiphertext: sealed, SmtpPurpose: "installation_auth"}
	if e = w.sendEmailTransport(context.Background(), d, dispatch.Message{}); e != nil || old.calls != 1 {
		t.Fatal("genuine sealed recovery mail failed", e)
	}
	d.StaffAuthCiphertext = nil
	if e = w.sendEmailTransport(context.Background(), d, dispatch.Message{}); e == nil || old.calls != 1 {
		t.Fatal("unsealed installation-auth marker accepted")
	}
}
