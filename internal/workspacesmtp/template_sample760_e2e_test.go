//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package workspacesmtp

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

type templateSampleCapture760 struct{ messages []dispatch.Message }

func (m *templateSampleCapture760) Send(_ context.Context, msg dispatch.Message) error {
	m.messages = append(m.messages, msg)
	return nil
}

// Actual owned PostgreSQL, genuine owner cookie/CAS/template and retained
// outbox/receipt. Only the last SMTP consumer is controlled: this is neither
// external SMTP acceptance nor inbox delivery qualification.
func TestSavedTemplateSample760ActualOwnerCASFreezeAndDeliveryReceiptE2E(t *testing.T) {
	f := smtpConsumerFixture(t)
	username, password := "synthetic-sample-user", "synthetic-sample-password"
	input := Input{Host: "smtp.example.invalid", Port: 587, TLSMode: "starttls", SenderName: "Synthetic workspace", SenderEmail: "sender@example.invalid", CredentialsAction: "replace", Username: &username, Password: &password}
	if _, err := f.s.Save(f.ctx, f.a, input); err != nil {
		t.Fatal(err)
	}
	runtime, err := pdfadmission.NewWorkRuntimeV1(f.s.Pool, workguard.LimitsV1{
		Global:       workguard.VectorV1{ParentBytes: 128 << 20, DBStagingBytes: 64 << 20, SQLSessions: 8},
		Organisation: workguard.VectorV1{ParentBytes: 64 << 20, DBStagingBytes: 32 << 20, SQLSessions: 4},
		MaxGrants:    256, MaxOrganisationGrants: 128,
	}, int64(f.s.Pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.CloseV1(ctx); err != nil {
			t.Error(err)
		}
	})
	editor := emailtemplates.Service{Pool: f.s.Pool, Audit: f.s.Audit, Work: runtime.WorkV1()}
	test := func(actor authoring.Actor, expectedSMTP, expectedTemplate int64) (TestStatus, error) {
		ctx, source, err := editor.BeginSourceReadV1(f.ctx, actor)
		if err != nil {
			return TestStatus{}, err
		}
		defer source.CloseConsumerV1()
		return f.s.TestSavedTemplateV1(ctx, actor, dispatch.KindInvite, expectedSMTP, expectedTemplate)
	}
	save := func(expected int64, edition string) {
		t.Helper()
		saved, err := editor.Save(f.ctx, f.a, dispatch.KindInvite, emailtemplates.Input{ExpectedRevision: expected, SubjectTemplate: "Sample edition " + edition, HTMLTemplate: "<p>Saved edition " + edition + " for {{recipient_name}}</p>", TextTemplate: "Saved edition " + edition + " for {{recipient_name}}"})
		if err != nil {
			t.Fatal(err)
		}
		saved.CloseConsumerV1()
	}
	save(0, "one")
	receipt, err := test(f.a, 1, 1)
	if err != nil || receipt.DeliveryID == uuid.Nil || receipt.Status != "pending" || receipt.SMTPAccepted || receipt.InboxDeliveryConfirmed {
		t.Fatal("genuine saved-template enqueue did not return pending", err)
	}
	var d generated.EmailDelivery
	err = f.s.Pool.QueryRow(f.ctx, `SELECT id,smtp_org_id,smtp_purpose,to_email,subject,html_body,text_body,reply_to,from_name,headers_json FROM email_deliveries WHERE id=$1`, receipt.DeliveryID).Scan(&d.ID, &d.SmtpOrgID, &d.SmtpPurpose, &d.ToEmail, &d.Subject, &d.HtmlBody, &d.TextBody, &d.ReplyTo, &d.FromName, &d.HeadersJson)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := f.q.GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: f.a.UserID, OrgID: f.a.OrgID})
	if err != nil || d.ToEmail != owner.Email || d.SmtpPurpose != "workspace_test" || !strings.Contains(d.HtmlBody, "Saved edition one") || !strings.Contains(d.HtmlBody, "https://example.invalid/sign/preview") {
		t.Fatal("sample destination, selected content or native inert action changed", err)
	}
	save(1, "two")
	if _, err = test(f.a, 1, 1); !errors.Is(err, emailtemplates.ErrStale) {
		t.Fatal("stale template CAS was allowed to enqueue", err)
	}
	if _, err = test(f.a, 2, 2); !errors.Is(err, ErrStale) {
		t.Fatal("stale transport CAS was allowed to enqueue", err)
	}
	if _, err = test(f.a, 1, 2); !errors.Is(err, ErrTestBusy) {
		t.Fatal("pending/rate fence was bypassed by using another edition", err)
	}
	var count int
	if err = f.s.Pool.QueryRow(f.ctx, `SELECT count(*) FROM org_smtp_test_requests_v1 WHERE org_id=$1`, f.a.OrgID).Scan(&count); err != nil || count != 1 {
		t.Fatal("refused sample attempts changed retained receipts", err, count)
	}
	capture := &templateSampleCapture760{}
	f.s.newMailer = func(config dispatch.SMTPConfig) (dispatch.Mailer, error) {
		if config.Host != input.Host || config.User != username || config.Password != password || !config.PublicOnly || config.AllowPrivate {
			t.Fatal("sample selected another workspace's transport")
		}
		return capture, nil
	}
	msg := dispatch.Message{To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody}
	if err = f.s.Deliver(f.ctx, &d, msg, nil); err != nil || len(capture.messages) != 1 || !strings.Contains(capture.messages[0].HTML, "Saved edition one") || strings.Contains(capture.messages[0].HTML, "Saved edition two") {
		t.Fatal("delivery reread the changed template head", err)
	}
	changed := msg
	changed.To = "another@example.invalid"
	if err = f.s.Deliver(f.ctx, &d, changed, nil); !errors.Is(err, ErrUnavailable) || len(capture.messages) != 1 {
		t.Fatal("sample receipt became an arbitrary-recipient transport", err)
	}
	input.ExpectedRevision, input.CredentialsAction = 1, "keep"
	input.Username, input.Password = nil, nil
	input.SenderName = "New configured identity"
	if _, err = f.s.Save(f.ctx, f.a, input); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Deliver(f.ctx, &d, msg, nil); !errors.Is(err, ErrUnavailable) || len(capture.messages) != 1 {
		t.Fatal("sample used a replacement transport revision", err)
	}
	foreign := f.a
	foreign.OrgID = uuid.New()
	if _, err = test(foreign, 2, 2); err == nil {
		t.Fatal("foreign workspace sample accepted")
	}
	if _, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.a.UserID, OrgID: f.a.OrgID, Role: string(auth.RoleSender)}); err != nil {
		t.Fatal(err)
	}
	if _, err = test(f.a, 2, 2); err == nil {
		t.Fatal("demoted owner queued a sample")
	}
}
