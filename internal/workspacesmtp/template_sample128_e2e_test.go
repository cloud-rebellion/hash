//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package workspacesmtp

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
)

// Genuine owner transaction, native process admission and PostgreSQL queue.
// No worker/Deliver/SMTP consumer is invoked; this proves prepared bytes only.
func TestWorkspaceEmail128SavedSampleLanguageAndFrozenQueueE2E(t *testing.T) {
	for _, kind := range []string{dispatch.KindQuotaWarning80, dispatch.KindDeclined} {
		t.Run(kind, func(t *testing.T) {
			f := smtpConsumerFixture(t)
			username, password := "synthetic-sample-user", "synthetic-sample-password"
			if _, err := f.s.Save(f.ctx, f.a, Input{Host: "smtp.example.invalid", Port: 587, TLSMode: "starttls", SenderName: "Synthetic workspace", SenderEmail: "sender@example.invalid", CredentialsAction: "replace", Username: &username, Password: &password}); err != nil {
				t.Fatal(err)
			}
			f.s.newMailer = func(dispatch.SMTPConfig) (dispatch.Mailer, error) {
				t.Fatal("queued-only qualification attempted SMTP")
				return nil, ErrUnavailable
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
			if _, err = editor.SavePreferencesV1(f.ctx, f.a, emailtemplates.PreferencesInputV1{Locale: "sv"}); err != nil {
				t.Fatal(err)
			}
			saved, err := editor.Save(f.ctx, f.a, kind, emailtemplates.Input{SubjectTemplate: "Selected edition one", HTMLTemplate: "<p>Saved sample one</p>", TextTemplate: "Saved sample one"})
			if err != nil {
				t.Fatal(err)
			}
			saved.CloseConsumerV1()
			ctx, source, err := editor.BeginSourceReadV1(f.ctx, f.a)
			if err != nil {
				t.Fatal(err)
			}
			defer source.CloseConsumerV1()
			receipt, err := f.s.TestSavedTemplateV1(ctx, f.a, kind, 1, 1)
			if err != nil || receipt.Status != "pending" || receipt.SMTPAccepted || receipt.InboxDeliveryConfirmed {
				t.Fatal("saved sample did not freeze pending bytes", err)
			}
			var d generated.EmailDelivery
			var headerKind pgtype.Text
			var revision pgtype.Int8
			var sh, hh, th []byte
			err = f.s.Pool.QueryRow(f.ctx, `SELECT d.to_email,d.subject,d.html_body,d.text_body,d.reply_to,d.from_name,d.headers_json,r.template_kind,r.template_revision,r.subject_sha256,r.html_sha256,r.text_sha256 FROM email_deliveries d JOIN org_smtp_test_requests_v1 r ON r.email_delivery_id=d.id WHERE d.id=$1 AND r.org_id=$2`, receipt.DeliveryID, f.a.OrgID).Scan(&d.ToEmail, &d.Subject, &d.HtmlBody, &d.TextBody, &d.ReplyTo, &d.FromName, &d.HeadersJson, &headerKind, &revision, &sh, &hh, &th)
			if err != nil {
				t.Fatal(err)
			}
			owner, err := f.q.GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: f.a.UserID, OrgID: f.a.OrgID})
			if err != nil || d.ToEmail != owner.Email || !strings.Contains(d.HtmlBody, "Saved sample one") || !strings.Contains(d.HtmlBody, templateSampleHTMLNoticeV1) {
				t.Fatal("sample changed owner destination, edition or notice", err)
			}
			if kind == dispatch.KindQuotaWarning80 {
				if !strings.Contains(d.HtmlBody, "har nått") || !strings.Contains(d.TextBody, "Perioden") {
					t.Fatal("quota test ignored saved Swedish preference")
				}
			} else if strings.Contains(d.HtmlBody, "avböj") || !strings.Contains(d.TextBody, "declined") {
				t.Fatal("workspace preference changed nonquota synthetic English")
			}
			msg := dispatch.Message{To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody}
			if !workspaceTestContentMatchesV1(&d, msg, headerKind, revision, sh, hh, th) {
				t.Fatal("native saved-sample receipt lost exact bytes")
			}
			before := [3][32]byte{sha256.Sum256([]byte(d.Subject)), sha256.Sum256([]byte(d.HtmlBody)), sha256.Sum256([]byte(d.TextBody))}
			if _, err = editor.SavePreferencesV1(f.ctx, f.a, emailtemplates.PreferencesInputV1{ExpectedRevision: 1, Locale: "en"}); err != nil {
				t.Fatal(err)
			}
			next, err := editor.Save(f.ctx, f.a, kind, emailtemplates.Input{ExpectedRevision: 1, SubjectTemplate: "Selected edition two"})
			if err != nil {
				t.Fatal(err)
			}
			next.CloseConsumerV1()
			var subject, html, text, status string
			var count int
			if err = f.s.Pool.QueryRow(f.ctx, `SELECT subject,html_body,text_body,status,(SELECT count(*) FROM org_smtp_test_requests_v1 WHERE org_id=$2) FROM email_deliveries WHERE id=$1`, receipt.DeliveryID, f.a.OrgID).Scan(&subject, &html, &text, &status, &count); err != nil {
				t.Fatal(err)
			}
			after := [3][32]byte{sha256.Sum256([]byte(subject)), sha256.Sum256([]byte(html)), sha256.Sum256([]byte(text))}
			if before != after || status != "pending" || count != 1 {
				t.Fatal("settings update rewrote or delivered the frozen sample")
			}
		})
	}
}
