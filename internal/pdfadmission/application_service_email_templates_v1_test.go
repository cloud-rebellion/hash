// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func serviceEmailSourceFixtureV1(t *testing.T, kind string) (uuid.UUID, *generated.GetServiceEmailTemplateHeaderV1Row, *generated.GetServiceEmailTemplateV1Row) {
	t.Helper()
	org := uuid.New()
	x, err := dispatch.ValidateServiceEmailTemplateV1(kind, dispatch.ServiceEmailTemplateV1{Revision: 7, SubjectTemplate: "{{document_name}} · {{org_name}}", HTMLTemplate: "<p>Hello {{recipient_name}} from {{sender_name}}.</p>", TextTemplate: "Hello {{recipient_name}} from {{sender_name}}."})
	if err != nil {
		t.Fatal(err)
	}
	stamp := pgtype.Timestamptz{Time: time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC), Valid: true}
	h := &generated.GetServiceEmailTemplateHeaderV1Row{OrgID: org, Kind: kind, Revision: x.Revision, SubjectBytes: int64(len(x.SubjectTemplate)), HtmlBytes: int64(len(x.HTMLTemplate)), TextBytes: int64(len(x.TextTemplate)), UpdatedAt: stamp}
	r := &generated.GetServiceEmailTemplateV1Row{OrgID: org, Kind: kind, Revision: x.Revision, SubjectTemplate: x.SubjectTemplate, HtmlTemplate: x.HTMLTemplate, TextTemplate: x.TextTemplate, UpdatedAt: stamp}
	return org, h, r
}

func TestServiceEmailActualSourceHeaderRejectsScopeAndSizeDriftV1(t *testing.T) {
	org, h, _ := serviceEmailSourceFixtureV1(t, dispatch.KindInvite)
	work, wire, err := applicationServiceEmailSourceWorkV1(h, org, dispatch.KindInvite)
	if err != nil || wire != h.SubjectBytes+h.HtmlBytes+h.TextBytes || work < 64*wire+65536 {
		t.Fatal("actual source not fully funded", work, wire, err)
	}
	for name, mutate := range map[string]func(*generated.GetServiceEmailTemplateHeaderV1Row){
		"other-org":    func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.OrgID = uuid.New() },
		"other-kind":   func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.Kind = dispatch.KindReminder },
		"unknown-kind": func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.Kind = "email.arbitrary" },
		"no-revision":  func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.Revision = 0 },
		"no-timestamp": func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.UpdatedAt.Valid = false },
		"negative":     func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.TextBytes = -1 },
		"subject-over": func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.SubjectBytes = 257 },
		"html-over":    func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.HtmlBytes = 16385 },
		"text-over":    func(v *generated.GetServiceEmailTemplateHeaderV1Row) { v.TextBytes = 8193 },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *h
			mutate(&copy)
			if _, _, err := applicationServiceEmailSourceWorkV1(&copy, org, dispatch.KindInvite); err == nil {
				t.Fatal("invalid scalar source admitted")
			}
		})
	}
	if _, _, err = applicationServiceEmailSourceWorkV1(nil, org, dispatch.KindInvite); err == nil {
		t.Fatal("nil header admitted")
	}
}

func TestServiceEmailSelectedBodyMustMatchLockedHeaderExactlyV1(t *testing.T) {
	org, h, r := serviceEmailSourceFixtureV1(t, dispatch.KindInvite)
	if _, err := applicationServiceEmailFromRowsV1(h, r, org, dispatch.KindInvite); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*generated.GetServiceEmailTemplateV1Row){
		"org":      func(v *generated.GetServiceEmailTemplateV1Row) { v.OrgID = uuid.New() },
		"kind":     func(v *generated.GetServiceEmailTemplateV1Row) { v.Kind = dispatch.KindReminder },
		"revision": func(v *generated.GetServiceEmailTemplateV1Row) { v.Revision++ },
		"timestamp": func(v *generated.GetServiceEmailTemplateV1Row) {
			v.UpdatedAt.Time = v.UpdatedAt.Time.Add(time.Microsecond)
		},
		"bytes": func(v *generated.GetServiceEmailTemplateV1Row) { v.TextTemplate += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *r
			mutate(&copy)
			if _, err := applicationServiceEmailFromRowsV1(h, &copy, org, dispatch.KindInvite); err == nil {
				t.Fatal("changed selected revision accepted")
			}
		})
	}
	copy := *r
	copy.HtmlTemplate = "<p onclick=\"bad()\">unsafe</p>"
	header := *h
	header.HtmlBytes = int64(len(copy.HtmlTemplate))
	if _, err := applicationServiceEmailFromRowsV1(&header, &copy, org, dispatch.KindInvite); err == nil {
		t.Fatal("corrupt stored HTML accepted")
	}
}

func TestServiceEmailNativeBoundsCoverCustomEscapingAndQueueReturnsV1(t *testing.T) {
	for _, kind := range []string{dispatch.KindInvite, dispatch.KindReminder, dispatch.KindCompletedSigner, dispatch.KindCompletedSender, dispatch.KindNewComment, dispatch.KindChangesRequested} {
		t.Run(kind, func(t *testing.T) {
			org, h, r := serviceEmailSourceFixtureV1(t, kind)
			tpl, err := applicationServiceEmailFromRowsV1(h, r, org, kind)
			if err != nil {
				t.Fatal(err)
			}
			for _, locale := range []string{"en", "sv"} {
				for _, ack := range []bool{false, true} {
					ctx := dispatch.TemplateContext{DocumentName: "DPA & <Agreement>", SenderName: `Åsa & <"Seller">`, SenderEmail: "sender@example.test", RecipientName: strings.Repeat(`ä<&'">`, 100), OrgName: "Example & Co", Locale: locale, Acknowledgement: ack, SignURL: "https://hash.example.test/sign/" + strings.Repeat("z", 43), DownloadURL: "https://hash.example.test/sign/" + strings.Repeat("z", 43) + "/final-pdf", AuditCertURL: "https://hash.example.test/sign/" + strings.Repeat("z", 43) + "/audit-cert", PackagePortalURL: "https://hash.example.test/completed/" + strings.Repeat("z", 43), DownloadExpiresAt: "2030-01-02T03:04:05Z", OpenURL: "https://hash.example.test/documents/id", ApproveURL: "https://hash.example.test/a/cr?t=synthetic", DenyURL: "https://hash.example.test/a/cr?t=synthetic-deny", BeaconURL: "https://tracking.example.test/forbidden"}
					s, html, text, err := applicationServiceEmailComponentsV1(kind, ctx, tpl)
					if err != nil {
						t.Fatal(err)
					}
					subject, actualHTML, actualText, err := dispatch.RenderServiceEmailV1(kind, ctx, tpl)
					if err != nil {
						t.Fatal(err)
					}
					if int64(len(subject)) > s || int64(len(actualHTML)) > html || int64(len(actualText)) > text {
						t.Fatal("actual custom output exceeded prepaid native bound")
					}
					_, baseHTML, baseText, err := dispatch.Render(kind, ctx)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.HasSuffix(actualText, baseText) || !strings.Contains(actualHTML, "&lt;") || strings.Contains(actualHTML, ctx.BeaconURL) {
						t.Fatal("mandatory text/escaping/no-tracking contract changed")
					}
					for _, url := range []string{ctx.SignURL, ctx.DownloadURL, ctx.AuditCertURL, ctx.PackagePortalURL, ctx.OpenURL, ctx.ApproveURL, ctx.DenyURL} {
						if strings.Contains(baseHTML, url) && !strings.Contains(actualHTML, url) {
							t.Fatal("mandatory native link lost")
						}
					}
					bound, err := htmlAuthoringSumV1(int64(len("recipient@example.test")), s, html, text, int64(len(ctx.SenderEmail)), int64(len(ctx.OrgName)), int64(len("pending")))
					if err != nil {
						t.Fatal(err)
					}
					shape := applicationPackageSendOutboxShapeV1{raw: bound, subject: s, html: html, text: text}
					message := dispatch.Message{To: "recipient@example.test", Subject: subject, HTML: actualHTML, Text: actualText, ReplyTo: ctx.SenderEmail, FromName: ctx.OrgName}
					if !shape.coversV1(bound, message) {
						t.Fatal("custom output cannot consume its original queue-return shape")
					}
				}
			}
		})
	}
}

func TestServiceEmailSelectionIsFrozenBeforeAReplacementHeadV1(t *testing.T) {
	org, h, r := serviceEmailSourceFixtureV1(t, dispatch.KindInvite)
	selected, err := applicationServiceEmailFromRowsV1(h, r, org, dispatch.KindInvite)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dispatch.TemplateContext{DocumentName: "Agreement", OrgName: "Workspace", RecipientName: "Signer", SenderName: "Sender", SignURL: "https://hash.example.test/sign/token"}
	a, b, c, err := dispatch.RenderServiceEmailV1(dispatch.KindInvite, ctx, selected)
	if err != nil {
		t.Fatal(err)
	}
	r.Revision++
	r.TextTemplate = "New revision"
	h.Revision = r.Revision
	h.TextBytes = int64(len(r.TextTemplate))
	replacement, err := applicationServiceEmailFromRowsV1(h, r, org, dispatch.KindInvite)
	if err != nil {
		t.Fatal(err)
	}
	x, y, z, err := dispatch.RenderServiceEmailV1(dispatch.KindInvite, ctx, selected)
	if err != nil || x != a || y != b || z != c {
		t.Fatal("later source changed an already selected edition")
	}
	_, _, newText, err := dispatch.RenderServiceEmailV1(dispatch.KindInvite, ctx, replacement)
	if err != nil || newText == c {
		t.Fatal("new producer did not see its distinct selected edition")
	}
}

func TestServiceEmailUnissuedNativeOwnersAndCachesRefuseV1(t *testing.T) {
	ctx := context.Background()
	for _, w := range []*ApplicationHTMLSendWorkV1{nil, {}} {
		if _, err := w.serviceEmailTemplateV1(ctx, dispatch.KindInvite); !errors.Is(err, ErrHTMLSendWorkV1) {
			t.Fatal("unissued owner issued source", err)
		}
	}
	var n *ApplicationHTMLChangeNotificationV1
	if _, close, err := n.BorrowMessageV1(ctx); close != nil || err == nil {
		t.Fatal("unissued change notification issued message")
	}
	w := &ApplicationHTMLSendWorkV1{sourceDocument: &generated.Document{OrgID: uuid.New()}}
	w.self = w
	if _, err := w.cachedServiceEmailTemplateV1(dispatch.KindInvite); err == nil {
		t.Fatal("unread source became built-in fallback")
	}
	w.serviceEmailTemplates[0] = applicationServiceEmailSlotV1{org: w.sourceDocument.OrgID, attempted: true}
	if _, err := w.cachedServiceEmailTemplateV1(dispatch.KindInvite); err == nil {
		t.Fatal("failed lookup became fallback")
	}
	w.serviceEmailTemplates[0].loaded = true
	if tpl, err := w.cachedServiceEmailTemplateV1(dispatch.KindInvite); err != nil || tpl != nil {
		t.Fatal("actual absent-head cache did not preserve built-in")
	}
	if _, err := w.cachedServiceEmailTemplateV1(dispatch.KindReminder); err == nil {
		t.Fatal("other kind borrowed wrong cache")
	}
	w.sourceDocument.OrgID = uuid.New()
	if _, err := w.cachedServiceEmailTemplateV1(dispatch.KindInvite); err == nil {
		t.Fatal("other org borrowed wrong cache")
	}
}

func TestServiceEmailRetirementKeepsSourceUntilLastBorrowerV1(t *testing.T) {
	w := &ApplicationHTMLSendWorkV1{closed: true, sourceBorrowers: 1}
	w.self = w
	w.serviceEmailTemplates[0] = applicationServiceEmailSlotV1{attempted: true, loaded: true, template: &dispatch.ServiceEmailTemplateV1{Revision: 1, TextTemplate: "retained"}}
	if closes, _ := w.retireSourcesLockedV1(); closes != nil || w.resourcesClosed || w.serviceEmailTemplates[0].template == nil {
		t.Fatal("active borrower lost selected source")
	}
	w.sourceBorrowers = 0
	w.retireSourcesLockedV1()
	if !w.resourcesClosed || w.serviceEmailTemplates[0].template != nil || w.serviceEmailTemplates[0].loaded {
		t.Fatal("source reference survived retirement credit")
	}
}

func TestServiceEmailChangeQueueRejectsWithinBoundsReplacementV1(t *testing.T) {
	msg := dispatch.Message{To: "owner@example.test", Subject: "Selected subject", HTML: "<p>Selected revision and original action</p>", Text: "Selected revision and original action", ReplyTo: "sender@example.test", FromName: "Workspace"}
	in := generated.EnqueueEmailDeliveryParams{ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text, ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: []byte("{}")}
	if !applicationChangeEmailDeliveryMatchesV1(in, msg) {
		t.Fatal("actual rendered message lost its private binding")
	}
	for name, change := range map[string]func(*generated.EnqueueEmailDeliveryParams){
		"subject":      func(v *generated.EnqueueEmailDeliveryParams) { v.Subject = "short" },
		"html":         func(v *generated.EnqueueEmailDeliveryParams) { v.HtmlBody = "<p>Other</p>" },
		"text":         func(v *generated.EnqueueEmailDeliveryParams) { v.TextBody = "Other" },
		"recipient":    func(v *generated.EnqueueEmailDeliveryParams) { v.ToEmail = "other@example.test" },
		"reply-to":     func(v *generated.EnqueueEmailDeliveryParams) { v.ReplyTo = "other@example.test" },
		"display-name": func(v *generated.EnqueueEmailDeliveryParams) { v.FromName = "Other" },
		"headers":      func(v *generated.EnqueueEmailDeliveryParams) { v.HeadersJson = []byte(`{"x":"other"}`) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := in
			change(&copy)
			if applicationChangeEmailDeliveryMatchesV1(copy, msg) {
				t.Fatal("different within-bounds message acquired queue authority")
			}
		})
	}
	if !applicationChangeEmailDeliveryMatchesV1(in, msg) {
		t.Fatal("negative comparisons consumed or rewrote the genuine message")
	}
}
