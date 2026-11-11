// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package workspacesmtp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/mail"
	"strings"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const templateSampleSubjectPrefixV1 = "[Test] "
const templateSampleHTMLNoticeV1 = "<p><strong>Test email — no signing request</strong><br>This sample uses synthetic document and recipient details. Its action links cannot be used to sign.</p>"
const templateSampleTextNoticeV1 = "Test email — no signing request. This sample uses synthetic document and recipient details. Its action links cannot be used to sign.\n\n"

func renderedTemplateSampleV1(kind string, tpl dispatch.ServiceEmailTemplateV1) (subject, html, text string, err error) {
	return renderedTemplateSampleContextV1(kind, tpl, emailtemplates.SyntheticContext())
}

func renderedTemplateSampleContextV1(kind string, tpl dispatch.ServiceEmailTemplateV1, sample dispatch.TemplateContext) (subject, html, text string, err error) {
	subject, html, text, err = dispatch.RenderServiceEmailV1(kind, sample, &tpl)
	if err != nil {
		return "", "", "", err
	}
	start := strings.Index(html, "<body")
	if start < 0 || strings.Count(html, "<body") != 1 {
		return "", "", "", ErrInput
	}
	end := strings.IndexByte(html[start:], '>')
	if end < 0 || len(subject) > dispatch.ServiceEmailRenderedSubjectBytesV1 || len(html) > dispatch.ServiceEmailDesignRenderedBytesV1 || len(text) > dispatch.ServiceEmailRenderedBodyBytesV1 {
		return "", "", "", ErrInput
	}
	end += start + 1
	return templateSampleSubjectPrefixV1 + subject, html[:end] + templateSampleHTMLNoticeV1 + html[end:], templateSampleTextNoticeV1 + text, nil
}

// TestSavedTemplateV1 sends only an already saved edition, through the selected
// workspace transport, to the authenticated owner's current address. Both CAS
// observations and the genuine owner locks belong to this single transaction.
func (s Service) TestSavedTemplateV1(ctx context.Context, a authoring.Actor, kind string, expectedSMTP, expectedTemplate int64) (out TestStatus, err error) {
	if expectedSMTP < 1 || expectedTemplate < 0 || !dispatch.ServiceEmailKindV1(kind) {
		return out, ErrInput
	}
	err = s.owner(ctx, a, func(ctx context.Context, tx pgx.Tx, guard *authoring.MemberGuard) (audit.PendingEvent, error) {
		tpl, e := emailtemplates.ReadSavedForOwnerTestV1(ctx, tx, a, guard, kind, expectedTemplate)
		if e != nil {
			return audit.PendingEvent{}, e
		}
		r, e := read(ctx, tx, a.OrgID, false)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		if r.revision != expectedSMTP {
			return audit.PendingEvent{}, ErrStale
		}
		if _, e = s.open(a.OrgID, r); e != nil {
			return audit.PendingEvent{}, e
		}
		u, e := generated.New(tx).GetUserForShare(ctx, generated.GetUserForShareParams{ID: a.UserID, OrgID: a.OrgID})
		if e != nil || u.Role != string(auth.RoleOwner) {
			return audit.PendingEvent{}, auth.ErrMutationPermissionRevoked
		}
		address, e := mail.ParseAddress(u.Email)
		if e != nil || address.Address != u.Email {
			return audit.PendingEvent{}, ErrInput
		}
		sample, e := emailtemplates.SavedSampleContextForOwnerV1(ctx, tx, a, guard, kind)
		if e != nil {
			return audit.PendingEvent{}, e
		}
		subject, html, text, e := renderedTemplateSampleContextV1(kind, tpl, sample)
		if e != nil {
			return audit.PendingEvent{}, e
		}
		var updated uuid.UUID
		e = tx.QueryRow(ctx, `UPDATE org_smtp_settings_v1 SET last_test_at=clock_timestamp() WHERE org_id=$1 AND revision=$2 AND mode='configured' AND(last_test_at IS NULL OR last_test_at<clock_timestamp()-interval '60 seconds') AND NOT EXISTS(SELECT 1 FROM org_smtp_test_requests_v1 t JOIN email_deliveries d ON d.id=t.email_delivery_id WHERE t.org_id=$1 AND d.status IN ('pending','retrying')) RETURNING org_id`, a.OrgID, expectedSMTP).Scan(&updated)
		if errors.Is(e, pgx.ErrNoRows) {
			return audit.PendingEvent{}, ErrTestBusy
		}
		if e != nil || updated != a.OrgID {
			return audit.PendingEvent{}, ErrUnavailable
		}
		var id uuid.UUID
		e = tx.QueryRow(ctx, `INSERT INTO email_deliveries(smtp_org_id,smtp_purpose,to_email,subject,html_body,text_body,reply_to,from_name,headers_json) VALUES($1,'workspace_test',$2,$3,$4,$5,'','','{}') RETURNING id`, a.OrgID, u.Email, subject, html, text).Scan(&id)
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		sh, hh, th := sha256.Sum256([]byte(subject)), sha256.Sum256([]byte(html)), sha256.Sum256([]byte(text))
		_, e = tx.Exec(ctx, `INSERT INTO org_smtp_test_requests_v1(email_delivery_id,org_id,owner_id,settings_revision,template_kind,template_revision,subject_sha256,html_sha256,text_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, a.OrgID, a.UserID, expectedSMTP, kind, tpl.Revision, sh[:], hh[:], th[:])
		if e != nil {
			return audit.PendingEvent{}, ErrUnavailable
		}
		out = TestStatus{DeliveryID: id, Status: "pending"}
		return s.Audit.LogTx(ctx, tx, audit.Entry{OrgID: a.OrgID, ActorUserID: &a.UserID, Kind: "email_template.test_queued", Payload: map[string]any{"delivery_id": id, "settings_revision": expectedSMTP, "template_kind": kind, "template_revision": tpl.Revision}})
	})
	return
}

// A NULL template receipt preserves the exact canned transport-test contract.
// A saved-template receipt binds the original synthetic rendered bytes; edits
// to its current template head cannot rewrite or reauthorize this delivery.
func workspaceTestContentMatchesV1(d *generated.EmailDelivery, msg dispatch.Message, kind pgtype.Text, revision pgtype.Int8, subjectHash, htmlHash, textHash []byte) bool {
	if d == nil || d.ReplyTo != "" || d.FromName != "" || string(d.HeadersJson) != "{}" {
		return false
	}
	if !kind.Valid {
		return !revision.Valid && subjectHash == nil && htmlHash == nil && textHash == nil && d.Subject == testSubject && d.HtmlBody == testHTML && d.TextBody == testText
	}
	if !dispatch.ServiceEmailKindV1(kind.String) || !revision.Valid || revision.Int64 < 0 || len(subjectHash) != sha256.Size || len(htmlHash) != sha256.Size || len(textHash) != sha256.Size || !strings.HasPrefix(d.Subject, templateSampleSubjectPrefixV1) || !strings.Contains(d.HtmlBody, templateSampleHTMLNoticeV1) || !strings.HasPrefix(d.TextBody, templateSampleTextNoticeV1) {
		return false
	}
	if msg.To != d.ToEmail || msg.Subject != d.Subject || msg.HTML != d.HtmlBody || msg.Text != d.TextBody || msg.ReplyTo != "" || msg.FromName != "" || len(msg.Headers) != 0 {
		return false
	}
	sh, hh, th := sha256.Sum256([]byte(d.Subject)), sha256.Sum256([]byte(d.HtmlBody)), sha256.Sum256([]byte(d.TextBody))
	return subtle.ConstantTimeCompare(sh[:], subjectHash) == 1 && subtle.ConstantTimeCompare(hh[:], htmlHash) == 1 && subtle.ConstantTimeCompare(th[:], textHash) == 1
}
