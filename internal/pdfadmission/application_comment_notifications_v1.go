// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
)

type applicationCommentNotificationsV1 struct {
	messages, views              []dispatch.Message
	deliveries                   []*generated.EmailDelivery
	rendered, enqueued, borrowed bool
}

// Only the private comment, actual locked sender/recipient models and the two
// configured strings feed this fixed KindNewComment producer. No caller DTO,
// rendered message, byte estimate or transaction callback is accepted.
func (w *ApplicationHTMLSendWorkV1) RenderCommentNotificationsV1(call context.Context, orgName, baseURL string) error {
	if w == nil || w.self != w {
		return ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || w.comment.row == nil || w.comment.notifications != nil || w.sourceActor == nil {
		return ErrCommentRequestV1
	}
	m := w.comment
	signer := m.request.signer
	if signer {
		if w.sourceActor.ID != w.sourceDocument.SenderID {
			return ErrCommentRequestV1
		}
	} else if !w.recipientsRead {
		return ErrCommentRequestV1
	}
	out := &applicationCommentNotificationsV1{}
	m.notifications = out
	count := int64(0)
	if signer {
		count = 1
	} else {
		for _, r := range w.sourceRecipients {
			if recipients.CanRespond(r.Role) {
				count++
			}
		}
	}
	raw := int64(2 * unsafe.Sizeof(applicationCommentNotificationsV1{}))
	controls := int64(4*unsafe.Sizeof(dispatch.Message{}) + 4*unsafe.Sizeof(dispatch.TemplateContext{}) + 4*unsafe.Sizeof(generated.EmailDelivery{}) + 4*unsafe.Sizeof(generated.EnqueueEmailDeliveryParams{}) + 8*unsafe.Sizeof(uintptr(0)) + 4*unsafe.Sizeof(sync.Once{}))
	if !htmlInputAddV1(&raw, count, controls) || !htmlInputAddV1(&raw, count, dispatch.CommentNotificationTemplateSourceBytesV1()*64) || !htmlInputAddV1(&raw, int64(len(orgName)), 2*(count+1)) || !htmlInputAddV1(&raw, int64(len(baseURL)), 2) || !htmlInputAddV1(&raw, 1, 2*(int64(len("/documents/"))+36)) {
		return ErrCommentRequestV1
	}
	closeInputs, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeInputs)
	openURL := ""
	if signer {
		openURL = strings.TrimRight(baseURL, "/") + "/documents/" + w.sourceDocument.ID.String()
	}
	template := dispatch.TemplateContext{DocumentName: w.sourceDocument.Name, RecipientName: m.row.AuthorName, DeclineReason: m.row.Body, OrgName: orgName, OpenURL: openURL}
	if signer {
		template.SenderName = w.sourceActor.Name
		template.SenderEmail = w.sourceActor.Email
	}
	s, h, t, err := dispatch.CommentNotificationComponentsV1(template)
	if err != nil {
		return err
	}
	output := int64(0)
	for _, n := range [...]int64{s, h, t, int64(len(template.SenderEmail)), int64(len(orgName))} {
		one := int64(0)
		if !htmlInputAddV1(&one, n, 4) || !htmlInputAddV1(&output, count, one) {
			return ErrCommentRequestV1
		}
	}
	if signer {
		if !htmlInputAddV1(&output, int64(len(w.sourceActor.Email)), 4) {
			return ErrCommentRequestV1
		}
	} else {
		for _, r := range w.sourceRecipients {
			if recipients.CanRespond(r.Role) && !htmlInputAddV1(&output, int64(len(r.Email)), 4) {
				return ErrCommentRequestV1
			}
		}
	}
	closeOutput, err := w.actor.acquireOwnedRetainedBodyV1(call, output, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeOutput)
	out.messages = make([]dispatch.Message, 0, int(count))
	out.views = make([]dispatch.Message, 0, int(count))
	render := func(to string) error {
		subject, html, text, e := dispatch.Render(dispatch.KindNewComment, template)
		if e != nil {
			return e
		}
		if int64(len(subject)) > s || int64(len(html)) > h || int64(len(text)) > t {
			return ErrCommentRequestV1
		}
		msg := dispatch.Message{To: to, Subject: subject, HTML: html, Text: text, ReplyTo: template.SenderEmail, FromName: orgName}
		private := dispatch.Message{To: strings.Clone(msg.To), Subject: strings.Clone(msg.Subject), HTML: strings.Clone(msg.HTML), Text: strings.Clone(msg.Text), ReplyTo: strings.Clone(msg.ReplyTo), FromName: strings.Clone(msg.FromName)}
		out.messages = append(out.messages, private)
		out.views = append(out.views, msg)
		return nil
	}
	if signer {
		if err = render(w.sourceActor.Email); err != nil {
			return err
		}
	} else {
		for _, r := range w.sourceRecipients {
			if recipients.CanRespond(r.Role) {
				if err = render(r.Email); err != nil {
					return err
				}
			}
		}
	}
	out.rendered = true
	return nil
}

func (w *ApplicationHTMLSendWorkV1) EnqueueCommentNotificationsV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || w.comment.notifications == nil {
		return ErrCommentRequestV1
	}
	out := w.comment.notifications
	if !out.rendered || out.enqueued {
		return ErrCommentRequestV1
	}
	out.enqueued = true
	raw, wire := int64(0), int64(0)
	for _, m := range out.messages {
		for _, v := range [...]string{m.To, m.Subject, m.HTML, m.Text, m.ReplyTo, m.FromName, "pending", "{}"} {
			if !htmlInputAddV1(&raw, int64(len(v)), 2) || !htmlInputAddV1(&wire, int64(len(v)), 1) {
				return ErrCommentRequestV1
			}
		}
	}
	if !htmlInputAddV1(&raw, int64(len(out.messages)), int64(2*unsafe.Sizeof(generated.EmailDelivery{})+2*unsafe.Sizeof(generated.EnqueueEmailDeliveryParams{})+2*unsafe.Sizeof((*generated.EmailDelivery)(nil)))) {
		return ErrCommentRequestV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeRows)
	out.deliveries = make([]*generated.EmailDelivery, 0, len(out.messages))
	for _, m := range out.messages {
		row, e := w.queries.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: m.To, Subject: m.Subject, HtmlBody: m.HTML, TextBody: m.Text, ReplyTo: m.ReplyTo, FromName: m.FromName, HeadersJson: []byte("{}")})
		if e != nil {
			return e
		}
		if row == nil || row.ID == uuid.Nil || row.LastError != "" || row.Attempts != 0 || row.SentAt.Valid || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.NextAttemptAt) || row.ToEmail != m.To || row.Subject != m.Subject || row.HtmlBody != m.HTML || row.TextBody != m.Text || row.ReplyTo != m.ReplyTo || row.FromName != m.FromName || row.Status != "pending" || !bytes.Equal(row.HeadersJson, []byte("{}")) {
			return ErrCommentRequestV1
		}
		out.deliveries = append(out.deliveries, row)
	}
	return nil
}

// Borrow BEFORE commit. The fixed application caller joins synchronous local
// delivery before releasing; SQL close/cancellation cannot retire these views.
func (w *ApplicationHTMLSendWorkV1) BorrowCommentMessagesV1(call context.Context) ([]dispatch.Message, func(), error) {
	if w == nil || w.self != w {
		return nil, nil, ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || w.comment.notifications == nil {
		return nil, nil, ErrCommentRequestV1
	}
	out := w.comment.notifications
	if !out.rendered || out.borrowed {
		return nil, nil, ErrCommentRequestV1
	}
	out.borrowed = true
	w.sourceBorrowers++
	var once sync.Once
	return out.views, func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
		})
	}, nil
}
