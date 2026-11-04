// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This opaque same-work source consumer is prepared BEFORE audit chain locking.
// It grants no delivery/event authority. Enqueue still requires the genuine
// just-appended audit consumer in the original transaction. Copying its shell
// cannot consume it or release the original source loan.
type ApplicationSenderEventNoticeV1 struct {
	mu                               sync.Mutex
	self                             *ApplicationSenderEventNoticeV1
	work                             *ApplicationHTMLSendWorkV1
	org, document, sender, recipient uuid.UUID
	sentAt                           pgtype.Timestamptz
	signature                        pgtype.UUID
	kind                             string
	message                          dispatch.Message
	enabled, used, closed            bool
}

// Same ordering as existing settings/user writers: actual sender SHARE, then
// preference SHARE, then (in the adapter) audit chain. No audit-chain owner ever
// waits for these source locks. Every scalar/body/driver copy is admitted first.
func (w *ApplicationHTMLSendWorkV1) PrepareSenderEventNoticeV1(call context.Context, publicURL string) (*ApplicationSenderEventNoticeV1, error) {
	if w == nil || w.self != w {
		return nil, dispatch.ErrSenderEventNoticeV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	recipient, signature, kind, err := w.senderEventMutationLockedV1(call)
	if err != nil {
		return nil, err
	}
	doc := w.sourceDocument
	controls := int64(32<<10) + int64(4*unsafe.Sizeof(generated.EmailDelivery{})+4*unsafe.Sizeof(ApplicationSenderEventNoticeV1{}))
	closeControls, err := w.actor.acquireOwnedRetainedBodyV1(call, controls, 8<<10)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeControls)
	p := &ApplicationSenderEventNoticeV1{work: w, org: doc.OrgID, document: doc.ID, sender: doc.SenderID, recipient: recipient.ID, sentAt: doc.SentAt, signature: signature, kind: kind}
	p.self = p
	w.sourceBorrowers++
	ok := false
	defer func() {
		if !ok {
			w.sourceBorrowers--
		}
	}()
	// Role/email writers lock this same row before their audit append. It must
	// therefore precede both the preference lock and the new audit append.
	sender, err := w.queries.GetSenderAutomationRecipientV1(call, generated.GetSenderAutomationRecipientV1Params{SenderUserID: doc.SenderID, OrgID: doc.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		ok = true
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if sender == nil || sender.ID != doc.SenderID || sender.OrgID != doc.OrgID || len(sender.Email) < 3 || len(sender.Email) > 254 {
		return nil, dispatch.ErrSenderEventNoticeV1
	}
	pref, err := w.queries.GetSenderAutomationPreferenceV1(call, generated.GetSenderAutomationPreferenceV1Params{OrgID: doc.OrgID, SenderUserID: doc.SenderID})
	if errors.Is(err, pgx.ErrNoRows) {
		ok = true
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if pref == nil || pref.OrgID != doc.OrgID || pref.SenderUserID != doc.SenderID || pref.Revision <= 0 {
		return nil, dispatch.ErrSenderEventNoticeV1
	}
	if (kind == "document.viewed" && !pref.NotifyViewed) || (kind == "document.signed" && !pref.NotifySigned) {
		ok = true
		return p, nil
	}
	if !applicationStampV1(doc.SentAt) {
		return nil, dispatch.ErrSenderEventNoticeV1
	}
	raw, wire, err := dispatch.SenderEventNoticeOutputBoundV1(int64(len(doc.Name)), int64(len(recipient.Name)), int64(len(publicURL)))
	if err != nil {
		return nil, err
	}
	closeOutput, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeOutput)
	p.message, err = dispatch.SenderEventNoticeMessageV1(kind, publicURL, sender.Email, doc.ID, doc.Name, recipient.Name)
	if err != nil {
		return nil, err
	}
	p.message.OrgID = doc.OrgID
	if err = call.Err(); err != nil {
		return nil, err
	}
	p.enabled = true
	ok = true
	return p, nil
}

// The fixed adapter calls this AFTER the actual audit append and BEFORE its
// final credential recheck/commit. No sender/preference lock is acquired here.
// A durable receipt and its exact fresh outbox row commit or roll back together.
func (p *ApplicationSenderEventNoticeV1) EnqueueV1(call context.Context, audit *ApplicationHTMLAuditEventConsumerV1) error {
	if p == nil || p.self != p || audit == nil || audit.self != audit {
		return dispatch.ErrSenderEventNoticeV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	w := p.work
	if p.closed || p.used || w == nil || w.self != w {
		return dispatch.ErrSenderEventNoticeV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	audit.mu.Lock()
	defer audit.mu.Unlock()
	recipient, signature, kind, err := w.senderEventMutationLockedV1(call)
	if err != nil {
		return err
	}
	doc := w.sourceDocument
	if p.org != doc.OrgID || p.document != doc.ID || p.sender != doc.SenderID || p.recipient != recipient.ID || p.sentAt != doc.SentAt || p.signature != signature || p.kind != kind || !audit.valid(call) || audit.session != w.session || audit.published || !audit.used || !audit.attempted || audit.eventID == uuid.Nil || audit.org != p.org || audit.document != p.document || audit.physicalDocument != p.document || !audit.recipient.Valid || uuid.UUID(audit.recipient.Bytes) != p.recipient || audit.actor.Valid || audit.kind != kind {
		return dispatch.ErrSenderEventNoticeV1
	}
	if (kind == "document.viewed" && audit.purpose != HTMLAuditSignerViewedV1) || (kind == "document.signed" && audit.purpose != HTMLAuditBlockSignedV1 && audit.purpose != HTMLAuditPackageSignedV1) {
		return dispatch.ErrSenderEventNoticeV1
	}
	p.used = true
	if !p.enabled {
		return nil
	}
	identity, err := w.queries.GetSenderAutomationEventIdentityV1(call, generated.GetSenderAutomationEventIdentityV1Params{AuditEventID: audit.eventID, OrgID: p.org, DocumentID: p.document, RecipientID: p.recipient, EventKind: kind, SenderUserID: p.sender})
	if err != nil {
		return err
	}
	wantSignature := uuid.Nil
	if signature.Valid {
		wantSignature = uuid.UUID(signature.Bytes)
	}
	if identity == nil || identity.AuditEventID != audit.eventID || !applicationStampV1(identity.SentAt) || identity.SentAt != p.sentAt || identity.SignatureID != wantSignature {
		return dispatch.ErrSenderEventNoticeV1
	}
	emailID := uuid.New()
	claimed, err := w.queries.TryClaimSenderEventNoticeV1(call, generated.TryClaimSenderEventNoticeV1Params{AuditEventID: audit.eventID, OrgID: p.org, DocumentID: p.document, RecipientID: p.recipient, SenderUserID: p.sender, SentAt: p.sentAt, EventKind: kind, SignatureID: signature, EmailDeliveryID: emailID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if claimed != audit.eventID || claimed == uuid.Nil {
		return dispatch.ErrSenderEventNoticeV1
	}
	m := p.message
	row, err := w.queries.EnqueueSenderEventNoticeV1(call, generated.EnqueueSenderEventNoticeV1Params{ID: emailID, OrgID: p.org, ToEmail: m.To, Subject: m.Subject, HtmlBody: m.HTML, TextBody: m.Text, FromName: m.FromName})
	if err != nil {
		return err
	}
	if !applicationWorkspaceEmailDeliveryMatchesV1(row, p.org) || row.ID != emailID || row.ToEmail != m.To || row.Subject != m.Subject || row.HtmlBody != m.HTML || row.TextBody != m.Text || row.FromName != m.FromName || row.ReplyTo != "" || row.Status != "pending" || row.Attempts != 0 || row.LastError != "" || row.SentAt.Valid || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.NextAttemptAt) || !bytes.Equal(row.HeadersJson, []byte("{}")) {
		return dispatch.ErrSenderEventNoticeV1
	}
	return call.Err()
}

func (p *ApplicationSenderEventNoticeV1) CloseConsumerV1() {
	if p == nil || p.self != p {
		return
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	w := p.work
	p.work = nil
	p.message = dispatch.Message{}
	if w == nil {
		p.mu.Unlock()
		return
	}
	w.mu.Lock()
	w.sourceBorrowers--
	closes, actor := w.retireSourcesLockedV1()
	w.mu.Unlock()
	p.mu.Unlock()
	htmlSendCloseSourceResourcesV1(closes, actor)
}

// w is locked. Only the actual marked private view/sign mutation supplies kind,
// recipient and signature. Preparing a message is not audit/delivery authority.
func (w *ApplicationHTMLSendWorkV1) senderEventMutationLockedV1(call context.Context) (*generated.Recipient, pgtype.UUID, string, error) {
	bad := func() (*generated.Recipient, pgtype.UUID, string, error) {
		return nil, pgtype.UUID{}, "", dispatch.ErrSenderEventNoticeV1
	}
	if !w.valid(call) || w.sourceDocument == nil || w.actor == nil || w.queries == nil || w.stage == nil || w.familyRoot != nil || w.sourceDocument.SenderID == uuid.Nil {
		return bad()
	}
	var recipient *generated.Recipient
	var signature pgtype.UUID
	kind := ""
	switch w.stage.purpose {
	case HTMLSignerViewMutationV1:
		m := w.signerView
		if m == nil || m.done || !m.marked || m.recipient == nil || m.request == nil || (m.recipient.Status != "pending" && m.recipient.Status != "sent") {
			return bad()
		}
		recipient = m.recipient
		kind = "document.viewed"
	case HTMLBlockSignMutationV1:
		m := w.blockSignature
		if m == nil || !m.marked || m.signature == nil || m.recipient == nil || m.request == nil || m.signature.ID == uuid.Nil || m.signature.DocumentID != w.sourceDocument.ID || m.signature.RecipientID != m.recipient.ID {
			return bad()
		}
		recipient = m.recipient
		signature = pgtype.UUID{Bytes: m.signature.ID, Valid: true}
		kind = "document.signed"
	default:
		return bad()
	}
	if recipient.ID == uuid.Nil || recipient.DocumentID != w.sourceDocument.ID {
		return bad()
	}
	return recipient, signature, kind, nil
}
