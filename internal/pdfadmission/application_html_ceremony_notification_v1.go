// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/actiontoken"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
)

// A concrete single owner notification, derived ONLY from the actual request,
// locked sender/recipient/document and configured values. It exposes no costs,
// supplied models, generic transaction, callback or foreign delivery capability.
type ApplicationHTMLChangeNotificationV1 struct {
	mu                                 sync.Mutex
	self                               *ApplicationHTMLChangeNotificationV1
	owner                              *ApplicationHTMLCeremonyWorkflowV1
	org                                uuid.UUID
	context                            dispatch.TemplateContext
	selectedTemplate                   *dispatch.ServiceEmailTemplateV1
	message                            dispatch.Message
	to, fromName                       string
	subjectBytes, htmlBytes, textBytes int64
	attempted                          bool
	renderAttempted, rendered          bool
}

func (w *ApplicationHTMLCeremonyWorkflowV1) NewChangeNotificationV1(call context.Context, orgName, baseURL, actionSecret string, approveAt, denyAt time.Time) (*ApplicationHTMLChangeNotificationV1, error) {
	if !w.validCallV1(call) || w.operation.state.workflow != htmlCeremonyParticipantChangeV1 {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.mu.Lock()
	if w.notification != nil || w.change == nil || w.participant == nil || w.sender == nil || w.snapshot == nil {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	document, recipient, sender, change, input := w.snapshot.document, w.participant, w.sender, w.change, w.changeInput
	w.mu.Unlock()
	companyName, err := w.readTenantPresentationNameV1(call)
	if err != nil {
		return nil, err
	}
	// Actual actiontoken payload is six joined strings/five separators. UUIDs are
	//36ASCII bytes each, kind cr2, longest action approve7 and signed int64 <=20.
	// RawURL base64 upper is4*ceil(n/3); HMAC-SHA256 adds43bytes plus one dot.
	const payloadUpper = int64(2 + 3*36 + 7 + 20 + 5)
	const tokenUpper = int64(4*((payloadUpper+2)/3) + 1 + 44)
	base := int64(len(baseURL))
	urls, err := htmlAuthoringSumV1(base, int64(len("/documents/"))+36)
	if err != nil {
		return nil, err
	}
	for i := 0; i < 2; i++ {
		urls, err = htmlAuthoringSumV1(urls, base, int64(len("/a/cr?t=")), tokenUpper)
		if err != nil {
			return nil, err
		}
	}
	inputs, err := htmlAuthoringSumV1(int64(unsafe.Sizeof("")), int64(len(orgName)), int64(len(companyName)), base, int64(len(actionSecret)), urls, 2*payloadUpper,
		int64(len(document.Name)), int64(len(document.DefaultLocale)), int64(len(recipient.Name)), int64(len(sender.Name)), int64(len(sender.Email)),
		int64(len(input.Message)), int64(len(input.Quote)), int64(len(input.Context)), int64(len(input.Proposed)))
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, inputs, 0); err != nil {
		return nil, err
	}
	// Only actual known producer output is constructed after its own input/URL
	// credit. No secret is retained in the result or exposed as source data.
	approveURL, denyURL := "", ""
	root := strings.TrimRight(baseURL, "/")
	if actionSecret != "" {
		claims := actiontoken.Claims{Kind: "cr", OrgID: document.OrgID.String(), DocID: document.ID.String(), TargetID: change.ID.String()}
		approve := claims
		approve.Action = "approve"
		deny := claims
		deny.Action = "deny"
		approveURL = root + "/a/cr?t=" + actiontoken.Mint(actionSecret, approve, approveAt, 14*24*time.Hour)
		denyURL = root + "/a/cr?t=" + actiontoken.Mint(actionSecret, deny, denyAt, 14*24*time.Hour)
	}
	context := dispatch.TemplateContext{DocumentName: document.Name, SenderName: sender.Name, SenderEmail: sender.Email, RecipientName: recipient.Name, Locale: document.DefaultLocale,
		OrgName: strings.Clone(companyName), DeclineReason: input.Message, ChangeQuote: input.Quote, ChangeContext: input.Context, ChangeProposed: input.Proposed,
		OpenURL: root + "/documents/" + document.ID.String(), ApproveURL: approveURL, DenyURL: denyURL}
	selectedTemplate, err := w.changeServiceEmailTemplateV1(call)
	if err != nil {
		return nil, err
	}
	s, h, t, err := applicationServiceEmailComponentsV1(dispatch.KindChangesRequested, context, selectedTemplate)
	if err != nil {
		return nil, err
	}
	output, err := htmlAuthoringSumV1(applicationWorkspaceSMTPPurposeBytesV1, s, h, t, 2*int64(len(sender.Email)), int64(len(orgName)), int64(len("pending")))
	if err != nil {
		return nil, err
	}
	// Complete logical TEXT output plus the actual two-byte headers JSON is
	// separately charged for DB staging as well as retained client/result copies.
	wire, err := htmlAuthoringSumV1(output, 2+applicationWorkspaceSMTPWireBytesV1)
	if err != nil {
		return nil, err
	}
	if err = w.retainV1(call, output, wire); err != nil {
		return nil, err
	}
	n := &ApplicationHTMLChangeNotificationV1{owner: w, org: document.OrgID, context: context, selectedTemplate: selectedTemplate, to: sender.Email, fromName: strings.Clone(orgName), subjectBytes: s, htmlBytes: h, textBytes: t}
	n.self = n
	w.mu.Lock()
	if w.notification != nil || w.closed {
		w.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	w.notification = n
	w.mu.Unlock()
	return n, nil
}

// This actual borrower spans template rendering, original commit and any
// synchronous local postcommit delivery. Cancellation/physical SQL retirement
// cannot credit its context, generated messages or output loans before release.
func (n *ApplicationHTMLChangeNotificationV1) BorrowContextV1(call context.Context) (dispatch.TemplateContext, string, func(), error) {
	if n == nil || n.self != n {
		return dispatch.TemplateContext{}, "", nil, ErrHTMLCeremonyWorkflowV1
	}
	n.mu.Lock()
	owner := n.owner
	context, to := n.context, n.to
	n.mu.Unlock()
	if owner == nil || !owner.validCallV1(call) {
		return dispatch.TemplateContext{}, "", nil, ErrHTMLCeremonyWorkflowV1
	}
	owner.mu.Lock()
	if owner.closed || owner.resourcesClosed {
		owner.mu.Unlock()
		return dispatch.TemplateContext{}, "", nil, ErrHTMLCeremonyWorkflowV1
	}
	owner.active++
	owner.mu.Unlock()
	var once sync.Once
	return context, to, func() { once.Do(owner.doneV1) }, nil
}

// The original native context and selected revision remain borrowed through
// render, enqueue, commit and any synchronous local postcommit delivery. The
// caller supplies no replacement renderer, source, destination or size claim.
func (n *ApplicationHTMLChangeNotificationV1) BorrowMessageV1(call context.Context) (dispatch.Message, func(), error) {
	if n == nil || n.self != n {
		return dispatch.Message{}, nil, ErrHTMLCeremonyWorkflowV1
	}
	n.mu.Lock()
	if n.renderAttempted {
		n.mu.Unlock()
		return dispatch.Message{}, nil, ErrHTMLCeremonyWorkflowV1
	}
	n.renderAttempted = true
	n.mu.Unlock()
	ctx, to, close, err := n.BorrowContextV1(call)
	if err != nil {
		return dispatch.Message{}, nil, err
	}
	n.mu.Lock()
	tpl, fromName, s, h, t := n.selectedTemplate, n.fromName, n.subjectBytes, n.htmlBytes, n.textBytes
	n.mu.Unlock()
	subject, html, text, err := dispatch.RenderServiceEmailV1(dispatch.KindChangesRequested, ctx, tpl)
	if err != nil || int64(len(subject)) > s || int64(len(html)) > h || int64(len(text)) > t {
		close()
		if err != nil {
			return dispatch.Message{}, nil, err
		}
		return dispatch.Message{}, nil, ErrHTMLCeremonyWorkflowV1
	}
	message := dispatch.Message{OrgID: n.org, To: to, Subject: subject, HTML: html, Text: text, ReplyTo: ctx.SenderEmail, FromName: fromName}
	// Immutable strings alias the already-paid output. A returned message value
	// may be edited by its caller without altering this private queue binding.
	n.mu.Lock()
	n.message, n.rendered = message, true
	n.mu.Unlock()
	return message, close, nil
}

func applicationChangeEmailDeliveryMatchesV1(in generated.EnqueueEmailDeliveryParams, msg dispatch.Message) bool {
	return msg.OrgID != uuid.Nil && in.OrgID == msg.OrgID && len(msg.Headers) == 0 && bytes.Equal(in.HeadersJson, []byte("{}")) && in.ToEmail == msg.To && in.Subject == msg.Subject && in.HtmlBody == msg.HTML && in.TextBody == msg.Text && in.ReplyTo == msg.ReplyTo && in.FromName == msg.FromName
}

// This is exactly the original outbox interface, with dispatch kept inside the
// SAME actual native callback and this one concrete notification's paid bounds.
func (n *ApplicationHTMLChangeNotificationV1) EnqueueEmailDelivery(call context.Context, in generated.EnqueueEmailDeliveryParams) (*generated.EmailDelivery, error) {
	if n == nil || n.self != n {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	n.mu.Lock()
	owner := n.owner
	n.mu.Unlock()
	if owner == nil || !owner.validCallV1(call) {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	n.mu.Lock()
	if n.owner != owner || n.attempted || !n.rendered || !applicationChangeEmailDeliveryMatchesV1(in, n.message) {
		n.mu.Unlock()
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	n.attempted = true
	expected, to, fromName, s, h, t := n.context, n.to, n.fromName, n.subjectBytes, n.htmlBytes, n.textBytes
	n.mu.Unlock()
	if in.ToEmail != to || in.ReplyTo != expected.SenderEmail || in.FromName != fromName || !bytes.Equal(in.HeadersJson, []byte("{}")) ||
		int64(len(in.Subject)) > s || int64(len(in.HtmlBody)) > h || int64(len(in.TextBody)) > t {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	q, err := owner.queriesV1(call)
	if err != nil {
		return nil, err
	}
	row, err := q.EnqueueEmailDelivery(call, in)
	if err != nil {
		return nil, err
	}
	if !applicationWorkspaceEmailDeliveryMatchesV1(row, n.org) || row == nil || row.ID == uuid.Nil || row.ToEmail != in.ToEmail || row.Subject != in.Subject || row.HtmlBody != in.HtmlBody || row.TextBody != in.TextBody ||
		row.ReplyTo != in.ReplyTo || row.FromName != in.FromName || !bytes.Equal(row.HeadersJson, in.HeadersJson) || row.Status != "pending" || row.LastError != "" {
		return nil, ErrHTMLCeremonyWorkflowV1
	}
	return row, nil
}
func (n *ApplicationHTMLChangeNotificationV1) clearV1() {
	if n == nil || n.self != n {
		return
	}
	n.mu.Lock()
	n.context = dispatch.TemplateContext{}
	n.selectedTemplate = nil
	n.message = dispatch.Message{}
	n.to, n.fromName = "", ""
	n.owner = nil
	n.mu.Unlock()
}
