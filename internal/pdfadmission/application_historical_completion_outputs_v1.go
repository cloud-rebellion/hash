// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"time"
	"unsafe"
)

type applicationHistoricalCompletionOutputsV1 struct {
	rows                                          []*generated.Recipient
	required                                      map[string]struct{}
	tokens                                        []historicalCompletionCredentialV1
	sender                                        *generated.User
	messages, views                               []dispatch.Message
	deliveries                                    []*generated.EmailDelivery
	read, rotated, senderRead, rendered, enqueued bool
}
type historicalCompletionCredentialV1 struct {
	recipient *generated.Recipient
	token     string
	expiry    time.Time
}

// Actual parent/recipient locks already established readiness. Expiring the old
// tokens changes only fixed timestamps; the full second original row read is
// funded from those actual locked private rows before transfer and revalidated.
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalCompletionRecipientsV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	if !p.tokensInvalidated || p.outputs != nil || !w.recipientsRead {
		return ErrHTMLSendWorkV1
	}
	raw := 2 * int64(unsafe.Sizeof(applicationHistoricalCompletionOutputsV1{}))
	for _, row := range w.sourceRecipients {
		if row == nil {
			return ErrHTMLSendWorkV1
		}
		n, e := htmlAuthoringSumV1(int64(len(row.Role)), int64(len(row.Email)), int64(len(row.Name)), int64(len(row.Status)), int64(len(row.Locale)), int64(len(row.DeclinedReason.String)), int64(len(row.MagicTokenHash)))
		if e != nil || !htmlInputAddV1(&raw, n, 2) || !htmlInputAddV1(&raw, 1, 4*int64(unsafe.Sizeof(generated.Recipient{}))+8*int64(unsafe.Sizeof((*generated.Recipient)(nil)))+4*int64(unsafe.Sizeof(historicalCompletionCredentialV1{}))+4*int64(unsafe.Sizeof(generated.RotateCompletedArtifactTokenParams{}))+2*(43+32)) {
			return ErrHTMLSendWorkV1
		}
	}
	if !htmlInputAddV1(&raw, int64(len(state.roles)), 8*int64(unsafe.Sizeof(""))+8*int64(unsafe.Sizeof(uintptr(0)))+64) {
		return ErrHTMLSendWorkV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeRows)
	rows, err := w.queries.ListRecipientsByDocument(call, p.completed.ID)
	if err != nil {
		return err
	}
	if len(rows) != len(w.sourceRecipients) {
		return ErrHTMLSendWorkV1
	}
	for i, row := range rows {
		if row == nil || !applicationStampV1(row.MagicTokenExpiresAt) {
			return ErrHTMLSendWorkV1
		}
		old := w.sourceRecipients[i]
		expected := *old
		expected.MagicTokenExpiresAt = row.MagicTokenExpiresAt
		if !historicalCompletionRecipientExactV1(&expected, row) {
			return ErrHTMLSendWorkV1
		}
	}
	out := &applicationHistoricalCompletionOutputsV1{rows: make([]*generated.Recipient, len(rows)), required: make(map[string]struct{}, len(state.roles)), tokens: make([]historicalCompletionCredentialV1, 0, len(rows)), read: true}
	for i, row := range rows {
		out.rows[i] = htmlSendCloneRecipientV1(row)
	}
	for _, role := range state.roles {
		out.required[role] = struct{}{}
	}
	p.outputs = out
	return nil
}

// The exact existing24h credential lifetime uses the Engine's original clock
// at the original point after the second recipient read. Tokens/hashes are
// actually minted here and each original guarded row count is checked.
func (w *ApplicationHTMLSendWorkV1) RotateHistoricalCompletionCredentialsV1(call context.Context, now time.Time, capture uuid.UUID) (string, error) {
	if w == nil || w.self != w {
		return "", ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return "", err
	}
	out := p.outputs
	if out == nil || !out.read || out.rotated || now.IsZero() {
		return "", ErrHTMLSendWorkV1
	}
	out.rotated = true
	expires := pgtype.Timestamptz{Time: now.Add(24 * time.Hour), Valid: true}
	captured := ""
	// The immutable committed execution binds the one permanently disabled
	// provider. Ordinary documents have no such row; lookup errors fail closed.
	var disabledProvider uuid.UUID
	lookupErr := (&applicationOwnedDBTXV1{session: w.session.state}).QueryRow(call,
		`SELECT e.provider_recipient_id FROM presign_executions e WHERE e.org_id=$1 AND e.document_id=$2`,
		p.completed.OrgID, p.completed.ID).Scan(&disabledProvider)
	if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
		return "", lookupErr
	}
	if lookupErr == nil && disabledProvider == uuid.Nil {
		return "", ErrHTMLSendWorkV1
	}
	for _, row := range out.rows {
		// Keep the provider's evidence/internal row, but never mint its public
		// token or append it to the participant credential/delivery list.
		if disabledProvider != uuid.Nil && row != nil && row.ID == disabledProvider {
			continue
		}
		if !recipients.ReceivesCompletedArtifactV1(p.completed.RequiresSignature, row, out.required) {
			continue
		}
		token, hash, err := auth.MintMagicToken()
		if err != nil {
			return "", fmt.Errorf("mint completed artifact token: %w", err)
		}
		if len(token) != 43 || len(hash) != 32 {
			return "", ErrHTMLSendWorkV1
		}
		count, err := w.queries.RotateCompletedArtifactToken(call, generated.RotateCompletedArtifactTokenParams{ID: row.ID, DocumentID: p.completed.ID, MagicTokenHash: hash, MagicTokenExpiresAt: expires})
		if err != nil {
			return "", fmt.Errorf("rotate completed artifact token for recipient %s: %w", row.ID, err)
		}
		if count != 1 {
			return "", fmt.Errorf("rotate completed artifact token for recipient %s: updated %d rows", row.ID, count)
		}
		out.tokens = append(out.tokens, historicalCompletionCredentialV1{recipient: row, token: token, expiry: expires.Time.UTC()})
		if row.ID == capture {
			captured = token
		}
	}
	if capture != uuid.Nil && strings.TrimSpace(captured) == "" {
		return "", fmt.Errorf("completed recipient %s did not receive an artifact credential", capture)
	}
	return captured, nil
}
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalCompletionSenderV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	out := p.outputs
	if out == nil || !out.rotated || out.senderRead {
		return ErrHTMLSendWorkV1
	}
	out.senderRead = true
	h, err := w.queries.GetHistoricalCompletionSenderHeaderV1(call, generated.GetHistoricalCompletionSenderHeaderV1Params{DocumentID: p.completed.ID, OrgID: p.completed.OrgID})
	if err != nil {
		return err
	}
	if h == nil || h.ID != p.completed.SenderID || h.OrgID != p.completed.OrgID || h.RawTextBytes < 0 || !applicationStampV1(h.CreatedAt) {
		return ErrHTMLSendWorkV1
	}
	raw, err := htmlAuthoringSumV1(h.RawTextBytes, 4*int64(unsafe.Sizeof(generated.User{}))+2*int64(unsafe.Sizeof(generated.GetHistoricalCompletionSenderHeaderV1Row{}))+2*int64(unsafe.Sizeof(generated.ReadHistoricalCompletionSenderV1Params{})))
	if err != nil {
		return err
	}
	closeSender, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeSender)
	row, err := w.queries.ReadHistoricalCompletionSenderV1(call, generated.ReadHistoricalCompletionSenderV1Params{DocumentID: p.completed.ID, OrgID: p.completed.OrgID, ExpectedUserID: h.ID, ExpectedCreatedAt: h.CreatedAt, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return err
	}
	if row == nil {
		return ErrHTMLSendWorkV1
	}
	n, e := htmlAuthoringSumV1(int64(len(row.Email)), int64(len(row.Name)), int64(len(row.Role)), int64(len(row.ZitadelSub.String)))
	if e != nil || row.ID != h.ID || row.OrgID != h.OrgID || row.CreatedAt != h.CreatedAt || n > h.RawTextBytes {
		return ErrHTMLSendWorkV1
	}
	copy := *row
	out.sender = &copy
	return nil
}

// Native source/configuration fund URLs, exact fixed template work, original
// render outputs and independent queue/dispatch copies before construction.
func (w *ApplicationHTMLSendWorkV1) RenderHistoricalCompletionMessagesV1(call context.Context, baseURL, orgName string) ([]dispatch.Message, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return nil, err
	}
	out := p.outputs
	if out == nil || out.sender == nil || out.rendered {
		return nil, ErrHTMLSendWorkV1
	}
	out.rendered = true
	count := int64(len(out.tokens) + 1)
	raw := int64(0)
	if !htmlInputAddV1(&raw, int64(len(baseURL)), 2) || !htmlInputAddV1(&raw, int64(len(orgName)), 2) || !htmlInputAddV1(&raw, dispatch.CompletedSenderTemplateSourceBytesV1(), 64) || !htmlInputAddV1(&raw, count, 4*int64(unsafe.Sizeof(dispatch.Message{}))+4*int64(unsafe.Sizeof(dispatch.TemplateContext{}))+4*int64(unsafe.Sizeof(generated.EmailDelivery{}))+4*int64(unsafe.Sizeof(generated.EnqueueEmailDeliveryParams{}))+4*int64(unsafe.Sizeof((*generated.EmailDelivery)(nil)))+4*int64(unsafe.Sizeof(map[string]string{}))+8*int64(unsafe.Sizeof(""))+4*int64(unsafe.Sizeof(time.Time{}))) {
		return nil, ErrHTMLSendWorkV1
	}
	for range out.tokens {
		if !htmlInputAddV1(&raw, int64(len(baseURL)), 6) || !htmlInputAddV1(&raw, 1, 2*int64(2*(len("/sign/")+43)+len("/final-pdf")+len("/audit-cert")+len("/completed/")+43)+2*int64(len(time.RFC3339))) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if !htmlInputAddV1(&raw, int64(len(baseURL)), 4) || !htmlInputAddV1(&raw, 1, 2*int64(2*(len("/api/v1/documents/")+36)+len("/final-pdf")+len("/audit-cert"))) {
		return nil, ErrHTMLSendWorkV1
	}
	closeInput, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeInput)
	baseURL = strings.TrimRight(baseURL, "/")
	probe := baseURL + "/sign/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/final-pdf"
	auditProbe := baseURL + "/sign/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/audit-cert"
	senderURL := baseURL + "/api/v1/documents/" + p.completed.ID.String() + "/final-pdf"
	output := int64(0)
	for _, credential := range out.tokens {
		r := credential.recipient
		ctx := dispatch.TemplateContext{DocumentName: p.completed.Name, SenderName: out.sender.Name, SenderEmail: out.sender.Email, RecipientName: r.Name, OrgName: orgName, Locale: r.Locale, DownloadURL: probe, AuditCertURL: auditProbe, PackagePortalURL: baseURL + "/completed/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", DownloadExpiresAt: credential.expiry.UTC().Format(time.RFC3339), Acknowledgement: !p.completed.RequiresSignature}
		a, b, c, e := dispatch.CompletedNotificationComponentsV1(dispatch.KindCompletedSigner, ctx)
		if e != nil {
			return nil, e
		}
		for _, v := range []int64{a, b, c} {
			if !htmlInputAddV1(&output, v, 4) {
				return nil, ErrHTMLSendWorkV1
			}
		}
	}
	senderContext := dispatch.TemplateContext{DocumentName: p.completed.Name, SenderName: out.sender.Name, SenderEmail: out.sender.Email, RecipientName: out.sender.Name, OrgName: orgName, DownloadURL: senderURL, AuditCertURL: baseURL + "/api/v1/documents/" + p.completed.ID.String() + "/audit-cert", Acknowledgement: !p.completed.RequiresSignature}
	a, b, c, err := dispatch.CompletedNotificationComponentsV1(dispatch.KindCompletedSender, senderContext)
	if err != nil {
		return nil, err
	}
	for _, v := range []int64{a, b, c} {
		if !htmlInputAddV1(&output, v, 4) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	closeOutput, err := w.actor.acquireOwnedRetainedBodyV1(call, output, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeOutput)
	out.messages = make([]dispatch.Message, 0, len(out.tokens)+1)
	render := func(kind, to string, ctx dispatch.TemplateContext) error {
		subject, html, text, e := dispatch.Render(kind, ctx)
		if e != nil {
			return fmt.Errorf("render %s: %w", kind, e)
		}
		out.messages = append(out.messages, dispatch.Message{To: to, Subject: subject, HTML: html, Text: text, ReplyTo: ctx.SenderEmail, FromName: ctx.OrgName})
		return nil
	}
	for _, credential := range out.tokens {
		r := credential.recipient
		ctx := dispatch.TemplateContext{DocumentName: p.completed.Name, SenderName: out.sender.Name, SenderEmail: out.sender.Email, RecipientName: r.Name, OrgName: orgName, Locale: r.Locale, DownloadURL: baseURL + "/sign/" + credential.token + "/final-pdf", AuditCertURL: baseURL + "/sign/" + credential.token + "/audit-cert", PackagePortalURL: baseURL + "/completed/" + credential.token, DownloadExpiresAt: credential.expiry.UTC().Format(time.RFC3339), Acknowledgement: !p.completed.RequiresSignature}
		if err = render(dispatch.KindCompletedSigner, r.Email, ctx); err != nil {
			return nil, err
		}
	}
	if err = render(dispatch.KindCompletedSender, out.sender.Email, senderContext); err != nil {
		return nil, err
	}
	out.views = make([]dispatch.Message, len(out.messages))
	for i, msg := range out.messages {
		out.messages[i] = dispatch.Message{To: strings.Clone(msg.To), Subject: strings.Clone(msg.Subject), HTML: strings.Clone(msg.HTML), Text: strings.Clone(msg.Text), ReplyTo: strings.Clone(msg.ReplyTo), FromName: strings.Clone(msg.FromName)}
		out.views[i] = msg
	}
	return out.views, nil
}
func (w *ApplicationHTMLSendWorkV1) EnqueueHistoricalCompletionMessagesV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	out := p.outputs
	if out == nil || !out.rendered || out.enqueued {
		return ErrHTMLSendWorkV1
	}
	out.enqueued = true
	raw, wire := int64(0), int64(0)
	if !htmlInputAddV1(&raw, int64(len(out.messages)), 4*int64(unsafe.Sizeof(generated.InsertParticipantReportDeliveryV1Params{}))+4096) {
		return ErrHTMLSendWorkV1
	}
	for _, msg := range out.messages {
		n, e := htmlAuthoringSumV1(int64(len(msg.To)), int64(len(msg.Subject)), int64(len(msg.HTML)), int64(len(msg.Text)), int64(len(msg.ReplyTo)), int64(len(msg.FromName)), int64(len("pending")))
		if e != nil || !htmlInputAddV1(&raw, n, 2) || !htmlInputAddV1(&wire, 1, 2) {
			return ErrHTMLSendWorkV1
		}
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return err
	}
	w.closes = append(w.closes, closeRows)
	out.deliveries = make([]*generated.EmailDelivery, 0, len(out.messages))
	for index, msg := range out.messages {
		row, e := w.queries.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: msg.To, Subject: msg.Subject, HtmlBody: msg.HTML, TextBody: msg.Text, ReplyTo: msg.ReplyTo, FromName: msg.FromName, HeadersJson: []byte("{}")})
		if e != nil {
			return fmt.Errorf("enqueue notification email to %s: %w", dispatch.MaskEmail(msg.To), e)
		}
		if row == nil {
			return fmt.Errorf("enqueue notification email to %s returned no delivery", dispatch.MaskEmail(msg.To))
		}
		if row.ToEmail != msg.To || row.Subject != msg.Subject || row.HtmlBody != msg.HTML || row.TextBody != msg.Text || row.ReplyTo != msg.ReplyTo || row.FromName != msg.FromName || row.Status != "pending" || row.LastError != "" || string(row.HeadersJson) != "{}" {
			return ErrHTMLSendWorkV1
		}
		audience, recipient := "sender", uuid.Nil
		if index < len(out.tokens) {
			audience = "recipient"
			recipient = out.tokens[index].recipient.ID
		}
		count, err := w.queries.InsertParticipantReportDeliveryV1(call, generated.InsertParticipantReportDeliveryV1Params{DocumentID: p.completed.ID, OrgID: p.completed.OrgID, Audience: audience, RecipientID: recipient, EmailDeliveryID: row.ID})
		if err != nil || count < 0 || count > 1 {
			return fmt.Errorf("persist participant report delivery reference: %w", err)
		}
		// A zero insert is reserved for exact pre-migration retained intents;
		// the deferred terminal guard rejects it for every new completion.
		out.deliveries = append(out.deliveries, row)
	}
	return nil
}

func historicalCompletionRecipientExactV1(a, b *generated.Recipient) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.ID == b.ID && a.DocumentID == b.DocumentID && a.Role == b.Role && a.Email == b.Email && a.Name == b.Name && a.OrderIndex == b.OrderIndex && a.Status == b.Status && bytes.Equal(a.MagicTokenHash, b.MagicTokenHash) && a.SentAt == b.SentAt && a.FirstViewedAt == b.FirstViewedAt && a.SignedAt == b.SignedAt && a.DeclinedReason == b.DeclinedReason && a.CreatedAt == b.CreatedAt && a.Locale == b.Locale && a.MagicTokenExpiresAt == b.MagicTokenExpiresAt
}
