// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// QueueingMailer implements Mailer by persisting each message to the
// email_deliveries table instead of sending it inline. The worker's
// email-dispatch loop drains the queue with backoff retries, so a transient
// SMTP outage never drops an invite, reminder, or completion email. Inject
// this everywhere an engine needs a Mailer; only the drain loop talks to SMTP.
type QueueingMailer struct {
	Q *generated.Queries
}

// Send enqueues the message. It returns an error only if the row cannot be
// written; actual delivery happens asynchronously in the worker.
func (m QueueingMailer) Send(ctx context.Context, msg Message) error {
	if msg.OrgID == uuid.Nil {
		return errors.New("email outbox requires a genuine workspace org")
	}
	headers := json.RawMessage("{}")
	if len(msg.Headers) > 0 {
		if b, err := json.Marshal(msg.Headers); err == nil {
			headers = b
		}
	}
	row, err := m.Q.EnqueueEmailDelivery(ctx, generated.EnqueueEmailDeliveryParams{
		OrgID:       msg.OrgID,
		ToEmail:     msg.To,
		Subject:     msg.Subject,
		HtmlBody:    msg.HTML,
		TextBody:    msg.Text,
		ReplyTo:     msg.ReplyTo,
		FromName:    msg.FromName,
		HeadersJson: headers,
	})
	if err != nil {
		return err
	}
	if row == nil || !row.SmtpOrgID.Valid || uuid.UUID(row.SmtpOrgID.Bytes) != msg.OrgID || row.SmtpPurpose != "workspace" || row.SmtpClaimNonce.Valid || row.StaffAuthCiphertext != nil {
		return errors.New("email outbox route not preserved")
	}
	return nil
}
