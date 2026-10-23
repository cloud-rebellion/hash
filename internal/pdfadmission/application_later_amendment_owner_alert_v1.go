// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type laterAmendmentOwnerAlertV1 struct {
	user, email uuid.UUID
	messageSHA  [32]byte
}

func (a laterAmendmentOwnerAlertV1) payloadV1() map[string]any {
	return map[string]any{"user_id": a.user.String(), "email_delivery_id": a.email.String(), "message_sha256": hex.EncodeToString(a.messageSHA[:]), "state": "queued"}
}

// Private paired-native scope only. Read and SHARE-lock the actual original
// SenderID/current member BEFORE copying its bounded email or queue outputs.
// Existing pair/read gates already hold current actor and all-subject privacy.
func laterAmendmentOwnerAlertForV1(call context.Context, s *applicationDocumentPackageSelectionStateV1, kind, publicURL string) (out laterAmendmentOwnerAlertV1, failure error) {
	if s == nil || s.session == nil || s.actor == nil || s.readers[0] == nil || s.readers[0].snapshot == nil || s.readers[0].snapshot.document == nil {
		return out, amendments.ErrUnavailableV1
	}
	original := s.readers[0].snapshot.document
	close, e := s.actor.acquireOwnedRetainedBodyV1(call, 128<<10, 32<<10)
	if e != nil {
		return out, e
	}
	s.closes = append(s.closes, close)
	db := &applicationOwnedDBTXV1{session: s.session.state}
	var user uuid.UUID
	var email string
	e = db.QueryRow(call, `SELECT u.id,u.email FROM documents d JOIN users u ON u.id=d.sender_id AND u.org_id=d.org_id
 WHERE d.id=$1 AND d.org_id=$2 AND d.sender_id=$3 AND d.deleted_at IS NULL AND d.status='completed' AND u.role IN ('owner','sender')
 AND octet_length(u.email) BETWEEN 3 AND 254
 AND hash_try_document_package_privacy_fence_v1(d.org_id,d.id)
 AND NOT EXISTS(SELECT 1 FROM data_subject_requests p WHERE p.org_id=d.org_id AND p.status IN ('open','in_progress') AND (p.document_id IS NULL OR p.document_id=d.id))
 FOR SHARE OF d,u`, original.ID, original.OrgID, original.SenderID).Scan(&user, &email)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, amendments.ErrChangedV1
	}
	if e != nil {
		return out, e
	}
	if user != original.SenderID || user == uuid.Nil {
		return out, amendments.ErrChangedV1
	}
	message, e := dispatch.AmendmentOwnerAlertMessageV1(kind, publicURL, email, original.ID)
	if e != nil {
		return out, e
	}
	sum, e := dispatch.AmendmentOwnerAlertMessageSHA256V1(message)
	if e != nil {
		return out, e
	}
	q := generated.New(db)
	row, e := q.EnqueueEmailDelivery(call, generated.EnqueueEmailDeliveryParams{ToEmail: message.To, Subject: message.Subject, HtmlBody: message.HTML, TextBody: message.Text, FromName: message.FromName, ReplyTo: "", HeadersJson: []byte(dispatch.AmendmentOwnerAlertHeadersJSONV1)})
	if e != nil {
		return out, e
	}
	if row == nil || row.ID == uuid.Nil || row.ToEmail != email || row.Subject != message.Subject || row.HtmlBody != message.HTML || row.TextBody != message.Text || row.FromName != "Hash" || row.ReplyTo != "" || row.Status != "pending" || row.LastError != "" {
		return out, amendments.ErrUnavailableV1
	}
	var observed []byte
	if e = db.QueryRow(call, `SELECT hash_package_send_message_sha256_v1($1)`, row.ID).Scan(&observed); e != nil || !bytes.Equal(observed, sum[:]) {
		return out, amendments.ErrUnavailableV1
	}
	return laterAmendmentOwnerAlertV1{user: user, email: row.ID, messageSHA: sum}, call.Err()
}
