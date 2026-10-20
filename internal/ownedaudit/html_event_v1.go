// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ownedaudit

import (
	"context"
	"net/netip"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// LogV1 is additive: generic Log/LogTx keep their historical contract.
// Only the actual native session may derive a fresh event cache, under its own
// fixed payload producer. Earlier/uncached event history is never repaired here.
func LogV1(l *audit.Logger, ctx context.Context, session *pdfadmission.ApplicationSessionV1, purpose pdfadmission.HTMLAuditPurposeV1, e audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || e.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrHTMLAuditEventV1
	}
	document := *e.DocumentID
	owner, err := session.NewHTMLAuditEventV1(ctx, purpose, e.OrgID, document, ownedHTMLPgUUIDV1(e.RecipientID), ownedHTMLPgUUIDV1(e.ActorUserID), e.Kind, e.IP, e.UserAgent, e.Payload)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(l, ctx, owner, e)
}
func LogEnvelopeMemberV1(l *audit.Logger, ctx context.Context, member *pdfadmission.ApplicationHTMLSendWorkV1, purpose pdfadmission.HTMLAuditPurposeV1, e audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	if l == nil || member == nil || e.DocumentID == nil {
		return audit.PendingEvent{}, nil, pdfadmission.ErrHTMLAuditEventV1
	}
	owner, err := member.NewEnvelopeMemberAuditV1(ctx, purpose, ownedHTMLPgUUIDV1(e.RecipientID), ownedHTMLPgUUIDV1(e.ActorUserID), e.Kind, e.IP, e.UserAgent, e.Payload)
	if err != nil {
		return audit.PendingEvent{}, nil, err
	}
	return logPreparedOwnerV1(l, ctx, owner, e)
}
func logPreparedOwnerV1(l *audit.Logger, ctx context.Context, owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1, e audit.Entry) (audit.PendingEvent, *pdfadmission.ApplicationHTMLAuditEventConsumerV1, error) {
	var err error
	var pending audit.PendingEvent
	err = owner.WithPreparedV1(ctx, func(in pdfadmission.ApplicationHTMLAuditPreparedV1, appendOne func(generated.InsertEventIdentityV1Params) (uuid.UUID, error)) error {
		if e.DocumentID == nil || in.DocumentID != *e.DocumentID || in.OrgID != e.OrgID {
			return pdfadmission.ErrHTMLAuditEventV1
		}
		// Preserve original concrete audit.Entry values and exact payload hashing. Scalar
		// UUID addresses and every variable payload string are detached from source
		// models while this native consumer is retained through publication.
		entry := e
		entry.OrgID = in.OrgID
		entry.Kind = in.Kind
		entry.IP = in.IP
		entry.UserAgent = in.UserAgent
		entry.Payload = in.Payload
		docID := in.DocumentID
		entry.DocumentID = &docID
		entry.RecipientID = ownedHTMLUUIDV1(in.RecipientID)
		entry.ActorUserID = ownedHTMLUUIDV1(in.ActorUserID)
		var ipAddr *netip.Addr
		ipString := ""
		if entry.IP != "" {
			if addr, parseErr := netip.ParseAddr(entry.IP); parseErr == nil {
				ipAddr = &addr
				ipString = addr.String()
			}
		}
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		if in.PreviousCreatedAt.Valid {
			createdAt = ownedAuditTimestampV1(createdAt, in.PreviousCreatedAt.Time)
		}
		hashIn := audit.HashInput{Prev: in.PreviousHash, OrgID: entry.OrgID, DocID: docID, Kind: entry.Kind, IP: ipString, UA: entry.UserAgent, CreatedAt: createdAt, Payload: in.Raw}
		if entry.RecipientID != nil {
			hashIn.RecID = *entry.RecipientID
		}
		if entry.ActorUserID != nil {
			hashIn.ActorID = *entry.ActorUserID
		}
		id, appendErr := appendOne(generated.InsertEventIdentityV1Params{OrgID: entry.OrgID, DocumentID: ownedHTMLPgUUIDV1(entry.DocumentID), RecipientID: ownedHTMLPgUUIDV1(entry.RecipientID), ActorUserID: ownedHTMLPgUUIDV1(entry.ActorUserID), Kind: entry.Kind, Ip: ipAddr, Ua: ownedHTMLTextV1(entry.UserAgent), PayloadJson: in.Raw, PayloadHashed: in.Raw, PrevHash: in.PreviousHash, RowHash: audit.ChainHashRecord(hashIn), CreatedAt: pgtype.Timestamptz{Time: createdAt, Valid: true}})
		if appendErr != nil {
			return appendErr
		}
		pending = audit.PendingEvent{ID: id, Entry: entry}
		return nil
	})
	if err != nil {
		owner.CloseConsumerV1()
		return audit.PendingEvent{}, nil, err
	}
	return pending, owner, nil
}

// PublishV1 joins actual last use of this detached event payload by
// every existing hook. Cancellation alone never ends it; a hook which ignores
// its deadline retains the original consumer and real coordinator debt.
func PublishV1(l *audit.Logger, p audit.PendingEvent, owner *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
	if l == nil || owner == nil {
		return pdfadmission.ErrHTMLAuditEventV1
	}
	in, finished, err := owner.BeginPublicationV1(p.ID)
	if err != nil {
		return err
	}
	eventID := p.ID
	docID := in.DocumentID
	e := audit.Entry{OrgID: in.OrgID, DocumentID: &docID, RecipientID: ownedHTMLUUIDV1(in.RecipientID), ActorUserID: ownedHTMLUUIDV1(in.ActorUserID), Kind: in.Kind, IP: in.IP, UserAgent: in.UserAgent, Payload: in.Payload}
	// The owned producer already detached all values; detach pointer identities
	// again at dispatch to preserve the same invariant if caller reused audit.Entry.
	if e.DocumentID != nil {
		id := *e.DocumentID
		e.DocumentID = &id
	}
	if e.RecipientID != nil {
		id := *e.RecipientID
		e.RecipientID = &id
	}
	if e.ActorUserID != nil {
		id := *e.ActorUserID
		e.ActorUserID = &id
	}
	l.PublishJoinedV1(audit.PendingEvent{ID: eventID, Entry: e}, finished)
	return nil
}

func ownedHTMLUUIDV1(in pgtype.UUID) *uuid.UUID {
	if !in.Valid {
		return nil
	}
	id := uuid.UUID(in.Bytes)
	return &id
}

func ownedHTMLPgUUIDV1(in *uuid.UUID) pgtype.UUID {
	if in == nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: *in, Valid: true}
}
func ownedHTMLTextV1(in string) pgtype.Text {
	if in == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: in, Valid: true}
}

// Exact original audit.nextAuditTimestamp normalization/order contract.
func ownedAuditTimestampV1(candidate, previous time.Time) time.Time {
	candidate = candidate.UTC().Truncate(time.Microsecond)
	previous = previous.UTC().Truncate(time.Microsecond)
	if !candidate.After(previous) {
		return previous.Add(time.Microsecond)
	}
	return candidate
}
