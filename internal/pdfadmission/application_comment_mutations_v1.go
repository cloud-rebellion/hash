// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type applicationCommentMutationV1 struct {
	request                     *applicationCommentRequestV1
	recipient                   *generated.Recipient
	row                         *generated.DocumentComment
	notifications               *applicationCommentNotificationsV1
	recipientReads              int
	created, done, evidenceRead bool
}

// This actual dual borrower spans commit, physical SQL close, notification
// delivery and HTTP response serialization. The outer result owns its release.
func (w *ApplicationHTMLSendWorkV1) BeginCommentMutationV1(call context.Context, h *ApplicationCommentRequestV1) (func(), error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, ErrCommentRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	purpose := HTMLStaffCommentMutationV1
	if s.signer {
		purpose = HTMLSignerCommentMutationV1
	}
	if !w.valid(call) || w.comment != nil || w.stage == nil || w.stage.purpose != purpose || w.familyRoot != nil || w.sourceDocument == nil || s.self != s || s.consumerClosed || s.closed || s.bound || s.grant == nil || s.inputRelease == nil || s.ctx == nil || s.ctx.Err() != nil || w.stage.operation != s.operation || w.stage.operation.factory != s.factory || w.sourceDocument.ID != s.document || w.sourceDocument.OrgID != s.org {
		return nil, ErrCommentRequestV1
	}
	raw := int64(2*unsafe.Sizeof(applicationCommentMutationV1{}) + 2*unsafe.Sizeof(generated.CreateCommentParams{}) + 2*unsafe.Sizeof(generated.GetRecipientForShareParams{}) + 2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Params{}) + 8*unsafe.Sizeof(sync.Once{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	w.comment = &applicationCommentMutationV1{request: s}
	s.bound = true
	s.active++
	w.sourceBorrowers++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			w.mu.Lock()
			w.comment.done = true
			w.sourceBorrowers--
			s.active--
			closes, actor := w.retireSourcesLockedV1()
			retire := s.retireLockedV1()
			w.mu.Unlock()
			s.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			if retire != nil {
				retire()
			}
		})
	}, nil
}
func (w *ApplicationHTMLSendWorkV1) commentRequestV1() *applicationCommentRequestV1 {
	if w == nil || w.self != w {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.comment == nil || w.comment.done {
		return nil
	}
	return w.comment.request
}
func (w *ApplicationHTMLSendWorkV1) validCommentLockedV1(call context.Context) bool {
	m := w.comment
	return w.valid(call) && m != nil && !m.done && m.request != nil && m.request.ctx != nil && m.request.ctx.Err() == nil && w.sourceDocument != nil && w.stage != nil && w.stage.operation == m.request.operation
}

func (w *ApplicationHTMLSendWorkV1) ReadSignerCommentRecipientV1(call context.Context) (*generated.Recipient, error) {
	s := w.commentRequestV1()
	if s == nil {
		return nil, ErrCommentRequestV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	m := w.comment
	if !w.validCommentLockedV1(call) || !s.signer || s.consumerClosed || s.closed || m.recipientReads >= 2 {
		return nil, ErrCommentRequestV1
	}
	m.recipientReads++
	h, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: s.document, OrgID: s.org, RecipientID: s.recipient, TokenHash: s.hash[:]})
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != s.document || h.OrgID != s.org || h.RecipientID != s.recipient || !bytes.Equal(h.MagicTokenHash, s.hash[:]) || h.RawTextBytes < 0 {
		return nil, ErrCommentRequestV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, h.RawTextBytes, h.RawTextBytes)
	if err != nil {
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.GetRecipientForShare(call, generated.GetRecipientForShareParams{ID: s.recipient, DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != s.recipient || row.DocumentID != s.document || !bytes.Equal(row.MagicTokenHash, s.hash[:]) || row.MagicTokenExpiresAt != h.MagicTokenExpiresAt {
		return nil, ErrCommentRequestV1
	}
	raw, err := htmlAuthoringSumV1(int64(len(row.Role)), int64(len(row.Email)), int64(len(row.Name)), int64(len(row.Status)), int64(len(row.Locale)), int64(len(row.MagicTokenHash)), signerTextBytesV1(row.DeclinedReason), int64(len(w.sourceDocument.Status)))
	if err != nil || raw != h.RawTextBytes {
		return nil, ErrCommentRequestV1
	}
	m.recipient = htmlSendCloneRecipientV1(row)
	return row, nil
}

// Body, author, identity and side derive only from the private bound request
// and the actual native locked models. There is no caller parameter/cost API.
func (w *ApplicationHTMLSendWorkV1) CreateCommentV1(call context.Context) (*generated.DocumentComment, error) {
	if w == nil || w.self != w {
		return nil, ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || w.comment.created {
		return nil, ErrCommentRequestV1
	}
	m, s := w.comment, w.comment.request
	m.created = true
	name, side := "", "sender"
	recipient, user := pgtype.UUID{}, pgtype.UUID{}
	if s.signer {
		if m.recipient == nil || m.recipient.ID != s.recipient {
			return nil, ErrCommentRequestV1
		}
		name, side = m.recipient.Name, "signer"
		recipient = pgtype.UUID{Bytes: s.recipient, Valid: true}
	} else {
		if w.sourceActor == nil || w.sourceActor.ID != s.user || w.sourceActor.OrgID != s.org {
			return nil, ErrCommentRequestV1
		}
		name = w.sourceActor.Name
		if name == "" {
			name = w.sourceActor.Email
		}
		user = pgtype.UUID{Bytes: s.user, Valid: true}
	}
	text, err := htmlAuthoringSumV1(int64(len(name)), int64(len(side)), int64(len(s.body)))
	if err != nil {
		return nil, err
	}
	// Actual returned strings, detached private row, response UUID/time strings,
	// concrete DTO/result controls and sixfold JSON escaping before INSERT.
	// The fixed five-key evidence map, interface boxes, UUID/digest/time encodings
	// and transient encoding scratch are also prepaid here, before their producer
	// runs. The later audit consumer still prices its own retained append copies.
	raw := int64(4*unsafe.Sizeof(generated.DocumentComment{}) + 4*unsafe.Sizeof(generated.CreateCommentParams{}) + 32*unsafe.Sizeof("") + 8*unsafe.Sizeof(sync.Once{}) + 512 + 4*unsafe.Sizeof(CommentAuditEvidenceV1{}) + 2048)
	if !htmlInputAddV1(&raw, text, 8) {
		return nil, ErrCommentRequestV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, text)
	if err != nil {
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.CreateComment(call, generated.CreateCommentParams{DocumentID: s.document, RecipientID: recipient, UserID: user, AuthorName: name, AuthorSide: side, Body: s.body})
	if err != nil {
		return nil, err
	}
	if !commentPersistedRowMatchesV1(row, generated.CreateCommentParams{DocumentID: s.document, RecipientID: recipient, UserID: user, AuthorName: name, AuthorSide: side, Body: s.body}) {
		return nil, ErrCommentRequestV1
	}
	own := *row
	own.AuthorName = strings.Clone(row.AuthorName)
	own.AuthorSide = strings.Clone(row.AuthorSide)
	own.Body = strings.Clone(row.Body)
	m.row = &own
	return row, nil
}

// This suite includes paused ceremonies and every recipient role. Only the
// notification selector later applies CanRespond; no signing/HTML predicate.
func (w *ApplicationHTMLSendWorkV1) ReadStaffCommentRecipientsV1(call context.Context) ([]*generated.Recipient, error) {
	if w == nil || w.self != w {
		return nil, ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || w.comment.request.signer || w.sourceActor == nil || w.models == nil || w.recipientsAttempted {
		return nil, ErrCommentRequestV1
	}
	w.recipientsAttempted = true
	doc, org := w.logicalDocumentV1(), w.session.state.org
	params := generated.GetCommentRecipientReadHeaderV1Params{DocumentID: doc, OrgID: org}
	h, err := w.queries.GetCommentRecipientReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if h == nil || h.DocumentID != doc || h.OrgID != org || h.RecipientCount < 0 || h.RecipientRawBytes < 0 || h.ServerVersionNum <= 0 || h.ServerVersionNum != w.sourceServerVersion {
		return nil, ErrCommentRequestV1
	}
	// Cost encoding from this ACTUAL header, not synthetic measurement fields.
	// The existing retained-body class charges8*raw+16*wire+fixed;4*N wire
	// covers64*N row staging, and full model+UUID costs cover body/pin copies.
	raw, wire := h.RecipientRawBytes, int64(0)
	if !htmlInputAddV1(&raw, h.RecipientCount, int64(unsafe.Sizeof(generated.Recipient{}))+int64(unsafe.Sizeof(uuid.UUID{}))) || !htmlInputAddV1(&wire, h.RecipientCount, 4) {
		return nil, ErrCommentRequestV1
	}
	fixed := int64(2*unsafe.Sizeof(generated.GetCommentRecipientReadHeaderV1Row{}) + unsafe.Sizeof(generated.LockCommentRecipientRowsV1Row{}) + 2*unsafe.Sizeof(generated.GetCommentRecipientReadHeaderV1Params{}) + unsafe.Sizeof(generated.LockCommentRecipientRowsV1Params{}) + unsafe.Sizeof(generated.ListCommentRecipientsV1Params{}) + 2*unsafe.Sizeof([]*generated.Recipient(nil)))
	if !htmlInputAddV1(&raw, fixed, 1) {
		return nil, ErrCommentRequestV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return nil, errors.Join(ErrCommentRequestV1, err)
	}
	w.closes = append(w.closes, closeRows)
	pins, err := w.queries.LockCommentRecipientRowsV1(call, generated.LockCommentRecipientRowsV1Params{DocumentID: doc, OrgID: org})
	if err != nil {
		return nil, err
	}
	if pins == nil || pins.DocumentID != doc || pins.OrgID != org || pins.RecipientCount != h.RecipientCount {
		return nil, ErrCommentRequestV1
	}
	fresh, err := w.queries.GetCommentRecipientReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *h {
		return nil, ErrCommentRequestV1
	}
	rows, err := w.queries.ListCommentRecipientsV1(call, generated.ListCommentRecipientsV1Params{DocumentID: doc, OrgID: org, ExpectedCount: h.RecipientCount, ExpectedRawBytes: h.RecipientRawBytes})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != h.RecipientCount {
		return nil, ErrCommentRequestV1
	}
	actual := int64(0)
	for _, row := range rows {
		if row == nil || row.DocumentID != doc {
			return nil, ErrCommentRequestV1
		}
		n, e := htmlAuthoringSumV1(int64(len(row.Role)), int64(len(row.Email)), int64(len(row.Name)), int64(len(row.Status)), int64(len(row.Locale)), signerTextBytesV1(row.DeclinedReason), int64(len(row.MagicTokenHash)))
		if e != nil || !htmlInputAddV1(&actual, n, 1) {
			return nil, ErrCommentRequestV1
		}
	}
	if actual != h.RecipientRawBytes {
		return nil, ErrCommentRequestV1
	}
	w.sourceRecipients = make([]*generated.Recipient, len(rows))
	for i, row := range rows {
		w.sourceRecipients[i] = htmlSendCloneRecipientV1(row)
	}
	w.models.Recipients = rows
	w.recipientsRead = true
	return rows, nil
}

// This projection is evidence metadata, never a new mutation credential. Only
// the actual bound Work can derive it from its independently owned INSERT row.
const CommentAuditEvidenceSchemaV1 = "hash-comment-evidence-v1"

type CommentAuditEvidenceV1 struct {
	CommentID  uuid.UUID
	BodySHA256 [32]byte
	CreatedAt  pgtype.Timestamptz
	Side       string
}

func commentPersistedRowMatchesV1(row *generated.DocumentComment, intended generated.CreateCommentParams) bool {
	return row != nil && row.ID != uuid.Nil && row.DocumentID == intended.DocumentID && row.RecipientID == intended.RecipientID && row.UserID == intended.UserID && row.AuthorName == intended.AuthorName && row.AuthorSide == intended.AuthorSide && row.Body == intended.Body && applicationStampV1(row.CreatedAt) && row.CreatedAt.Time.Nanosecond()%1000 == 0
}
func (w *ApplicationHTMLSendWorkV1) CommentAuditEvidenceV1(call context.Context) (CommentAuditEvidenceV1, error) {
	var empty CommentAuditEvidenceV1
	if w == nil || w.self != w {
		return empty, ErrCommentRequestV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validCommentLockedV1(call) || !w.comment.created || w.comment.evidenceRead || w.comment.row == nil {
		return empty, ErrCommentRequestV1
	}
	m, s := w.comment, w.comment.request
	row := m.row
	if row.DocumentID != s.document || row.ID == uuid.Nil || row.Body != s.body || !applicationStampV1(row.CreatedAt) || row.CreatedAt.Time.Nanosecond()%1000 != 0 {
		return empty, ErrCommentRequestV1
	}
	if s.signer {
		if m.recipient == nil || m.recipient.ID != s.recipient || row.RecipientID != (pgtype.UUID{Bytes: s.recipient, Valid: true}) || row.UserID.Valid || row.AuthorSide != "signer" || row.AuthorName != m.recipient.Name {
			return empty, ErrCommentRequestV1
		}
	} else {
		if w.sourceActor == nil || w.sourceActor.ID != s.user || w.sourceActor.OrgID != s.org || row.UserID != (pgtype.UUID{Bytes: s.user, Valid: true}) || row.RecipientID.Valid || row.AuthorSide != "sender" {
			return empty, ErrCommentRequestV1
		}
		name := w.sourceActor.Name
		if name == "" {
			name = w.sourceActor.Email
		}
		if row.AuthorName != name {
			return empty, ErrCommentRequestV1
		}
	}
	m.evidenceRead = true
	// The original CreateComment loan covers hash scratch and this fixed result.
	stamp := row.CreatedAt
	stamp.Time = stamp.Time.UTC().Truncate(time.Microsecond)
	return CommentAuditEvidenceV1{CommentID: row.ID, BodySHA256: sha256.Sum256([]byte(row.Body)), CreatedAt: stamp, Side: row.AuthorSide}, nil
}
