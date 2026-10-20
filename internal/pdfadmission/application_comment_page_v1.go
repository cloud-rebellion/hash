// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/commentwindow"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type CommentPageEntryV1 struct {
	ID         string `json:"id"`
	AuthorName string `json:"author_name"`
	AuthorSide string `json:"author_side"`
	Body       string `json:"body"`
	CreatedAt  string `json:"created_at"`
}

type CommentPageResponseV1 struct {
	Comments    []CommentPageEntryV1 `json:"comments"`
	OlderCursor *string              `json:"older_cursor"`
	NewerCursor *string              `json:"newer_cursor"`
}

type commentPageHeaderV1 = generated.ListLatestCommentWindowHeadersV1Row

// Scalar credential preflight under the SAME actual parent/recipient locks.
// Core still validates the original deadline and repeats full current policy
// on its original opaque lease before publishing any response.
func (w *ApplicationHTMLSendWorkV1) ReadCommentPageCredentialV1(call context.Context, recipient uuid.UUID, hash [32]byte) (ApplicationSignerReadAccessV1, error) {
	if w == nil || w.self != w {
		return ApplicationSignerReadAccessV1{}, ErrCommentPageV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil || w.commentPageCredentialRead || w.stage == nil || w.stage.purpose != HTMLSignerCommentReadV1 || recipient == uuid.Nil {
		return ApplicationSignerReadAccessV1{}, ErrCommentPageV1
	}
	w.commentPageCredentialRead = true
	fixed := int64(2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Row{}) + 2*unsafe.Sizeof(generated.GetSignerRecipientReadHeaderV1Params{}) + 2*unsafe.Sizeof(ApplicationSignerReadAccessV1{}) + 128)
	closeHeader, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return ApplicationSignerReadAccessV1{}, errors.Join(ErrCommentPageV1, err)
	}
	w.closes = append(w.closes, closeHeader)
	h, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org, RecipientID: recipient, TokenHash: hash[:]})
	if err != nil {
		return ApplicationSignerReadAccessV1{}, err
	}
	if h == nil || h.DocumentID != w.logicalDocumentV1() || h.OrgID != w.session.state.org || h.RecipientID != recipient || !bytes.Equal(h.MagicTokenHash, hash[:]) {
		return ApplicationSignerReadAccessV1{}, ErrSignerReadCredentialV1
	}
	status := w.state.BoundedStatus
	return ApplicationSignerReadAccessV1{DocumentExpiresAt: w.state.ExpiresAt, RecipientExpiresAt: h.MagicTokenExpiresAt, ActiveCeremony: status == "sent" || status == "in_progress" || status == "changes_requested"}, nil
}

func compareCommentPageHeadersV1(a, b *commentPageHeaderV1) int {
	if !a.CreatedAt.Time.Equal(b.CreatedAt.Time) {
		if a.CreatedAt.Time.Before(b.CreatedAt.Time) {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.ID[:], b.ID[:])
}

// This is a materialization/resource owner, never an authorization boundary.
// Core must retain the actual public lease or locked staff session policy and
// run its final checks before publishing this body's headers. The native parent
// and exact selected rows stay locked until read commit. No pool fallback exists.
func (w *ApplicationHTMLSendWorkV1) ReadCommentPageV1(call context.Context, selection commentwindow.Selection) (body []byte, finish func(), failure error) {
	if w == nil || w.self != w {
		return nil, nil, ErrCommentPageV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil || w.commentPageRead || w.familyRoot != nil || w.stage == nil || (w.stage.purpose != HTMLSignerCommentReadV1 && w.stage.purpose != HTMLStaffCommentReadV1) {
		return nil, nil, ErrCommentPageV1
	}
	org, document := w.session.state.org, w.logicalDocumentV1()
	direction, at, id, err := selection.ForScope(org, document)
	if err != nil {
		return nil, nil, err
	}
	w.commentPageRead = true
	// All51 scalar rows, transient generated and normalized pointer arrays,
	// parameters, page/result and release controls precede the roster query.
	fixed := int64(4*unsafe.Sizeof(CommentPageResponseV1{}) + 8*unsafe.Sizeof(sync.Once{}) + unsafe.Sizeof(generated.ReadCommentWindowRowsV1Params{}) + unsafe.Sizeof(generated.GetCommentWindowEdgesV1Params{}) + unsafe.Sizeof(generated.GetCommentWindowEdgesV1Row{}) + 8192)
	perHeader := int64(2*unsafe.Sizeof(generated.ListLatestCommentWindowHeadersV1Row{}) + 2*unsafe.Sizeof(generated.ListOlderCommentWindowHeadersV1Row{}) + 2*unsafe.Sizeof(generated.ListNewerCommentWindowHeadersV1Row{}) + 8*unsafe.Sizeof(uintptr(0)))
	if !htmlInputAddV1(&fixed, commentwindow.Limit+1, perHeader) {
		return nil, nil, ErrCommentPageV1
	}
	closeHeaders, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		return nil, nil, errors.Join(ErrCommentPageV1, err)
	}
	// Header rows are transient. Their actual SQL fence still gates credit.
	defer closeHeaders()
	var headers []*commentPageHeaderV1
	boundary := pgtype.Timestamptz{Time: at, Valid: true}
	switch direction {
	case commentwindow.Latest:
		headers, err = w.queries.ListLatestCommentWindowHeadersV1(call, generated.ListLatestCommentWindowHeadersV1Params{DocumentID: document, OrgID: org})
	case commentwindow.Older:
		var rows []*generated.ListOlderCommentWindowHeadersV1Row
		rows, err = w.queries.ListOlderCommentWindowHeadersV1(call, generated.ListOlderCommentWindowHeadersV1Params{DocumentID: document, OrgID: org, BoundaryAt: boundary, BoundaryID: id})
		headers = make([]*commentPageHeaderV1, len(rows))
		for i, row := range rows {
			headers[i] = (*commentPageHeaderV1)(row)
		}
	case commentwindow.Newer:
		var rows []*generated.ListNewerCommentWindowHeadersV1Row
		rows, err = w.queries.ListNewerCommentWindowHeadersV1(call, generated.ListNewerCommentWindowHeadersV1Params{DocumentID: document, OrgID: org, BoundaryAt: boundary, BoundaryID: id})
		headers = make([]*commentPageHeaderV1, len(rows))
		for i, row := range rows {
			headers[i] = (*commentPageHeaderV1)(row)
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if len(headers) > commentwindow.Limit+1 {
		return nil, nil, ErrCommentPageV1
	}
	for i, h := range headers {
		if h == nil || h.ID == uuid.Nil || h.DocumentID != document || !applicationStampV1(h.CreatedAt) || !h.CreatedAt.Time.Equal(h.CreatedAt.Time.Truncate(time.Microsecond)) || h.AuthorBytes < 0 || h.SideBytes < 0 || h.BodyBytes < 0 {
			return nil, nil, ErrCommentPageV1
		}
		if i > 0 {
			order := compareCommentPageHeadersV1(headers[i-1], h)
			if (direction == commentwindow.Newer && order >= 0) || (direction != commentwindow.Newer && order <= 0) {
				return nil, nil, ErrCommentPageV1
			}
		}
	}
	// The sentinel pays only its fixed metadata. It never causes a text body
	// read/loan and is never a skipped/truncated visible row or cursor boundary.
	if len(headers) > commentwindow.Limit {
		headers = headers[:commentwindow.Limit]
	}
	if direction != commentwindow.Newer {
		slices.Reverse(headers)
	}
	raw, text, upper := int64(0), int64(0), int64(512)
	for _, h := range headers {
		n, err := htmlAuthoringSumV1(h.AuthorBytes, h.SideBytes, h.BodyBytes)
		if err != nil || !htmlInputAddV1(&text, n, 1) {
			return nil, nil, ErrCommentPageV1
		}
	}
	// Stored SQL text, full native rows, concrete DTOs, UUID/time strings,
	// array growth, encoder scratch and worst-case sixfold JSON escaping coexist.
	perRow := int64(4*unsafe.Sizeof(generated.DocumentComment{}) + 4*unsafe.Sizeof(CommentPageEntryV1{}) + 8*unsafe.Sizeof(uintptr(0)) + 4*unsafe.Sizeof(uuid.UUID{}) + 512)
	if !htmlInputAddV1(&raw, text, 4) || !htmlInputAddV1(&raw, int64(len(headers)), perRow) || !htmlInputAddV1(&upper, text, 6) || !htmlInputAddV1(&upper, int64(len(headers)), 512) {
		return nil, nil, ErrCommentPageV1
	}
	controls, err := readJSONRetainedControlBytesV1()
	if err != nil || !htmlInputAddV1(&raw, controls, 1) {
		return nil, nil, ErrCommentPageV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, text)
	if err != nil {
		return nil, nil, errors.Join(ErrCommentPageV1, err)
	}
	// Only independently admitted JSON ownership escapes this producer.
	consumer := &applicationReadJSONConsumerV1{release: closeRows}
	defer func() {
		if failure != nil {
			consumer.CloseConsumerV1()
			body, finish = nil, nil
		}
	}()
	response := CommentPageResponseV1{Comments: make([]CommentPageEntryV1, 0, len(headers))}
	if len(headers) > 0 {
		ids := make([]uuid.UUID, len(headers))
		for i, h := range headers {
			ids[i] = h.ID
		}
		rows, err := w.queries.ReadCommentWindowRowsV1(call, generated.ReadCommentWindowRowsV1Params{DocumentID: document, OrgID: org, CommentIds: ids})
		if err != nil {
			return nil, nil, err
		}
		if len(rows) != len(headers) {
			return nil, nil, ErrCommentPageV1
		}
		for i, row := range rows {
			h := headers[i]
			if row == nil || row.ID != h.ID || row.DocumentID != document || row.CreatedAt != h.CreatedAt || int64(len(row.AuthorName)) != h.AuthorBytes || int64(len(row.AuthorSide)) != h.SideBytes || int64(len(row.Body)) != h.BodyBytes || (row.AuthorSide != "sender" && row.AuthorSide != "signer") {
				return nil, nil, ErrCommentPageV1
			}
			response.Comments = append(response.Comments, CommentPageEntryV1{ID: row.ID.String(), AuthorName: row.AuthorName, AuthorSide: row.AuthorSide, Body: row.Body, CreatedAt: row.CreatedAt.Time.UTC().Format(time.RFC3339Nano)})
		}
		first, last := headers[0], headers[len(headers)-1]
		edges, err := w.queries.GetCommentWindowEdgesV1(call, generated.GetCommentWindowEdgesV1Params{DocumentID: document, OrgID: org, OldestAt: first.CreatedAt, OldestID: first.ID, NewestAt: last.CreatedAt, NewestID: last.ID})
		if err != nil {
			return nil, nil, err
		}
		if edges == nil {
			return nil, nil, ErrCommentPageV1
		}
		if edges.HasOlder {
			cursor, err := commentwindow.Cursor(org, document, first.ID, first.CreatedAt.Time)
			if err != nil {
				return nil, nil, err
			}
			response.OlderCursor = &cursor
		}
		if edges.HasNewer {
			cursor, err := commentwindow.Cursor(org, document, last.ID, last.CreatedAt.Time)
			if err != nil {
				return nil, nil, err
			}
			response.NewerCursor = &cursor
		}
	}
	body, err = json.Marshal(response)
	if err != nil || int64(len(body)) > upper || call.Err() != nil {
		return nil, nil, errors.Join(ErrCommentPageV1, err, call.Err())
	}
	return body, consumer.CloseConsumerV1, nil
}
