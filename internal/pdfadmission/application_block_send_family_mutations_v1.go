// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"fmt"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type blockSendFamilyMutationKindV1 uint8

const (
	blockSendFamilyBeginV1 blockSendFamilyMutationKindV1 = iota + 1
	blockSendFamilyCompleteV1
	blockSendFamilyExpireV1
)

// One fixed family mutation continuation belongs to this actual phase only.
// Completed rows are independent private clones; neither caller-returned rows
// nor mutation results replace the old source tuples used by native validation.
type blockSendFamilyMutationsV1 struct {
	root                                                                                 *ApplicationHTMLSendWorkV1
	members                                                                              []*ApplicationHTMLSendWorkV1
	completedRows                                                                        []*generated.Document
	completedRoot                                                                        *generated.Document
	completedOrder                                                                       []int
	active, beginAttempted, completeAttempted, expireAttempted, completeDone, expireDone bool
}

// Parent integration requires only root Work.familyMutations of the above type
// and Work.completedDocument: the genuine CompleteDocumentSendV1 returned pointer,
// installed after exact validation. That pointer must equal the caller argument
// AND the separately retained native post-completion source clone must match it.
// The old source-owner snapshot remains independently retained and unchanged.
func (w *ApplicationHTMLSendWorkV1) startFamilyMutationV1(call context.Context, kind blockSendFamilyMutationKindV1, sentRoot *generated.Document) (*blockSendFamilyMutationsV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.familyRoot != nil || w.memberDocument != uuid.Nil ||
		!w.familyMembersAttempted || len(w.familyMembers) == 0 || w.state == nil ||
		!w.state.IsEnvelope || w.state.ParentEnvelopeID.Valid || w.sourceDocument == nil ||
		!w.sourceDocument.IsEnvelope || w.sourceDocument.ParentEnvelopeID.Valid {
		return nil, ErrHTMLSendWorkV1
	}
	switch kind {
	case blockSendFamilyBeginV1:
		if w.stage.purpose != HTMLSendAdmissionV1 || !w.intentCreated || w.sourceDocument.Status != "draft" {
			return nil, ErrHTMLSendWorkV1
		}
	case blockSendFamilyCompleteV1:
		if w.stage.purpose != HTMLSendCompletionV1 || !w.completedAttempted ||
			sentRoot == nil || w.completedDocument != sentRoot ||
			!htmlSendDocumentExactTupleEqualV1(w.sourceDocument, sentRoot) ||
			sentRoot.Status != "sent" || !sentRoot.SentAt.Valid ||
			sentRoot.SentAt != sentRoot.Article13NoticeEpochAt ||
			sentRoot.Article13NoticeSchema == "" || !sentRoot.Article13NoticeEpochV61Committed {
			return nil, ErrHTMLSendWorkV1
		}
	case blockSendFamilyExpireV1:
		if w.stage.purpose != HTMLSendCompletionV1 || !w.expiredAttempted ||
			w.sourceDocument.Status != "expired" {
			return nil, ErrHTMLSendWorkV1
		}
	default:
		return nil, ErrHTMLSendWorkV1
	}
	state := w.familyMutations
	if state == nil {
		n := int64(len(w.familyMembers))
		// All fixed per-operation slice/return bookkeeping is admitted before make.
		// Expanded RETURNING rows and independent clones are additionally priced by
		// EACH actual member's native admitDocumentReturnV1, before any mutation SQL.
		raw := 2 * int64(unsafe.Sizeof(blockSendFamilyMutationsV1{}))
		per := 8*int64(unsafe.Sizeof((*generated.Document)(nil))) +
			8*int64(unsafe.Sizeof(int(0))) + 8*int64(unsafe.Sizeof(false)) +
			4*int64(unsafe.Sizeof(uuid.UUID{}))
		if !htmlInputAddV1(&raw, n, per) {
			return nil, ErrHTMLSendWorkV1
		}
		closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
		if err != nil {
			return nil, err
		}
		w.closes = append(w.closes, closeBody)
		state = &blockSendFamilyMutationsV1{root: w, members: w.familyMembers,
			completedRows:  make([]*generated.Document, len(w.familyMembers)),
			completedOrder: make([]int, len(w.familyMembers))}
		w.familyMutations = state
	}
	if state.root != w || state.active || len(state.members) != len(w.familyMembers) {
		return nil, ErrHTMLSendWorkV1
	}
	for i, m := range state.members {
		if m != w.familyMembers[i] {
			return nil, ErrHTMLSendWorkV1
		}
	}
	switch kind {
	case blockSendFamilyBeginV1:
		if state.beginAttempted {
			return nil, ErrHTMLSendWorkV1
		}
		state.beginAttempted = true
	case blockSendFamilyCompleteV1:
		if state.completeAttempted {
			return nil, ErrHTMLSendWorkV1
		}
		state.completeAttempted = true
		state.completedRoot = w.sourceDocument // actual private completed clone, never caller data
	case blockSendFamilyExpireV1:
		if state.expireAttempted || !state.completeDone {
			return nil, ErrHTMLSendWorkV1
		}
		state.expireAttempted = true
	}
	state.active = true
	w.sourceBorrowers++ // original synchronous mutation/verification continuation
	return state, nil
}

func (w *ApplicationHTMLSendWorkV1) finishFamilyMutationV1(state *blockSendFamilyMutationsV1, borrowed []bool) {
	for i, m := range state.members {
		if !borrowed[i] {
			continue
		}
		m.mu.Lock()
		m.sourceBorrowers--
		closes, actor := m.retireSourcesLockedV1()
		m.mu.Unlock()
		htmlSendCloseSourceResourcesV1(closes, actor)
		m.releaseFamilyRootIfRetiredV1()
	}
	w.mu.Lock()
	state.active = false
	w.sourceBorrowers--
	closes, actor := w.retireSourcesLockedV1()
	w.mu.Unlock()
	htmlSendCloseSourceResourcesV1(closes, actor)
	w.releaseFamilyRootIfRetiredV1()
}

func (w *ApplicationHTMLSendWorkV1) prepareFamilyMutationV1(call context.Context, state *blockSendFamilyMutationsV1, kind blockSendFamilyMutationKindV1, sentRoot *generated.Document, borrowed []bool, raws []int64) error {
	for i, m := range state.members {
		if m == nil || m == w || m.self != m {
			return ErrHTMLSendWorkV1
		}
		m.mu.Lock()
		if !m.valid(call) || m.familyRoot != w || m.sourceDocument == nil ||
			m.logicalDocumentV1() != m.sourceDocument.ID ||
			!m.sourceDocument.ParentEnvelopeID.Valid ||
			uuid.UUID(m.sourceDocument.ParentEnvelopeID.Bytes) != w.session.state.document ||
			m.sourceDocument.OrgID != w.session.state.org {
			m.mu.Unlock()
			return ErrHTMLSendWorkV1
		}
		m.sourceBorrowers++
		borrowed[i] = true
		before := m.sourceDocument
		extra := int64(0)
		switch kind {
		case blockSendFamilyBeginV1:
			if before.Status != "draft" {
				m.mu.Unlock()
				return ErrHTMLSendWorkV1
			}
			extra = int64(len("sealing"))
		case blockSendFamilyCompleteV1:
			if before.Status != "sealing" || sentRoot == nil {
				m.mu.Unlock()
				return ErrHTMLSendWorkV1
			}
			extra = int64(len("sent") + len(sentRoot.Article13NoticeSchema))
		case blockSendFamilyExpireV1:
			before = state.completedRows[i]
			if before == nil {
				m.mu.Unlock()
				return ErrHTMLSendWorkV1
			}
			switch before.Status {
			case "expired":
				m.mu.Unlock()
				continue
			case "sent", "in_progress":
			default:
				m.mu.Unlock()
				return fmt.Errorf("expire envelope: child %s has incompatible status %s", before.ID, before.Status)
			}
			// This native member's original source is sealing; the independently owned
			// completed row also contains the actual copied root Article13 schema.
			extra = int64(len("expired") + len(before.Article13NoticeSchema))
		default:
			m.mu.Unlock()
			return ErrHTMLSendWorkV1
		}
		raw, _, err := m.admitDocumentReturnV1(call, extra)
		if err != nil {
			m.mu.Unlock()
			return err
		}
		raws[i] = raw
		m.mu.Unlock()
	}
	return nil
}

func (w *ApplicationHTMLSendWorkV1) BeginEnvelopeMembersSealingV1(call context.Context) error {
	state, err := w.startFamilyMutationV1(call, blockSendFamilyBeginV1, nil)
	if err != nil {
		return err
	}
	borrowed := make([]bool, len(state.members))
	defer w.finishFamilyMutationV1(state, borrowed)
	raws := make([]int64, len(state.members))
	seen := make([]bool, len(state.members))
	if err = w.prepareFamilyMutationV1(call, state, blockSendFamilyBeginV1, nil, borrowed, raws); err != nil {
		return err
	}
	// EVERY real full-row return is now owned before this single atomic SQL write.
	rows, err := w.queries.BeginEnvelopeChildrenSendSealing(call, generated.BeginEnvelopeChildrenSendSealingParams{
		ParentEnvelopeID: pgtype.UUID{Bytes: w.session.state.document, Valid: true}, OrgID: w.session.state.org,
	})
	if err != nil {
		return err
	}
	if len(rows) != len(state.members) {
		return fmt.Errorf("seal envelope children: updated %d of %d", len(rows), len(state.members))
	}
	for _, row := range rows {
		index := blockSendFamilyReturnedIndexV1(state.members, row)
		if index < 0 || seen[index] {
			return ErrHTMLSendWorkV1
		}
		m := state.members[index]
		if !m.verifyDocumentReturnV1(row, raws[index]) || !blockSendFamilyBeginTupleV1(m.sourceDocument, row) {
			return ErrHTMLSendWorkV1
		}
		seen[index] = true
	}
	return nil
}

func (w *ApplicationHTMLSendWorkV1) CompleteEnvelopeMembersSealingV1(call context.Context, sentRoot *generated.Document) ([]*generated.Document, error) {
	state, err := w.startFamilyMutationV1(call, blockSendFamilyCompleteV1, sentRoot)
	if err != nil {
		return nil, err
	}
	borrowed := make([]bool, len(state.members))
	defer w.finishFamilyMutationV1(state, borrowed)
	raws := make([]int64, len(state.members))
	seen := make([]bool, len(state.members))
	if err = w.prepareFamilyMutationV1(call, state, blockSendFamilyCompleteV1, state.completedRoot, borrowed, raws); err != nil {
		return nil, err
	}
	rows, err := w.queries.CompleteEnvelopeChildrenSendSealing(call, generated.CompleteEnvelopeChildrenSendSealingParams{
		ParentEnvelopeID: pgtype.UUID{Bytes: w.session.state.document, Valid: true}, OrgID: w.session.state.org,
	})
	if err != nil {
		return nil, err
	}
	if len(rows) != len(state.members) {
		return nil, fmt.Errorf("complete envelope child send sealing: updated %d of %d", len(rows), len(state.members))
	}
	for at, row := range rows {
		index := blockSendFamilyReturnedIndexV1(state.members, row)
		if index < 0 || seen[index] {
			return nil, ErrHTMLSendWorkV1
		}
		m := state.members[index]
		if !m.verifyDocumentReturnV1(row, raws[index]) || !blockSendFamilyCompleteTupleV1(m.sourceDocument, row, state.completedRoot) {
			return nil, ErrHTMLSendWorkV1
		}
		seen[index] = true
		state.completedRows[index] = htmlSendCloneDocumentV1(row)
		state.completedOrder[at] = index // preserve the actual SQL return order for expiry
	}
	state.completeDone = true
	return rows, nil
}

func (w *ApplicationHTMLSendWorkV1) ExpireEnvelopeMembersV1(call context.Context) ([]uuid.UUID, error) {
	state, err := w.startFamilyMutationV1(call, blockSendFamilyExpireV1, nil)
	if err != nil {
		return nil, err
	}
	borrowed := make([]bool, len(state.members))
	defer w.finishFamilyMutationV1(state, borrowed)
	raws := make([]int64, len(state.members))
	// Validate every child and admit ALL prospective return rows before the first
	// update. No child's individual expiry can prevent root expiry propagation.
	if err = w.prepareFamilyMutationV1(call, state, blockSendFamilyExpireV1, nil, borrowed, raws); err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(state.members))
	for _, index := range state.completedOrder {
		before := state.completedRows[index]
		if before.Status == "expired" {
			continue
		}
		row, err := w.queries.SetDocumentStatus(call, generated.SetDocumentStatusParams{
			ID: before.ID, OrgID: before.OrgID, Status: "expired",
		})
		if err != nil {
			return nil, fmt.Errorf("expire envelope child %s: %w", before.ID, err)
		}
		m := state.members[index]
		if !m.verifyDocumentReturnV1(row, raws[index]) || !blockSendFamilyExpireTupleV1(before, row) {
			return nil, fmt.Errorf("expire envelope child %s: transition returned invalid state", before.ID)
		}
		ids = append(ids, before.ID)
	}
	state.expireDone = true
	return ids, nil
}

// Native membership is immutable for this root callback. Linear lookup avoids
// an unpriced map; exact cardinality plus seen[] rejects missing/duplicate IDs.
func blockSendFamilyReturnedIndexV1(members []*ApplicationHTMLSendWorkV1, row *generated.Document) int {
	if row == nil {
		return -1
	}
	for i, m := range members {
		if m != nil && m.sourceDocument != nil && m.sourceDocument.ID == row.ID {
			return i
		}
	}
	return -1
}
func blockSendFamilyBeginTupleV1(before, after *generated.Document) bool {
	if before == nil || after == nil || before.Status != "draft" || after.Status != "sealing" {
		return false
	}
	expected := *before
	expected.Status = after.Status
	expected.UpdatedAt = after.UpdatedAt
	return htmlSendDocumentExactTupleEqualV1(&expected, after)
}
func blockSendFamilyCompleteTupleV1(before, after, root *generated.Document) bool {
	if before == nil || after == nil || root == nil || before.Status != "sealing" || after.Status != "sent" ||
		!before.ParentEnvelopeID.Valid || uuid.UUID(before.ParentEnvelopeID.Bytes) != root.ID ||
		before.OrgID != root.OrgID || !root.IsEnvelope || root.ParentEnvelopeID.Valid ||
		root.Status != "sent" || !root.SentAt.Valid || root.SentAt != root.Article13NoticeEpochAt ||
		root.Article13NoticeSchema == "" || !root.Article13NoticeEpochV61Committed ||
		after.SentAt != root.SentAt || after.Article13NoticeEpochAt != root.Article13NoticeEpochAt ||
		after.Article13NoticeSchema != root.Article13NoticeSchema || !after.Article13NoticeEpochV61Committed {
		return false
	}
	expected := *before
	expected.Status = after.Status
	expected.UpdatedAt = after.UpdatedAt
	expected.SentAt = root.SentAt
	expected.Article13NoticeEpochAt = root.Article13NoticeEpochAt
	expected.Article13NoticeSchema = root.Article13NoticeSchema
	expected.Article13NoticeEpochV61Committed = true
	return htmlSendDocumentExactTupleEqualV1(&expected, after)
}
func blockSendFamilyExpireTupleV1(before, after *generated.Document) bool {
	if before == nil || after == nil || (before.Status != "sent" && before.Status != "in_progress") || after.Status != "expired" {
		return false
	}
	expected := *before
	expected.Status = after.Status
	expected.UpdatedAt = after.UpdatedAt
	return htmlSendDocumentExactTupleEqualV1(&expected, after)
}
