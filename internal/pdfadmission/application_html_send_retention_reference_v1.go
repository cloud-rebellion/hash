// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"unsafe"
)

// This purpose-specific scalar projection is not a partial generated model.
// Only a genuine actual private native intent can create one opaque state.
type HTMLSendRetentionProjectionV1 struct {
	DocumentID, OrgID                                                             uuid.UUID
	PresignExecutionID, PackageSendAttemptID                                      pgtype.UUID
	Article13NoticeEpochAt, RetainUntil, RetentionStartedAt, RetentionCompletedAt pgtype.Timestamptz
}
type ApplicationHTMLSendRetentionStateV1 struct {
	owner *applicationHTMLSendRetentionReferenceV1
	index int
}
type applicationHTMLSendRetentionReferenceV1 struct {
	mu        sync.Mutex
	self      *applicationHTMLSendRetentionReferenceV1
	operation *ApplicationHTMLSendOperationV1
	grant     *workguard.GrantV1
	values    [htmlSendMaxSQLStagesV1]HTMLSendRetentionProjectionV1
	states    [htmlSendMaxSQLStagesV1]ApplicationHTMLSendRetentionStateV1
	count     int
	closed    bool
}

func (s *ApplicationHTMLSendRetentionStateV1) SnapshotV1() (HTMLSendRetentionProjectionV1, error) {
	if s == nil || s.owner == nil {
		return HTMLSendRetentionProjectionV1{}, ErrHTMLSendWorkV1
	}
	owner := s.owner
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.self != owner || owner.closed || owner.operation == nil || owner.grant == nil || s.index < 0 || s.index >= owner.count || s != &owner.states[s.index] {
		return HTMLSendRetentionProjectionV1{}, ErrHTMLSendWorkV1
	}
	return owner.values[s.index], nil
}
func (s *applicationHTMLSendRetentionReferenceV1) closeV1() {
	if s == nil || s.self != s {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	grant := s.grant
	s.grant = nil
	s.operation = nil
	s.values = [htmlSendMaxSQLStagesV1]HTMLSendRetentionProjectionV1{}
	s.mu.Unlock()
	if grant != nil {
		grant.Close()
	}
}

// The array size is the existing immutable maximum16 SQL stages, not added
// capacity. Its genuine Parent-only grant funds all fixed scalar view headers
// before allocation; copied values contain no variable string/JSON/DB body.
func (w *ApplicationHTMLSendWorkV1) CaptureSendRetentionStateV1(call context.Context) (*ApplicationHTMLSendRetentionStateV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLSendIntentReadV1 || w.stage.operation == nil || !w.intentRead || w.sourceIntent == nil {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	intent := w.sourceIntent
	op := w.stage.operation
	if intent.PackageSendAttemptID.Valid {
		w.mu.Unlock()
		return nil, ErrHTMLSendPackagePathRequiredV1
	}
	if intent.DocumentID != op.document || intent.OrgID != op.org {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	value := HTMLSendRetentionProjectionV1{DocumentID: intent.DocumentID, OrgID: intent.OrgID, PresignExecutionID: intent.PresignExecutionID, PackageSendAttemptID: intent.PackageSendAttemptID, Article13NoticeEpochAt: intent.Article13NoticeEpochAt, RetainUntil: intent.RetainUntil, RetentionStartedAt: intent.RetentionStartedAt, RetentionCompletedAt: intent.RetentionCompletedAt}
	value.Article13NoticeEpochAt.Time = value.Article13NoticeEpochAt.Time.UTC()
	value.RetainUntil.Time = value.RetainUntil.Time.UTC()
	value.RetentionStartedAt.Time = value.RetentionStartedAt.Time.UTC()
	value.RetentionCompletedAt.Time = value.RetentionCompletedAt.Time.UTC()
	w.mu.Unlock()
	op.mu.Lock()
	defer op.mu.Unlock()
	if op.closed || op.original == nil || op.original.Err() != nil || op.factory == nil || op.factory.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	owner := op.retentionReference
	if owner == nil {
		factory := op.factory.state
		factory.mu.Lock()
		available := !factory.closing && factory.work != nil && factory.work.coordinator != nil
		var coordinator *workguard.CoordinatorV1
		if available {
			coordinator = factory.work.coordinator
		}
		factory.mu.Unlock()
		if !available {
			return nil, ErrHTMLSendWorkV1
		}
		fixed := 8 * (int64(unsafe.Sizeof(applicationHTMLSendRetentionReferenceV1{})) + 2*int64(unsafe.Sizeof(workguard.GrantV1{})) + 8*int64(unsafe.Sizeof(uintptr(0))))
		grant, err := coordinator.TryAcquireV1(op.original, op.org, workguard.VectorV1{ParentBytes: fixed})
		if err != nil {
			return nil, err
		}
		owner = &applicationHTMLSendRetentionReferenceV1{operation: op, grant: grant}
		owner.self = owner
		op.retentionReference = owner
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.self != owner || owner.closed || owner.operation != op || owner.count >= len(owner.values) {
		return nil, ErrHTMLSendWorkV1
	}
	index := owner.count
	owner.count++
	owner.values[index] = value
	owner.states[index] = ApplicationHTMLSendRetentionStateV1{owner: owner, index: index}
	return &owner.states[index], nil
}
