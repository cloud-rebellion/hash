// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
)

// ReadRetainedPreSignV1 scans canonical evidence only after the fixed scalar
// measurement and SAME work loan. The actual SQL borrower never escapes.
func (w *ApplicationHTMLSendWorkV1) ReadRetainedPreSignV1(call context.Context) (result presignexecute.RetainedAssetsV1, failure error) {
	stage := "publication_retained_scope"
	defer func() { failure = htmlPreSignPublicationFailureV1(stage, failure) }()
	var out presignexecute.RetainedAssetsV1
	if w == nil || w.self != w {
		return out, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.presignEvidenceAttempted && w.state != nil
	if valid && w.presignRetained != nil {
		out = *w.presignRetained
		w.mu.Unlock()
		return out, nil
	}
	if w.presignRetainedAttempted {
		stage = "publication_retained_repeat"
		w.mu.Unlock()
		return out, ErrHTMLSendWorkV1
	}
	if valid {
		w.presignRetainedAttempted = true
	}
	w.mu.Unlock()
	if !valid {
		return out, ErrHTMLSendWorkV1
	}
	stage = "publication_retained_borrow"
	owned, tx, done, err := applicationSessionSQLBorrowV1(call, w.session.state, true)
	if err != nil {
		return out, err
	}
	defer done()
	stage = "publication_retained_load"
	out, err = presignexecute.LoadRetainedAssetsV1(owned, tx, w.session.state.org, w.logicalDocumentV1())
	done() // The synchronous loader and its Rows have finished; body owners remain held.
	if err != nil {
		return out, err
	}
	stage = "publication_retained_postread"
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) {
		return presignexecute.RetainedAssetsV1{}, ErrHTMLSendWorkV1
	}
	w.presignRetained = &out
	return out, nil
}

// This is one actual native retention run, not a receipt supplied by Send.
// It keeps the original model loan and every actual SDK handle through the
// fresh completing transaction. Close joins active calls before body credit.
type ApplicationPreSignRetentionV1 struct {
	mu                                sync.Mutex
	activity                          applicationJoinedActivityV1
	closed                            atomic.Bool
	self                              *ApplicationPreSignRetentionV1
	work                              *ApplicationHTMLSendWorkV1
	initial                           *ApplicationSessionV1
	retained                          presignexecute.RetainedAssetsV1
	client                            *storage.Client
	coordinator                       *workguard.CoordinatorV1
	pins                              [9]presign.ArtifactPin
	closes                            []func()
	release                           func()
	attempted, retainedAll, completed bool
}

func (w *ApplicationHTMLSendWorkV1) StartPreSignRetentionV1(call context.Context, client *storage.Client) (*ApplicationPreSignRetentionV1, error) {
	if w == nil || w.self != w || client == nil {
		return nil, ErrHTMLSendWorkV1
	}
	r, err := w.ReadRetainedPreSignV1(call)
	if err != nil {
		return nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLPreSignRetentionV1 || w.presignRetention != nil || w.sourceDocument == nil ||
		w.sourceDocument.Status != "sealing" || w.sourceIntent == nil || !w.sourceIntent.PresignExecutionID.Valid ||
		!r.Publication().RetentionCompletedAt.IsZero() || r.Publication().State != "retaining" {
		return nil, ErrHTMLSendWorkV1
	}
	// Both durable markers are changed together before any irreversible request.
	n, err := w.queries.MarkSendSealingRetentionStarted(call, generated.MarkSendSealingRetentionStartedParams{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil || n != 1 {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	tag, err := db.Exec(call, `UPDATE presign_execution_publications_v1 p SET retention_started_at=i.retention_started_at
  FROM send_sealing_intents i WHERE p.org_id=$1 AND p.document_id=$2 AND p.execution_id=$3
  AND i.org_id=p.org_id AND i.document_id=p.document_id AND i.presign_execution_id=p.execution_id
  AND p.state='retaining' AND p.retention_completed_at IS NULL AND i.retention_started_at IS NOT NULL`,
		w.session.state.org, w.logicalDocumentV1(), r.Execution().Snapshot().ID)
	if err != nil || tag.RowsAffected() != 1 {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	factory := w.stage.operation.factory.state
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHTMLSendWorkV1
	}
	// ReadRetained's original body loan survives this work's SQL retirement.
	w.sourceBorrowers++
	var once sync.Once
	release := func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
		})
	}
	h := &ApplicationPreSignRetentionV1{work: w, initial: w.session, retained: r, client: client, coordinator: coordinator, release: release}
	h.self = h
	h.pins[0] = r.Execution().Snapshot().Document.BasePDF.Artifact
	for i, a := range r.Assets().Snapshot().Objects {
		h.pins[i+1] = a.Object
	}
	w.presignRetention = h
	return h, nil
}

func (h *ApplicationPreSignRetentionV1) lockV1() bool {
	if h == nil || h.self != h || !h.activity.enterV1() {
		return false
	}
	h.mu.Lock()
	return true
}
func (h *ApplicationPreSignRetentionV1) unlockV1() {
	h.mu.Unlock()
	if h.activity.leaveV1() {
		h.retireV1()
	}
}
func (h *ApplicationPreSignRetentionV1) retireV1() {
	for _, close := range h.closes {
		close()
	}
	h.closes = nil
	if h.release != nil {
		h.release()
		h.release = nil
	}
	h.work = nil
	h.initial = nil
	h.client = nil
	h.coordinator = nil
	h.retained = presignexecute.RetainedAssetsV1{}
}
func (h *ApplicationPreSignRetentionV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.closed.Store(true)
	if h.activity.closeV1() {
		h.retireV1()
	}
}

func (h *ApplicationPreSignRetentionV1) RetainV1() error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if h.closed.Load() || h.attempted || !preSignKnownCommitV1(h.initial) {
		return ErrHTMLSendWorkV1
	}
	h.attempted = true
	for _, pin := range h.pins {
		digest, err := hex.DecodeString(pin.SHA256)
		if err != nil || len(digest) != 32 {
			return ErrHTMLSendWorkV1
		}
		handle, _, err := h.client.RetainFinalizationEvidenceLocalOwnedV1(h.work.stage.operation.original, pin.StorageKey, pin.VersionID, digest, h.retained.Publication().RetainUntil, h.coordinator, h.retained.Execution().Snapshot().OrgID)
		if handle != nil {
			h.closes = append(h.closes, handle.CloseConsumerV1)
		}
		if err != nil {
			return err
		}
		if handle == nil {
			return ErrHTMLSendWorkV1
		}
	}
	h.retainedAll = true
	return nil
}

func (h *ApplicationPreSignRetentionV1) CompleteV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if h.closed.Load() || !h.retainedAll || h.completed || w == nil || w.stage == nil || h.work == nil || w.stage.operation != h.work.stage.operation || w.stage.purpose != HTMLPreSignRetentionV1 {
		return ErrHTMLSendWorkV1
	}
	current, err := w.ReadRetainedPreSignV1(call)
	if err != nil {
		return err
	}
	if current.Execution().Commitment() != h.retained.Execution().Commitment() || current.Assets().Commitment() != h.retained.Assets().Commitment() ||
		current.Publication().State != "retaining" || current.Publication().RetentionStartedAt.IsZero() || !current.Publication().RetentionCompletedAt.IsZero() ||
		!current.Publication().RetainUntil.Equal(h.retained.Publication().RetainUntil) {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.sourceDocument == nil || w.sourceDocument.Status != "sealing" {
		return ErrHTMLSendWorkV1
	}
	n, err := w.queries.MarkSendSealingRetentionComplete(call, generated.MarkSendSealingRetentionCompleteParams{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil || n != 1 {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	tag, err := db.Exec(call, `UPDATE presign_execution_publications_v1 p SET retention_started_at=i.retention_started_at,retention_completed_at=i.retention_completed_at
  FROM send_sealing_intents i WHERE p.org_id=$1 AND p.document_id=$2 AND p.execution_id=$3
  AND i.org_id=p.org_id AND i.document_id=p.document_id AND i.presign_execution_id=p.execution_id
  AND p.state='retaining' AND p.retention_completed_at IS NULL AND i.retention_completed_at IS NOT NULL`, w.session.state.org, w.logicalDocumentV1(), current.Execution().Snapshot().ID)
	if err != nil || tag.RowsAffected() != 1 {
		return errors.Join(ErrHTMLSendWorkV1, err)
	}
	h.completed = true
	return nil
}
