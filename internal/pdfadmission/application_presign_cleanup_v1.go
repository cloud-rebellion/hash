// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrPreSignCleanupPendingV1 = errors.New("pdfadmission: unresolved pre-sign upload remains inventory debt")

type preSignCleanupObjectV1 struct {
	reservation                   storage.PresignTransientReservationV1
	knownVersion, observedVersion string
	found, alreadyAbsent, deleted bool
}

// Only an explicitly closed original M82 request permits transient cleanup.
// An unresolved attempted key with empty history remains debt: absence now
// cannot prove an unknown earlier PUT can never complete. No PUT is retried.
type ApplicationPreSignCleanupV1 struct {
	mu                                                                         sync.Mutex
	activity                                                                   applicationJoinedActivityV1
	closed                                                                     atomic.Bool
	self                                                                       *ApplicationPreSignCleanupV1
	work                                                                       *ApplicationHTMLSendWorkV1
	start, resolution                                                          *ApplicationSessionV1
	client                                                                     *storage.Client
	coordinator                                                                *workguard.CoordinatorV1
	preparation                                                                uuid.UUID
	objects                                                                    [8]preSignCleanupObjectV1
	count                                                                      int
	observeAttempted, observed, recorded, deleteAttempted, deleteDone, pending bool
	closes                                                                     []func()
	release                                                                    func()
}

func (h *ApplicationPreSignCleanupV1) lockV1() bool {
	if h == nil || h.self != h || !h.activity.enterV1() {
		return false
	}
	h.mu.Lock()
	return true
}
func (h *ApplicationPreSignCleanupV1) unlockV1() {
	h.mu.Unlock()
	if h.activity.leaveV1() {
		h.retireV1()
	}
}
func (h *ApplicationPreSignCleanupV1) retireV1() {
	for _, close := range h.closes {
		close()
	}
	h.closes = nil
	if h.release != nil {
		h.release()
		h.release = nil
	}
	h.work = nil
	h.start = nil
	h.resolution = nil
	h.client = nil
	h.coordinator = nil
	h.objects = [8]preSignCleanupObjectV1{}
}
func (h *ApplicationPreSignCleanupV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.closed.Store(true)
	if h.activity.closeV1() {
		h.retireV1()
	}
}

func (w *ApplicationHTMLSendWorkV1) StartPreSignCleanupV1(call context.Context, preparation uuid.UUID, client *storage.Client) (*ApplicationPreSignCleanupV1, error) {
	if w == nil || w.self != w || client == nil || preparation == uuid.Nil {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLPreSignRecoveryV1 || w.state == nil || w.presignCleanup != nil {
		return nil, ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	var closed bool
	err := db.QueryRow(call, `SELECT p.state='closed' AND p.execution_id IS NULL AND EXISTS(SELECT 1 FROM presign_execution_requests r
  WHERE r.org_id=p.org_id AND r.executor_kind=p.executor_kind AND r.executor_user_id=p.executor_user_id
   AND r.executor_credential_id=p.executor_credential_id AND r.request_id=p.request_id AND r.state='closed')
  FROM presign_preparations_v1 p WHERE p.org_id=$1 AND p.id=$2 AND p.document_id=$3 FOR UPDATE`, w.session.state.org, preparation, w.logicalDocumentV1()).Scan(&closed)
	if err != nil || !closed {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	var n, raw int64
	err = db.QueryRow(call, `SELECT count(*)::bigint,COALESCE(sum(octet_length(role)+octet_length(object_key)+octet_length(content_type)+COALESCE(octet_length(version_id),0)+32),0)::bigint
  FROM presign_preparation_objects_v1 WHERE org_id=$1 AND preparation_id=$2 AND upload_attempted AND deleted_at IS NULL`, w.session.state.org, preparation).Scan(&n, &raw)
	if err != nil || n < 0 || n > 8 || raw < 0 || raw > 8*(32+1024+128+1024+32) {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw+32768, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeBody)
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
	h := &ApplicationPreSignCleanupV1{work: w, start: w.session, client: client, coordinator: coordinator, preparation: preparation}
	h.self = h
	rows, err := db.Query(call, `SELECT role,object_key,content_type,object_sha256,object_bytes,version_id FROM presign_preparation_objects_v1
  WHERE org_id=$1 AND preparation_id=$2 AND upload_attempted AND deleted_at IS NULL ORDER BY role`, w.session.state.org, preparation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		if h.count >= 8 {
			return nil, ErrHTMLSendWorkV1
		}
		var role, key, mime string
		var sha []byte
		var size int64
		var version pgtype.Text
		if err = rows.Scan(&role, &key, &mime, &sha, &size, &version); err != nil {
			return nil, err
		}
		r := storage.PresignTransientReservationV1{OrgID: w.session.state.org, DocumentID: w.logicalDocumentV1(), PreparationID: preparation, Role: role, Bytes: size}
		if len(sha) != 32 {
			return nil, ErrHTMLSendWorkV1
		}
		copy(r.SHA256[:], sha)
		if r.KeyV1() != key || r.ContentTypeV1() != mime || size < 1 || size > 50<<20 {
			return nil, ErrHTMLSendWorkV1
		}
		h.objects[h.count] = preSignCleanupObjectV1{reservation: r, knownVersion: version.String}
		h.count++
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if int64(h.count) != n {
		return nil, ErrHTMLSendWorkV1
	}
	_, err = db.Exec(call, `UPDATE presign_preparation_objects_v1 SET cleanup_started_at=COALESCE(cleanup_started_at,clock_timestamp())
  WHERE org_id=$1 AND preparation_id=$2 AND upload_attempted AND deleted_at IS NULL`, w.session.state.org, preparation)
	if err != nil {
		return nil, err
	}
	w.sourceBorrowers++
	var once sync.Once
	h.release = func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
		})
	}
	w.presignCleanup = h
	return h, nil
}

func (h *ApplicationPreSignCleanupV1) ObserveV1() error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if h.closed.Load() || h.observeAttempted || !preSignKnownCommitV1(h.start) {
		return ErrHTMLSendWorkV1
	}
	h.observeAttempted = true
	for i := 0; i < h.count; i++ {
		o := &h.objects[i]
		handle, found, err := h.client.ResolvePresignTransientLocalOwnedV1(h.work.stage.operation.original, o.reservation, h.coordinator, o.reservation.OrgID)
		if handle != nil {
			h.closes = append(h.closes, handle.CloseConsumerV1)
		}
		if err != nil {
			return err
		}
		if handle == nil {
			return ErrHTMLSendWorkV1
		}
		if !found {
			if o.knownVersion == "" {
				h.pending = true
			} else {
				o.alreadyAbsent = true
			}
			continue
		}
		err = handle.WithStoredV1(func(stored storage.StoredObject) error {
			// The constructor-owned resolver used this exact validated reservation's
			// key. StoredObject carries only its immutable version and content digest.
			if stored.VersionID == "" || stored.SHA256 != o.reservation.SHA256 || (o.knownVersion != "" && o.knownVersion != stored.VersionID) {
				return ErrHTMLSendWorkV1
			}
			o.found = true
			o.observedVersion = stored.VersionID
			return nil
		})
		if err != nil {
			return err
		}
	}
	h.observed = true
	return nil
}
func (h *ApplicationPreSignCleanupV1) currentV1(call context.Context, w *ApplicationHTMLSendWorkV1) bool {
	if w == nil || w.self != w {
		return false
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return !h.closed.Load() && w.stage != nil && h.work != nil && w.stage.operation == h.work.stage.operation && w.stage.purpose == HTMLPreSignRecoveryV1 && w.valid(call)
}

// Concrete newly observed versions are persisted before DELETE. A commit
// error authorizes no deletion. Empty unresolved keys are deliberately kept.
func (h *ApplicationPreSignCleanupV1) RecordResolutionsV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if !h.currentV1(call, w) || !h.observed || h.recorded {
		return ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	for i := 0; i < h.count; i++ {
		o := &h.objects[i]
		if !o.found && !o.alreadyAbsent {
			continue
		}
		version := o.observedVersion
		if o.alreadyAbsent {
			version = o.knownVersion
		}
		tag, err := db.Exec(call, `UPDATE presign_preparation_objects_v1 o SET version_id=COALESCE(o.version_id,$4),resolved_at=COALESCE(o.resolved_at,clock_timestamp()),
    deleted_at=CASE WHEN $5 THEN COALESCE(o.deleted_at,clock_timestamp()) ELSE o.deleted_at END
   FROM presign_preparations_v1 p WHERE p.org_id=o.org_id AND p.id=o.preparation_id AND p.org_id=$1 AND p.id=$2
    AND p.document_id=$6 AND p.state='closed' AND p.execution_id IS NULL AND o.role=$3 AND o.upload_attempted AND o.cleanup_started_at IS NOT NULL
    AND (o.version_id IS NULL OR o.version_id=$4) AND o.object_key=$7 AND o.object_sha256=$8 AND o.object_bytes=$9`,
			o.reservation.OrgID, h.preparation, o.reservation.Role, version, o.alreadyAbsent, w.logicalDocumentV1(), o.reservation.KeyV1(), o.reservation.SHA256[:], o.reservation.Bytes)
		if err != nil || tag.RowsAffected() != 1 {
			return errors.Join(ErrHTMLSendWorkV1, err)
		}
	}
	h.resolution = w.session
	h.recorded = true
	return nil
}
func (h *ApplicationPreSignCleanupV1) DeleteV1() error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if h.closed.Load() || !h.recorded || h.deleteAttempted || !preSignKnownCommitV1(h.resolution) {
		return ErrHTMLSendWorkV1
	}
	h.deleteAttempted = true
	for i := 0; i < h.count; i++ {
		o := &h.objects[i]
		if !o.found {
			continue
		}
		handle, err := h.client.DeletePresignTransientLocalOwnedV1(h.work.stage.operation.original, o.reservation, o.observedVersion, h.coordinator, o.reservation.OrgID)
		if handle != nil {
			h.closes = append(h.closes, handle.CloseConsumerV1)
		}
		if err != nil {
			return err
		}
		if handle == nil {
			return ErrHTMLSendWorkV1
		}
		o.deleted = true
	}
	h.deleteDone = true
	return nil
}
func (h *ApplicationPreSignCleanupV1) MarkDeletedV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if !h.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer h.unlockV1()
	if !h.currentV1(call, w) || !h.deleteDone {
		return ErrHTMLSendWorkV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	for i := 0; i < h.count; i++ {
		o := &h.objects[i]
		if !o.deleted {
			continue
		}
		tag, err := db.Exec(call, `UPDATE presign_preparation_objects_v1 o SET deleted_at=COALESCE(o.deleted_at,clock_timestamp())
   FROM presign_preparations_v1 p WHERE p.org_id=o.org_id AND p.id=o.preparation_id AND p.org_id=$1 AND p.id=$2
    AND p.document_id=$6 AND p.state='closed' AND p.execution_id IS NULL AND o.role=$3 AND o.version_id=$4
    AND o.cleanup_started_at IS NOT NULL AND o.object_key=$5 AND o.object_sha256=$7 AND o.object_bytes=$8`,
			o.reservation.OrgID, h.preparation, o.reservation.Role, o.observedVersion, o.reservation.KeyV1(), w.logicalDocumentV1(), o.reservation.SHA256[:], o.reservation.Bytes)
		if err != nil || tag.RowsAffected() != 1 {
			return errors.Join(ErrHTMLSendWorkV1, err)
		}
	}
	return nil
}
func (h *ApplicationPreSignCleanupV1) PendingV1() bool {
	if !h.lockV1() {
		return true
	}
	defer h.unlockV1()
	return h.pending
}
