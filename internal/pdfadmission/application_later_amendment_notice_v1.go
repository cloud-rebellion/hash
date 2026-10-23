// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"strconv"
	"sync"
	"time"
)

// The initial paired native snapshot owns provider preparation. After known SQL
// retirement and exact-object verification, a separately funded detached metadata
// snapshot owns only the original comparison pins through the fresh second read.
// Fresh locked actor/privacy/files/head policy remains mandatory for COMMIT.
type ApplicationLaterAmendmentNoticeV1 struct {
	self                       *ApplicationLaterAmendmentNoticeV1
	mu                         sync.Mutex
	source                     *applicationDocumentPackageSelectionStateV1
	factory                    *applicationSessionFactoryStateV1
	ids                        [2]uuid.UUID
	snapshotGrant              *workguard.GrantV1
	ctx                        context.Context
	input                      noticeaccess.InputV1
	request                    amendments.IssueNoticeV1
	requestSHA256              [32]byte
	headRevision               int64
	originalPins               []byte
	prepared                   *noticeaccess.PreparedV1
	active                     int
	attempted, closed, retired bool
}

func (h *ApplicationLaterAmendmentNoticeV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.mu.Lock()
	h.closed = true
	retire := h.active == 0 && !h.retired
	if retire {
		h.retired = true
	}
	h.mu.Unlock()
	if retire {
		h.retireV1()
	}
}
func (h *ApplicationLaterAmendmentNoticeV1) retireV1() {
	if h.prepared != nil {
		h.prepared.CloseConsumerV1()
	}
	clear(h.originalPins)
	h.originalPins = nil
	clear(h.input.FileSetBytes)
	h.input = noticeaccess.InputV1{}
	h.request = amendments.IssueNoticeV1{}
	h.factory = nil
	h.ids = [2]uuid.UUID{}
	if h.snapshotGrant != nil {
		h.snapshotGrant.Close()
		h.snapshotGrant = nil
	}
	if h.source != nil {
		h.source.finishV1()
		h.source = nil
	}
}
func (h *ApplicationLaterAmendmentNoticeV1) beginV1() error {
	if h == nil || h.self != h {
		return amendments.ErrUnavailableV1
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed || h.retired || h.ctx == nil || h.ctx.Err() != nil || (h.source == nil && (h.factory == nil || h.snapshotGrant == nil)) {
		return amendments.ErrUnavailableV1
	}
	h.active++
	return nil
}
func (h *ApplicationLaterAmendmentNoticeV1) finishV1() {
	h.mu.Lock()
	h.active--
	retire := h.closed && !h.retired && h.active == 0
	if retire {
		h.retired = true
	}
	h.mu.Unlock()
	if retire {
		h.retireV1()
	}
}

func (w *ApplicationDocumentPackageSelectionV1) NewLaterAmendmentNoticeV1(call, operationCtx context.Context, amendmentID uuid.UUID, in amendments.IssueNoticeV1, actor uuid.UUID) (owner *ApplicationLaterAmendmentNoticeV1, replay *amendments.NoticeV1, failure error) {
	if w == nil || w.state == nil || actor == uuid.Nil || amendmentID == uuid.Nil || !applicationContextV1(operationCtx) {
		return nil, nil, amendments.ErrUnavailableV1
	}
	if e := in.ValidateV1(); e != nil {
		return nil, nil, e
	}
	s := w.state
	if e := s.beginV1(call); e != nil {
		return nil, nil, e
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attempted || s.readActor != actor || s.readers[0] == nil || s.readers[1] == nil || s.readers[0].snapshot == nil || s.readers[1].snapshot == nil {
		return nil, nil, amendments.ErrUnavailableV1
	}
	original, candidate := s.readers[0].snapshot.document, s.readers[1].snapshot.document
	if original == nil || candidate == nil || original.Status != "completed" || original.OrgID != candidate.OrgID {
		return nil, nil, amendments.ErrChangedV1
	}
	close, e := s.actor.acquireOwnedRetainedBodyV1(call, 16<<20, 4<<20)
	if e != nil {
		return nil, nil, e
	}
	s.closes = append(s.closes, close)
	db := &applicationOwnedDBTXV1{session: s.session.state}
	requestSHA, e := amendments.NoticeDigestV1(in)
	if e != nil {
		return nil, nil, e
	}
	requestHash, _ := hex.DecodeString(requestSHA)
	var priorID uuid.UUID
	var priorHash []byte
	e = db.QueryRow(call, `SELECT id,request_sha256 FROM document_amendment_notices_v1 WHERE amendment_id=$1 AND org_id=$2`, amendmentID, original.OrgID).Scan(&priorID, &priorHash)
	if e == nil {
		if !bytes.Equal(priorHash, requestHash) {
			return nil, nil, amendments.ErrChangedV1
		}
		out, e := laterAmendmentNoticeRecordV1(call, db, priorID, original.OrgID)
		return nil, &out, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return nil, nil, e
	}
	if candidate.Status != "draft" || candidate.RequiresSignature || !candidate.UpdatedAt.Valid || !candidate.UpdatedAt.Time.Equal(in.ExpectedDocumentUpdatedAt) {
		return nil, nil, amendments.ErrChangedV1
	}
	h := &ApplicationLaterAmendmentNoticeV1{source: s, ctx: operationCtx, request: in}
	h.self = h
	h.request.RecipientEmails = append([]string(nil), in.RecipientEmails...)
	var mode string
	var files, currentFiles, originalPins, currentOriginal, basis []byte
	var fileHash []byte
	var document uuid.UUID
	e = db.QueryRow(call, `SELECT a.document_id,a.mode,a.revision,a.file_set,a.file_commitment_sha256,a.original_pins,a.basis,
 convert_to(hash_amendment_file_set_v1(a.document_id,a.org_id)::text,'UTF8'),convert_to(hash_amendment_original_pins_v1(a.original_document_id,a.org_id)::text,'UTF8'),clock_timestamp()
 FROM document_amendments_v1 a WHERE a.id=$1 AND a.org_id=$2 AND a.original_document_id=$3
 AND a.revision=(SELECT max(revision) FROM document_amendments_v1 WHERE org_id=a.org_id AND original_document_id=a.original_document_id)`, amendmentID, original.OrgID, original.ID).Scan(&document, &mode, &h.headRevision, &files, &fileHash, &originalPins, &basis, &currentFiles, &currentOriginal, &h.input.IssuedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return nil, nil, amendments.ErrChangedV1
	}
	if e != nil {
		return nil, nil, e
	}
	if mode != string(amendments.AgreedNoticeV1) || document != candidate.ID || in.ExpectedHeadRevision != stringRevisionV1(h.headRevision) || !bytes.Equal(files, currentFiles) || !bytes.Equal(originalPins, currentOriginal) || len(fileHash) != 32 || len(files) > 65536 || len(originalPins) > 32768 {
		return nil, nil, amendments.ErrChangedV1
	}
	var selected amendments.BasisV1
	if json.Unmarshal(basis, &selected) != nil || !containsLaterNoticeEmailV1(selected) {
		return nil, nil, amendments.ErrChangedV1
	}
	if json.Unmarshal(files, &h.input.FileSet) != nil || h.input.FileSet.DocumentID != candidate.ID || len(h.input.FileSet.Files) < 1 || len(h.input.FileSet.Files) > 17 {
		return nil, nil, amendments.ErrUnavailableV1
	}
	// Same all-subject privacy fence as creation, including frozen annex subjects.
	for _, f := range h.input.FileSet.Files {
		var clear bool
		if e = db.QueryRow(call, `SELECT hash_try_document_package_privacy_fence_v1($1,$2) AND NOT EXISTS(SELECT 1 FROM data_subject_requests WHERE org_id=$1 AND status IN ('open','in_progress') AND (document_id IS NULL OR document_id=$2))`, original.OrgID, f.DocumentID).Scan(&clear); e != nil {
			return nil, nil, e
		}
		if !clear {
			return nil, nil, amendments.ErrChangedV1
		}
	}
	h.input.OrgID = original.OrgID
	h.input.NoticeID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("hash:notice:v1:"+original.OrgID.String()+":"+amendmentID.String()+":"+requestSHA))
	h.input.AmendmentID = amendmentID
	h.input.OriginalDocumentID = original.ID
	h.input.DocumentID = candidate.ID
	h.input.IssuedBy = actor
	h.input.Subject = in.Subject
	h.input.Text = in.Text
	h.input.RecipientEmails = append([]string(nil), in.RecipientEmails...)
	h.input.FileSetBytes = bytes.Clone(files)
	copy(h.input.FileCommitmentSHA256[:], fileHash)
	copy(h.requestSHA256[:], requestHash)
	copy(h.input.NoticeSHA256[:], requestHash)
	h.input.IssuedAt = h.input.IssuedAt.UTC()
	h.input.RetainUntil = storage.EvidenceRetentionDeadline(h.input.IssuedAt, article13.RetentionYearsV1)
	h.originalPins = bytes.Clone(originalPins)
	var email, name string
	if e = db.QueryRow(call, `SELECT email,name FROM users WHERE id=$1 AND org_id=$2 AND role='owner' FOR SHARE`, actor, original.OrgID).Scan(&email, &name); e != nil {
		return nil, nil, e
	}
	if len(email) > 254 || len(name) > 512 {
		return nil, nil, amendments.ErrUnavailableV1
	}
	h.input.ReplyTo = email
	h.input.FromName = name
	// This genuine private borrower survives physical initial SQL retirement.
	s.active++
	return h, nil, call.Err()
}
func containsLaterNoticeEmailV1(b amendments.BasisV1) bool {
	mode, email := false, false
	for _, m := range b.AllowedModes {
		mode = mode || m == amendments.AgreedNoticeV1
	}
	for _, c := range b.AllowedChannels {
		email = email || c == "email"
	}
	return mode && email
}
func stringRevisionV1(n int64) string { return strconv.FormatInt(n, 10) }
func (h *ApplicationLaterAmendmentNoticeV1) PrepareV1(engine *noticeaccess.EngineV1) error {
	if e := h.beginV1(); e != nil {
		return e
	}
	defer h.finishV1()
	h.mu.Lock()
	if h.attempted || h.prepared != nil {
		h.mu.Unlock()
		return amendments.ErrUnavailableV1
	}
	h.attempted = true
	h.mu.Unlock()
	source := h.source
	if engine == nil || source == nil || !source.session.RetiredV1() || source.session.CommitUnknownV1() {
		return amendments.ErrUnavailableV1
	}
	p := source.session.state.factory
	p.mu.Lock()
	work, closing := p.work, p.closing
	p.mu.Unlock()
	if closing || work == nil || work.coordinator == nil || !engine.MatchesCoordinatorV1(work.coordinator) {
		return amendments.ErrUnavailableV1
	}
	prepared, e := engine.PrepareV1(h.ctx, h.input)
	if e != nil {
		return e
	}
	// Pay the independently bounded comparison owner BEFORE cloning/detaching.
	// Its grant is not DB/session credit. The first native pair's actual loans
	// remain charged until its borrower ends, CloseConsumer joins, and the SAME
	// original admission re-proves physical retirement outside all entity locks.
	cost, e := laterNoticeSnapshotResourcesV1(h.input, h.request, h.originalPins)
	if e != nil {
		prepared.CloseConsumerV1()
		return e
	}
	grant, e := work.coordinator.TryAcquireV1(h.ctx, h.input.OrgID, workguard.VectorV1{ParentBytes: cost})
	if e != nil {
		prepared.CloseConsumerV1()
		return e
	}
	input, request, pins := laterNoticeCloneSnapshotV1(h.input, h.request, h.originalPins)
	h.mu.Lock()
	if h.closed || h.retired || h.source != source || h.prepared != nil || h.ctx.Err() != nil {
		h.mu.Unlock()
		clear(input.FileSetBytes)
		clear(pins)
		grant.Close()
		prepared.CloseConsumerV1()
		return amendments.ErrUnavailableV1
	}
	h.input, h.request, h.originalPins = input, request, pins
	h.factory, h.ids = p, source.ids
	h.snapshotGrant = grant
	h.prepared = prepared
	h.source = nil
	h.mu.Unlock()
	// Only this genuine borrower has finished. The still-owned pair and its
	// native admission/fence decide when the broad read loans can really retire.
	source.finishV1()
	return h.ctx.Err()
}

// Called only inside the fixed second fresh paired owner policy+transaction.
func (w *ApplicationDocumentPackageSelectionV1) CommitLaterAmendmentNoticeV1(call context.Context, h *ApplicationLaterAmendmentNoticeV1, actor uuid.UUID, ip, ua, publicURL string, appendAudit func(context.Context, *ApplicationHTMLAuditEventConsumerV1) error) (out amendments.OutcomeV1, failure error) {
	if w == nil || w.state == nil || h == nil || actor == uuid.Nil || appendAudit == nil {
		return out, amendments.ErrUnavailableV1
	}
	if e := h.beginV1(); e != nil {
		return out, e
	}
	defer h.finishV1()
	s := w.state
	if e := s.beginV1(call); e != nil {
		return out, e
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	h.mu.Lock()
	ready := h.source == nil && h.factory != nil && h.snapshotGrant != nil && s.session.state.factory == h.factory && s.ids == h.ids && s.readActor == actor && s.attempted && h.prepared != nil
	h.mu.Unlock()
	if !ready {
		return out, amendments.ErrUnavailableV1
	}
	db := &applicationOwnedDBTXV1{session: s.session.state}
	candidate := s.readers[1].snapshot.document
	if candidate == nil || candidate.Status != "draft" || !candidate.UpdatedAt.Valid || !candidate.UpdatedAt.Time.Equal(h.request.ExpectedDocumentUpdatedAt) {
		return out, amendments.ErrChangedV1
	}
	close, e := s.actor.acquireOwnedRetainedBodyV1(call, 32<<20, 8<<20)
	if e != nil {
		return out, e
	}
	s.closes = append(s.closes, close)
	var files, original []byte
	var revision int64
	var retain time.Time
	var currentReply, currentName string
	if e = db.QueryRow(call, `SELECT email,name FROM users WHERE id=$1 AND org_id=$2 AND role='owner' FOR SHARE`, actor, h.input.OrgID).Scan(&currentReply, &currentName); e != nil {
		return out, e
	}
	if currentReply != h.input.ReplyTo || currentName != h.input.FromName {
		return out, amendments.ErrChangedV1
	}
	var priorID uuid.UUID
	var priorHash []byte
	e = db.QueryRow(call, `SELECT id,request_sha256 FROM document_amendment_notices_v1 WHERE amendment_id=$1 AND org_id=$2`, h.input.AmendmentID, h.input.OrgID).Scan(&priorID, &priorHash)
	if e == nil {
		if !bytes.Equal(priorHash, h.requestSHA256[:]) {
			return out, amendments.ErrChangedV1
		}
		notice, e := laterAmendmentNoticeRecordV1(call, db, priorID, h.input.OrgID)
		if e != nil {
			return out, e
		}
		return amendments.OutcomeV1{State: "unchanged", RequestID: h.request.RequestID, Notice: &notice}, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return out, e
	}
	e = db.QueryRow(call, `SELECT a.file_set,a.original_pins,a.revision,hash_evidence_retain_until($4,7) FROM document_amendments_v1 a WHERE a.id=$1 AND a.org_id=$2 AND a.original_document_id=$3
 AND a.mode='agreed_notice' AND a.revision=(SELECT max(revision) FROM document_amendments_v1 WHERE org_id=a.org_id AND original_document_id=a.original_document_id)
 AND convert_from(a.file_set,'UTF8')::jsonb=hash_amendment_file_set_v1(a.document_id,a.org_id)
 AND convert_from(a.original_pins,'UTF8')::jsonb=hash_amendment_original_pins_v1(a.original_document_id,a.org_id)`, h.input.AmendmentID, h.input.OrgID, h.input.OriginalDocumentID, h.input.IssuedAt).Scan(&files, &original, &revision, &retain)
	if errors.Is(e, pgx.ErrNoRows) {
		return out, amendments.ErrChangedV1
	}
	if e != nil {
		return out, e
	}
	if !bytes.Equal(files, h.input.FileSetBytes) || !bytes.Equal(original, h.originalPins) || revision != h.headRevision || !retain.Equal(h.input.RetainUntil) || actor != h.input.IssuedBy {
		return out, amendments.ErrChangedV1
	}
	// The prepared handle, never a caller DTO, attests its own original immutable
	// binding. No SQL audit/outbox occurs before successful exact file retention.
	e = h.prepared.WithInputV1(func(in noticeaccess.InputV1) error {
		if in.OrgID != h.input.OrgID || in.OriginalDocumentID != h.input.OriginalDocumentID || in.DocumentID != h.input.DocumentID || in.Subject != h.input.Subject || in.Text != h.input.Text || in.ReplyTo != h.input.ReplyTo || in.FromName != h.input.FromName || !in.IssuedAt.Equal(h.input.IssuedAt) || !sameNoticeAudienceV1(in.RecipientEmails, h.input.RecipientEmails) || in.NoticeID != h.input.NoticeID || in.AmendmentID != h.input.AmendmentID || in.IssuedBy != actor || in.NoticeSHA256 != h.input.NoticeSHA256 || in.FileCommitmentSHA256 != h.input.FileCommitmentSHA256 || !bytes.Equal(in.FileSetBytes, files) || !in.RetainUntil.Equal(retain) {
			return amendments.ErrChangedV1
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	alert, e := laterAmendmentOwnerAlertForV1(call, s, HTMLAuditLaterAmendmentNoticeV1.KindV1(), publicURL)
	if e != nil {
		return out, e
	}
	payload := map[string]any{"schema": amendments.SchemaV1, "amendment_id": h.input.AmendmentID.String(), "notice_id": h.input.NoticeID.String(), "notice_sha256": hex.EncodeToString(h.input.NoticeSHA256[:]), "file_commitment_sha256": hex.EncodeToString(h.input.FileCommitmentSHA256[:]), "request_id": h.request.RequestID.String(), "recipient_count": len(h.input.RecipientEmails)}
	payload["owner_alert"] = alert.payloadV1()
	event, e := s.session.NewHTMLAuditEventV1(call, HTMLAuditLaterAmendmentNoticeV1, h.input.OrgID, h.input.OriginalDocumentID, pgtype.UUID{}, pgtype.UUID{Bytes: actor, Valid: true}, HTMLAuditLaterAmendmentNoticeV1.KindV1(), ip, ua, payload)
	if e != nil {
		return out, e
	}
	if e = appendAudit(call, event); e != nil {
		event.CloseConsumerV1()
		return out, e
	}
	event.mu.Lock()
	eventID := event.eventID
	event.mu.Unlock()
	if eventID == uuid.Nil {
		return out, amendments.ErrUnavailableV1
	}
	noticeRaw, e := json.Marshal(h.request)
	if e != nil {
		return out, e
	}
	_, e = db.Exec(call, `INSERT INTO document_amendment_notices_v1(id,amendment_id,org_id,request_id,request_sha256,subject,text_body,notice_bytes,notice_sha256,file_commitment_sha256,issued_by,issued_at,retain_until,event_id,owner_alert_user_id,owner_alert_email_delivery_id,owner_alert_message_sha256) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, h.input.NoticeID, h.input.AmendmentID, h.input.OrgID, h.request.RequestID, h.requestSHA256[:], h.input.Subject, h.input.Text, noticeRaw, h.input.NoticeSHA256[:], h.input.FileCommitmentSHA256[:], actor, h.input.IssuedAt, retain, eventID, alert.user, alert.email, alert.messageSHA[:])
	if e != nil {
		return out, e
	}
	for i := range h.input.RecipientEmails {
		e = h.prepared.WithDeliveryV1(i, func(d noticeaccess.DeliveryV1) error {
			if d.OrgID != h.input.OrgID || d.NoticeID != h.input.NoticeID || d.FileCommitmentSHA256 != h.input.FileCommitmentSHA256 || d.RecipientEmail != h.input.RecipientEmails[i] || !d.CreatedAt.Equal(h.input.IssuedAt) || !d.ExpiresAt.Equal(h.input.IssuedAt.Add(noticeaccess.AccessTTL)) || d.AccessID == uuid.Nil || d.EmailDeliveryID == uuid.Nil {
				return amendments.ErrChangedV1
			}
			headers := []byte("{}")
			if len(d.Message.Headers) != 0 {
				return amendments.ErrChangedV1
			}
			if d.Message.To != d.RecipientEmail || d.Message.Subject != h.input.Subject || d.Message.ReplyTo != h.input.ReplyTo || d.Message.FromName != h.input.FromName {
				return amendments.ErrChangedV1
			}
			_, e = db.Exec(call, `INSERT INTO email_deliveries(id,to_email,subject,html_body,text_body,reply_to,from_name,headers_json) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, d.EmailDeliveryID, d.Message.To, d.Message.Subject, d.Message.HTML, d.Message.Text, d.Message.ReplyTo, d.Message.FromName, headers)
			if e != nil {
				return e
			}
			_, e = db.Exec(call, `INSERT INTO document_amendment_notice_deliveries_v1(notice_id,org_id,position,email_delivery_id,recipient_email,message_sha256) VALUES($1,$2,$3,$4,$5,$6)`, d.NoticeID, d.OrgID, i, d.EmailDeliveryID, d.RecipientEmail, d.MessageSHA256[:])
			if e != nil {
				return e
			}
			_, e = db.Exec(call, `INSERT INTO document_amendment_notice_access_v1(id,org_id,notice_id,email_delivery_id,recipient_email,token_sha256,file_commitment_sha256,created_at,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, d.AccessID, d.OrgID, d.NoticeID, d.EmailDeliveryID, d.RecipientEmail, d.TokenSHA256[:], d.FileCommitmentSHA256[:], d.CreatedAt, d.ExpiresAt)
			return e
		})
		if e != nil {
			return out, e
		}
	}
	notice, e := laterAmendmentNoticeRecordV1(call, db, h.input.NoticeID, h.input.OrgID)
	if e != nil {
		return out, e
	}
	return amendments.OutcomeV1{State: "committed", RequestID: h.request.RequestID, Notice: &notice}, nil
}

// Identity-only routing hint precedes globally sorted subject row locks. It
// grants no read/mutation authority: both actual documents and owner credential
// are still admitted by the paired reader before any complete body or action.
func (h *ApplicationSessionV1) ResolveLaterAmendmentCandidateV1(call context.Context, id uuid.UUID) (uuid.UUID, error) {
	if h == nil || h.state == nil || id == uuid.Nil {
		return uuid.Nil, amendments.ErrUnavailableV1
	}
	actor, e := h.NewHTMLAuthoringReaderV1(call)
	if e != nil {
		return uuid.Nil, e
	}
	defer actor.CloseConsumerV1()
	close, e := actor.acquireOwnedRetainedBodyV1(call, 4096, 4096)
	if e != nil {
		return uuid.Nil, e
	}
	defer close()
	db := &applicationOwnedDBTXV1{session: h.state}
	var candidate uuid.UUID
	e = db.QueryRow(call, `SELECT document_id FROM document_amendments_v1 WHERE id=$1 AND org_id=$2 AND original_document_id=$3`, id, h.state.org, h.state.document).Scan(&candidate)
	if e != nil {
		return uuid.Nil, e
	}
	if candidate == uuid.Nil || candidate == h.state.document {
		return uuid.Nil, amendments.ErrUnavailableV1
	}
	return candidate, call.Err()
}

func (w *ApplicationDocumentPackageSelectionV1) RevokeLaterAmendmentAccessV1(call context.Context, amendmentID, accessID, actor uuid.UUID, ip, ua string, appendAudit func(context.Context, *ApplicationHTMLAuditEventConsumerV1) error) (out amendments.RevokeOutcomeV1, failure error) {
	if w == nil || w.state == nil || amendmentID == uuid.Nil || accessID == uuid.Nil || actor == uuid.Nil || appendAudit == nil {
		return out, amendments.ErrUnavailableV1
	}
	s := w.state
	if e := s.beginV1(call); e != nil {
		return out, e
	}
	defer s.finishV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.attempted || s.readActor != actor || s.readers[0] == nil || s.readers[1] == nil {
		return out, amendments.ErrUnavailableV1
	}
	close, e := s.actor.acquireOwnedRetainedBodyV1(call, 32768, 16384)
	if e != nil {
		return out, e
	}
	s.closes = append(s.closes, close)
	db := &applicationOwnedDBTXV1{session: s.session.state}
	var notice uuid.UUID
	e = db.QueryRow(call, `SELECT n.id FROM document_amendment_notices_v1 n JOIN document_amendments_v1 a ON a.id=n.amendment_id AND a.org_id=n.org_id JOIN document_amendment_notice_access_v1 c ON c.notice_id=n.id AND c.org_id=n.org_id WHERE a.id=$1 AND a.org_id=$2 AND a.original_document_id=$3 AND a.document_id=$4 AND c.id=$5`, amendmentID, s.session.state.org, s.ids[0], s.ids[1], accessID).Scan(&notice)
	if e != nil {
		return out, e
	}
	at, changed, e := noticeaccess.RevokeV1(call, &laterAmendmentPolicyTxV1{DBTX: db}, s.session.state.org, notice, accessID, actor)
	if e != nil {
		return out, e
	}
	out = amendments.RevokeOutcomeV1{Schema: amendments.SchemaV1, State: "unchanged", AccessID: accessID, RevokedAt: &at}
	if !changed {
		return out, nil
	}
	payload := map[string]any{"schema": amendments.SchemaV1, "amendment_id": amendmentID.String(), "notice_id": notice.String(), "access_id": accessID.String(), "revoked_at": at.UTC().Format(time.RFC3339Nano)}
	event, e := s.session.NewHTMLAuditEventV1(call, HTMLAuditLaterAmendmentAccessRevokedV1, s.session.state.org, s.ids[0], pgtype.UUID{}, pgtype.UUID{Bytes: actor, Valid: true}, HTMLAuditLaterAmendmentAccessRevokedV1.KindV1(), ip, ua, payload)
	if e != nil {
		return out, e
	}
	if e = appendAudit(call, event); e != nil {
		event.CloseConsumerV1()
		return out, e
	}
	out.State = "committed"
	return out, call.Err()
}

func sameNoticeAudienceV1(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
