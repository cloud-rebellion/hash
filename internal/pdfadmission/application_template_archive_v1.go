// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"time"
	"unsafe"
)

var ErrTemplateArchiveV1 = errors.New("pdfadmission: native template archive unavailable")

type ApplicationTemplateArchiveV1 struct {
	state *applicationTemplateArchiveStateV1
}
type applicationTemplateArchiveStateV1 struct {
	mu                                                               sync.Mutex
	session                                                          *ApplicationSessionV1
	reader                                                           *ApplicationHTMLAuthoringReaderV1
	queries                                                          *generated.Queries
	closes                                                           []func()
	target                                                           *generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Row
	archived                                                         *generated.ArchiveNativeTemplateIdentityV1Row
	pending                                                          audit.PendingEvent
	consumerClosed, closed, auditStarted, published, publicationDone bool
}

func (h *ApplicationSessionV1) NewTemplateArchiveV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1) (*ApplicationTemplateArchiveV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) {
		return nil, ErrTemplateArchiveV1
	}
	raw := 2*int64(unsafe.Sizeof(applicationTemplateArchiveStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationTemplateArchiveV1{})) + 2*int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Row{})) + int64(unsafe.Sizeof(generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{})) + 2*int64(unsafe.Sizeof(generated.ArchiveNativeTemplateIdentityV1Row{})) + int64(unsafe.Sizeof(generated.ArchiveNativeTemplateIdentityV1Params{})) + 12
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, 0)
	if err != nil {
		return nil, errors.Join(ErrTemplateArchiveV1, err)
	}
	return &ApplicationTemplateArchiveV1{state: &applicationTemplateArchiveStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), closes: []func(){close}}}, nil
}
func (s *applicationTemplateArchiveStateV1) validV1(ctx context.Context) bool {
	return s != nil && !s.consumerClosed && !s.closed && s.session != nil && s.session.state != nil && s.reader != nil && s.reader.session == s.session && s.reader.valid(ctx) && s.queries != nil
}

// This fixed actual header locks every existing kind, including an uncached
// legacy template. Archive never selects its source body or adopts a cache.
func (h *ApplicationTemplateArchiveV1) LockTargetV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return ErrTemplateArchiveV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.target != nil {
		return ErrTemplateArchiveV1
	}
	row, err := s.queries.GetNonHTMLTemplateSourceHeaderForUpdateV1(ctx, generated.GetNonHTMLTemplateSourceHeaderForUpdateV1Params{TemplateID: s.session.state.document, OrgID: s.session.state.org})
	if err != nil {
		return err
	}
	if row == nil || row.ID != s.session.state.document || row.OrgID != s.session.state.org || row.Version < 1 || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || (row.SourceKind != "html" && row.SourceKind != "pdf" && row.SourceKind != "blocks") {
		return ErrTemplateArchiveV1
	}
	s.target = row
	return nil
}
func (h *ApplicationTemplateArchiveV1) ArchiveV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return ErrTemplateArchiveV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.target == nil || s.archived != nil {
		return ErrTemplateArchiveV1
	}
	row, err := s.queries.ArchiveNativeTemplateIdentityV1(ctx, generated.ArchiveNativeTemplateIdentityV1Params{TemplateID: s.target.ID, OrgID: s.target.OrgID, ExpectedVersion: s.target.Version, ExpectedUpdatedAt: s.target.UpdatedAt})
	if err != nil {
		return err
	}
	if row == nil || row.ID != s.target.ID || row.OrgID != s.target.OrgID || row.Version != s.target.Version || !applicationStampV1(row.UpdatedAt) || !applicationStampV1(row.ArchivedAt) {
		return ErrTemplateArchiveV1
	}
	s.archived = row
	return nil
}

// The existing Logger already reads only scalar row_hash/created_at head data.
// This fixed native producer keeps that original chain/hash meaning while
// bounding its actual head and identity-only append, then joins every hook;
// org-only template events are not document snapshot-history/M94 rows.
func (h *ApplicationTemplateArchiveV1) LogArchivedV1(ctx context.Context, logger *audit.Logger, actor uuid.UUID) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrTemplateArchiveV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.archived == nil || s.auditStarted || s.target == nil || actor == uuid.Nil {
		return ErrTemplateArchiveV1
	}
	s.auditStarted = true

	shape := htmlAuditShapeV1{}
	if err := shape.text("template_id", true); err != nil {
		return err
	}
	if err := shape.add(0, 2, 1); err != nil {
		return err
	}
	if err := shape.value(ctx, s.target.ID, 1); err != nil {
		return err
	}
	if err := shape.add(192, 4098, 17); err != nil {
		return err
	}
	for _, text := range [...]string{audit.KindTemplateArchived, "", ""} {
		if err := shape.text(text, false); err != nil {
			return err
		}
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil {
		return err
	}
	close, err := s.acquireAuditV1(ctx, shape, resources)
	if err != nil {
		return err
	}
	s.closes = append(s.closes, close)
	payload := map[string]any{"template_id": s.target.ID}
	// Use the same original scalar chain/timestamp/hash behavior, with the
	// bounded native hash32 head guard. No historical payload model or fresh
	// RETURNING* event is needed for this org-only template event.
	if err = s.queries.AcquireOrgChainLock(ctx, s.target.OrgID.String()); err != nil {
		return err
	}
	head, err := s.queries.GetOwnedHTMLAuditChainHeadV1(ctx, s.target.OrgID)
	var previous []byte
	created := time.Now().UTC().Truncate(time.Microsecond)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else {
		if !htmlAuditHeadValidV1(head) {
			return ErrTemplateArchiveV1
		}
		previous = bytes.Clone(head.RowHash)
		if !created.After(head.CreatedAt.Time) {
			created = head.CreatedAt.Time.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		}
	}
	raw, err := json.Marshal(payload)
	if err != nil || int64(len(raw)) > shape.wire {
		return ErrTemplateArchiveV1
	}
	hash := audit.ChainHashRecord(audit.HashInput{Prev: previous, OrgID: s.target.OrgID, ActorID: actor, Kind: audit.KindTemplateArchived, CreatedAt: created, Payload: raw})
	id, err := s.queries.InsertEventIdentityV1(ctx, generated.InsertEventIdentityV1Params{OrgID: s.target.OrgID, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Kind: audit.KindTemplateArchived, PayloadJson: raw, PayloadHashed: raw, PrevHash: previous, RowHash: hash, CreatedAt: pgtype.Timestamptz{Time: created, Valid: true}})
	if err != nil {
		return err
	}
	if id == uuid.Nil {
		return ErrTemplateArchiveV1
	}
	s.pending = audit.PendingEvent{ID: id, Entry: audit.Entry{OrgID: s.target.OrgID, ActorUserID: &actor, Kind: audit.KindTemplateArchived, Payload: payload}}
	return nil
}

func (s *applicationTemplateArchiveStateV1) acquireAuditV1(ctx context.Context, shape htmlAuditShapeV1, resources ApplicationRequestPayloadResourcesV1) (func(), error) {
	physical := s.session.state
	p := physical.factory
	if p == nil {
		return nil, ErrTemplateArchiveV1
	}
	p.mu.Lock()
	physical.mu.Lock()
	defer p.mu.Unlock()
	defer physical.mu.Unlock()
	a := physical.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || !physical.dialed || physical.observer || physical.closed || physical.unknown || physical.ended || physical.retired || physical.creating || physical.sqlActive || physical.tx == nil || physical.conn == nil || physical.fence == nil || !applicationIdentityValidV1(physical.fence.identity) || a == nil || !a.valid() || a.fence != physical.fence || a.cleanupDone != physical.fence.clientDone || !physical.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != physical || (p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		return nil, ErrTemplateArchiveV1
	}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	return a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: physical.org, DocumentID: physical.document, HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
}
func (h *ApplicationTemplateArchiveV1) PublishV1(logger *audit.Logger) error {
	if h == nil || h.state == nil || logger == nil {
		return ErrTemplateArchiveV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.published || s.pending.ID == uuid.Nil || s.session == nil || s.session.state == nil {
		s.mu.Unlock()
		return ErrTemplateArchiveV1
	}
	native := s.session.state
	native.mu.Lock()
	ack := native.commitAttempted && native.ended && !native.commitUnknown
	native.mu.Unlock()
	if !ack {
		s.mu.Unlock()
		return ErrTemplateArchiveV1
	}
	s.published = true
	pending := s.pending
	s.mu.Unlock()
	var once sync.Once
	logger.PublishJoinedV1(pending, func() {
		once.Do(func() { s.mu.Lock(); s.publicationDone = true; s.releaseIfCompleteV1(); s.mu.Unlock() })
	})
	return nil
}
func (s *applicationTemplateArchiveStateV1) releaseIfCompleteV1() {
	if s.closed || !s.consumerClosed || (s.published && !s.publicationDone) {
		return
	}
	s.closed = true
	s.target = nil
	s.archived = nil
	s.pending = audit.PendingEvent{}
	for _, close := range s.closes {
		close()
	}
	s.closes = nil
}
func (h *ApplicationTemplateArchiveV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	s.consumerClosed = true
	s.releaseIfCompleteV1()
}
