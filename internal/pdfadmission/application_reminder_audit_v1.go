// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"sync"
	"unsafe"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Event registration holds factory/session locks. Its independent mutex must
// never acquire the mutable reminder/Work lock underneath those locks.
type applicationReminderAuditBatchV1 struct {
	mu                       sync.Mutex
	self                     *applicationReminderAuditBatchV1
	parent                   *applicationReminderStateV1
	session                  *ApplicationSessionV1
	org, document            uuid.UUID
	actor                    pgtype.UUID
	purpose                  HTMLAuditPurposeV1
	ip                       string
	slots                    []applicationReminderAuditSlotV1
	close                    func()
	opened, opening          int
	consumerClosed, released bool
}
type applicationReminderAuditSlotV1 struct {
	self                  *applicationReminderAuditSlotV1
	batch                 *applicationReminderAuditBatchV1
	shape                 htmlAuditShapeV1
	callbackDone          <-chan struct{}
	recipient             pgtype.UUID
	owner                 *ApplicationHTMLAuditEventConsumerV1
	ready, issued, closed bool
}

func (s *applicationReminderStateV1) auditPurposeV1() HTMLAuditPurposeV1 {
	if s.automatic {
		return HTMLAuditReminderAutomaticV1
	}
	return HTMLAuditReminderManualV1
}
func (s *applicationReminderStateV1) auditPayloadV1() map[string]any {
	p := map[string]any{}
	if s.automatic {
		p["automatic"] = true
	} else {
		p["manual"] = true
	}
	if s.via != "" {
		p["via"] = s.via
	}
	if s.tool != "" {
		p["tool"] = s.tool
	}
	return p
}

// One original retained-body loan sums every real native event's complete
// resource formula BEFORE finite private slots. Limits, events and hooks are
// unchanged. The parent retains its real Work/body borrower through the batch.
func (s *applicationReminderStateV1) prepareAuditBatchLockedV1(call context.Context) error {
	if len(s.recipients) == 0 {
		return nil
	}
	purpose := s.auditPurposeV1()
	shape, err := htmlAuditPayloadShapeV1(call, purpose, s.auditPayloadV1())
	if err != nil {
		return err
	}
	for _, v := range []string{purpose.KindV1(), s.ip, ""} {
		if err = shape.text(v, false); err != nil {
			return err
		}
	}
	if err = shape.add(192, 4096, 16); err != nil {
		return err
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil {
		return err
	}
	raw, wire := int64(65536)+8*int64(unsafe.Sizeof(applicationReminderAuditBatchV1{})), int64(0)
	if !htmlInputAddV1(&raw, int64(len(s.recipients)), resources.WorkingBytes+8*int64(unsafe.Sizeof(applicationReminderAuditSlotV1{}))) || !htmlInputAddV1(&wire, int64(len(s.recipients)), resources.DBStagingBytes) {
		return ErrReminderV1
	}
	close, err := s.work.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return err
	}
	g := &applicationReminderAuditBatchV1{parent: s, session: s.work.session, org: s.document.OrgID, document: s.document.ID, actor: s.actor, purpose: purpose, ip: s.ip, close: close}
	g.self = g
	g.slots = make([]applicationReminderAuditSlotV1, len(s.recipients))
	for i := range g.slots {
		slot := &g.slots[i]
		slot.batch = g
		slot.self = slot
		slot.shape = shape
		slot.callbackDone = call.Done()
		slot.recipient = pgtype.UUID{Bytes: s.recipients[i].recipient.ID, Valid: true}
	}
	s.audits = g
	s.auditHeld = true
	return nil
}
func (g *applicationReminderAuditBatchV1) retireLockedV1() (func(), *applicationReminderStateV1) {
	if !g.consumerClosed || g.released || g.opened != 0 || g.opening != 0 {
		return nil, nil
	}
	g.released = true
	close, parent := g.close, g.parent
	g.close = nil
	g.parent = nil
	g.slots = nil
	g.session = nil
	g.ip = ""
	return close, parent
}
func releaseReminderAuditsV1(close func(), parent *applicationReminderStateV1) {
	if close != nil {
		close()
	}
	if parent != nil {
		parent.releaseAuditV1()
	}
}
func (slot *applicationReminderAuditSlotV1) acquireV1(call context.Context, h *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, shape htmlAuditShapeV1) (func(), error) {
	if slot == nil || slot.self != slot || slot.batch == nil {
		return nil, ErrReminderV1
	}
	g := slot.batch
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.self != g || g.consumerClosed || g.released || g.close == nil || g.session != h || !slot.ready || slot.issued || slot.closed || slot.shape != shape || g.purpose != purpose || slot.recipient != recipient || g.actor != actor || g.org != org || g.document != document || kind != purpose.KindV1() || g.ip != ip || ua != "" || call.Done() != slot.callbackDone || call.Value(applicationSessionCallbackKeyV1{}) != h.state {
		return nil, ErrReminderV1
	}
	slot.issued = true
	g.opened++
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			if !slot.closed {
				slot.closed = true
				g.opened--
			}
			close, parent := g.retireLockedV1()
			g.mu.Unlock()
			releaseReminderAuditsV1(close, parent)
		})
	}, nil
}
func (g *applicationReminderAuditBatchV1) closeConsumerV1() {
	g.mu.Lock()
	if g.consumerClosed {
		g.mu.Unlock()
		return
	}
	g.consumerClosed = true
	// Independent fixed pointers are funded with the original actual slot count.
	owners := make([]*ApplicationHTMLAuditEventConsumerV1, len(g.slots))
	for i := range g.slots {
		owners[i] = g.slots[i].owner
	}
	g.mu.Unlock()
	for _, owner := range owners {
		if owner != nil {
			owner.CloseConsumerV1()
		}
	}
	g.mu.Lock()
	close, parent := g.retireLockedV1()
	g.mu.Unlock()
	releaseReminderAuditsV1(close, parent)
}
func (r *ApplicationReminderV1) NewNextAuditV1(call context.Context) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if r == nil || r.state == nil {
		return nil, ErrReminderV1
	}
	s := r.state
	s.mu.Lock()
	w := s.work
	if w == nil {
		s.mu.Unlock()
		return nil, ErrReminderV1
	}
	w.mu.Lock()
	if !s.validLockedV1(call) || !s.prepared || (!s.automatic && !s.reset) || s.auditOpening || s.audits == nil || s.auditNext >= len(s.recipients) {
		w.mu.Unlock()
		s.mu.Unlock()
		return nil, ErrReminderV1
	}
	for _, item := range s.recipients {
		if !item.rotated || (s.delivery && !item.rendered) || (s.queue && !item.enqueued) {
			w.mu.Unlock()
			s.mu.Unlock()
			return nil, ErrReminderV1
		}
	}
	g, index := s.audits, s.auditNext
	g.mu.Lock()
	if g.consumerClosed || g.released {
		g.mu.Unlock()
		w.mu.Unlock()
		s.mu.Unlock()
		return nil, ErrReminderV1
	}
	slot := &g.slots[index]
	slot.ready = true
	g.opening++
	g.mu.Unlock()
	s.auditOpening = true
	purpose, org, document, actor, ip := s.auditPurposeV1(), s.document.OrgID, s.document.ID, s.actor, s.ip
	payload := s.auditPayloadV1()
	recipient := slot.recipient
	session := w.session
	w.mu.Unlock()
	s.mu.Unlock()
	owner, err := session.newHTMLAuditEventCoreReminderV1(call, purpose, org, document, recipient, actor, purpose.KindV1(), ip, "", payload, nil, nil, nil, nil, slot)
	g.mu.Lock()
	g.opening--
	if owner != nil {
		slot.owner = owner
	}
	closed := g.consumerClosed
	close, parent := g.retireLockedV1()
	g.mu.Unlock()
	s.mu.Lock()
	s.auditOpening = false
	if err == nil && !s.consumerClosed {
		s.auditNext++
	} else {
		closed = true
	}
	s.mu.Unlock()
	if closed && owner != nil {
		owner.CloseConsumerV1()
	}
	releaseReminderAuditsV1(close, parent)
	if err != nil {
		return nil, err
	}
	if closed {
		return nil, ErrReminderV1
	}
	return owner, nil
}
