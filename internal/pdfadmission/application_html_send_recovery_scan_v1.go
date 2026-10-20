// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"time"
	"unsafe"
)

// Recovery scopes are point-in-time UUID observations, not tenant, credential,
// source, policy or mutation authority. Resume opens its own genuine org/doc
// owner and repeats every original lifecycle check. The original fixed50 queue
// predicates and ordering are preserved; no full intent TEXT is fetched here.
type HTMLSendRecoveryScopeV1 struct{ DocumentID, OrgID uuid.UUID }
type ApplicationHTMLSendRecoveryScanV1 struct {
	state *applicationHTMLSendRecoveryScanStateV1
}
type applicationHTMLSendRecoveryScanStateV1 struct {
	mu                                                    sync.Mutex
	factory                                               *applicationSessionFactoryStateV1
	session                                               *ApplicationSessionV1
	ctx                                                   context.Context
	cancel                                                context.CancelFunc
	scopes                                                [50]HTMLSendRecoveryScopeV1
	count                                                 int
	release                                               func()
	active, resolved, delivered, consumerClosed, released bool
}

func (f *ApplicationSessionFactoryV1) ScanPendingHTMLSendRecoveryScopesV1(ctx context.Context) (*ApplicationHTMLSendRecoveryScanV1, error) {
	if f == nil || f.state == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLSendWorkV1
	}
	p := f.state
	original, cancel := context.WithCancel(ctx)
	s := &applicationHTMLSendRecoveryScanStateV1{factory: p, ctx: original, cancel: cancel, active: true}
	h := &ApplicationHTMLSendRecoveryScanV1{state: s}
	// Register BEFORE the real process loan/Open. active keeps this owner visible
	// if shutdown/reconciliation observes it while native Open is still in flight.
	p.mu.Lock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.sendRecoveryScans == nil || len(p.sendRecoveryScans) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		cancel()
		return nil, ErrHTMLSendWorkV1
	}
	p.sendRecoveryScans[s] = struct{}{}
	// Reuse the existing fixed process-lookup header CLASS, with separately named
	// complete actual UUID row/container staging. This is a logical admission
	// policy, never a PostgreSQL executor/allocator or process-RSS proof.
	fixed := applicationSignerScopeHeaderBytesV1 + int64(unsafe.Sizeof(applicationHTMLSendRecoveryScanStateV1{})) + 50*(int64(unsafe.Sizeof(generated.ListPendingSendRecoveryScopesV1Row{}))+2*int64(unsafe.Sizeof(HTMLSendRecoveryScopeV1{}))+2*int64(unsafe.Sizeof(uintptr(0))))
	grant, err := p.work.coordinator.TryAcquireProcessV1(original, workguard.VectorV1{ParentBytes: fixed, DBStagingBytes: fixed})
	if err == nil {
		s.release = grant.Close
	}
	p.mu.Unlock()
	if err != nil {
		s.mu.Lock()
		s.active = false
		s.consumerClosed = true
		s.mu.Unlock()
		cancel()
		s.reconcileV1()
		return h, errors.Join(ErrHTMLSendWorkV1, err)
	}
	// The existing opener is the actual explicit processControl native session,
	// with the same coordinator, physical fence and unknown-start recovery. No
	// signer scope, fake tenant UUID or caller DB/transaction is adopted.
	session, err := f.openSignerProbeSessionV1(original)
	s.mu.Lock()
	s.session = session
	closed := s.consumerClosed
	s.mu.Unlock()
	if err == nil && !closed {
		err = session.WithTxV1(original, func(call context.Context, db generated.DBTX) error {
			rows, readErr := generated.New(db).ListPendingSendRecoveryScopesV1(call)
			if readErr != nil {
				return readErr
			}
			if len(rows) > 50 {
				return ErrHTMLSendWorkV1
			}
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.consumerClosed {
				return ErrHTMLSendWorkV1
			}
			for i, row := range rows {
				if row == nil || row.DocumentID == uuid.Nil || row.OrgID == uuid.Nil {
					return ErrHTMLSendWorkV1
				}
				s.scopes[i] = HTMLSendRecoveryScopeV1{DocumentID: row.DocumentID, OrgID: row.OrgID}
			}
			s.count = len(rows)
			s.resolved = true
			return nil
		})
	} else if err == nil {
		err = ErrHTMLSendWorkV1
	}
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	if session != nil {
		if closeErr := session.CloseV1(cleanup); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}
	stop()
	s.mu.Lock()
	s.active = false
	s.mu.Unlock()
	s.reconcileV1()
	if err != nil {
		h.CloseConsumerV1()
		return h, errors.Join(ErrHTMLSendWorkV1, err)
	}
	if session == nil || !session.RetiredV1() {
		h.CloseConsumerV1()
		return h, ErrApplicationSessionUnknownV1
	}
	return h, nil
}

// Exactly one defensive view is delivered under the original fixed producer
// budget. Copies share the same consumer/delivery state and cannot replay it.
func (h *ApplicationHTMLSendRecoveryScanV1) ScopesV1() ([]HTMLSendRecoveryScopeV1, error) {
	if h == nil || h.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active || !s.resolved || s.delivered || s.consumerClosed || s.released || s.session == nil || !s.session.RetiredV1() {
		return nil, ErrHTMLSendWorkV1
	}
	s.delivered = true
	out := make([]HTMLSendRecoveryScopeV1, s.count)
	copy(out, s.scopes[:s.count])
	return out, nil
}
func (h *ApplicationHTMLSendRecoveryScanV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.consumerClosed = true
	cancel := s.cancel
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.reconcileV1()
}
func (s *applicationHTMLSendRecoveryScanStateV1) reconcileV1() bool {
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return true
	}
	if !s.consumerClosed || s.active || (s.session != nil && !s.session.RetiredV1()) {
		s.mu.Unlock()
		return false
	}
	release := s.release
	s.release = nil
	s.scopes = [50]HTMLSendRecoveryScopeV1{}
	s.count = 0
	s.ctx = nil
	s.cancel = nil
	s.released = true
	p := s.factory
	s.mu.Unlock()
	if release != nil {
		release()
	}
	p.mu.Lock()
	delete(p.sendRecoveryScans, s)
	p.mu.Unlock()
	return true
}
func (f *ApplicationSessionFactoryV1) reconcileHTMLSendRecoveryScansV1() {
	if f == nil || f.state == nil {
		return
	}
	p := f.state
	p.mu.Lock()
	list := make([]*applicationHTMLSendRecoveryScanStateV1, 0, len(p.sendRecoveryScans))
	for s := range p.sendRecoveryScans {
		list = append(list, s)
	}
	p.mu.Unlock()
	for _, s := range list {
		s.reconcileV1()
	}
}
