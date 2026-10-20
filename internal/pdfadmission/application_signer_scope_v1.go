// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

// ApplicationSignerScopeV1 is an actual factory-owned, fixed-size lookup
// observation. Its private scope is produced only by the capped unique CASE32
// query on a genuinely globally admitted native session. It is not tenant,
// readiness, controller, source review, signing or mutation authority.
type ApplicationSignerScopeV1 struct {
	state *applicationSignerScopeStateV1
}
type applicationSignerScopeSnapshotV1 struct {
	org, document, recipient uuid.UUID
	hash                     [sha256.Size]byte
}
type applicationSignerScopeStateV1 struct {
	mu                                 sync.Mutex
	factory                            *applicationSessionFactoryStateV1
	session                            *ApplicationSessionV1
	snapshot                           applicationSignerScopeSnapshotV1
	release                            func()
	resolved, consumerClosed, released bool
	borrowers                          int
	diagnostic                         applicationSignerScopeDiagnosticV1
}

// Caller holds p.mu. The process control owner is explicit and separate from
// the authentic-tenant registry; no Nil or made-up UUID is a tenant account.
func (p *applicationSessionFactoryStateV1) controlsV1Locked() []*applicationSessionOrganisationV1 {
	out := make([]*applicationSessionOrganisationV1, 0, len(p.organisations)+1)
	for _, o := range p.organisations {
		out = append(out, o)
	}
	if p.signerControl != nil {
		out = append(out, p.signerControl)
	}
	return out
}
func (f *ApplicationSessionFactoryV1) signerControlV1(ctx context.Context) (*applicationSessionOrganisationV1, error) {
	if f == nil || f.state == nil || !applicationContextV1(ctx) {
		return nil, ErrApplicationSessionV1
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.signerScopes == nil {
		return nil, ErrApplicationSessionV1
	}
	if p.signerControl == nil {
		p.signerControl = &applicationSessionOrganisationV1{factory: p, processControl: true, guard: make(chan struct{}, 1)}
	}
	return p.signerControl, nil
}
func (f *ApplicationSessionFactoryV1) openSignerProbeSessionV1(ctx context.Context) (*ApplicationSessionV1, error) {
	return f.openSignerProbeSessionWithDiagnosticV1(ctx, nil)
}
func (f *ApplicationSessionFactoryV1) openSignerProbeSessionWithDiagnosticV1(ctx context.Context, scope *applicationSignerScopeStateV1) (*ApplicationSessionV1, error) {
	scope.setProbePhaseV1(signerScopeControlV1)
	o, err := f.signerControlV1(ctx)
	if err != nil {
		return nil, err
	}
	scope.setProbePhaseV1(signerScopeObserverV1)
	if err := o.ensureObserverV1(ctx); err != nil {
		return nil, err
	}
	p := f.state
	scope.setProbePhaseV1(signerScopeOwnerV1)
	s, err := applicationSignerProbeOwnerWithDiagnosticV1(ctx, p, o, scope)
	if err != nil {
		return nil, err
	}
	handle := &ApplicationSessionV1{state: s}
	if scope != nil {
		scope.mu.Lock()
		scope.session = handle
		scope.mu.Unlock()
	}
	scope.setProbePhaseV1(signerScopeStartV1)
	if err := applicationSessionStartForSignerScopeV1(ctx, s, nil, scope); err != nil {
		s.mu.Lock()
		retired := s.retired
		s.mu.Unlock()
		if retired {
			p.mu.Lock()
			delete(p.sessions, s)
			p.mu.Unlock()
		}
		return handle, err
	}
	scope.setProbePhaseV1(signerScopeBeginV1)
	return applicationSessionBeginOwnedV1(ctx, handle)
}

// Select/register only; the caller still performs the original physical
// session start and transaction begin after this pre-dispatch gate.
func applicationSignerProbeOwnerV1(ctx context.Context, p *applicationSessionFactoryStateV1, o *applicationSessionOrganisationV1) (*applicationOwnedSessionV1, error) {
	return applicationSignerProbeOwnerWithDiagnosticV1(ctx, p, o, nil)
}
func applicationSignerProbeOwnerWithDiagnosticV1(ctx context.Context, p *applicationSessionFactoryStateV1, o *applicationSessionOrganisationV1, scope *applicationSignerScopeStateV1) (*applicationOwnedSessionV1, error) {
	for {
		p.mu.Lock()
		if p.closing {
			p.mu.Unlock()
			return nil, ErrApplicationSessionV1
		}
		var joining *applicationOwnedSessionV1
		// Match tenant OpenV1: only an original actively retiring owner may be
		// joined. True unknown/abandoned work still quarantines process dispatch.
		for old := range p.sessions {
			old.mu.Lock()
			blocked := old.organisation == o && (old.closed || old.unknown) && !old.retired
			canJoin := old.organisation == o && old.closed && old.retiring > 0 && (!old.unknown || old.retired)
			old.mu.Unlock()
			if blocked && !canJoin {
				p.mu.Unlock()
				scope.setProbePhaseV1(signerScopeQuarantineV1)
				return nil, ErrApplicationSessionUnknownV1
			}
			if canJoin {
				joining = old
			}
		}
		if joining != nil {
			p.mu.Unlock()
			scope.setProbePhaseV1(signerScopeJoinV1)
			if err := applicationSessionWaitRetiringV1(ctx, joining); err != nil {
				return nil, err
			}
			scope.setProbePhaseV1(signerScopeOwnerV1)
			continue
		}
		if len(p.sessions) >= applicationSessionMaxWorkV1 {
			p.mu.Unlock()
			scope.setProbePhaseV1(signerScopeRegistryV1)
			return nil, ErrApplicationSessionV1
		}
		if !applicationContextV1(ctx) {
			p.mu.Unlock()
			return nil, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, nil)
		}
		s := applicationSessionNewOwnerV1(o, uuid.Nil, false)
		p.sessions[s] = struct{}{}
		p.mu.Unlock()
		return s, nil
	}
}
func applicationSessionBeginOwnedV1(ctx context.Context, handle *ApplicationSessionV1) (*ApplicationSessionV1, error) {
	if handle == nil || handle.state == nil || !applicationContextV1(ctx) {
		return handle, ErrApplicationSessionV1
	}
	s := handle.state
	ownCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed || s.retired || s.unknown || !s.dialed || s.factory == nil || s.organisation == nil || s.conn == nil || s.fence == nil {
		s.mu.Unlock()
		cancel()
		return handle, ErrApplicationSessionUnknownV1
	}
	s.active = 1
	s.creating = true
	s.cancel = cancel
	conn := s.conn
	s.mu.Unlock()
	tx, err := conn.BeginTx(ownCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	cancel()
	s.mu.Lock()
	s.active = 0
	s.creating = false
	s.cancel = nil
	s.tx = tx
	terminal := s.closed || s.retired
	if err != nil || terminal {
		s.unknown = true
	}
	applicationSessionSignalV1(s)
	s.mu.Unlock()
	if err != nil || terminal {
		return handle, applicationSessionErrorV1(ctx, ErrApplicationSessionUnknownV1, err)
	}
	return handle, nil
}

// ProbeSignerScopeV1 copies exactly32 presented bytes before any wait. Global
// header and SQL grants share the configured coordinator; no caller tenant is
// consulted. Ambiguous/missing scope is refused by the fixed cap-two query.
// On uncertainty the factory retains actual session and parent loan ownership.
func (f *ApplicationSessionFactoryV1) ProbeSignerScopeV1(ctx context.Context, hash []byte) (*ApplicationSignerScopeV1, error) {
	return f.ProbeSignerScopeForRouteV1(ctx, hash, SignerReadDiagnosticOtherV1)
}

// The route is a fixed diagnostic label only. It cannot select a scope, query,
// credential, resource limit or retry policy.
func (f *ApplicationSessionFactoryV1) ProbeSignerScopeForRouteV1(ctx context.Context, hash []byte, route SignerReadDiagnosticRouteV1) (*ApplicationSignerScopeV1, error) {
	if f == nil || f.state == nil || len(hash) != sha256.Size || !applicationContextV1(ctx) {
		return nil, ErrApplicationSessionV1
	}
	var presented [sha256.Size]byte
	copy(presented[:], hash)
	p := f.state
	release, err := p.work.signerProcessHeaderV1(ctx)
	if err != nil {
		return nil, err
	}
	state := &applicationSignerScopeStateV1{factory: p, release: release}
	scope := &ApplicationSignerScopeV1{state: state}
	p.mu.Lock()
	if p.closing || p.signerScopes == nil || len(p.signerScopes) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		release()
		return nil, ErrApplicationSessionV1
	}
	p.signerScopes[state] = struct{}{}
	p.mu.Unlock()
	handle, err := f.openSignerProbeSessionWithDiagnosticV1(ctx, state)
	state.mu.Lock()
	state.session = handle
	state.mu.Unlock()
	if err == nil {
		state.setProbePhaseV1(signerScopeQueryV1)
		err = handle.WithTxV1(ctx, func(owned context.Context, db generated.DBTX) error {
			row, readErr := generated.New(db).ProbeSignerScopeByTokenHashV1(owned, presented[:])
			if readErr != nil {
				return readErr
			}
			if row == nil || row.RecipientID == uuid.Nil || row.DocumentID == uuid.Nil || row.OrgID == uuid.Nil || len(row.MagicTokenHash) != sha256.Size || !bytes.Equal(row.MagicTokenHash, presented[:]) {
				return ErrApplicationSessionV1
			}
			state.mu.Lock()
			state.snapshot = applicationSignerScopeSnapshotV1{org: row.OrgID, document: row.DocumentID, recipient: row.RecipientID, hash: presented}
			state.resolved = true
			state.mu.Unlock()
			return nil
		})
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if handle != nil {
		if err == nil {
			state.setProbePhaseV1(signerScopeCloseV1)
		}
		if closeErr := handle.CloseV1(cleanup); closeErr != nil {
			state.mu.Lock()
			state.diagnostic.cleanupClass = signerScopeErrorClassV1(closeErr)
			state.mu.Unlock()
			if err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		scope.logProbeRefusalV1(ctx, route, SignerReadDiagnosticLookupV1, err)
		scope.CloseConsumerV1()
		return scope, err
	}
	if !handle.RetiredV1() {
		state.setProbePhaseV1(signerScopeRetirementV1)
		scope.logProbeRefusalV1(ctx, route, SignerReadDiagnosticLookupV1, ErrApplicationSessionUnknownV1)
		scope.CloseConsumerV1()
		return scope, ErrApplicationSessionUnknownV1
	}
	return scope, nil
}
func (s *ApplicationSignerScopeV1) borrowV1(factory *ApplicationSessionFactoryV1) (applicationSignerScopeSnapshotV1, func(), error) {
	if s == nil || s.state == nil || factory == nil || factory.state == nil {
		return applicationSignerScopeSnapshotV1{}, nil, ErrApplicationSessionV1
	}
	p := s.state
	p.mu.Lock()
	if p.factory != factory.state || p.consumerClosed || p.released || !p.resolved || p.session == nil || !p.session.RetiredV1() {
		p.mu.Unlock()
		return applicationSignerScopeSnapshotV1{}, nil, ErrApplicationSessionV1
	}
	snapshot := p.snapshot
	p.borrowers++
	p.mu.Unlock()
	var once sync.Once
	return snapshot, func() { once.Do(func() { p.mu.Lock(); p.borrowers--; p.mu.Unlock(); p.reconcileV1() }) }, nil
}

// CloseConsumerV1 closes this fixed scope's actual consumer only. Borrowers and
// actual client/backend retirement must also finish; it never credits SQL or
// declares any scope/credential/operation replayable after uncertainty.
func (s *ApplicationSignerScopeV1) CloseConsumerV1() {
	if s == nil || s.state == nil {
		return
	}
	p := s.state
	p.mu.Lock()
	p.consumerClosed = true
	p.mu.Unlock()
	p.reconcileV1()
}
func (p *applicationSignerScopeStateV1) reconcileV1() bool {
	p.mu.Lock()
	if p.released {
		p.mu.Unlock()
		return true
	}
	if !p.consumerClosed || p.borrowers != 0 || (p.session != nil && !p.session.RetiredV1()) {
		p.mu.Unlock()
		return false
	}
	release := p.release
	p.release = nil
	p.released = true
	p.snapshot = applicationSignerScopeSnapshotV1{}
	factory := p.factory
	p.mu.Unlock()
	if release != nil {
		release()
	}
	factory.mu.Lock()
	delete(factory.signerScopes, p)
	factory.mu.Unlock()
	return true
}
func (f *ApplicationSessionFactoryV1) reconcileSignerScopesV1(ctx context.Context) error {
	if f == nil || f.state == nil || !applicationContextV1(ctx) {
		return ErrApplicationSessionV1
	}
	p := f.state
	p.mu.Lock()
	list := make([]*applicationSignerScopeStateV1, 0, len(p.signerScopes))
	for scope := range p.signerScopes {
		list = append(list, scope)
	}
	p.mu.Unlock()
	// Open consumers/borrowers are healthy retained ownership, not a global
	// cleanup error. Factory.Close separately checks the retained map after all
	// session retirement, as it does for the existing admission registries.
	for _, scope := range list {
		scope.reconcileV1()
	}
	return nil
}
