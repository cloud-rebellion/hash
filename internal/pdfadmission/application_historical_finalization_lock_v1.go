// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"sync"
	"time"
	"unsafe"
)

const applicationFinalizationCleanupBudgetV1 = 5 * time.Second

var ErrHistoricalFinalizationLockV1 = errors.New("pdfadmission: owned finalization serialization unavailable")
var ErrHistoricalFinalizationBusyV1 = errors.New("pdfadmission: finalization already serialized")

// One dedicated actual native connection owns the original session advisory
// lock across separate committed claim/stage/publish phases. It never remains
// idle in a transaction while rendering, exposes no connection/DBTX/SQL, and
// cannot be substituted by a caller lock boolean. Copies share the same owner.
type ApplicationHistoricalFinalizationLockV1 struct {
	state *applicationHistoricalFinalizationLockStateV1
}
type applicationHistoricalFinalizationLockStateV1 struct {
	mu                   sync.Mutex
	self                 *applicationHistoricalFinalizationLockStateV1
	factory              *ApplicationSessionFactoryV1
	session              *ApplicationSessionV1
	actor                *ApplicationHTMLAuthoringReaderV1
	closeBody            func()
	org, document        uuid.UUID
	acquired, closed     bool
	stageReference       ApplicationHistoricalFinalizationStageReferenceV1
	stageCommitment      applicationHistoricalFinalizationStageCommitmentV1
	stagePrepared        bool
	publicationReference ApplicationHistoricalFinalizationPublicationReferenceV1
	publicationIntent    *generated.DocumentFinalizationIntent
	publicationGrant     *workguard.GrantV1
	providerContext      context.Context
	stopProviders        context.CancelFunc
}

func (f *ApplicationSessionFactoryV1) NewHistoricalFinalizationLockV1(ctx context.Context, org, document uuid.UUID) (handle *ApplicationHistoricalFinalizationLockV1, failure error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrHistoricalFinalizationLockV1
	}
	session, err := f.OpenV1(ctx, org, document)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), applicationFinalizationCleanupBudgetV1)
			defer stop()
			err = errors.Join(err, session.CloseV1(cleanup))
		}
		return nil, errors.Join(ErrHistoricalFinalizationLockV1, err)
	}
	var actor *ApplicationHTMLAuthoringReaderV1
	var closeBody func()
	var owner *applicationHistoricalFinalizationLockStateV1
	keep := false
	defer func() {
		if keep {
			return
		}
		if owner != nil {
			owner.mu.Lock()
			owner.closed = true
			if owner.stopProviders != nil {
				owner.stopProviders()
				owner.stopProviders = nil
			}
			owner.providerContext = nil
			owner.mu.Unlock()
		}
		if closeBody != nil {
			closeBody()
		}
		if actor != nil {
			actor.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), applicationFinalizationCleanupBudgetV1)
		defer stop()
		failure = errors.Join(failure, session.CloseV1(cleanup))
		if err := f.ReconcileCleanupV1(cleanup); err != nil && !errors.Is(err, ErrApplicationSessionUnknownV1) {
			failure = errors.Join(failure, err)
		}
	}()
	if _, err = session.NewAdmissionV1(ctx); err != nil {
		return nil, errors.Join(ErrHistoricalFinalizationLockV1, err)
	}
	var got bool
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		actor, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		raw := 2*int64(unsafe.Sizeof(applicationHistoricalFinalizationLockStateV1{})) + 2*int64(unsafe.Sizeof(ApplicationHistoricalFinalizationLockV1{})) + 8*int64(unsafe.Sizeof(uintptr(0)))
		closeBody, err = actor.acquireOwnedRetainedBodyV1(call, raw, 0)
		if err != nil {
			return err
		}
		// Only this genuine serialization owner supplies the provider parent.
		// Its original context already has a finite deadline. Short SQL phases
		// may retire independently without cancelling later frozen-output IO.
		providerContext, stopProviders := context.WithCancel(ctx)
		owner = &applicationHistoricalFinalizationLockStateV1{factory: f, session: session, actor: actor, closeBody: closeBody, org: org, document: document, providerContext: providerContext, stopProviders: stopProviders}
		owner.self = owner
		// Same exact signed 64-bit key as the original public finalizer. The native
		// session SQL grant funds this fixed scalar before the real call.
		key := int64(binary.BigEndian.Uint64(document[:8]))
		if err = db.QueryRow(call, "SELECT pg_try_advisory_lock($1)", key).Scan(&got); err != nil {
			return err
		} //nolint:rawsql
		if !got {
			return ErrHistoricalFinalizationBusyV1
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(ErrHistoricalFinalizationLockV1, err)
	}
	if err = session.CommitV1(ctx); err != nil {
		_ = session.CommitDispatchObservationV1()
		return nil, errors.Join(ErrHistoricalFinalizationLockV1, err)
	}
	owner.acquired = true
	keep = true
	return &ApplicationHistoricalFinalizationLockV1{state: owner}, nil
}

// Verify performs only this fixed identity round-trip on the SAME retained
// dedicated backend. Only this owner acquired its advisory lock; no public
// method can unlock/reuse its connection. A moved/closed/unknown backend never
// grants a serialization proof or permits a compatibility pool fallback.
func (h *ApplicationHistoricalFinalizationLockV1) VerifyV1(ctx context.Context) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrHistoricalFinalizationLockV1
	}
	owner := h.state
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.self != owner || owner.closed || !owner.acquired || owner.session == nil || owner.session.state == nil || owner.factory == nil || owner.factory.state == nil {
		return ErrHistoricalFinalizationLockV1
	}
	s := owner.session.state
	p := owner.factory.state
	p.mu.Lock()
	s.mu.Lock()
	if p.closing || s.factory != p || s.org != owner.org || s.document != owner.document || s.closed || s.unknown || s.retired || s.creating || s.callbackActive || s.sqlActive || !s.ended || s.commitUnknown || s.conn == nil || s.conn.IsClosed() || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrHistoricalFinalizationLockV1
	}
	conn, want := s.conn, s.fence.identity.pid
	call, cancel := context.WithCancel(ctx)
	s.active++
	s.sqlActive = true
	s.cancelSQL = cancel
	s.mu.Unlock()
	p.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.active--
		s.sqlActive = false
		s.cancelSQL = nil
		applicationSessionSignalV1(s)
		s.mu.Unlock()
	}()
	var pid int64
	if err := conn.QueryRow(call, "SELECT pg_backend_pid()::bigint").Scan(&pid); err != nil {
		return errors.Join(ErrHistoricalFinalizationLockV1, err)
	} //nolint:rawsql
	if pid != int64(want) || call.Err() != nil {
		return errors.Join(ErrHistoricalFinalizationLockV1, call.Err())
	}
	return nil
}
func (h *ApplicationHistoricalFinalizationLockV1) CloseV1(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.state == nil || !applicationContextV1(ctx) {
		return ErrHistoricalFinalizationLockV1
	}
	owner := h.state
	owner.mu.Lock()
	if owner.self != owner || owner.session == nil || owner.factory == nil {
		owner.mu.Unlock()
		return ErrHistoricalFinalizationLockV1
	}
	owner.closed = true
	stopProviders := owner.stopProviders
	owner.stopProviders = nil
	owner.providerContext = nil
	owner.stagePrepared = false
	owner.stageCommitment = applicationHistoricalFinalizationStageCommitmentV1{}
	publicationGrant := owner.publicationGrant
	owner.publicationGrant = nil
	owner.publicationIntent = nil
	closeBody, actor, session, factory := owner.closeBody, owner.actor, owner.session, owner.factory
	owner.closeBody = nil
	owner.actor = nil
	owner.mu.Unlock()
	if stopProviders != nil {
		stopProviders()
	}
	if publicationGrant != nil {
		publicationGrant.Close()
	}
	if closeBody != nil {
		closeBody()
	}
	if actor != nil {
		actor.CloseConsumerV1()
	}
	// These are direct native connections, never returned to a pool. Actual
	// physical/backend retirement releases all session advisory locks. The
	// existing loan registry keeps unknown physical debt charged after this
	// logical consumer ends, without needing a synthetic unlock acknowledgement.
	err := session.CloseV1(ctx)
	session.state.mu.Lock()
	admission := session.state.admission
	session.state.mu.Unlock()
	if admission != nil {
		err = errors.Join(err, admission.CloseV1(ctx))
	}
	if failure := factory.ReconcileCleanupV1(ctx); failure != nil && (!errors.Is(failure, ErrApplicationSessionUnknownV1) || errors.Is(failure, context.Canceled) || errors.Is(failure, context.DeadlineExceeded)) {
		err = errors.Join(err, failure)
	}
	return err
}
