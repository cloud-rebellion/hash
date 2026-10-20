// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Fixed native connection reserved BEFORE request/provider processing. It is
// not an open transaction and exposes no Conn, DBTX, caller statement or row.
// Its one command can consume only this workflow's opaque actual observation.
type ApplicationDocumentAIAccountingV1 struct {
	state *applicationDocumentAIAccountingStateV1
}
type applicationDocumentAIAccountingStateV1 struct {
	mu                                             sync.Mutex
	self                                           *ApplicationDocumentAIAccountingV1
	factory                                        *ApplicationSessionFactoryV1
	session                                        *ApplicationSessionV1
	org, document                                  uuid.UUID
	lifetime                                       context.Context
	cancel, startingCancel                         context.CancelFunc
	initial, body                                  *workguard.GrantV1
	work                                           *applicationDocumentAIStateV1
	request                                        *ApplicationDocumentAIRequestReceiptV1
	runtime                                        *ApplicationDocumentAIRuntimeV1
	provider, model, prompt                        string
	version                                        int
	usage                                          *ApplicationDocumentAIUsageReceiptV1
	active                                         int
	creating, prepared, attempted, closed, retired bool
}

func (f *ApplicationSessionFactoryV1) ReserveDocumentAIAccountingV1(ctx context.Context, org, document uuid.UUID) (*ApplicationDocumentAIAccountingV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || document == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrDocumentAIAuditV1
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, ErrDocumentAIAuditV1
	}
	// This is the reservation's maximum lifespan, NOT the incurred-cost clock.
	// Only actual observation below starts a fresh ten-second accounting bound.
	life, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline.Add(authoring.MutationTimeout))
	start, stop := context.WithCancel(ctx)
	s := &applicationDocumentAIAccountingStateV1{factory: f, org: org, document: document, lifetime: life, cancel: cancel, startingCancel: stop, creating: true, active: 1}
	h := &ApplicationDocumentAIAccountingV1{state: s}
	s.self = h
	p := f.state
	p.mu.Lock()
	index := -1
	if !p.closing && p.work != nil && p.work.coordinator != nil {
		for i, old := range p.documentAIAccountings {
			if old == nil {
				index = i
				break
			}
		}
	}
	if index >= 0 {
		p.documentAIAccountings[index] = s
	}
	p.mu.Unlock()
	if index < 0 {
		stop()
		cancel()
		return nil, ErrDocumentAIAuditV1
	}
	fixed := 4*int64(unsafe.Sizeof(applicationDocumentAIAccountingStateV1{})) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIUsageReceiptV1{})) + 4096
	grant, err := p.work.coordinator.TryAcquireV1(ctx, org, workguard.VectorV1{ParentBytes: fixed})
	s.mu.Lock()
	s.initial = grant
	s.mu.Unlock()
	var physical *ApplicationSessionV1
	if err == nil {
		physical, err = f.openProfileV1(start, org, document, nil, true)
	}
	stop()
	s.mu.Lock()
	s.session = physical
	s.startingCancel = nil
	s.creating = false
	s.active--
	closed := s.closed
	s.mu.Unlock()
	if closed && err == nil {
		err = ErrDocumentAIAuditV1
	}
	if err != nil {
		h.CloseConsumerV1()
	}
	return h, err
}

// Original actual metadata is known before Shield/provider processing. Own the
// command's typed params, clones and DB staging BEFORE any external cost can be
// incurred. A capacity failure here cannot leave unrecordable provider usage.
func (h *ApplicationDocumentAIAccountingV1) PrepareUsageV1(ctx context.Context, w *ApplicationDocumentAIWorkV1, r *ApplicationDocumentAIRequestReceiptV1, owner *ApplicationDocumentAIRuntimeV1, provider, model, prompt string, version int) error {
	if h == nil || h.state == nil || w == nil || w.state == nil || owner == nil || !applicationContextV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != h || s.closed || s.retired || s.creating || s.prepared || s.session == nil || version < 0 || int64(version) > 1<<31-1 {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	s.active++
	s.prepared = true
	s.mu.Unlock()
	defer s.finishV1()
	d := w.state
	d.mu.Lock()
	valid := d.validV1(ctx) && !d.requested && d.snapshot != nil && d.runtimeOwner == owner && d.requestMatchesV1(r) && ai.NativeWorkflowFromContextV1(ctx) == owner && d.session.state.factory == s.factory.state && d.session.state.org == s.org && d.session.state.document == s.document
	d.mu.Unlock()
	if !valid {
		return ErrDocumentAIAuditV1
	}
	cost, err := documentAIAccountingQuoteV1(int64(len(provider)), int64(len(model)), int64(len(prompt)))
	if err != nil {
		return err
	}
	grant, err := s.factory.state.work.coordinator.TryAcquireV1(ctx, s.org, cost)
	if err != nil {
		return errors.Join(ErrDocumentAIAuditV1, err)
	}
	s.mu.Lock()
	s.body = grant
	if s.closed || s.lifetime.Err() != nil {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	s.work = d
	s.request = r
	s.runtime = owner
	s.provider = strings.Clone(provider)
	s.model = strings.Clone(model)
	s.prompt = strings.Clone(prompt)
	s.version = version
	s.mu.Unlock()
	return nil
}
func documentAIAccountingQuoteV1(provider, model, prompt int64) (workguard.VectorV1, error) {
	if provider < 0 || model < 0 || prompt < 0 {
		return workguard.VectorV1{}, ErrDocumentAIAuditV1
	}
	raw, err := htmlAuthoringSumV1(provider, model, prompt, 17, 9)
	if err != nil {
		return workguard.VectorV1{}, ErrDocumentAIAuditV1
	}
	parent := 8*int64(unsafe.Sizeof(generated.InsertAICompletionAuditParams{})) + 4*int64(unsafe.Sizeof(generated.PersistDocumentAIUsageV1Params{})) + 4*int64(unsafe.Sizeof(generated.PersistSignerAIUsageV1Params{})) + 4096
	db := int64(8192)
	if !htmlInputAddV1(&parent, raw, 16) || !htmlInputAddV1(&db, raw, 16) {
		return workguard.VectorV1{}, ErrDocumentAIAuditV1
	}
	return workguard.VectorV1{ParentBytes: parent, DBStagingBytes: db}, nil
}

// Only this actual runtime-created opaque observation may start cost-only work
// after original delivery cancellation. It supplies no new provider/result or
// credential authority and accepts no caller-computed usage params/row.
func (h *ApplicationDocumentAIAccountingV1) ObserveUsageV1(origin context.Context, w *ApplicationDocumentAIWorkV1, r *ApplicationDocumentAIRequestReceiptV1, owner *ApplicationDocumentAIRuntimeV1, observation *ai.CompletionObservationV1) (*ApplicationDocumentAIUsageReceiptV1, error) {
	if h == nil || h.state == nil || w == nil || w.state == nil || owner == nil || observation == nil || origin == nil {
		return nil, ErrDocumentAIAuditV1
	}
	params, err := observation.ParamsForV1(owner, origin)
	if err != nil {
		return nil, errors.Join(ErrDocumentAIAuditV1, err)
	}
	s := h.state
	s.mu.Lock()
	if s.self != h || s.closed || s.retired || s.creating || !s.prepared || s.body == nil || s.work != w.state || s.request != r || s.runtime != owner || s.usage != nil || s.lifetime.Err() != nil || params.Provider != s.provider || params.Model != s.model || params.PromptName != s.prompt || params.PromptVersion != int32(s.version) {
		s.mu.Unlock()
		return nil, ErrDocumentAIAuditV1
	}
	s.active++
	s.mu.Unlock()
	defer s.finishV1()
	d := w.state
	d.mu.Lock()
	// Parent cancellation is deliberately not a predicate here. The original
	// still-running callback, registered workflow borrower and opaque observation
	// prove an already-authorized completion; reader.valid(origin) would lose it.
	p := d.session.state
	p.mu.Lock()
	valid := !d.closed && !d.requested && d.snapshot != nil && d.runtimeOwner == owner && d.workflowActive > 0 && !d.usageObserved && d.requestMatchesV1(r) && p.callbackActive && !p.closed && !p.ended && !p.retired && !p.unknown && origin.Value(applicationSessionCallbackKeyV1{}) == p
	p.mu.Unlock()
	if valid {
		d.usageObserved = true
	}
	d.mu.Unlock()
	if !valid || params.OrgID != s.org || params.DocumentID.Bytes != s.document || !params.DocumentID.Valid || params.ActorUserID != d.auditActorV1() || params.InputTokens < 0 || params.OutputTokens < 0 || params.LatencyMs < 0 || (params.Error != "" && params.Error != "completion failed") {
		return nil, ErrDocumentAIAuditV1
	}
	switch params.TransferJurisdiction {
	case "EU->EU", "EU->US", "EU->OTHER", "unknown", "local":
	default:
		return nil, ErrDocumentAIAuditV1
	}
	deadline, _ := s.lifetime.Deadline()
	now := time.Now().Add(authoring.MutationTimeout)
	if now.Before(deadline) {
		deadline = now
	}
	cost, cancel := context.WithDeadline(context.WithoutCancel(origin), deadline)
	if cost.Err() != nil {
		cancel()
		return nil, ErrDocumentAIAuditV1
	}
	// Metadata and every clone were reserved before dispatch. Original numeric
	// usage survives cancellation; no generated text/diagnostics enter this row.
	params.Provider = strings.Clone(params.Provider)
	params.Model = strings.Clone(params.Model)
	params.PromptName = strings.Clone(params.PromptName)
	params.Error = strings.Clone(params.Error)
	params.TransferJurisdiction = strings.Clone(params.TransferJurisdiction)
	u := &ApplicationDocumentAIUsageReceiptV1{dispatch: d, request: r, params: params, observed: true, accounting: s, cost: cost, cancel: cancel}
	u.self = u
	u.cost = context.WithValue(cost, applicationDocumentAICostContextKeyV1{}, u)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.usage != nil {
		cancel()
		return nil, ErrDocumentAIAuditV1
	}
	s.usage = u
	return u, nil
}

// One autocommitted fixed INSERT. No retry or adoption of a duplicate/old row;
// command acknowledgement is independent of later cost-event/result rollback.
func (h *ApplicationDocumentAIAccountingV1) PersistUsageV1(u *ApplicationDocumentAIUsageReceiptV1) error {
	if h == nil || h.state == nil || u == nil {
		return ErrDocumentAIAuditV1
	}
	s := h.state
	if err := u.beginV1(false); err != nil {
		return err
	}
	defer u.finishV1()
	s.mu.Lock()
	if s.self != h || s.closed || s.retired || s.attempted || s.usage != u || s.session == nil || s.lifetime.Err() != nil {
		s.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	s.attempted = true
	s.active++
	physical := s.session
	s.mu.Unlock()
	defer s.finishV1()
	p := u.params
	q := generated.New(&documentAIUsageDBTXV1{state: s, usage: u})
	var rows int64
	var err error
	if u.dispatch.signer != nil {
		rows, err = q.PersistSignerAIUsageV1(u.cost, generated.PersistSignerAIUsageV1Params{RequestEventID: u.request.id, OrgID: p.OrgID, DocumentID: s.document, RecipientID: u.dispatch.signer.recipient, Provider: p.Provider, Model: p.Model, PromptName: p.PromptName, PromptVersion: p.PromptVersion, ShieldActive: p.ShieldActive, InputTokens: p.InputTokens, OutputTokens: p.OutputTokens, LatencyMs: p.LatencyMs, Success: p.Success, Error: p.Error, TransferJurisdiction: p.TransferJurisdiction})
	} else {
		rows, err = q.PersistDocumentAIUsageV1(u.cost, generated.PersistDocumentAIUsageV1Params{RequestEventID: u.request.id, OrgID: p.OrgID, DocumentID: s.document, ActorUserID: u.dispatch.actor, Provider: p.Provider, Model: p.Model, PromptName: p.PromptName, PromptVersion: p.PromptVersion, ShieldActive: p.ShieldActive, InputTokens: p.InputTokens, OutputTokens: p.OutputTokens, LatencyMs: p.LatencyMs, Success: p.Success, Error: p.Error, TransferJurisdiction: p.TransferJurisdiction})
	}
	physical.state.mu.Lock()
	physical.state.ended = true
	if err != nil || u.cost.Err() != nil {
		physical.state.unknown = true
	}
	physical.state.mu.Unlock()
	if err != nil || u.cost.Err() != nil {
		return applicationSessionErrorV1(u.cost, nil, err)
	}
	if rows != 1 {
		return ErrDocumentAIAuditV1
	}
	u.mu.Lock()
	u.persisted = true
	u.mu.Unlock()
	return nil
}

type documentAIUsageDBTXV1 struct {
	state *applicationDocumentAIAccountingStateV1
	usage *ApplicationDocumentAIUsageReceiptV1
}

func (d *documentAIUsageDBTXV1) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	if d == nil || d.state == nil || d.usage == nil || ctx != d.usage.cost || !applicationContextV1(ctx) {
		return pgconn.CommandTag{}, ErrDocumentAIAuditV1
	}
	a := d.state
	a.mu.Lock()
	valid := !a.closed && !a.retired && a.active > 0 && a.attempted && a.usage == d.usage && a.session != nil
	h := a.session
	a.mu.Unlock()
	if !valid {
		return pgconn.CommandTag{}, ErrDocumentAIAuditV1
	}
	s := h.state
	s.mu.Lock()
	if s.closed || s.ended || s.unknown || s.creating || s.sqlActive || s.callbackActive || s.tx != nil || s.conn == nil {
		s.mu.Unlock()
		return pgconn.CommandTag{}, ErrApplicationSessionV1
	}
	owned, cancel := context.WithCancel(ctx)
	s.active++
	s.sqlActive = true
	s.cancelSQL = cancel
	conn := s.conn
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		s.active--
		s.sqlActive = false
		s.cancelSQL = nil
		applicationSessionSignalV1(s)
		s.mu.Unlock()
	}()
	tag, err := conn.Exec(owned, query, args...)
	if err != nil {
		return tag, applicationSessionErrorV1(ctx, nil, err)
	}
	return tag, nil
}
func (*documentAIUsageDBTXV1) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, ErrDocumentAIAuditV1
}
func (*documentAIUsageDBTXV1) QueryRow(context.Context, string, ...any) pgx.Row {
	return documentAIUsageDeniedRowV1{}
}

type documentAIUsageDeniedRowV1 struct{}

func (documentAIUsageDeniedRowV1) Scan(...any) error { return ErrDocumentAIAuditV1 }

func (s *applicationDocumentAIAccountingStateV1) finishV1() { s.mu.Lock(); s.active--; s.mu.Unlock() }
func (h *ApplicationDocumentAIAccountingV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	s.closed = true
	cancel, start := s.cancel, s.startingCancel
	u := s.usage
	s.mu.Unlock()
	if start != nil {
		start()
	}
	if cancel != nil {
		cancel()
	}
	if u != nil {
		u.CloseConsumerV1()
	}
}
func (h *ApplicationDocumentAIAccountingV1) CloseV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	h.CloseConsumerV1()
	return h.state.reconcileV1(ctx)
}
func (s *applicationDocumentAIAccountingStateV1) reconcileV1(ctx context.Context) error {
	if !applicationContextV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	s.mu.Lock()
	if s.retired {
		s.mu.Unlock()
		return nil
	}
	if !s.closed || s.creating || s.active != 0 {
		s.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	h := s.session
	u := s.usage
	s.mu.Unlock()
	if h != nil {
		if err := h.CloseV1(ctx); err != nil {
			return err
		}
		if !h.RetiredV1() {
			return ErrApplicationSessionUnknownV1
		}
	}
	if u != nil && !u.retiredV1() {
		return ErrApplicationSessionUnknownV1
	}
	s.mu.Lock()
	if s.retired || s.active != 0 || s.creating {
		s.mu.Unlock()
		return ErrApplicationSessionUnknownV1
	}
	s.retired = true
	initial, body := s.initial, s.body
	s.initial = nil
	s.body = nil
	s.work = nil
	s.request = nil
	s.runtime = nil
	s.usage = nil
	s.lifetime = nil
	s.cancel = nil
	s.session = nil
	s.provider = ""
	s.model = ""
	s.prompt = ""
	s.mu.Unlock()
	if body != nil {
		body.Close()
	}
	if initial != nil {
		initial.Close()
	}
	p := s.factory.state
	p.mu.Lock()
	for i, old := range p.documentAIAccountings {
		if old == s {
			p.documentAIAccountings[i] = nil
		}
	}
	p.mu.Unlock()
	return nil
}
func (f *ApplicationSessionFactoryV1) reconcileDocumentAIAccountingsV1(ctx context.Context) error {
	if f == nil || f.state == nil {
		return nil
	}
	p := f.state
	p.mu.Lock()
	list := p.documentAIAccountings
	p.mu.Unlock()
	var out error
	for _, s := range list {
		if s == nil {
			continue
		}
		s.mu.Lock()
		closed := s.closed
		s.mu.Unlock()
		if closed {
			out = errors.Join(out, s.reconcileV1(ctx))
		}
	}
	return out
}
