// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ApplicationHTMLSendResolutionV1 struct {
	state *applicationHTMLSendResolverV1
}
type HTMLSendBindingObservationV1 struct {
	Resolved *generated.UpdateVariableBindingResolvedParams
	Failed   *generated.UpdateVariableBindingErrorParams
}
type HTMLSendResolutionSnapshotV1 struct {
	Frozen       []byte
	Definitions  []*generated.DocumentVariableBinding
	CRMReports   []resolver.ResolveReport
	Observations []HTMLSendBindingObservationV1
}

// The only producer is registered on the actual same native Work before any
// grant. Its source binding retains the genuine39-field Doc+Current12 body and
// original operation context. No caller JSON/value/report/fetch callback can
// be adopted as a successful resolution or a source allocation receipt.
type applicationHTMLSendResolverV1 struct {
	mu                         sync.Mutex
	self                       *applicationHTMLSendResolverV1
	work                       *ApplicationHTMLSendWorkV1
	source                     *applicationHTMLSendSourceStateV1
	configured                 *resolver.Resolver
	prepared                   *resolver.Resolver
	document                   *generated.Document
	bindings                   []*generated.DocumentVariableBinding
	crmRow                     *generated.CrmConnection
	crmError                   error
	observations               []HTMLSendBindingObservationV1
	crmReports, report         []resolver.ResolveReport
	frozen                     []byte
	sourceCalls                int
	active                     int
	attempted, closed, retired bool
	failure, capacityFailure   error
}

// NewResolverV1 belongs to the fixed preparation callback. Configuration is
// the server's actual Resolver. Native stores replace only its concrete DB
// reads; original Resolve/FreezeForSend/cache/freshness policy remains intact.
func (w *ApplicationHTMLSendWorkV1) NewResolverV1(call context.Context, h *ApplicationHTMLSendSourceV1, configured *resolver.Resolver) (*ApplicationHTMLSendResolutionV1, error) {
	if w == nil || w.self != w || h == nil || h.state == nil || h.state.work != w || h.state.owner == nil || configured == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if _, err := w.ReadBindingsV1(call); err != nil {
		return nil, err
	}
	w.mu.Lock()
	if !w.valid(call) || w.resolverOwner != nil || w.sourceOwner != h.state.owner || w.sourceDocument == nil || w.models == nil {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	p := &applicationHTMLSendResolverV1{work: w, source: h.state, configured: configured, document: w.sourceDocument, bindings: w.sourceBindings}
	p.self = p
	w.resolverOwner = p
	w.mu.Unlock()
	owner := h.state.owner
	if err := owner.beginV1(); err != nil {
		p.CloseConsumerV1()
		return nil, err
	}
	defer owner.finishV1()
	initial, err := htmlSendResolverInputLogicalV1(p.document, p.bindings)
	if err == nil {
		err = htmlSendResolverAddV1(&initial, 1, int64(unsafe.Sizeof(applicationHTMLSendResolverV1{}))+int64(unsafe.Sizeof(resolver.Resolver{}))+8*int64(unsafe.Sizeof(htmlSendNativeHTTPSourceV1{}))+8*int64(unsafe.Sizeof(htmlSendNativeOrgSourceV1{}))+8*64+htmlSendOrgReadScratchV1())
	}
	if err == nil {
		err = owner.holdV1(htmlRevisionSourcePrepareV1, 0, initial)
	}
	if err != nil {
		p.CloseConsumerV1()
		return nil, err
	}
	// This is a bounded configured-kind table, not an iteration/copy of the
	// server plugin map or a customer-provided Source implementation.
	configuredCopy := *configured
	configuredCopy.Q = p
	configuredCopy.Sources = make(map[resolver.SourceKind]resolver.Source, 8)
	crmCount := 0
	for _, b := range p.bindings {
		kind := resolver.SourceKind(b.SourceKind)
		if kind == resolver.SourceCRMDeal || kind == resolver.SourceCRMContact || kind == resolver.SourceCRMCompany {
			crmCount++
		}
		if kind == resolver.SourceStatic {
			continue
		}
		if _, exists := configuredCopy.Sources[kind]; exists {
			continue
		}
		original, exists := configured.Sources[kind]
		if !exists {
			continue
		}
		switch s := original.(type) {
		case *resolver.HTTPSource:
			if s == nil || s.Kind() != kind {
				return nil, ErrHTMLSendWorkV1
			}
			configuredCopy.Sources[kind] = &htmlSendNativeHTTPSourceV1{owner: p, source: s}
		case *resolver.OrgSettingSource:
			if s == nil || kind != resolver.SourceOrgSetting {
				return nil, ErrHTMLSendWorkV1
			}
			configuredCopy.Sources[kind] = &htmlSendNativeOrgSourceV1{owner: p, source: s}
		case resolver.AgentComputedSource:
			if kind != resolver.SourceAgentComputed {
				return nil, ErrHTMLSendWorkV1
			}
			configuredCopy.Sources[kind] = s
		case *resolver.AgentComputedSource:
			if s == nil || kind != resolver.SourceAgentComputed {
				return nil, ErrHTMLSendWorkV1
			}
			configuredCopy.Sources[kind] = s
		default:
			// No callback is treated as a bounded first-party producer. All existing
			// concrete HTTP/CRM/org/agent families above remain supported.
			return nil, ErrHTMLSendWorkV1
		}
	}
	if configured.CRM != nil {
		c := *configured.CRM
		c.Store = p
		configuredCopy.CRM = &c
		if crmCount != 0 && configured.CRM.Store != nil && configured.CRM.Client != nil && configured.CRM.Keys != nil {
			p.crmRow, p.crmError = w.readCRMSourceV1(call)
			if errors.Is(p.crmError, ErrHTMLSendWorkV1) {
				return nil, p.crmError
			}
			scratch, retained, e := htmlSendCRMResolverLogicalV1(crmCount)
			if e != nil {
				return nil, e
			}
			if e = owner.holdV1(htmlRevisionSourcePrepareV1, scratch, retained); e != nil {
				return nil, e
			}
		}
	}
	// At most one real OrgSetting SQL source stage per actual admitted binding;
	// no caller count or unbounded public OpenSQL purpose grants that allowance.
	if err = w.stage.operation.bindResolverV1(p); err != nil {
		return nil, err
	}
	p.prepared = &configuredCopy
	return &ApplicationHTMLSendResolutionV1{state: p}, nil
}
func (p *applicationHTMLSendResolverV1) recordCapacityFailureV1(err error) error {
	if err == nil {
		return nil
	}
	p.mu.Lock()
	if p.capacityFailure == nil {
		p.capacityFailure = err
	}
	p.mu.Unlock()
	return err
}
func (p *applicationHTMLSendResolverV1) liveV1() bool {
	return p != nil && p.self == p && !p.closed && !p.retired && p.work != nil && p.work.self == p.work && p.source != nil && p.source.owner != nil && p.document != nil
}
func (h *ApplicationHTMLSendResolutionV1) FreezeV1() error {
	if h == nil || h.state == nil {
		return ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	if !p.liveV1() || p.prepared == nil {
		p.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	if p.attempted {
		err := p.failure
		p.mu.Unlock()
		return err
	}
	p.attempted = true
	p.failure = ErrHTMLSendWorkV1
	p.active++
	source := p.source
	p.mu.Unlock()
	// The source's actual active borrower joins the unchanged synchronous
	// resolver, including HTTP Body.Close and protected CRM ReadRecords. Neither
	// cancellation nor operation shutdown alone signals a completed producer.
	if !source.lockV1() {
		p.finishV1(nil, nil, ErrHTMLSendWorkV1)
		return ErrHTMLSendWorkV1
	}
	defer source.unlockV1()
	if source.closeRequested.Load() {
		p.finishV1(nil, nil, ErrHTMLSendWorkV1)
		return ErrHTMLSendWorkV1
	}
	owner := source.owner
	if err := owner.beginV1(); err != nil {
		p.finishV1(nil, nil, err)
		return err
	}
	defer owner.finishV1()
	frozen, report, err := p.prepared.FreezeForSend(owner.binding.ctx, p.document)
	p.mu.Lock()
	capacity := p.capacityFailure
	closed := p.closed
	p.mu.Unlock()
	if capacity != nil {
		err = capacity
	}
	if closed && err == nil {
		err = ErrHTMLSendWorkV1
	}
	// Actual frozen/report output is already reserved before each produced value
	// and original final Marshal. Private result/view copies use that same fixed
	// component; no outcome is exposed before successful complete resolution.
	p.finishV1(frozen, report, err)
	return err
}
func (p *applicationHTMLSendResolverV1) finishV1(frozen []byte, report []resolver.ResolveReport, err error) {
	p.mu.Lock()
	if err == nil && !p.closed {
		p.frozen = frozen
		p.report = report
		p.failure = nil
	} else {
		p.failure = err
		if p.failure == nil {
			p.failure = ErrHTMLSendWorkV1
		}
	}
	p.active--
	p.retireV1()
	p.mu.Unlock()
}
func (p *applicationHTMLSendResolverV1) retireV1() {
	if !p.closed || p.retired || p.active != 0 {
		return
	}
	p.retired = true
	p.document = nil
	p.bindings = nil
	p.crmRow = nil
	p.prepared = nil
	p.configured = nil
	p.frozen = nil
	p.report = nil
	p.crmReports = nil
	p.observations = nil
	p.source = nil
	p.work = nil
	p.failure = nil
	p.capacityFailure = nil
}
func (p *applicationHTMLSendResolverV1) CloseConsumerV1() {
	if p == nil || p.self != p {
		return
	}
	p.mu.Lock()
	p.closed = true
	p.retireV1()
	p.mu.Unlock()
}

func (p *applicationHTMLSendResolverV1) ListVariableBindings(ctx context.Context, id uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || p.active == 0 || id != p.document.ID || ctx != p.source.owner.binding.ctx {
		return nil, ErrHTMLSendWorkV1
	}
	return p.bindings, nil
}
func (p *applicationHTMLSendResolverV1) GetCRMConnectionByOrg(ctx context.Context, id uuid.UUID) (*generated.CrmConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || p.active == 0 || id != p.document.OrgID || ctx != p.source.owner.binding.ctx {
		return nil, ErrHTMLSendWorkV1
	}
	if p.crmError != nil {
		return nil, p.crmError
	}
	if p.crmRow == nil {
		return nil, pgx.ErrNoRows
	}
	return p.crmRow, nil
}
func (p *applicationHTMLSendResolverV1) StageVariableBindingResolved(ctx context.Context, arg generated.UpdateVariableBindingResolvedParams) error {
	if err := p.retainValueV1(ctx, arg.DocumentID, arg.OrgID, arg.LastValue); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || p.active == 0 {
		return ErrHTMLSendWorkV1
	}
	copy := arg
	p.observations = append(p.observations, HTMLSendBindingObservationV1{Resolved: &copy})
	return nil
}
func (p *applicationHTMLSendResolverV1) StageVariableBindingError(ctx context.Context, arg generated.UpdateVariableBindingErrorParams) error {
	if err := p.retainValueV1(ctx, arg.DocumentID, arg.OrgID, arg.LastError); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || p.active == 0 {
		return ErrHTMLSendWorkV1
	}
	copy := arg
	p.observations = append(p.observations, HTMLSendBindingObservationV1{Failed: &copy})
	return nil
}
func (p *applicationHTMLSendResolverV1) retainValueV1(ctx context.Context, document, org uuid.UUID, value string) error {
	p.mu.Lock()
	if !p.liveV1() || p.active == 0 || document != p.document.ID || org != p.document.OrgID || ctx != p.source.owner.binding.ctx {
		p.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	owner := p.source.owner
	p.mu.Unlock()
	retained, err := htmlSendResolverValueLogicalV1(value)
	if err == nil {
		err = owner.holdV1(htmlRevisionSourcePrepareV1, 0, retained)
	}
	return p.recordCapacityFailureV1(err)
}
func (p *applicationHTMLSendResolverV1) StageCRMReports(ctx context.Context, org, id uuid.UUID, report []resolver.ResolveReport) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || p.active == 0 || p.crmReports != nil || id != p.document.ID || org != p.document.OrgID || ctx != p.source.owner.binding.ctx {
		return resolver.ErrSourceFreshness
	}
	p.crmReports = resolver.CloneSendReportsV1(report)
	return nil
}

// A defensive result view is available exactly once. Mutating that view cannot
// alter the native frozen/candidate proof, original bindings or CRM fences.
func (h *ApplicationHTMLSendResolutionV1) SnapshotV1() (HTMLSendResolutionSnapshotV1, error) {
	var empty HTMLSendResolutionSnapshotV1
	if h == nil || h.state == nil {
		return empty, ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.liveV1() || !p.attempted || p.failure != nil || p.active != 0 || p.sourceCalls != 0 {
		return empty, ErrHTMLSendWorkV1
	}
	p.sourceCalls++
	out := HTMLSendResolutionSnapshotV1{Frozen: bytes.Clone(p.frozen), CRMReports: resolver.CloneSendReportsV1(p.crmReports), Definitions: make([]*generated.DocumentVariableBinding, len(p.bindings)), Observations: make([]HTMLSendBindingObservationV1, len(p.observations))}
	for i, b := range p.bindings {
		copy := *b
		out.Definitions[i] = &copy
	}
	for i, o := range p.observations {
		if o.Resolved != nil {
			copy := *o.Resolved
			out.Observations[i].Resolved = &copy
		}
		if o.Failed != nil {
			copy := *o.Failed
			out.Observations[i].Failed = &copy
		}
	}
	return out, nil
}

// Fixed native resolver provider span. The genuine source and synchronous
// Freeze activity remain live; the factory/coordinator/org come only from that
// private binding. Parent scratch remains separately charged by existing holds.
func (p *applicationHTMLSendResolverV1) providerStreamV1(ctx context.Context) (*workguard.GrantV1, error) {
	if p == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p.mu.Lock()
	if !p.liveV1() || p.active == 0 || p.source.owner == nil || p.source.owner.binding == nil || ctx != p.source.owner.binding.ctx {
		p.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	b := p.source.owner.binding
	p.mu.Unlock()
	factory := b.factory
	if factory == nil || b.org == uuid.Nil {
		return nil, p.recordCapacityFailureV1(ErrHTMLSendWorkV1)
	}
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, p.recordCapacityFailureV1(ErrHTMLSendWorkV1)
	}
	grant, err := coordinator.TryAcquireV1(ctx, b.org, workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		return nil, p.recordCapacityFailureV1(errors.Join(ErrHTMLSendWorkV1, err))
	}
	return grant, nil
}

// Invoked only immediately around CRMRecords.observe's actual protected
// Client.ReadRecords. Refusal is sticky capacity failure, never CRM fallback.
func (p *applicationHTMLSendResolverV1) HoldCRMRecordReadV1(ctx context.Context, org uuid.UUID) (func(), error) {
	if p == nil {
		return nil, ErrHTMLSendWorkV1
	}
	p.mu.Lock()
	valid := p.liveV1() && p.active > 0 && p.document.OrgID == org && p.crmRow != nil && p.crmRow.OrgID == org
	p.mu.Unlock()
	if !valid {
		return nil, p.recordCapacityFailureV1(ErrHTMLSendWorkV1)
	}
	grant, err := p.providerStreamV1(ctx)
	if err != nil {
		return nil, err
	}
	return grant.Close, nil
}

type htmlSendNativeHTTPSourceV1 struct {
	owner  *applicationHTMLSendResolverV1
	source *resolver.HTTPSource
}

func (h *htmlSendNativeHTTPSourceV1) Kind() resolver.SourceKind { return h.source.Kind() }
func (h *htmlSendNativeHTTPSourceV1) Fetch(ctx context.Context, ref resolver.Ref) (string, error) {
	p := h.owner
	p.mu.Lock()
	if !p.liveV1() || p.active == 0 || ref.OrgID != p.document.OrgID || ref.DocID != p.document.ID || ctx != p.source.owner.binding.ctx {
		p.mu.Unlock()
		return "", ErrHTMLSendWorkV1
	}
	owner := p.source.owner
	p.mu.Unlock()
	readBytes, err := htmlSendHTTPReadLogicalV1(h.source, ref)
	if err == nil {
		err = owner.holdV1(htmlRevisionSourcePrepareV1, readBytes, 0)
	}
	if err != nil {
		return "", p.recordCapacityFailureV1(err)
	}
	stream, err := p.providerStreamV1(ctx)
	if err != nil {
		return "", err
	}
	defer stream.Close()
	read, err := h.source.OpenSendReadV1(ctx, ref)
	if err != nil {
		return "", err
	}
	defer read.CloseV1()
	if err = read.ReadBodyV1(); err != nil {
		return "", err
	}
	raw, err := read.BodyV1()
	if err != nil {
		return "", err
	}
	decode, err := htmlSendHTTPDecodeLogicalV1(int64(len(raw)))
	if err == nil {
		err = htmlSendResolverAddV1(&decode, readBytes, 1)
	}
	if err == nil {
		err = owner.holdV1(htmlRevisionSourcePrepareV1, decode, 0)
	}
	if err != nil {
		return "", p.recordCapacityFailureV1(err)
	}
	value, err := read.DecodeValueV1()
	if err != nil {
		return "", err
	}
	// Continuous scratch retains this transient result through the unchanged
	// immediate observation stage, which admits its ACTUAL retained copies
	// before out/report/cache insertion and final Marshal.
	return value, nil
}

type htmlSendNativeOrgSourceV1 struct {
	owner  *applicationHTMLSendResolverV1
	source *resolver.OrgSettingSource
}

func (h *htmlSendNativeOrgSourceV1) Kind() resolver.SourceKind { return resolver.SourceOrgSetting }
func (h *htmlSendNativeOrgSourceV1) Fetch(ctx context.Context, ref resolver.Ref) (string, error) {
	return h.owner.fetchOrgSourceV1(ctx, h.source, ref)
}
