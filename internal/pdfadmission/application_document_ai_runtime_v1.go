// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// One continuously retained parent grant grows before real parser, prompt,
// Shield, restoration and feature/output producers. It adds no SQL authority;
// fixed source reads use only this actual dispatch's original native queries.
type ApplicationDocumentAIRuntimeV1 struct {
	mu               sync.Mutex
	work             *ApplicationDocumentAIWorkV1
	grant            *workguard.GrantV1
	observer         ai.NativeUsageObserverV1
	origin           context.Context
	closed, observed bool
}

func (w *ApplicationDocumentAIWorkV1) NewRuntimeV1(ctx context.Context, observer ai.NativeUsageObserverV1) (*ApplicationDocumentAIRuntimeV1, error) {
	if w == nil || w.state == nil || observer == nil {
		return nil, ErrDocumentAIAuditV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.requested || s.snapshot == nil || s.policy == nil || s.runtimeOwner != nil || s.closeAfterProvider {
		return nil, ErrDocumentAIAuditV1
	}
	f := s.session.state.factory
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closing || f.work == nil || f.work.coordinator == nil {
		return nil, ErrDocumentAIAuditV1
	}
	fixed := int64(65536) + 4*int64(unsafe.Sizeof(ApplicationDocumentAIRuntimeV1{})) + 4*int64(unsafe.Sizeof(generated.OrgAiSetting{}))
	grant, err := f.work.coordinator.TryAcquireV1(ctx, s.session.state.org, workguard.VectorV1{ParentBytes: fixed})
	if err != nil {
		return nil, err
	}
	out := &ApplicationDocumentAIRuntimeV1{work: w, grant: grant, observer: observer, origin: ctx}
	s.runtimeOwner = out
	s.closes = append(s.closes, out.closeV1)
	return out, nil
}
func (o *ApplicationDocumentAIRuntimeV1) validV1(ctx context.Context) bool {
	if o == nil || o.work == nil || o.work.state == nil || o.origin == nil || ctx == nil || ctx.Value(applicationSessionCallbackKeyV1{}) != o.origin.Value(applicationSessionCallbackKeyV1{}) || ai.NativeWorkflowFromContextV1(ctx) != o {
		return false
	}
	s := o.work.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runtimeOwner == o && s.validV1(ctx) && !s.requested && s.snapshot != nil && !s.closeAfterProvider
}
func (o *ApplicationDocumentAIRuntimeV1) RetainV1(ctx context.Context, n int64) error {
	if n < 0 || !o.validV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	if n == 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.grant == nil {
		return ErrDocumentAIAuditV1
	}
	return o.grant.TryGrowParentV1(ctx, n)
}
func (o *ApplicationDocumentAIRuntimeV1) closeV1() {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return
	}
	o.closed = true
	if o.grant != nil {
		o.grant.Close()
		o.grant = nil
	}
	o.observer = nil
}
func (o *ApplicationDocumentAIRuntimeV1) PrepareUsageV1(ctx context.Context, provider, model, prompt string, version int) error {
	if !o.validV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	o.mu.Lock()
	if o.closed || o.observer == nil {
		o.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	observer := o.observer
	o.mu.Unlock()
	return observer.ReserveNativeUsageV1(ctx, o, provider, model, prompt, version)
}

// The only detached operation is a real already-observed cost. Cancellation
// cannot erase incurred usage. Exact opaque context/owner and the still-held
// whole-workflow registration replace a live ctx.Err check at this point.
func (o *ApplicationDocumentAIRuntimeV1) ObserveUsageV1(origin context.Context, observation *ai.CompletionObservationV1) error {
	if o == nil || o.work == nil || o.work.state == nil || o.origin == nil || origin == nil || origin.Value(applicationSessionCallbackKeyV1{}) != o.origin.Value(applicationSessionCallbackKeyV1{}) {
		return ErrDocumentAIAuditV1
	}
	if _, err := observation.ParamsForV1(o, origin); err != nil {
		return err
	}
	s := o.work.state
	s.mu.Lock()
	registered := !s.closed && s.runtimeOwner == o && s.snapshot != nil && !s.requested
	s.mu.Unlock()
	if !registered {
		return ErrDocumentAIAuditV1
	}
	o.mu.Lock()
	if o.closed || o.observed || o.observer == nil {
		o.mu.Unlock()
		return ErrDocumentAIAuditV1
	}
	o.observed = true
	observer := o.observer
	o.mu.Unlock()
	return observer.ObserveNativeUsageV1(origin, o, observation)
}
func (o *ApplicationDocumentAIRuntimeV1) WrapProviderV1(ctx context.Context, provider ai.Provider) (ai.Provider, error) {
	if !o.validV1(ctx) {
		return nil, ErrDocumentAIAuditV1
	}
	return o.work.NewProviderV1(ctx, provider)
}
func (o *ApplicationDocumentAIRuntimeV1) holdReadV1(ctx context.Context, raw, wire int64) error {
	if !o.validV1(ctx) {
		return ErrDocumentAIAuditV1
	}
	s := o.work.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.runtimeOwner != o {
		return ErrDocumentAIAuditV1
	}
	return s.holdV1(ctx, raw, wire)
}
func (o *ApplicationDocumentAIRuntimeV1) ReadRecipientNamesV1(ctx context.Context, document uuid.UUID) ([]string, error) {
	if !o.validV1(ctx) || document != o.work.state.session.state.document {
		return nil, ErrDocumentAIAuditV1
	}
	s := o.work.state
	p := s.session.state
	// Scalar/header controls and result shell are funded before even the header query.
	if err := o.holdReadV1(ctx, 4096, 4096); err != nil {
		return nil, err
	}
	h, err := s.queries.GetDocumentAIRecipientHeaderV1(ctx, generated.GetDocumentAIRecipientHeaderV1Params{DocumentID: document, OrgID: p.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.Rows < 0 || h.NameBytes < 0 {
		return nil, ErrDocumentAIAuditV1
	}
	raw, err := ai.NativeCostV1(h.NameBytes, h.Rows, 128)
	if err != nil {
		return nil, err
	}
	wire, err := ai.NativeCostV1(h.NameBytes, h.Rows, 32)
	if err != nil {
		return nil, err
	}
	if err = o.holdReadV1(ctx, raw, wire); err != nil {
		return nil, err
	}
	names, err := s.queries.ReadDocumentAIRecipientNamesV1(ctx, generated.ReadDocumentAIRecipientNamesV1Params{DocumentID: document, OrgID: p.org, ExpectedRows: h.Rows, ExpectedNameBytes: h.NameBytes})
	if err != nil {
		return nil, err
	}
	var actual int64
	for _, name := range names {
		actual += int64(len(name))
	}
	if int64(len(names)) != h.Rows || actual != h.NameBytes {
		return nil, ErrDocumentAIAuditV1
	}
	return names, nil
}
func (o *ApplicationDocumentAIRuntimeV1) ReadOrganizationProviderV1(ctx context.Context, org uuid.UUID) (*generated.OrgAiSetting, error) {
	if !o.validV1(ctx) || org != o.work.state.session.state.org {
		return nil, ErrDocumentAIAuditV1
	}
	s := o.work.state
	p := s.session.state
	if err := o.holdReadV1(ctx, 4096, 4096); err != nil {
		return nil, err
	}
	h, err := s.queries.GetDocumentAIOrganizationProviderHeaderV1(ctx, generated.GetDocumentAIOrganizationProviderHeaderV1Params{DocumentID: p.document, OrgID: p.org})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != org {
		return nil, ErrDocumentAIAuditV1
	}
	raw := int64(0)
	for _, n := range []int64{h.ProviderBytes, h.BaseUrlBytes, h.ModelBytes, h.KeyBytes, h.KeyLast4Bytes} {
		var e error
		raw, e = ai.NativeCostV1(raw, n, 1)
		if e != nil {
			return nil, e
		}
	}
	// Includes retained ciphertext, actual decrypt plaintext and fixed provider/URL/network construction.
	if err = o.holdReadV1(ctx, raw, raw+512); err != nil {
		return nil, err
	}
	cost, err := ai.NativeCostV1(65536, raw, 16)
	if err != nil {
		return nil, err
	}
	if err = o.RetainV1(ctx, cost); err != nil {
		return nil, err
	}
	return s.queries.ReadDocumentAIOrganizationProviderV1(ctx, generated.ReadDocumentAIOrganizationProviderV1Params{DocumentID: p.document, OrgID: p.org, UpdatedAt: h.UpdatedAt, CreatedAt: h.CreatedAt, Enabled: h.Enabled, ProviderBytes: h.ProviderBytes, BaseUrlBytes: h.BaseUrlBytes, ModelBytes: h.ModelBytes, KeyBytes: h.KeyBytes, KeyLast4Bytes: h.KeyLast4Bytes})
}

type documentAIRuntimeDecimalV1 struct {
	owner   *ApplicationDocumentAIRuntimeV1
	ctx     context.Context
	peak    int64
	failure error
}

func (a *documentAIRuntimeDecimalV1) BeforeDecimalV1(value string) (failure error) {
	defer func() {
		if failure != nil {
			a.failure = failure
		}
	}()
	b, err := blocks.DecimalLogicalBoundForSendV1(value)
	if err != nil {
		return err
	}
	bits := int64(0)
	for _, v := range []int64{b.MantissaBits, b.PowerFiveBits, b.NumeratorBits, b.DenominatorBits} {
		bits, err = ai.NativeCostV1(bits, v, 1)
		if err != nil {
			return err
		}
	}
	words := bits / 64
	if bits%64 != 0 {
		words++
	}
	cost, err := ai.NativeCostV1(32*int64(unsafe.Sizeof(big.Int{}))+8*int64(unsafe.Sizeof(big.Rat{})), words, 512)
	if err != nil {
		return err
	}
	cost, err = ai.NativeCostV1(cost, b.SourceBytes, 8)
	if err != nil {
		return err
	}
	if cost > a.peak {
		if err = a.owner.RetainV1(a.ctx, cost-a.peak); err != nil {
			return err
		}
		a.peak = cost
	}
	return nil
}
func (o *ApplicationDocumentAIRuntimeV1) ParseTreeV1(ctx context.Context, raw []byte) (*blocks.Tree, error) {
	if !o.validV1(ctx) {
		return nil, ErrDocumentAIAuditV1
	}
	// Only the genuine retained document bytes are admitted by this reader.
	source := o.work.state.snapshot.document.BlocksJson
	if !bytes.Equal(raw, source) {
		return nil, ErrDocumentAIAuditV1
	}
	cost, err := plainSendBlockLexicalWorkV1(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err = o.RetainV1(ctx, cost); err != nil {
		return nil, err
	}
	admission := &documentAIRuntimeDecimalV1{owner: o, ctx: ctx}
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, raw, admission)
	if admission.failure != nil {
		return nil, admission.failure
	}
	return tree, err
}

var _ ai.NativeWorkflowV1 = (*ApplicationDocumentAIRuntimeV1)(nil)
