// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"io"
	"net/http"
	"unsafe"
)

var ErrCatalogRuleInputV1 = errors.New("pdfadmission: owned rule input unavailable")

const catalogRuleHTTPBytesV1 int64 = 32 * 1024
const catalogRuleHTTPProfileV1 HTMLAuthoringInputProfileV1 = 254
const catalogRuleMCPProfileV1 HTMLAuthoringInputProfileV1 = 255

// Uses the actual factory's existing producer registry and coordinator. The
// private shared state survives copied handles, active Decode, cancellation,
// and premature Close until that SAME synchronous decoder/validator joins.
// This is finite logical expression credit, not an allocator or RSS ceiling.
type ApplicationCatalogRuleInputV1 struct {
	state *applicationHTMLAuthoringInputStateV1
}
type CatalogRuleCreateInputV1 struct {
	Name         string          `json:"name"`
	Priority     int32           `json:"priority"`
	Predicate    json.RawMessage `json:"predicate_json"`
	RequiredTier string          `json:"required_tier"`
	Reason       string          `json:"reason"`
	Active       *bool           `json:"active"`
}
type CatalogRulePatchInputV1 struct {
	Name         *string          `json:"name"`
	Priority     *int32           `json:"priority"`
	Predicate    *json.RawMessage `json:"predicate_json"`
	RequiredTier *string          `json:"required_tier"`
	Reason       *string          `json:"reason"`
	Active       *bool            `json:"active"`
}

// HTTP retains the original single streaming Decode and MaxBytesReader32KiB.
// It does not whole-read the body, require EOF, reject accepted trailing bytes,
// or use Content-Length as work proof. MCP passes its ACTUAL admitted args;
// its existing request parser/Unicode validation is preserved by the caller.
func (f *ApplicationSessionFactoryV1) NewCatalogRuleHTTPInputV1(ctx context.Context, org uuid.UUID) (*ApplicationCatalogRuleInputV1, error) {
	return f.newCatalogRuleInputV1(ctx, org, catalogRuleHTTPBytesV1, catalogRuleHTTPProfileV1)
}
func (f *ApplicationSessionFactoryV1) NewCatalogRuleArgumentsV1(ctx context.Context, org uuid.UUID, args json.RawMessage) (*ApplicationCatalogRuleInputV1, error) {
	return f.newCatalogRuleInputV1(ctx, org, int64(len(args)), catalogRuleMCPProfileV1)
}
func (f *ApplicationSessionFactoryV1) newCatalogRuleInputV1(ctx context.Context, org uuid.UUID, n int64, profile HTMLAuthoringInputProfileV1) (*ApplicationCatalogRuleInputV1, error) {
	if f == nil || f.state == nil || org == uuid.Nil || !applicationContextV1(ctx) || n < 0 || (profile != catalogRuleHTTPProfileV1 && profile != catalogRuleMCPProfileV1) || n > (1<<40)/128 {
		return nil, ErrCatalogRuleInputV1
	}
	p := f.state
	// The unchanged outer typed decoder creates at most the source-byte count
	// of RawMessage/string/primitive members;128B per source byte dominates its
	// logical slice/map/interface/header expressions. The fixed scanner stack
	// and both exact route structs stay additive even for empty MCP arguments.
	fixed := int64(unsafe.Sizeof(CatalogRuleCreateInputV1{})) + int64(unsafe.Sizeof(CatalogRulePatchInputV1{})) + 10000*9 + 4096
	if n > ((1<<40)-fixed)/128-1 {
		return nil, ErrCatalogRuleInputV1
	}
	cost := fixed + 128*(n+1)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlInputProducers == nil || len(p.htmlInputProducers) >= applicationSessionMaxWorkV1 {
		return nil, ErrCatalogRuleInputV1
	}
	s := &applicationHTMLAuthoringInputStateV1{factory: p, org: org, limit: n, profile: profile}
	p.htmlInputProducers[s] = struct{}{}
	release, err := p.work.acquire(ctx, org, workguard.VectorV1{ParentBytes: cost})
	if err != nil {
		delete(p.htmlInputProducers, s)
		return nil, errors.Join(ErrCatalogRuleInputV1, err)
	}
	s.releases = []func(){release}
	return &ApplicationCatalogRuleInputV1{state: s}, nil
}
func (h *ApplicationCatalogRuleInputV1) beginV1(ctx context.Context, decode bool) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrCatalogRuleInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || (decode && s.readStarted) {
		return ErrCatalogRuleInputV1
	}
	if decode {
		s.readStarted = true
	}
	s.active++
	return nil
}
func (h *ApplicationCatalogRuleInputV1) DecodeCreateV1(ctx context.Context, w http.ResponseWriter, body io.ReadCloser) (CatalogRuleCreateInputV1, error) {
	var v CatalogRuleCreateInputV1
	if body == nil || h == nil || h.state == nil || h.state.profile != catalogRuleHTTPProfileV1 || h.state.limit != catalogRuleHTTPBytesV1 {
		return v, ErrCatalogRuleInputV1
	}
	if err := h.beginV1(ctx, true); err != nil {
		return v, err
	}
	defer h.state.finishV1()
	err := json.NewDecoder(http.MaxBytesReader(w, body, catalogRuleHTTPBytesV1)).Decode(&v)
	return v, err
}
func (h *ApplicationCatalogRuleInputV1) DecodePatchV1(ctx context.Context, w http.ResponseWriter, body io.ReadCloser) (CatalogRulePatchInputV1, error) {
	var v CatalogRulePatchInputV1
	if body == nil || h == nil || h.state == nil || h.state.profile != catalogRuleHTTPProfileV1 || h.state.limit != catalogRuleHTTPBytesV1 {
		return v, ErrCatalogRuleInputV1
	}
	if err := h.beginV1(ctx, true); err != nil {
		return v, err
	}
	defer h.state.finishV1()
	err := json.NewDecoder(http.MaxBytesReader(w, body, catalogRuleHTTPBytesV1)).Decode(&v)
	return v, err
}

// Pricing sees actual retained bytes and concrete nesting spans BEFORE the
// unchanged recursive validator's RawMessage/path copies. It grants no rule,
// input validity, credential, source cache, or accepted shape authority.
func (h *ApplicationCatalogRuleInputV1) ValidateRuleV1(ctx context.Context, raw json.RawMessage, tier eidas.Tier) error {
	if err := h.beginV1(ctx, false); err != nil {
		return err
	}
	s := h.state
	defer s.finishV1()
	if len(raw) == 0 {
		return eidas.ValidateRule(raw, tier)
	}
	c, err := catalogRulePredicateComponentsForV1(raw)
	if err != nil {
		return errors.Join(ErrCatalogRuleInputV1, err)
	}
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		s.mu.Unlock()
		p.mu.Unlock()
		return ErrCatalogRuleInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: c.parentBytes})
	if err == nil {
		s.releases = append(s.releases, release)
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return errors.Join(ErrCatalogRuleInputV1, err)
	}
	return eidas.ValidateRule(raw, tier)
}
func (h *ApplicationCatalogRuleInputV1) CloseConsumerV1() {
	if h != nil && h.state != nil {
		(&ApplicationHTMLAuthoringInputV1{state: h.state}).CloseConsumerV1()
	}
}
