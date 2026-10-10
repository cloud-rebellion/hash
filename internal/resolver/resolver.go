// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package resolver implements Phase 8.2: pluggable variable resolution.
//
// The block tree references template variables as `{{name}}` placeholders.
// Phase 1 (week 2) resolved them from a static k/v stored in
// documents.variables_json. Phase 8.2 adds a binding layer: each variable
// can be bound to an external source (BrightCRM deal/contact, SVAR scanner
// finding, Hash org setting) or to an agent-supplied value resolved at
// render time.
//
// Resolver chain:
//
//  1. agent override          (caller-supplied at the top of every render)
//  2. document static value   (documents.variables_json, today's behaviour)
//  3. binding fetch           (live from the configured source)
//  4. binding fallback        (literal in the binding row)
//  5. unset                   (the {{var}} placeholder stays in the rendered
//     output, which the editor highlights)
//
// On send the snapshot pipeline calls FreezeForSend, which materializes the
// final resolved values into the document_versions row. From that moment on
// every render of the sent document uses the frozen values regardless of
// what happens to the live binding.
package resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// SourceKind enumerates the binding source plugins.
type SourceKind string

const (
	SourceStatic        SourceKind = "static"
	SourceCRMDeal       SourceKind = "crm.deal"
	SourceCRMContact    SourceKind = "crm.contact"
	SourceCRMCompany    SourceKind = "crm.company"
	SourceScannerFind   SourceKind = "scanner.finding"
	SourceOrgSetting    SourceKind = "org.setting"
	SourceAgentComputed SourceKind = "agent.computed"
)

// Valid reports whether s is one of the registered source kinds.
func (s SourceKind) Valid() bool {
	switch s {
	case SourceStatic, SourceCRMDeal, SourceCRMContact, SourceCRMCompany, SourceScannerFind, SourceOrgSetting, SourceAgentComputed:
		return true
	}
	return false
}

// Source plugins answer "what is the current value at this binding?".
// Implementations should:
//   - Be safe to call from multiple goroutines.
//   - Honour ctx cancellation for HTTP calls.
//   - Return ErrNotConfigured (or wrap it) when the source plugin lacks the
//     necessary credentials, so the caller can show a clear UI nudge instead
//     of a generic error.
//
// Source plugins do NOT consult the binding's fallback or the document's
// static variables_json; that's the resolver chain's job.
type Source interface {
	Kind() SourceKind
	Fetch(ctx context.Context, ref Ref) (string, error)
}

// Ref carries the binding row's source_ref + source_path so source plugins
// can look up the right entity and pluck the right field.
type Ref struct {
	OrgID  uuid.UUID
	DocID  uuid.UUID
	Source string // source_ref column, e.g. "deal_4f2c9e8a"
	Path   string // source_path column, e.g. "amount"
}

// ErrNotConfigured signals that a source plugin is missing credentials. The
// resolver propagates this so callers (UI, MCP) can render a "configure
// integration" hint instead of a 500.
var ErrNotConfigured = errors.New("source plugin not configured")

// ErrNotFound signals the source row was queried successfully but the
// referenced entity doesn't exist. Falls through to the binding's fallback.
var ErrNotFound = errors.New("source entity not found")

var ErrBindingPersistence = errors.New("binding observation could not be staged")
var ErrSourceFreshness = errors.New("current binding source value could not be verified for send")

// Resolver chains a static-document layer, a per-document binding layer, and
// an optional agent-override layer. It is the single entry point used by
// every render path (preview, signer view, final PDF) so resolution rules
// stay in one place.
type Resolver struct {
	Q       BindingStore
	Sources map[SourceKind]Source
	Cache   *cache
	CRM     *CRMRecords
}

type BindingStore interface {
	ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error)
}

// ObservationStager is deliberately not implemented by generated.Queries.
// Freeze preparation may stage observations in memory; only the send engine's
// authorized transaction may persist them with both revision predicates.
type ObservationStager interface {
	StageVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error
	StageVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error
}

type CRMReportStager interface {
	StageCRMReports(context.Context, uuid.UUID, uuid.UUID, []ResolveReport) error
}

// New builds a Resolver with the given source plugins. A static source is
// always registered automatically, since static values are an artifact of
// the document row, not of an external system.
func New(q *generated.Queries, sources ...Source) *Resolver {
	m := map[SourceKind]Source{
		SourceStatic: &staticSource{},
	}
	for _, s := range sources {
		m[s.Kind()] = s
	}
	return &Resolver{
		Q:       q,
		Sources: m,
		Cache:   newCache(30 * time.Second),
	}
}

// ResolveOptions tunes a single Resolve call.
type ResolveOptions struct {
	// AgentOverrides win over every other layer. Used by MCP callers that
	// already know the value (e.g. a workflow tool computing a derived value
	// before re-rendering for preview).
	AgentOverrides map[string]string
	// FreezeMode uses only the document snapshot variables. Binding rows are
	// consulted for reporting, never as a source of mutable replacement values.
	FreezeMode bool
	// Only FreezeForSend enables these private preparation options. Preview
	// callers cannot ask a default resolver to persist binding observations.
	stageObservations bool
	freshSources      bool
	crmSnapshot       *crmconnection.Snapshot
}

// Resolve produces the final variable map for a document. The block tree's
// HTML renderer accepts a map[string]string; this is what we hand it.
//
// It always also returns a per-binding ResolveReport so the audit log + UI
// can show which sources answered and which fell through to fallbacks.
func (r *Resolver) Resolve(ctx context.Context, doc *generated.Document, opts ResolveOptions) (map[string]string, []ResolveReport, error) {
	if doc == nil {
		return nil, nil, errors.New("resolve: nil document")
	}
	out := map[string]string{}
	report := []ResolveReport{}

	// Layer 1: document static values (variables_json).
	if len(doc.VariablesJson) > 0 {
		statics, err := blocks.ParseVariableValues(doc.VariablesJson)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve: invalid static variables: %w", err)
		}
		for key, value := range statics {
			out[key] = value
		}
	}

	// Layer 2: bindings.
	bindings, err := r.Q.ListVariableBindings(ctx, doc.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve: list bindings: %w", err)
	}
	for _, b := range bindings {
		if b == nil || b.DocumentID != doc.ID {
			return nil, nil, errors.New("resolve: invalid binding snapshot")
		}
	}
	if r.CRM != nil && !opts.FreezeMode {
		opts.crmSnapshot, err = r.CRM.observe(ctx, doc, bindings)
		if err != nil {
			return nil, nil, err
		}
	}
	for _, b := range bindings {
		bindingSnapshot := *b
		entry := ResolveReport{
			bindingSnapshot: &bindingSnapshot,
			Variable:        b.VariableName,
			SourceKind:      b.SourceKind,
			SourceRef:       b.SourceRef,
			SourcePath:      b.SourcePath,
		}
		if opts.FreezeMode {
			entry.Value = out[b.VariableName]
			entry.ResolvedFrom = "frozen"
			report = append(report, entry)
			continue
		}
		val, src, err := r.fetchOne(ctx, doc, b, opts)
		if err != nil {
			return nil, nil, err
		}
		entry.ResolvedFrom = src
		if r.CRM != nil && isCRMKind(b.SourceKind) && src == "source" {
			_, entry.CRMObservation, entry.crmFence, err = crmValue(opts.crmSnapshot, b)
			if err != nil {
				return nil, nil, err
			}
		}
		// Successful empty source values are authoritative, not fetch failures.
		if src == "source" || src == "cached" || val != "" {
			out[b.VariableName] = val
			entry.Value = val
		} else if b.Fallback != "" {
			out[b.VariableName] = b.Fallback
			entry.Value = b.Fallback
			entry.ResolvedFrom = "fallback"
		}
		report = append(report, entry)
	}

	if opts.FreezeMode && len(opts.AgentOverrides) != 0 {
		return nil, nil, errors.New("resolve: frozen variables cannot be overridden")
	}

	// Layer 3: agent overrides win.
	for k, v := range opts.AgentOverrides {
		out[k] = v
		for i := range report {
			if report[i].Variable == k {
				report[i].Value, report[i].ResolvedFrom = v, "agent_override"
				report[i].CRMObservation, report[i].crmFence = nil, nil
			}
		}
	}
	return out, report, nil
}

// FreezeForSend resolves every binding for a document and writes the result
// into the document's variables_json so the version snapshot captures it.
// After freeze, the document's bindings are kept (read-only) for audit
// transparency, but renders pull from the frozen variables_json.
//
// Callers (typically the send handler) should call FreezeForSend BEFORE
// transitioning the document status to 'sent' so the snapshot triggered by
// the state change captures the frozen values.
func (r *Resolver) FreezeForSend(ctx context.Context, doc *generated.Document) (json.RawMessage, []ResolveReport, error) {
	resolved, report, err := r.Resolve(ctx, doc, ResolveOptions{stageObservations: true, freshSources: true})
	if err != nil {
		return nil, nil, err
	}
	if err := CheckReviewedCRMValues(doc, report); err != nil {
		return nil, nil, err
	}
	for _, entry := range report {
		if entry.crmFence != nil {
			stager, ok := r.Q.(CRMReportStager)
			if !ok {
				return nil, nil, ErrBindingPersistence
			}
			if err := stager.StageCRMReports(ctx, doc.OrgID, doc.ID, report); err != nil {
				return nil, nil, err
			}
			break
		}
	}
	// Keep static values that weren't bound (they're already in variables_json
	// and resolved/report includes them). Just marshal the merged map.
	frozen, err := json.Marshal(resolved)
	if err != nil {
		return nil, nil, fmt.Errorf("freeze: marshal: %w", err)
	}
	return frozen, report, nil
}

// fetchOne is read-only unless FreezeForSend explicitly asks the send
// preparation adapter to stage an observation. Preview cache hits and source
// failures never update the customer's binding ledger.
func (r *Resolver) fetchOne(ctx context.Context, doc *generated.Document, b *generated.DocumentVariableBinding, opts ResolveOptions) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if b.SourceKind == string(SourceStatic) {
		return "", "", nil
	}
	stage := func(value string, failed bool) error {
		if !opts.stageObservations {
			return nil
		}
		stager, ok := r.Q.(ObservationStager)
		if !ok {
			return ErrBindingPersistence
		}
		var err error
		if failed {
			err = stager.StageVariableBindingError(ctx, generated.UpdateVariableBindingErrorParams{
				DocumentID: b.DocumentID, OrgID: doc.OrgID, VariableName: b.VariableName, LastError: value,
				ExpectedDocumentUpdatedAt: doc.UpdatedAt, ExpectedBindingCreatedAt: b.CreatedAt, ExpectedBindingUpdatedAt: b.UpdatedAt,
			})
		} else {
			err = stager.StageVariableBindingResolved(ctx, generated.UpdateVariableBindingResolvedParams{
				DocumentID: b.DocumentID, OrgID: doc.OrgID, VariableName: b.VariableName, LastValue: value,
				ExpectedDocumentUpdatedAt: doc.UpdatedAt, ExpectedBindingCreatedAt: b.CreatedAt, ExpectedBindingUpdatedAt: b.UpdatedAt,
			})
		}
		if err != nil {
			return ErrBindingPersistence
		}
		return nil
	}
	if r.CRM != nil && isCRMKind(b.SourceKind) {
		value, _, _, err := crmValue(opts.crmSnapshot, b)
		if err != nil {
			return "", "", err
		}
		if err = stage(value, false); err != nil {
			return "", "", err
		}
		return value, "source", nil
	}
	freshRequired := opts.freshSources && isCRMKind(b.SourceKind)
	src, ok := r.Sources[SourceKind(b.SourceKind)]
	if !ok {
		if err := stage(fmt.Sprintf("source kind %q not registered", b.SourceKind), true); err != nil {
			return "", "", err
		}
		if freshRequired {
			return "", "", ErrSourceFreshness
		}
		return "", "", nil
	}
	cacheKey := sourceCacheKey(doc.OrgID, b.SourceKind, b.SourceRef, b.SourcePath)
	hit, cached, generation := r.Cache.getWithGeneration(cacheKey)
	if cached && !opts.freshSources {
		return hit, "cached", nil
	}
	val, err := src.Fetch(ctx, Ref{OrgID: doc.OrgID, DocID: b.DocumentID, Source: b.SourceRef, Path: b.SourcePath})
	if err != nil {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		if err := stage(err.Error(), true); err != nil {
			return "", "", err
		}
		if freshRequired {
			return "", "", ErrSourceFreshness
		}
		return "", "", nil
	}
	if err := stage(val, false); err != nil {
		return "", "", err
	}
	if !r.Cache.putIfGeneration(cacheKey, val, generation) && opts.freshSources {
		// An admitted upstream change invalidated this observation while the
		// request was in flight. Never freeze its pre-change response.
		return "", "", ErrSourceFreshness
	}
	return val, "source", nil
}

// ResolveReport is one row in the per-document resolve audit. Returned to
// callers so the editor's debug panel + the audit log can show which path
// each variable took.
type ResolveReport struct {
	bindingSnapshot *generated.DocumentVariableBinding
	crmFence        *crmReportFence
	CRMObservation  *CRMValueObservation `json:"crm_observation,omitempty"`
	Variable        string               `json:"variable"`
	SourceKind      string               `json:"source_kind"`
	SourceRef       string               `json:"source_ref,omitempty"`
	SourcePath      string               `json:"source_path,omitempty"`
	Value           string               `json:"value"`
	ResolvedFrom    string               `json:"resolved_from"` // "source" | "cached" | "fallback" | "frozen" | ""
}

// stringify coerces JSON-decoded values to strings for the variable map.
// Strings are returned verbatim; numbers and bools stringify reasonably;
// nested objects/arrays become their JSON representation.
func stringify(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case float64:
		// JSON numbers come out as float64. Avoid scientific notation for
		// reasonable amounts.
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t)), true
		}
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), "."), true
	case bool:
		if t {
			return "true", true
		}
		return "false", true
	case nil:
		return "", false
	default:
		raw, err := json.Marshal(v)
		if err != nil {
			return "", false
		}
		return string(raw), true
	}
}

// sourceCacheKey encodes fields independently: delimiter-bearing CRM refs
// and paths must never share a cached value or invalidation identity.
func sourceCacheKey(orgID uuid.UUID, kind, ref, path string) string {
	encoded, _ := json.Marshal([4]string{orgID.String(), kind, ref, path})
	return string(encoded)
}

// cache is a bounded per-process TTL cache keyed by tenant+source+ref+path.
// Eviction follows insertion time rather than access time. 30s TTL means
// the editor reload cycle reuses the same value but a freshly-saved BrightCRM
// edit propagates within half a minute.
type cache struct {
	mu         sync.Mutex
	ttl        time.Duration
	m          map[string]cacheEntry
	generation uint64
}

type cacheEntry struct {
	value string
	at    time.Time
}

func newCache(ttl time.Duration) *cache {
	return &cache{ttl: ttl, m: map[string]cacheEntry{}}
}

func (c *cache) get(key string) (string, bool) {
	value, ok, _ := c.getWithGeneration(key)
	return value, ok
}

func (c *cache) getWithGeneration(key string) (string, bool, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[key]
	if !ok {
		return "", false, c.generation
	}
	if time.Since(e.at) > c.ttl {
		delete(c.m, key)
		return "", false, c.generation
	}
	return e.value, true, c.generation
}

const maxCacheEntries = 1024
const maxCacheBytes = 8 << 20

func (c *cache) put(key, value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.putLocked(key, value)
}

func (c *cache) putIfGeneration(key, value string, generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.generation != generation {
		return false
	}
	c.putLocked(key, value)
	return true
}

func (c *cache) putLocked(key, value string) {
	now := time.Now()
	// Bound both map cardinality and retained customer text. Expired keys are
	// removed even when no caller ever asks for them again.
	bytes := 0
	for k, entry := range c.m {
		if now.Sub(entry.at) > c.ttl || k == key {
			delete(c.m, k)
			continue
		}
		bytes += len(k) + len(entry.value)
	}
	size := len(key) + len(value)
	if size > maxCacheBytes {
		return
	}
	for len(c.m) >= maxCacheEntries || bytes+size > maxCacheBytes {
		var oldest string
		var timestamp time.Time
		for k, entry := range c.m {
			if timestamp.IsZero() || entry.at.Before(timestamp) {
				oldest = k
				timestamp = entry.at
			}
		}
		entry := c.m[oldest]
		bytes -= len(oldest) + len(entry.value)
		delete(c.m, oldest)
	}
	c.m[key] = cacheEntry{value: value, at: now}
}

// InvalidateForSourceOrgs drops cache entries for the supplied source tuple
// only in tenant ledgers the caller has already resolved and audited. A
// process-wide source reference is not a tenant identity: two organizations
// can legitimately use the same upstream ID, and one must not authorize an
// unaudited cache mutation for the other.
func (r *Resolver) InvalidateForSourceOrgs(sourceKind, sourceRef string, orgIDs []uuid.UUID) int {
	if r == nil || r.Cache == nil || len(orgIDs) == 0 {
		return 0
	}
	allowed := make(map[string]struct{}, len(orgIDs))
	for _, orgID := range orgIDs {
		if orgID != uuid.Nil {
			allowed[orgID.String()] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		return 0
	}
	r.Cache.mu.Lock()
	defer r.Cache.mu.Unlock()
	// Fence in-flight misses even when no matching cached entry exists yet.
	r.Cache.generation++
	dropped := 0
	for k := range r.Cache.m {
		var fields []string
		if err := json.Unmarshal([]byte(k), &fields); err != nil || len(fields) != 4 {
			continue
		}
		if _, ok := allowed[fields[0]]; ok && fields[1] == sourceKind && fields[2] == sourceRef {
			delete(r.Cache.m, k)
			dropped++
		}
	}
	return dropped
}

// staticSource is registered automatically by New so the static SourceKind
// is always present in the dispatch map. Resolve handles the actual lookup
// from variables_json before fetchOne runs, so this Fetch is just a stub
// that returns no value (the caller falls through to the static layer).
type staticSource struct{}

func (staticSource) Kind() SourceKind                               { return SourceStatic }
func (staticSource) Fetch(_ context.Context, _ Ref) (string, error) { return "", nil }
