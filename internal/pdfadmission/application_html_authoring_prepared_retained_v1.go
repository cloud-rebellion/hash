// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
)

// Opaque Compiled is immutable by htmlmaster's contract. Every mutable output
// is a defensive copy; this supplies no actor/template approval/CRM authority.
type HTMLAuthoringPreparedRetainedTemplateV1 struct {
	Compiled *htmlmaster.Compiled
	Values   []htmlmaster.Value
	Defaults map[string]string
}
type htmlAuthoringPreparedRetainedTemplateV1 struct {
	compiled *htmlmaster.Compiled
	values   []htmlmaster.Value
	defaults map[string]string
}

// Exact copies, not JSON encoding expansion: two retained RawMessage outputs,
// declaration array and cloned string map. Values share immutable backing whose
// original producer stays retained. Existing<=64 map topology bounds all groups.
func htmlAuthoringCanonicalCopyResourcesV1(content htmlmaster.TemplateCommitment, values, defaults int) (int64, error) {
	if values < 0 || values > htmlmaster.MaxDefinitions || defaults < 0 || defaults > htmlmaster.MaxDefinitions {
		return 0, ErrHTMLAuthoringReadV1
	}
	n := int64(4096)
	for _, length := range [...]int64{int64(len(content.MasterJSON)), int64(len(content.DefaultsJSON))} {
		if length > 0 && (!htmlInputAddV1(&n, length, 2) || !htmlInputAddV1(&n, 1, 16)) {
			return 0, ErrHTMLAuthoringReadV1
		}
	}
	if !htmlInputAddV1(&n, int64(values), 2*32) {
		return 0, ErrHTMLAuthoringReadV1
	}
	slots := int64(16)
	if defaults != 0 {
		slots = 2 * htmlInputPowerV1(max(8, (int64(defaults)*8+6)/7))
	}
	if !htmlInputAddV1(&n, slots, 2*(32+1)) || !htmlInputAddV1(&n, 1, 8191) {
		return 0, ErrHTMLAuthoringReadV1
	}
	return n / 8192 * 8192, nil
}

// Called exactly at lockCRMTemplate's original Decode/Compile/defaults policy
// point, after its fresh SQL model and CanonicalRetained result were checked.
// The fixed recheck producer owns ONE future canonical Compile arena and
// parser/default passes; full preparation owns at least that. Execute at most ONE actual Compile
// for identical private source within this same reader; rechecks reuse that
// immutable result rather than silently spending another raster arena.
func (r *ApplicationHTMLAuthoringReaderV1) PreparedRetainedTemplateV1(ctx context.Context, id uuid.UUID, version int32) (HTMLAuthoringPreparedRetainedTemplateV1, error) {
	var empty HTMLAuthoringPreparedRetainedTemplateV1
	if r == nil || r.self != r {
		return empty, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) {
		return empty, ErrHTMLAuthoringReadV1
	}
	var entry *htmlAuthoringCanonicalSourceV1
	for i := r.canonicalCount - 1; i >= 0; i-- {
		s := &r.canonicalSources[i]
		if s.id == id && s.version == version && s.revision {
			entry = s
			break
		}
	}
	if entry == nil || !entry.ready || !entry.delivered || entry.preparedDelivered || !entry.purpose.coversV1(htmlStoredTemplateRecheckV1) {
		return empty, ErrHTMLAuthoringReadV1
	}
	entry.preparedDelivered = true
	if entry.prepared == nil {
		for i := r.canonicalCount - 1; i >= 0; i-- {
			s := &r.canonicalSources[i]
			if s != entry && s.ready && s.prepared != nil && htmlAuthoringCanonicalSameV1(s, entry) {
				entry.prepared = s.prepared
				break
			}
		}
	}
	if entry.prepared == nil {
		master, err := htmlmaster.Decode(entry.content.MasterJSON)
		if err != nil {
			return empty, err
		}
		compiled, err := htmlmaster.Compile(master)
		if err != nil {
			return empty, err
		}
		defaults := map[string]string{}
		if json.Unmarshal(entry.content.DefaultsJSON, &defaults) != nil || defaults == nil {
			return empty, ErrHTMLAuthoringChangedV1
		}
		entry.prepared = &htmlAuthoringPreparedRetainedTemplateV1{compiled: compiled, values: slices.Clone(master.Values), defaults: defaults}
	}
	// This new per-read map/array projection gets its own real grant before any
	// defensive copy. Original result and all future work remain held to route end.
	owner, err := r.session.newHTMLCanonicalModelConsumerV1(ctx)
	if err != nil {
		return empty, err
	}
	r.closeConsumers = append(r.closeConsumers, owner.CloseConsumerV1)
	defer owner.finishV1()
	cost, err := htmlAuthoringCanonicalCopyResourcesV1(htmlmaster.TemplateCommitment{}, len(entry.prepared.values), len(entry.prepared.defaults))
	if err != nil {
		return empty, err
	}
	if err = owner.holdV1(ctx, cost); err != nil {
		return empty, err
	}
	// byte identity is checked at the private fresh-source cache boundary; no
	// caller buffer is compared or adopted here. Strings remain immutable.
	return HTMLAuthoringPreparedRetainedTemplateV1{Compiled: entry.prepared.compiled, Values: slices.Clone(entry.prepared.values), Defaults: maps.Clone(entry.prepared.defaults)}, nil
}
