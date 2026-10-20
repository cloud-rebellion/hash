// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

// The actual catalog owner uses the existing native reader's registered body
// loans and physical retirement fence. Its positive typed union dominates a
// full10-column routing model/cache/header even at zero TEXT bytes. Each old,
// new, SQL staging and returned model gets a distinct additive body loan.
// No source read here confers owner/credential or rule-validity authority.
func (r *ApplicationHTMLAuthoringReaderV1) AcquireCatalogOwnerV1(ctx context.Context, org, user uuid.UUID) error {
	if r == nil || r.self != r {
		return ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || org != r.session.state.org || user == uuid.Nil {
		return ErrHTMLAuthoringReadV1
	}
	// Original blocking organization fence, then real scoped User header. Do NOT
	// fetch the discarded unbounded Org model merely to establish its existence.
	id, err := r.queries.GetCatalogRuleOrgExistenceV1(ctx, org)
	if err != nil {
		return err
	}
	if id != org {
		return ErrHTMLAuthoringReadV1
	}
	h, err := r.queries.GetHTMLAuthoringActorHeaderV1(ctx, generated.GetHTMLAuthoringActorHeaderV1Params{UserID: user, OrgID: org})
	if err != nil {
		return err
	}
	if h == nil || h.UserID != user || h.OrgID != org || h.RawTextBytes < 0 {
		return ErrHTMLAuthoringReadV1
	}
	return r.acquire(ctx, h.RawTextBytes, 0)
}
func (r *ApplicationHTMLAuthoringReaderV1) ReadCatalogRuleV1(ctx context.Context, id uuid.UUID) (*generated.EidasRoutingRule, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || id == uuid.Nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	org := r.session.state.org
	h, err := r.queries.GetCatalogRuleSourceHeaderV1(ctx, generated.GetCatalogRuleSourceHeaderV1Params{OrgID: org, RuleID: id})
	if err != nil {
		return nil, err
	}
	if h == nil || h.RuleID != id || h.OrgID != org || !applicationStampV1(h.CreatedAt) || !applicationStampV1(h.UpdatedAt) || h.RawTextBytes < 0 || h.PredicateWireBytes <= 0 || h.MeasurementServerVersionNum <= 0 || h.MeasurementServerVersionNum != h.ServerVersionNum {
		return nil, ErrHTMLAuthoringReadV1
	}
	if err = r.acquire(ctx, h.RawTextBytes, h.PredicateWireBytes); err != nil {
		return nil, err
	}
	row, err := r.queries.ReadCatalogRuleSourceV1(ctx, generated.ReadCatalogRuleSourceV1Params{OrgID: org, RuleID: id, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt, ExpectedRawTextBytes: h.RawTextBytes, ExpectedPredicateWireBytes: h.PredicateWireBytes, ExpectedMeasurementServerVersionNum: h.MeasurementServerVersionNum})
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	raw, e := htmlAuthoringSumV1(int64(len(row.Name)), int64(len(row.RequiredTier)), int64(len(row.Reason)))
	if e != nil || row.ID != id || row.OrgID != org || row.CreatedAt != h.CreatedAt || row.UpdatedAt != h.UpdatedAt || raw != h.RawTextBytes || int64(len(row.PredicateJson)) != h.PredicateWireBytes {
		return nil, ErrHTMLAuthoringReadV1
	}
	return row, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) acquireFreshCatalogRuleV1(ctx context.Context, name, tier, reason string, predicate []byte) (int64, int64, error) {
	raw, err := htmlAuthoringSumV1(int64(len(name)), int64(len(tier)), int64(len(reason)))
	if err != nil {
		return 0, 0, err
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, predicate)
	if err != nil || wire < 1 {
		return 0, 0, ErrHTMLAuthoringReadV1
	}
	// SQL input, its JSONB materialization/intrinsic measurement and the fresh
	// full result coexist; three actual positive loans retain all expressions.
	for range 3 {
		if err = r.acquire(ctx, raw, wire); err != nil {
			return 0, 0, err
		}
	}
	return raw, wire, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) CreateCatalogRuleV1(ctx context.Context, p generated.InsertEIDASRuleParams) (*generated.EidasRoutingRule, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || p.OrgID != r.session.state.org {
		return nil, ErrHTMLAuthoringReadV1
	}
	raw, upper, err := r.acquireFreshCatalogRuleV1(ctx, p.Name, p.RequiredTier, p.Reason, p.PredicateJson)
	if err != nil {
		return nil, err
	}
	fresh, err := r.queries.CreateFreshEIDASRuleSourceV1(ctx, generated.CreateFreshEIDASRuleSourceV1Params{OrgID: p.OrgID, Name: p.Name, Priority: p.Priority, PredicateJson: p.PredicateJson, RequiredTier: p.RequiredTier, Reason: p.Reason, Active: p.Active})
	if err != nil {
		return nil, err
	}
	if fresh == nil || fresh.ID == uuid.Nil || fresh.OrgID != p.OrgID || !applicationStampV1(fresh.CreatedAt) || !applicationStampV1(fresh.UpdatedAt) {
		return nil, ErrHTMLAuthoringReadV1
	}
	m, err := r.queries.MeasureEIDASRuleSourceV1(ctx, generated.MeasureEIDASRuleSourceV1Params{RuleID: fresh.ID, OrgID: fresh.OrgID, ExpectedCreatedAt: fresh.CreatedAt, ExpectedUpdatedAt: fresh.UpdatedAt})
	if err != nil {
		return nil, err
	}
	if m == nil || m.RuleID != fresh.ID || m.OrgID != fresh.OrgID || m.RuleCreatedAt != fresh.CreatedAt || m.RuleUpdatedAt != fresh.UpdatedAt || m.PredicateWireBytes < 1 || m.PredicateWireBytes > upper || m.MeasurementServerVersionNum <= 0 || !applicationStampV1(m.MeasuredAt) {
		return nil, ErrHTMLAuthoringReadV1
	}
	row, err := r.queries.ReadCatalogRuleSourceV1(ctx, generated.ReadCatalogRuleSourceV1Params{OrgID: fresh.OrgID, RuleID: fresh.ID, ExpectedCreatedAt: fresh.CreatedAt, ExpectedUpdatedAt: fresh.UpdatedAt, ExpectedRawTextBytes: raw, ExpectedPredicateWireBytes: m.PredicateWireBytes, ExpectedMeasurementServerVersionNum: m.MeasurementServerVersionNum})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != fresh.ID || row.OrgID != p.OrgID || row.CreatedAt != fresh.CreatedAt || row.UpdatedAt != fresh.UpdatedAt || row.Name != p.Name || row.Priority != p.Priority || row.RequiredTier != p.RequiredTier || row.Reason != p.Reason || row.Active != p.Active || int64(len(row.PredicateJson)) != m.PredicateWireBytes {
		return nil, ErrHTMLAuthoringReadV1
	}
	return row, nil
}
func (r *ApplicationHTMLAuthoringReaderV1) UpdateCatalogRuleV1(ctx context.Context, p generated.UpdateEIDASRuleParams) (*generated.EidasRoutingRule, error) {
	if r == nil || r.self != r {
		return nil, ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || p.ID != r.session.state.document || p.OrgID != r.session.state.org {
		return nil, ErrHTMLAuthoringReadV1
	}
	raw, upper, err := r.acquireFreshCatalogRuleV1(ctx, p.Name, p.RequiredTier, p.Reason, p.PredicateJson)
	if err != nil {
		return nil, err
	}
	// Preserve the original UPDATE and full actual generated model. Its source
	// and SQL return were charged before this mutation; no old-row measurement.
	row, err := r.queries.UpdateEIDASRule(ctx, p)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != p.ID || row.OrgID != p.OrgID || !applicationStampV1(row.CreatedAt) || !applicationStampV1(row.UpdatedAt) || row.Name != p.Name || row.Priority != p.Priority || row.RequiredTier != p.RequiredTier || row.Reason != p.Reason || row.Active != p.Active {
		return nil, ErrHTMLAuthoringReadV1
	}
	actualRaw, e := htmlAuthoringSumV1(int64(len(row.Name)), int64(len(row.RequiredTier)), int64(len(row.Reason)))
	if e != nil || actualRaw != raw || int64(len(row.PredicateJson)) > upper {
		return nil, ErrHTMLAuthoringReadV1
	}
	m, err := r.queries.MeasureEIDASRuleSourceV1(ctx, generated.MeasureEIDASRuleSourceV1Params{RuleID: row.ID, OrgID: row.OrgID, ExpectedCreatedAt: row.CreatedAt, ExpectedUpdatedAt: row.UpdatedAt})
	if err != nil {
		return nil, err
	}
	if m == nil || m.RuleID != row.ID || m.OrgID != row.OrgID || m.RuleCreatedAt != row.CreatedAt || m.RuleUpdatedAt != row.UpdatedAt || m.PredicateWireBytes != int64(len(row.PredicateJson)) || m.PredicateWireBytes > upper || m.MeasurementServerVersionNum <= 0 || !applicationStampV1(m.MeasuredAt) {
		return nil, ErrHTMLAuthoringReadV1
	}
	return row, nil
}

// Delete checks only the scoped scalar identity. An unmeasured old rule can
// still be removed; it never expands or validates a predicate to authorize
// deletion, and never refreshes its cache as a reader side effect.
func (r *ApplicationHTMLAuthoringReaderV1) DeleteCatalogRuleV1(ctx context.Context, id uuid.UUID) error {
	if r == nil || r.self != r {
		return ErrHTMLAuthoringReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || id != r.session.state.document {
		return ErrHTMLAuthoringReadV1
	}
	org := r.session.state.org
	h, err := r.queries.GetCatalogRuleSourceHeaderV1(ctx, generated.GetCatalogRuleSourceHeaderV1Params{OrgID: org, RuleID: id})
	if err != nil {
		return err
	}
	if h == nil || h.RuleID != id || h.OrgID != org {
		return ErrHTMLAuthoringReadV1
	}
	return r.queries.DeleteEIDASRule(ctx, generated.DeleteEIDASRuleParams{ID: id, OrgID: org})
}
