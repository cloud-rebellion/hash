// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrCatalogMaintenanceV1 = errors.New("pdfadmission: controlled catalog maintenance unavailable")

// CatalogMeasurementReceiptV1 contains only an acknowledged intrinsic cache
// result. It grants no tenant, billing, routing, source or replay authority.
type CatalogMeasurementReceiptV1 struct {
	Kind                             string
	SourceID, OrgID                  uuid.UUID
	CreatedAt, UpdatedAt, MeasuredAt pgtype.Timestamptz
	WireBytes                        int64
	ServerVersionNum                 int32
}

type catalogMaintenanceKindV1 uint8

const (
	catalogMaintenancePlanV1 catalogMaintenanceKindV1 = iota + 1
	catalogMaintenanceRuleV1
)

type ApplicationCatalogMaintenanceV1 struct {
	state *applicationCatalogMaintenanceStateV1
}
type applicationCatalogMaintenanceStateV1 struct {
	mu                                                     sync.Mutex
	factory                                                *applicationSessionFactoryStateV1
	session                                                *ApplicationSessionV1
	original                                               context.Context
	cancel                                                 context.CancelFunc
	receipt                                                CatalogMeasurementReceiptV1
	releases                                               []func()
	kind                                                   catalogMaintenanceKindV1
	sourceID, orgID                                        uuid.UUID
	attempted                                              bool
	active, committed, delivered, consumerClosed, released bool
}

// ControlledMeasurePlanSourceV1 is an EXPLICIT one-source maintenance entry,
// never a normal PlanForOrg/read fallback. Only the direct stored uncompressed
// PG16.15 header proves its finite expanded text envelope before measurement.
func (f *ApplicationSessionFactoryV1) ControlledMeasurePlanSourceV1(ctx context.Context, planID uuid.UUID) (*ApplicationCatalogMaintenanceV1, error) {
	if planID == uuid.Nil {
		return nil, ErrCatalogMaintenanceV1
	}
	return f.runCatalogMaintenanceV1(ctx, catalogMaintenancePlanV1, uuid.Nil, planID)
}

// ControlledMeasureEIDASRuleSourceV1 retains the actual Org UPDATE fence and
// Rule UPDATE lock from its scalar header through the same transaction's
// measurement and acknowledged commit. UUIDs select work, never authorization.
func (f *ApplicationSessionFactoryV1) ControlledMeasureEIDASRuleSourceV1(ctx context.Context, orgID, ruleID uuid.UUID) (*ApplicationCatalogMaintenanceV1, error) {
	if orgID == uuid.Nil || ruleID == uuid.Nil {
		return nil, ErrCatalogMaintenanceV1
	}
	return f.runCatalogMaintenanceV1(ctx, catalogMaintenanceRuleV1, orgID, ruleID)
}

func (s *applicationCatalogMaintenanceStateV1) measurePlanV1(call context.Context, q *generated.Queries, planID uuid.UUID) error {
	if !s.beginMeasurementV1(call, catalogMaintenancePlanV1, uuid.Nil, planID) {
		return ErrCatalogMaintenanceV1
	}

	h, err := q.GetPlanSourceControlledBackfillHeaderV1(call, planID)
	if err != nil {
		return err
	}
	if h == nil || h.ID != planID || !applicationStampV1(h.CreatedAt) || !h.FeaturesUncompressed || h.FeaturesStorageBytes <= 0 || h.FeaturesWireUpperBound <= 0 || h.RawTextBytes < 0 || h.ServerVersionNum != 160015 {
		return ErrCatalogMaintenanceV1
	}
	if err = s.holdStoredSourceV1(call, h.RawTextBytes, h.FeaturesWireUpperBound); err != nil {
		return err
	}
	m, err := q.MeasurePlanSourceFeaturesV1(call, generated.MeasurePlanSourceFeaturesV1Params{PlanID: h.ID, ExpectedCreatedAt: h.CreatedAt})
	if err != nil {
		return err
	}
	if m == nil || m.PlanID != h.ID || m.PlanCreatedAt != h.CreatedAt || m.FeaturesWireBytes <= 0 || m.FeaturesWireBytes > h.FeaturesWireUpperBound || m.MeasurementServerVersionNum != h.ServerVersionNum || !applicationStampV1(m.MeasuredAt) {
		return ErrCatalogMaintenanceV1
	}
	s.receipt = CatalogMeasurementReceiptV1{Kind: "plan", SourceID: m.PlanID, CreatedAt: m.PlanCreatedAt, MeasuredAt: m.MeasuredAt, WireBytes: m.FeaturesWireBytes, ServerVersionNum: m.MeasurementServerVersionNum}
	return nil
}

func (s *applicationCatalogMaintenanceStateV1) measureRuleV1(call context.Context, q *generated.Queries, orgID, ruleID uuid.UUID) error {
	if !s.beginMeasurementV1(call, catalogMaintenanceRuleV1, orgID, ruleID) {
		return ErrCatalogMaintenanceV1
	}

	h, err := q.GetEIDASRuleControlledBackfillHeaderV1(call, generated.GetEIDASRuleControlledBackfillHeaderV1Params{OrgID: orgID, RuleID: ruleID})
	if err != nil {
		return err
	}
	if h == nil || h.RuleID != ruleID || h.OrgID != orgID || !applicationStampV1(h.CreatedAt) || !applicationStampV1(h.UpdatedAt) || !h.IsUncompressed || h.StoredBytes <= 0 || h.PredicateWireUpperBytes <= 0 || h.RawTextBytes < 0 || h.ServerVersionNum != 160015 {
		return ErrCatalogMaintenanceV1
	}
	if err = s.holdStoredSourceV1(call, h.RawTextBytes, h.PredicateWireUpperBytes); err != nil {
		return err
	}
	m, err := q.MeasureEIDASRuleSourceV1(call, generated.MeasureEIDASRuleSourceV1Params{RuleID: h.RuleID, OrgID: h.OrgID, ExpectedCreatedAt: h.CreatedAt, ExpectedUpdatedAt: h.UpdatedAt})
	if err != nil {
		return err
	}
	if m == nil || m.RuleID != h.RuleID || m.OrgID != h.OrgID || m.RuleCreatedAt != h.CreatedAt || m.RuleUpdatedAt != h.UpdatedAt || m.PredicateWireBytes <= 0 || m.PredicateWireBytes > h.PredicateWireUpperBytes || m.MeasurementServerVersionNum != h.ServerVersionNum || !applicationStampV1(m.MeasuredAt) {
		return ErrCatalogMaintenanceV1
	}
	s.receipt = CatalogMeasurementReceiptV1{Kind: "eidas-rule", SourceID: m.RuleID, OrgID: m.OrgID, CreatedAt: m.RuleCreatedAt, UpdatedAt: m.RuleUpdatedAt, MeasuredAt: m.MeasuredAt, WireBytes: m.PredicateWireBytes, ServerVersionNum: m.MeasurementServerVersionNum}
	return nil
}

// Only the two fixed methods above select this private continuation. A caller
// cannot supply SQL, costs, a transaction, retirement proof or a permission bit.
func (f *ApplicationSessionFactoryV1) runCatalogMaintenanceV1(ctx context.Context, kind catalogMaintenanceKindV1, orgID, sourceID uuid.UUID) (*ApplicationCatalogMaintenanceV1, error) {
	if f == nil || f.state == nil || (kind != catalogMaintenancePlanV1 && kind != catalogMaintenanceRuleV1) || sourceID == uuid.Nil || !applicationContextV1(ctx) {
		return nil, ErrCatalogMaintenanceV1
	}
	p := f.state
	original, cancel := context.WithCancel(ctx)
	s := &applicationCatalogMaintenanceStateV1{factory: p, original: original, cancel: cancel, kind: kind, sourceID: sourceID, orgID: orgID, active: true}
	h := &ApplicationCatalogMaintenanceV1{state: s}
	// Register BEFORE any grant/Open, so Close cannot mistake an in-flight nil
	// session for disposal. This registry is distinct from actual signer scopes.
	p.mu.Lock()
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlCatalogMaintenance == nil || len(p.htmlCatalogMaintenance) >= applicationSessionMaxWorkV1 {
		p.mu.Unlock()
		cancel()
		return nil, ErrCatalogMaintenanceV1
	}
	p.htmlCatalogMaintenance[s] = struct{}{}
	fixed := applicationSignerScopeHeaderBytesV1 + int64(unsafe.Sizeof(applicationCatalogMaintenanceStateV1{})) + 2*int64(unsafe.Sizeof(CatalogMeasurementReceiptV1{}))
	grant, err := p.work.coordinator.TryAcquireProcessV1(original, workguard.VectorV1{ParentBytes: fixed, DBStagingBytes: fixed})
	if err == nil {
		s.releases = append(s.releases, grant.Close)
	}
	p.mu.Unlock()
	if err == nil {
		var session *ApplicationSessionV1
		// This is the existing genuine processControl opener and same physical
		// observer/coordinator. It performs no signer lookup and uses no fake tenant.
		session, err = f.openSignerProbeSessionV1(original)
		s.mu.Lock()
		s.session = session
		s.mu.Unlock()
		if err == nil {
			err = session.WithTxV1(original, func(call context.Context, db generated.DBTX) error {
				q := generated.New(db)
				if kind == catalogMaintenancePlanV1 {
					return s.measurePlanV1(call, q, sourceID)
				}
				return s.measureRuleV1(call, q, orgID, sourceID)
			})
		}
		if err == nil {
			err = session.CommitV1(original)
			if err == nil {
				s.mu.Lock()
				s.committed = true
				s.mu.Unlock()
			}
		}
	}
	// Cleanup can only close/reconcile this SAME attempted native handle. It
	// cannot run the continuation, reopen a transaction or replay unknown commit.
	cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	s.mu.Lock()
	session := s.session
	s.mu.Unlock()
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
		return h, errors.Join(ErrCatalogMaintenanceV1, err)
	}
	if session == nil || !session.RetiredV1() {
		h.CloseConsumerV1()
		return h, ErrApplicationSessionUnknownV1
	}
	return h, nil
}

func (s *applicationCatalogMaintenanceStateV1) holdStoredSourceV1(call context.Context, raw, wire int64) error {
	if s == nil || !applicationContextV1(call) || raw < 0 || wire <= 0 {
		return ErrCatalogMaintenanceV1
	}
	// Complete fixed header/cache/receipt containers stay positive at zero raw.
	// 8*raw+16*wire is logical staging credit, NOT a PG heap or RSS upper bound.
	typed := int64(unsafe.Sizeof(generated.GetPlanSourceControlledBackfillHeaderV1Row{})) + int64(unsafe.Sizeof(generated.GetEIDASRuleControlledBackfillHeaderV1Row{})) + int64(unsafe.Sizeof(generated.BillingPlanFeatureSizesV1{})) + int64(unsafe.Sizeof(generated.EidasRuleWireSizesV1{})) + 2*int64(unsafe.Sizeof(CatalogMeasurementReceiptV1{}))
	const max int64 = 1 << 40
	if typed <= 0 || typed > max || raw > (max-typed)/8 {
		return ErrCatalogMaintenanceV1
	}
	n := typed + 8*raw
	if wire > (max-n)/16 {
		return ErrCatalogMaintenanceV1
	}
	n += 16 * wire
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.consumerClosed || s.released || s.original == nil || s.original.Err() != nil || s.session == nil || call.Value(applicationSessionCallbackKeyV1{}) != s.session.state {
		return ErrCatalogMaintenanceV1
	}
	p := s.factory
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.htmlCatalogMaintenance == nil {
		return ErrCatalogMaintenanceV1
	}
	if _, ok := p.htmlCatalogMaintenance[s]; !ok {
		return ErrCatalogMaintenanceV1
	}
	g, err := p.work.coordinator.TryAcquireProcessV1(s.original, workguard.VectorV1{ParentBytes: n, DBStagingBytes: n})
	if err != nil {
		return err
	}
	s.releases = append(s.releases, g.Close)
	return nil
}

// ReceiptV1 delivers one fixed defensive numeric view. Successful SQL commit
// alone is insufficient: physical client/backend retirement must also finish.
func (h *ApplicationCatalogMaintenanceV1) ReceiptV1() (CatalogMeasurementReceiptV1, error) {
	if h == nil || h.state == nil {
		return CatalogMeasurementReceiptV1{}, ErrCatalogMaintenanceV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active || !s.committed || s.delivered || s.consumerClosed || s.released || s.session == nil || !s.session.RetiredV1() {
		return CatalogMeasurementReceiptV1{}, ErrCatalogMaintenanceV1
	}
	s.delivered = true
	return s.receipt, nil
}
func (h *ApplicationCatalogMaintenanceV1) CloseConsumerV1() {
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
func (s *applicationCatalogMaintenanceStateV1) reconcileV1() bool {
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return true
	}
	if !s.consumerClosed || s.active || (s.session != nil && !s.session.RetiredV1()) {
		s.mu.Unlock()
		return false
	}
	releases := s.releases
	s.releases = nil
	s.receipt = CatalogMeasurementReceiptV1{}
	s.original = nil
	s.cancel = nil
	s.released = true
	p := s.factory
	s.mu.Unlock()
	for _, release := range releases {
		release()
	}
	p.mu.Lock()
	delete(p.htmlCatalogMaintenance, s)
	p.mu.Unlock()
	return true
}
func (f *ApplicationSessionFactoryV1) reconcileCatalogMaintenanceV1() {
	if f == nil || f.state == nil {
		return
	}
	p := f.state
	p.mu.Lock()
	list := make([]*applicationCatalogMaintenanceStateV1, 0, len(p.htmlCatalogMaintenance))
	for s := range p.htmlCatalogMaintenance {
		list = append(list, s)
	}
	p.mu.Unlock()
	for _, s := range list {
		s.reconcileV1()
	}
}

func (s *applicationCatalogMaintenanceStateV1) beginMeasurementV1(call context.Context, kind catalogMaintenanceKindV1, orgID, sourceID uuid.UUID) bool {
	if s == nil || !applicationContextV1(call) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.active || s.consumerClosed || s.released || s.session == nil || s.original == nil || s.original.Err() != nil || s.kind != kind || s.orgID != orgID || s.sourceID != sourceID || s.attempted || call.Value(applicationSessionCallbackKeyV1{}) != s.session.state {
		return false
	}
	s.attempted = true
	return true
}

// CloseV1 is cleanup of the same attempted handle. An original Open/callback
// which has not joined is retained/unknown; nil session is not disposal proof.
func (h *ApplicationCatalogMaintenanceV1) CloseV1(ctx context.Context) error {
	if h == nil || h.state == nil {
		return nil
	}
	if !applicationContextV1(ctx) {
		return ErrApplicationSessionUnknownV1
	}
	h.CloseConsumerV1()
	s := h.state
	s.mu.Lock()
	active := s.active
	session := s.session
	s.mu.Unlock()
	if active {
		return ErrApplicationSessionUnknownV1
	}
	if session != nil {
		if err := session.CloseV1(ctx); err != nil {
			return err
		}
	}
	if !s.reconcileV1() {
		return ErrApplicationSessionUnknownV1
	}
	return nil
}
