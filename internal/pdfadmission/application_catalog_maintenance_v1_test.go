// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Actual factory/coordinator/owned callback/generated methods below use explicit
// synthetic typed SQL acknowledgments and backend evidence. They exercise the
// native accounting and once/consumer/physical conjunction, NOT PG codecs,
// trigger execution, native Open or maintenance authorization acceptance.
type catalogMaintenanceFixtureV1 struct {
	factory     *ApplicationSessionFactoryV1
	owner       *ApplicationCatalogMaintenanceV1
	session     *ApplicationSessionV1
	coordinator *workguard.CoordinatorV1
	tx          *htmlRevisionReadTxTestV1
	observed    atomic.Bool
}

func newCatalogMaintenanceFixtureV1(t *testing.T, kind catalogMaintenanceKindV1, org, id uuid.UUID, rows ...pgx.Row) (context.Context, *catalogMaintenanceFixtureV1) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	coord, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 256 << 20, DBStagingBytes: 256 << 20, SQLSessions: 2}, Organisation: workguard.VectorV1{ParentBytes: 256 << 20, DBStagingBytes: 256 << 20, SQLSessions: 2}, MaxGrants: 16, MaxOrganisationGrants: 16})
	if err != nil {
		t.Fatal(err)
	}
	work, err := NewWorkAdmissionV1(coord)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	f := &catalogMaintenanceFixtureV1{factory: factory, coordinator: coord}
	control, err := factory.signerControlV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sqlGrant, err := work.signerProcessSQLV1(ctx)
	if err != nil {
		t.Fatal(err)
	}
	native := applicationSessionNewOwnerV1(control, uuid.Nil, false)
	native.grant = sqlGrant
	native.dialed = true
	done := make(chan struct{})
	close(done)
	native.fence = &applicationSessionFenceV1{clientDone: done, observe: func(context.Context, applicationBackendIdentityV1) (bool, error) { return f.observed.Load(), nil }}
	f.tx = &htmlRevisionReadTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, rows: rows}
	native.tx = f.tx
	session := &ApplicationSessionV1{state: native}
	f.session = session
	factory.state.sessions[native] = struct{}{}
	original, stop := context.WithCancel(ctx)
	s := &applicationCatalogMaintenanceStateV1{factory: factory.state, session: session, original: original, cancel: stop, kind: kind, orgID: org, sourceID: id, active: true}
	f.owner = &ApplicationCatalogMaintenanceV1{state: s}
	factory.state.htmlCatalogMaintenance[s] = struct{}{}
	fixed := applicationSignerScopeHeaderBytesV1 + int64(unsafe.Sizeof(applicationCatalogMaintenanceStateV1{})) + 2*int64(unsafe.Sizeof(CatalogMeasurementReceiptV1{}))
	g, err := coord.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: fixed, DBStagingBytes: fixed})
	if err != nil {
		t.Fatal(err)
	}
	s.releases = append(s.releases, g.Close)
	t.Cleanup(func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		f.owner.CloseConsumerV1()
		native.mu.Lock()
		native.closed = true
		native.mu.Unlock()
		f.observed.Store(true)
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := session.ReconcileCleanupV1(cleanup); err != nil {
			t.Error(err)
		}
		factory.reconcileCatalogMaintenanceV1()
		if got := coord.SnapshotV1(uuid.Nil); got != (workguard.SnapshotV1{}) {
			t.Error("joined synthetic maintenance retained original debt", got)
		}
		if factory.PendingV1().CatalogMaintenance != 0 {
			t.Error("maintenance owner remained registered")
		}
	})
	return ctx, f
}
func catalogMaintenanceStampV1() pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC), Valid: true}
}
func catalogPlanReceiptsV1(id uuid.UUID) (generated.GetPlanSourceControlledBackfillHeaderV1Row, generated.BillingPlanFeatureSizesV1) {
	stamp := catalogMaintenanceStampV1()
	return generated.GetPlanSourceControlledBackfillHeaderV1Row{ID: id, CreatedAt: stamp, RawTextBytes: 9, FeaturesUncompressed: true, FeaturesStorageBytes: 32, FeaturesWireUpperBound: 100, ServerVersionNum: 160015}, generated.BillingPlanFeatureSizesV1{PlanID: id, PlanCreatedAt: stamp, FeaturesWireBytes: 20, MeasurementServerVersionNum: 160015, MeasuredAt: stamp}
}

func TestCatalogMaintenanceActualPlanMeasurementAndConjunctionV1(t *testing.T) {
	for _, consumerFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "consumer-first", false: "physical-first"}[consumerFirst], func(t *testing.T) {
			id := uuid.New()
			header, measured := catalogPlanReceiptsV1(id)
			ctx, f := newCatalogMaintenanceFixtureV1(t, catalogMaintenancePlanV1, uuid.Nil, id, htmlRevisionReadRowTestV1{record: header}, htmlRevisionReadRowTestV1{record: measured})
			s := f.owner.state
			before := f.coordinator.SnapshotV1(uuid.Nil)
			if before.GlobalGrants != 2 || before.ActiveOrganisations != 0 {
				t.Fatal("process work manufactured a tenant")
			}
			err := f.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
				return s.measurePlanV1(call, generated.New(db), id)
			})
			if err != nil {
				t.Fatal(err)
			}
			charged := f.coordinator.SnapshotV1(uuid.Nil)
			if charged.GlobalGrants != 3 || charged.Global.ParentBytes <= before.Global.ParentBytes || charged.Global.DBStagingBytes <= before.Global.DBStagingBytes || charged.ActiveOrganisations != 0 {
				t.Fatal("actual scalar source did not fund its separate process body")
			}
			if err := f.session.CommitV1(ctx); err != nil {
				t.Fatal(err)
			}
			s.mu.Lock()
			s.committed = true
			s.active = false
			s.mu.Unlock()
			if _, err := f.owner.ReceiptV1(); err == nil {
				t.Fatal("logical commit supplied physical receipt authority")
			}
			if consumerFirst {
				f.owner.CloseConsumerV1()
				if f.coordinator.SnapshotV1(uuid.Nil) != charged {
					t.Fatal("consumer completion refunded physical work")
				}
			}
			f.session.state.mu.Lock()
			f.session.state.closed = true
			f.session.state.mu.Unlock()
			if err := f.session.ReconcileCleanupV1(ctx); !errors.Is(err, ErrApplicationSessionUnknownV1) {
				t.Fatal("missing synthetic backend evidence was credited")
			}
			if f.coordinator.SnapshotV1(uuid.Nil) != charged {
				t.Fatal("unknown physical cleanup refunded source")
			}
			f.observed.Store(true)
			if err := f.session.ReconcileCleanupV1(ctx); err != nil {
				t.Fatal(err)
			}
			if f.coordinator.SnapshotV1(uuid.Nil).GlobalGrants != 2 {
				t.Fatal("SQL grant was not independently retired")
			}
			if !consumerFirst {
				receipt, err := f.owner.ReceiptV1()
				if err != nil || receipt.SourceID != id || receipt.WireBytes != 20 || receipt.ServerVersionNum != 160015 {
					t.Fatal("acknowledged native result was lost", err)
				}
				if _, err = f.owner.ReceiptV1(); err == nil {
					t.Fatal("receipt view was replayed")
				}
				copyHandle := *f.owner
				copyHandle.CloseConsumerV1()
			}
			f.factory.reconcileCatalogMaintenanceV1()
			if got := f.coordinator.SnapshotV1(uuid.Nil); got != (workguard.SnapshotV1{}) {
				t.Fatal("complete conjunction retained original process grants", got)
			}
		})
	}
}

func TestCatalogMaintenanceControlledHeaderRefusesBeforeExpansionV1(t *testing.T) {
	cases := []struct {
		name   string
		change func(*generated.GetPlanSourceControlledBackfillHeaderV1Row)
	}{
		{"compressed", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) { h.FeaturesUncompressed = false }},
		{"unsupported-server", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) { h.ServerVersionNum = 160014 }},
		{"negative-wire", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) { h.FeaturesWireUpperBound = -1 }},
		{"overflow-staging", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) { h.FeaturesWireUpperBound = 1 << 40 }},
		{"foreign", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) { h.ID = uuid.New() }},
		{"infinite-source", func(h *generated.GetPlanSourceControlledBackfillHeaderV1Row) {
			h.CreatedAt.InfinityModifier = pgtype.Infinity
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id := uuid.New()
			header, _ := catalogPlanReceiptsV1(id)
			tc.change(&header)
			ctx, f := newCatalogMaintenanceFixtureV1(t, catalogMaintenancePlanV1, uuid.Nil, id, htmlRevisionReadRowTestV1{record: header})
			before := f.coordinator.SnapshotV1(uuid.Nil)
			err := f.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
				return f.owner.state.measurePlanV1(call, generated.New(db), id)
			})
			if err == nil {
				t.Fatal("invalid controlled source admitted")
			}
			if len(f.tx.rows) != 0 || f.tx.calls != 1 || f.coordinator.SnapshotV1(uuid.Nil) != before {
				t.Fatal("refusal expanded/measured or changed original debt")
			}
			if err = f.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
				return f.owner.state.measurePlanV1(call, generated.New(db), id)
			}); err == nil {
				t.Fatal("failed original measurement attempt was replayed")
			}
		})
	}
}

func TestCatalogMaintenanceRealCapacityDenialNoMeasurementV1(t *testing.T) {
	id := uuid.New()
	header, _ := catalogPlanReceiptsV1(id)
	header.FeaturesWireUpperBound = 32 << 20
	ctx, f := newCatalogMaintenanceFixtureV1(t, catalogMaintenancePlanV1, uuid.Nil, id, htmlRevisionReadRowTestV1{record: header})
	before := f.coordinator.SnapshotV1(uuid.Nil)
	err := f.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		return f.owner.state.measurePlanV1(call, generated.New(db), id)
	})
	if !errors.Is(err, workguard.ErrUnavailableV1) || f.coordinator.SnapshotV1(uuid.Nil) != before || len(f.tx.rows) != 0 || f.tx.calls != 1 {
		t.Fatal("actual process coordinator denial changed debt or dispatched measure", err)
	}
}

func TestCatalogMaintenanceRuleScopeWireAndCallbackV1(t *testing.T) {
	for _, fault := range []string{"none", "org", "wire", "version", "callback"} {
		t.Run(fault, func(t *testing.T) {
			org, id := uuid.New(), uuid.New()
			stamp := catalogMaintenanceStampV1()
			header := generated.GetEIDASRuleControlledBackfillHeaderV1Row{RuleID: id, OrgID: org, CreatedAt: stamp, UpdatedAt: stamp, RawTextBytes: 8, StoredBytes: 32, IsUncompressed: true, PredicateWireUpperBytes: 100, ServerVersionNum: 160015}
			measured := generated.EidasRuleWireSizesV1{RuleID: id, OrgID: org, RuleCreatedAt: stamp, RuleUpdatedAt: stamp, PredicateWireBytes: 20, MeasurementServerVersionNum: 160015, MeasuredAt: stamp}
			switch fault {
			case "org":
				measured.OrgID = uuid.New()
			case "wire":
				measured.PredicateWireBytes = 101
			case "version":
				measured.MeasurementServerVersionNum = 160014
			}
			ctx, f := newCatalogMaintenanceFixtureV1(t, catalogMaintenanceRuleV1, org, id, htmlRevisionReadRowTestV1{record: header}, htmlRevisionReadRowTestV1{record: measured})
			err := f.session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
				if fault == "callback" {
					call = ctx
				}
				return f.owner.state.measureRuleV1(call, generated.New(db), org, id)
			})
			if (fault == "none") != (err == nil) {
				t.Fatal("rule measurement accepted wrong scope/receipt", err)
			}
			if fault == "callback" && len(f.tx.rows) != 2 {
				t.Fatal("foreign callback dispatched source header")
			}
			if f.coordinator.SnapshotV1(org).OrganisationGrants != 0 {
				t.Fatal("catalog process source was charged to fake tenant")
			}
		})
	}
}

func TestCatalogMaintenancePublicEntryDeniesUnboundedAndZeroDispatchV1(t *testing.T) {
	coordinator, work := applicationSessionResourcesTestV1(t, 2)
	factory, err := NewApplicationSessionFactoryV1(applicationSessionConfigTestV1(t), work, ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	if h, err := factory.ControlledMeasurePlanSourceV1(context.Background(), uuid.New()); err == nil || h != nil {
		t.Fatal("unbounded input attempted maintenance")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	h, err := factory.ControlledMeasurePlanSourceV1(ctx, uuid.New())
	if err == nil || h == nil {
		t.Fatal("zero Parent allocation did not refuse original grant")
	}
	if factory.PendingV1().CatalogMaintenance != 0 || factory.PendingV1().WorkSessions != 0 || factory.PendingV1().ObserverSessions != 0 || coordinator.SnapshotV1(uuid.Nil) != (workguard.SnapshotV1{}) {
		t.Fatal("pre-Open capacity refusal retained or dialed work")
	}
}

func TestCatalogMaintenanceCancellationCannotEndOriginalOpeningV1(t *testing.T) {
	id := uuid.New()
	ctx, f := newCatalogMaintenanceFixtureV1(t, catalogMaintenancePlanV1, uuid.Nil, id)
	s := f.owner.state
	before := f.coordinator.SnapshotV1(uuid.Nil)
	s.cancel()
	if got := f.coordinator.SnapshotV1(uuid.Nil); got != before {
		t.Fatal("cancellation refunded original debt")
	}
	saved := s.session
	s.mu.Lock()
	s.session = nil
	s.mu.Unlock()
	cleanup, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := f.owner.CloseV1(cleanup); !errors.Is(err, ErrApplicationSessionUnknownV1) {
		t.Fatal("in-flight nil session was declared disposed")
	}
	if f.coordinator.SnapshotV1(uuid.Nil) != before || f.factory.PendingV1().CatalogMaintenance != 1 {
		t.Fatal("opening ownership was lost")
	}
	s.mu.Lock()
	s.session = saved
	s.mu.Unlock()
	_ = ctx
}
