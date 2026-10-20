// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These real pgx pools are offline construction fixtures. MinConns is zero;
// neither this test nor the runtime constructor dispatches a SQL connection.
func workRuntimePoolTestV1(t *testing.T, maximum int32) *pgxpool.Pool {
	t.Helper()
	config, err := pgxpool.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable&pool_min_conns=0")
	if err != nil {
		t.Fatal("parse synthetic pool profile")
	}
	config.MaxConns = maximum
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("construct real offline pool")
	}
	t.Cleanup(pool.Close)
	return pool
}
func workRuntimeLimitsTestV1() workguard.LimitsV1 {
	v := workguard.VectorV1{ParentBytes: 8 << 20, DBStagingBytes: 8 << 20, SQLSessions: 2}
	return workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 8, MaxOrganisationGrants: 8}
}
func TestWorkRuntimeUsesOneActualCoordinatorAndFactoryV1(t *testing.T) {
	pool := workRuntimePoolTestV1(t, 2)
	runtime, err := NewWorkRuntimeV1(pool, workRuntimeLimitsTestV1(), 4)
	if err != nil {
		t.Fatal("explicit exact-boundary allocation refused")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		if err := runtime.CloseV1(cleanupCtx); err != nil {
			t.Error("empty actual factory did not close")
		}
	})
	if !runtime.MatchesPoolV1(pool) || runtime.WorkV1() != runtime.work || runtime.SessionsV1() != runtime.sessions || runtime.sessions.state.work != runtime.work || runtime.work.coordinator != runtime.coordinator {
		t.Fatal("runtime split the actual pool, coordinator, adapter or factory")
	}
	if runtime.MatchesPoolV1(workRuntimePoolTestV1(t, 2)) {
		t.Fatal("different real pool accepted as the runtime owner")
	}
	org := uuid.New()
	budget := ApplicationBudgetV1{Phase: "locked-request-header", OrgID: org, DocumentID: uuid.New(), RecipientID: uuid.New(), WorkingBytes: 8 << 20, DBStagingBytes: 8 << 20}
	release, err := runtime.WorkV1().ApplicationV1(ctx, budget)
	if err != nil {
		t.Fatal("actual fixed header adapter refused configured capacity")
	}
	defer release()
	snap := runtime.coordinator.SnapshotV1(org)
	if snap.Global.ParentBytes != 8<<20 || snap.Global.DBStagingBytes != 8<<20 || snap.GlobalGrants != 1 {
		t.Fatal("fixed adapter did not debit the configured coordinator")
	}
	// A second consumer through the factory's exact adapter must compete with
	// the first; a fresh per-engine coordinator would wrongly grant this call.
	if extra, err := runtime.SessionsV1().state.work.ApplicationV1(ctx, budget); err == nil || extra != nil {
		if extra != nil {
			extra()
		}
		t.Fatal("factory bypassed the held process allocation")
	}
	other := budget
	other.OrgID = uuid.New()
	if extra, err := runtime.WorkV1().ApplicationV1(ctx, other); err == nil || extra != nil {
		if extra != nil {
			extra()
		}
		t.Fatal("another organisation bypassed global process allocation")
	}
	release()
	if snap := runtime.coordinator.SnapshotV1(org); snap.GlobalGrants != 0 || snap.Global != (workguard.VectorV1{}) {
		t.Fatal("retired local-only fixture retained a grant")
	}
	again, err := runtime.SessionsV1().state.work.ApplicationV1(ctx, budget)
	if err != nil {
		t.Fatal("same shared adapter could not reuse genuinely released local-only capacity")
	}
	again()
	if err := runtime.CloseV1(ctx); err != nil {
		t.Fatal("empty factory cleanup failed")
	}
	if _, err := runtime.SessionsV1().organisationV1(ctx, org); err == nil {
		t.Fatal("closed runtime factory accepted new session organisation ownership")
	}
}
func TestWorkRuntimeRejectsImpossibleAllocationAndProfileV1(t *testing.T) {
	pool := workRuntimePoolTestV1(t, 2)
	cases := []struct {
		name       string
		limits     workguard.LimitsV1
		allocation int64
	}{
		{"pool plus direct exceeds allocation", workRuntimeLimitsTestV1(), 3},
		{"allocation below pool alone", workRuntimeLimitsTestV1(), 1},
		{"zero allocation", workRuntimeLimitsTestV1(), 0},
		{"negative allocation", workRuntimeLimitsTestV1(), -1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := NewWorkRuntimeV1(pool, tc.limits, tc.allocation); got != nil || !errors.Is(err, ErrWorkRuntimeV1) {
				t.Fatal("impossible process connection allocation created a runtime")
			}
		})
	}
	for _, mutate := range []func(*workguard.LimitsV1){
		func(l *workguard.LimitsV1) { l.Global.ParentBytes = 1<<40 + 1 },
		func(l *workguard.LimitsV1) { l.Global.RendererRequests = 1<<16 + 1 },
		func(l *workguard.LimitsV1) { l.Organisation.ParentBytes = l.Global.ParentBytes + 1 },
		func(l *workguard.LimitsV1) { l.MaxGrants = 0 },
		func(l *workguard.LimitsV1) { l.MaxGrants = 1<<16 + 1 },
		func(l *workguard.LimitsV1) { l.MaxOrganisationGrants = l.MaxGrants + 1 },
		func(l *workguard.LimitsV1) { l.Global.SQLSessions = 0; l.Organisation.SQLSessions = 0 },
	} {
		limits := workRuntimeLimitsTestV1()
		mutate(&limits)
		if got, err := NewWorkRuntimeV1(pool, limits, 1<<63-1); got != nil || !errors.Is(err, ErrWorkRuntimeV1) {
			t.Fatal("invalid vector/grant configuration created a runtime")
		}
	}
	if got, err := NewWorkRuntimeV1(nil, workRuntimeLimitsTestV1(), 4); got != nil || !errors.Is(err, ErrWorkRuntimeV1) {
		t.Fatal("nil pool created a runtime")
	}
	// An effective pgx callback changes the actual connection profile. The
	// runtime must keep the real fixed factory's refusal, not substitute a dialer.
	config, err := pgxpool.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable&pool_min_conns=0")
	if err != nil {
		t.Fatal("parse unsupported synthetic profile")
	}
	config.MaxConns = 2
	config.ConnConfig.OnNotice = func(_ *pgconn.PgConn, _ *pgconn.Notice) {}
	unsupported, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal("construct unsupported real offline pool")
	}
	defer unsupported.Close()
	if got, err := NewWorkRuntimeV1(unsupported, workRuntimeLimitsTestV1(), 4); got != nil || !errors.Is(err, ErrWorkRuntimeV1) {
		t.Fatal("runtime replaced the actual unsupported connection profile")
	}
}
func TestWorkRuntimeAbsentValueCreatesNoObjectsV1(t *testing.T) {
	var absent *WorkRuntimeV1
	zero := &WorkRuntimeV1{}
	for _, r := range []*WorkRuntimeV1{absent, zero} {
		if r.WorkV1() != nil || r.SessionsV1() != nil || r.MatchesPoolV1(nil) {
			t.Fatal("absent runtime manufactured admission objects")
		}
		if !errors.Is(r.CloseV1(context.Background()), ErrWorkRuntimeV1) || !errors.Is(r.ReconcileCleanupV1(context.Background()), ErrWorkRuntimeV1) {
			t.Fatal("absent runtime claimed physical cleanup")
		}
	}
}
