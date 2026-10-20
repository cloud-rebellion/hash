// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgxpool"
)

func applicationRuntimeBindingPoolTestV1(t *testing.T) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://synthetic:synthetic@127.0.0.1:9/synthetic?sslmode=disable&pool_min_conns=0")
	if err != nil {
		t.Fatal("parse offline actual pool profile")
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal("construct offline actual pool")
	}
	t.Cleanup(pool.Close)
	return pool
}
func TestApplicationJournalReusesActualProcessFactoryV1(t *testing.T) {
	pool := applicationRuntimeBindingPoolTestV1(t)
	v := workguard.VectorV1{ParentBytes: 16 << 20, DBStagingBytes: 16 << 20, SQLSessions: 2}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 8, MaxOrganisationGrants: 8}, 4)
	if err != nil {
		t.Fatal("construct actual runtime")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := runtime.CloseV1(ctx); err != nil {
			t.Error("close empty actual runtime")
		}
	})
	engine := &Engine{Pool: pool, WorkRuntime: runtime}
	if got, err := engine.applicationWorkJournalV1(); err == nil || got != nil {
		t.Fatal("uninitialized engine manufactured a request journal")
	}
	if err := engine.InitializeWorkRuntimeV1(); err != nil {
		t.Fatal("engine refused its exact real runtime")
	}
	first, err := engine.applicationWorkJournalV1()
	if err != nil {
		t.Fatal("installed journal unavailable")
	}
	var workers sync.WaitGroup
	results := make(chan *applicationRequestJournalV1, 16)
	failures := make(chan error, 16)
	for i := 0; i < 16; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := engine.InitializeWorkRuntimeV1(); err != nil {
				failures <- err
				return
			}
			journal, err := engine.applicationWorkJournalV1()
			if err != nil {
				failures <- err
				return
			}
			results <- journal
		}()
	}
	workers.Wait()
	close(results)
	close(failures)
	for range failures {
		t.Fatal("concurrent startup replaced/refused the installed lifetime")
	}
	for journal := range results {
		if journal != first {
			t.Fatal("concurrent initializer manufactured independent journals")
		}
	}
	if first != engine.applicationJournal || first.factory != runtime.SessionsV1() || first.engine != engine {
		t.Fatal("journal created independent process/session authority")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := engine.CloseWorkRuntimeRequestsV1(ctx); err != nil {
		t.Fatal("empty journal could not close")
	}
	if runtime.SessionsV1().PendingV1().Closing {
		t.Fatal("journal close closed the shared authoring/process factory")
	}
	if journal, err := engine.applicationWorkJournalV1(); err == nil || journal != nil {
		t.Fatal("closed engine dispatched another journal")
	}
	if err := engine.InitializeWorkRuntimeV1(); err == nil || engine.applicationJournal != first {
		t.Fatal("closed engine replaced its original lifetime")
	}
	for _, wrong := range []*Engine{nil, {Pool: pool}, {Pool: applicationRuntimeBindingPoolTestV1(t), WorkRuntime: runtime}, {WorkRuntime: runtime}} {
		if journal, err := newApplicationRequestJournalV1(wrong); err == nil || journal != nil {
			t.Fatal("journal accepted missing or differently bound process runtime")
		}
	}
	// No token, row, readiness flag or captured operation is supplied. Successful
	// construction above proves dependency identity only, never signing authority.
}

func TestApplicationEngineCloseRetainsSameUnknownOwnersForRetryV1(t *testing.T) {
	pool := applicationRuntimeBindingPoolTestV1(t)
	v := workguard.VectorV1{ParentBytes: 16 << 20, DBStagingBytes: 16 << 20, SQLSessions: 2}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, workguard.LimitsV1{Global: v, Organisation: v, MaxGrants: 8, MaxOrganisationGrants: 8}, 4)
	if err != nil {
		t.Fatal("construct actual offline runtime")
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = runtime.CloseV1(ctx)
	})
	engine := &Engine{Pool: pool, WorkRuntime: runtime}
	if err := engine.InitializeWorkRuntimeV1(); err != nil {
		t.Fatal("initialize actual lifetime")
	}
	journal := engine.applicationJournal
	// Existing private cleanup spies prove bookkeeping only. They install zero
	// opaque session/registry objects and a synthetic exact-row premise; neither
	// this test nor its real empty factory claims physical or row authority.
	f := newApplicationCleanupStateFixtureTestV1()
	f.original.journal = journal
	f.child.journal = journal
	journal.owners[f.original.key] = f.original
	first, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// Close disposes the child before the original registry. Refuse the child
	// registry here so the asserted unknown child must remain reachable.
	f.newCleanup.onClose = func(ctx context.Context) error { cancel(); return ctx.Err() }
	if err := engine.CloseWorkRuntimeRequestsV1(first); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("unknown owner cleanup was credited")
	}
	if engine.applicationJournal != journal || journal.owners[f.original.key] != f.original || f.original.recovery != f.child || runtime.SessionsV1().PendingV1().Closing {
		t.Fatal("failed local cleanup discarded its original owner or closed the shared process factory")
	}
	if err := engine.InitializeWorkRuntimeV1(); err == nil || engine.applicationJournal != journal {
		t.Fatal("unknown engine lifetime created a replacement journal")
	}
	if got, err := engine.applicationWorkJournalV1(); err == nil || got != nil {
		t.Fatal("closing unknown lifetime obtained fresh dispatch authority")
	}
	fresh, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	f.newCleanup.onClose = nil
	if err := engine.CloseWorkRuntimeRequestsV1(fresh); err != nil || len(journal.owners) != 0 || !f.original.closed || !f.child.closed || f.originalConsumerCloses != 1 || f.childConsumerCloses != 1 {
		t.Fatal("fresh-context cleanup did not dispose the SAME retained bookkeeping owners")
	}
	if runtime.SessionsV1().PendingV1().Closing {
		t.Fatal("successful local cleanup closed the shared authoring/process factory")
	}
	if _, _, _, err := f.child.dataV1(); !errors.Is(err, errApplicationBoundRequestUnknownV1) {
		t.Fatal("synthetic cleanup fixture manufactured actual retained-session authority")
	}
}
