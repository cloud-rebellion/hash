// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Use the real shared coordinator, fixed-cost methods, tracked owned SQL wrapper
// and cleanup registry. Protocol rows and observer responses remain the existing
// explicitly synthetic native fixture: this proves the ownership conjunction,
// not real PostgreSQL/cache/COMMIT/restart/controller/provider retirement.
func TestApplicationPolicyJournalLoanV1SurvivesLiveProjectedScan(t *testing.T) {
	for _, order := range []string{"consumer-first", "retirement-first"} {
		t.Run(order, func(t *testing.T) {
			f, h, c := applicationRequestLoanFixtureV1(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			sqlGrant, err := h.state.factory.work.SQLSessionV1(ctx, f.scope.OrgID)
			if err != nil {
				t.Fatal(err)
			}
			h.state.grant = sqlGrant
			recipient := uuid.New()
			header, err := h.AcquireRequestHeaderV1(ctx, f.scope.OrgID, f.scope.DocumentID, recipient)
			if err != nil {
				t.Fatal(err)
			}
			cost := ApplicationRequestJournalCostV1{Kind: ApplicationRequestJournalCaptureV1, OriginBytes: 2000, IntentBytes: 7000, AuthorityBytes: manualfit.MaxAuthorityBytesV1, SpanBytes: manualfit.MaxSpanBytesV1, CurrentContextBytes: 23000, OriginalRawContextBytes: 29000, PolicyBytes: 31000}
			journal, err := h.AcquireRequestJournalV1(ctx, f.scope, recipient, cost)
			if err != nil {
				t.Fatal(err)
			}
			scan := &applicationSessionScanTestV1{entered: make(chan struct{}), finish: make(chan struct{})}
			h.state.tx = &applicationSessionTxTestV1{row: scan}
			done := make(chan error, 1)
			joined := make(chan struct{})
			var finishOnce sync.Once
			finishScan := func() { finishOnce.Do(func() { close(scan.finish) }) }
			go func() {
				defer close(joined)
				done <- h.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
					_, err := generated.New(db).ReadSignatureFitPolicyOrgV1(call, f.scope.OrgID)
					if err != nil {
						return err
					}
					return call.Err()
				})
			}()
			t.Cleanup(func() {
				cancel()
				finishScan()
				select {
				case <-joined:
				case <-time.After(time.Second):
					t.Error("synthetic projected scan cleanup did not join")
				}
			})
			select {
			case <-scan.entered:
			case <-ctx.Done():
				t.Fatal("generated projection scan never dispatched")
			}
			before := c.SnapshotV1(f.scope.OrgID)
			if before.GlobalGrants != 3 || before.Global.SQLSessions != 1 || f.adapter.PendingV1().Loans != 2 {
				t.Fatal("actual policy/session grants missing", before)
			}
			cancel()
			if order == "consumer-first" {
				header()
				journal()
			}
			short, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
			closeErr := h.CloseV1(short)
			stop()
			if !errors.Is(closeErr, ErrApplicationSessionUnknownV1) || h.RetiredV1() || c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("close timeout/cancellation credited live SQL or policy", closeErr)
			}
			// A cleanup receipt cannot be produced while this tracked SQL scan is live.
			reconcile := applicationTestContextV1(t)
			if err := h.ReconcileCleanupV1(reconcile); !errors.Is(err, ErrApplicationSessionUnknownV1) {
				t.Fatal("live scan escaped session join")
			}
			finishScan()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("owned callback lost cancellation", err)
				}
			case <-reconcile.Done():
				t.Fatal("projected SQL scan did not join")
			}
			if err := h.ReconcileCleanupV1(reconcile); !errors.Is(err, ErrApplicationSessionUnknownV1) || c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("scan return replaced client/backend cleanup")
			}
			gone := false
			f.adapter.fence.observe = func(context.Context, applicationBackendIdentityV1) (bool, error) { return gone, nil }
			close(f.done) // Synthetic client cleanup only, after its tracked call joined.
			if err := h.ReconcileCleanupV1(reconcile); !errors.Is(err, ErrApplicationSessionUnknownV1) || c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("client-only cleanup credited live backend")
			}
			gone = true
			if err := h.ReconcileCleanupV1(reconcile); err != nil || !h.RetiredV1() {
				t.Fatal("joined owned backend did not reconcile", err)
			}
			retired := c.SnapshotV1(f.scope.OrgID)
			if retired.Global.SQLSessions != 0 || retired.GlobalGrants != 2 || retired.Global.ParentBytes != before.Global.ParentBytes || retired.Global.DBStagingBytes != before.Global.DBStagingBytes {
				t.Fatal("SQL retirement credited live policy consumer", retired)
			}
			pending, err := f.adapter.ReconcileCleanupV1(reconcile)
			if order == "retirement-first" {
				if err != nil || pending != 2 || c.SnapshotV1(f.scope.OrgID) != retired {
					t.Fatal("physical retirement freed retained consumers")
				}
				header()
				journal()
				pending, err = f.adapter.ReconcileCleanupV1(reconcile)
			}
			if err != nil || pending != 0 || c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("joined SQL/client/backend plus consumer close did not release once", pending, err)
			}
			header()
			journal()
			if pending, err = f.adapter.ReconcileCleanupV1(reconcile); err != nil || pending != 0 || c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("duplicate cleanup changed accounting")
			}
		})
	}
}
