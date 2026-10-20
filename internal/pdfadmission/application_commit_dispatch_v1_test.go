// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
)

// The actual owned session's dispatch bookkeeping is exercised over a synthetic
// pgx transaction. This is not real PostgreSQL acknowledgement/retirement or row
// reconciliation. The shared resource coordinator remains real and charged.
type applicationCommitDispatchTxTestV1 struct {
	pgx.Tx
	calls  atomic.Int32
	result error
	before func()
}

func (tx *applicationCommitDispatchTxTestV1) Commit(context.Context) error {
	tx.calls.Add(1)
	if tx.before != nil {
		tx.before()
	}
	return tx.result
}
func TestApplicationCommitDispatchV1DistinguishesPreDispatchRefusalFromAttempt(t *testing.T) {
	cases := []struct {
		name      string
		prepare   func(*ApplicationSessionV1, *applicationCommitDispatchTxTestV1, context.CancelFunc)
		attempted bool
		unknown   bool
	}{
		{"cancelled before method", func(_ *ApplicationSessionV1, _ *applicationCommitDispatchTxTestV1, cancel context.CancelFunc) {
			cancel()
		}, false, false},
		{"closed before method", func(h *ApplicationSessionV1, _ *applicationCommitDispatchTxTestV1, _ context.CancelFunc) {
			h.state.closed = true
		}, false, false},
		{"callback owns session", func(h *ApplicationSessionV1, _ *applicationCommitDispatchTxTestV1, _ context.CancelFunc) {
			h.state.callbackActive = true
		}, false, false},
		{"SQL owns session", func(h *ApplicationSessionV1, _ *applicationCommitDispatchTxTestV1, _ context.CancelFunc) {
			h.state.sqlActive = true
		}, false, false},
		{"acknowledged attempt", func(_ *ApplicationSessionV1, _ *applicationCommitDispatchTxTestV1, _ context.CancelFunc) {}, true, false},
		{"failed attempt", func(_ *ApplicationSessionV1, tx *applicationCommitDispatchTxTestV1, _ context.CancelFunc) {
			tx.result = errors.New("synthetic uncertain Commit")
		}, true, true},
		{"cancelled during attempt", func(_ *ApplicationSessionV1, tx *applicationCommitDispatchTxTestV1, cancel context.CancelFunc) {
			tx.before = cancel
		}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, h, c := applicationRequestLoanFixtureV1(t)
			ctx, cancel := context.WithCancel(applicationTestContextV1(t))
			defer cancel()
			sessionGrant, err := h.state.factory.work.SQLSessionV1(ctx, f.scope.OrgID)
			if err != nil {
				t.Fatal(err)
			}
			h.state.grant = sessionGrant
			tx := &applicationCommitDispatchTxTestV1{}
			h.state.tx = tx
			before := c.SnapshotV1(f.scope.OrgID)
			tc.prepare(h, tx, cancel)
			err = h.CommitV1(ctx)
			if tc.attempted && !tc.unknown && err != nil {
				t.Fatal("acknowledged fixture attempt failed", err)
			}
			if (!tc.attempted || tc.unknown) && err == nil {
				t.Fatal("refusal/unknown fixture reported acknowledgement")
			}
			if (tx.calls.Load() != 0) != tc.attempted || h.CommitDispatchObservationV1().NeverDispatchedV1() == tc.attempted || h.CommitUnknownV1() != tc.unknown {
				t.Fatal("owned actual dispatch state misclassified", tx.calls.Load(), h.CommitUnknownV1())
			}
			copyHandle := *h
			if copyHandle.CommitDispatchObservationV1().NeverDispatchedV1() != h.CommitDispatchObservationV1().NeverDispatchedV1() {
				t.Fatal("copied handle invented dispatch observation")
			}
			if c.SnapshotV1(f.scope.OrgID) != before {
				t.Fatal("dispatch observation or cancellation credited actual coordinator")
			}
			// The observation does not release resources. Native fixture cleanup is
			// separate from real protocol retirement and kept explicitly synthetic.
			sessionGrant()
			h.state.grant = nil
			if c.SnapshotV1(f.scope.OrgID) != (workguard.SnapshotV1{}) {
				t.Fatal("native fixture grant did not close")
			}
		})
	}
}
func TestApplicationCommitDispatchV1ZeroObservationCannotClaimNeverDispatched(t *testing.T) {
	var observation ApplicationCommitDispatchObservationV1
	var nilSession *ApplicationSessionV1
	if observation.NeverDispatchedV1() || nilSession.CommitDispatchObservationV1().NeverDispatchedV1() || (&ApplicationSessionV1{}).CommitDispatchObservationV1().NeverDispatchedV1() {
		t.Fatal("caller zero/absent handle manufactured never-dispatched authority")
	}
}
