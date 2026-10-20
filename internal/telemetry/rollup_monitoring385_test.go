// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package telemetry

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"reflect"
	"testing"
	"time"
)

type rollupQueries385 struct {
	calls                                  []string
	listErr, rollupErr, rawErr, summaryErr error
	unrolled                               int64
}

func (q *rollupQueries385) ListDocumentsWithPendingRollup(context.Context) ([]uuid.UUID, error) {
	q.calls = append(q.calls, "list")
	if q.listErr != nil {
		return nil, q.listErr
	}
	return []uuid.UUID{uuid.UUID{1}, uuid.UUID{2}}, nil
}
func (q *rollupQueries385) RollupBlockViews(context.Context, uuid.UUID) (int64, error) {
	q.calls = append(q.calls, "rollup")
	return 0, q.rollupErr
}
func (q *rollupQueries385) PruneTelemetryOlderThan(context.Context, pgtype.Timestamptz) (*generated.PruneTelemetryOlderThanRow, error) {
	q.calls = append(q.calls, "prune-raw")
	return &generated.PruneTelemetryOlderThanRow{UnrolledViews: q.unrolled}, q.rawErr
}
func (q *rollupQueries385) PruneEngagementOlderThan(context.Context, pgtype.Timestamptz) (int64, error) {
	q.calls = append(q.calls, "prune-summary")
	return 0, q.summaryErr
}
func Test385RollupFailureIsVisibleWithoutDelayingOriginalPrivacyRetention(t *testing.T) {
	q := &rollupQueries385{rollupErr: errors.New("synthetic rollup refusal"), unrolled: 2}
	got := RunRollupOnceObserved(context.Background(), q, 90*24*time.Hour)
	want := []string{"list", "rollup", "rollup", "prune-raw", "prune-summary"}
	if !got.Partial || got.Unavailable || !reflect.DeepEqual(q.calls, want) {
		t.Fatal("partial failure hidden or original privacy ordering changed", got, q.calls)
	}
	// Original public void entrypoint still executes the same real helper; no
	// retention behavior is copied into a test-only implementation.
	old := &rollupQueries385{rollupErr: q.rollupErr, unrolled: 2}
	RunRollupOnce(context.Background(), old, 90*24*time.Hour)
	if !reflect.DeepEqual(old.calls, want) {
		t.Fatal("legacy entrypoint lost original ordering", old.calls)
	}
}
func Test385RollupUnavailablePhasesNeverBecomeHealthyNoWork(t *testing.T) {
	failure := errors.New("synthetic query unavailable")
	cases := []struct {
		name string
		q    *rollupQueries385
		want []string
	}{
		{"list", &rollupQueries385{listErr: failure}, []string{"list"}},
		{"raw", &rollupQueries385{rawErr: failure}, []string{"list", "rollup", "rollup", "prune-raw"}},
		{"summary", &rollupQueries385{summaryErr: failure}, []string{"list", "rollup", "rollup", "prune-raw", "prune-summary"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RunRollupOnceObserved(context.Background(), c.q, time.Hour)
			if !got.Unavailable || !reflect.DeepEqual(c.q.calls, c.want) {
				t.Fatal("failure hidden or original early-return ordering changed", got, c.q.calls)
			}
		})
	}
	good := &rollupQueries385{}
	if got := RunRollupOnceObserved(context.Background(), good, time.Hour); got.Partial || got.Unavailable {
		t.Fatal("successful invocation reported as failure", got)
	}
}
