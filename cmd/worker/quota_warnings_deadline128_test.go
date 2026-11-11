// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type quotaDeadlineContextKey128 struct{}

// Observe the original producer's first real query boundary, then refuse the
// row. This supplies no fake SQL result, Work permit, enqueue or owner identity.
type quotaDeadlineDB128 struct {
	generated.DBTX
	deadline time.Time
	bounded  bool
	err      error
	value    any
	queries  int
}
type quotaDeadlineRow128 struct{}

func (quotaDeadlineRow128) Scan(...any) error { return pgx.ErrNoRows }
func (d *quotaDeadlineDB128) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	d.queries++
	d.deadline, d.bounded = ctx.Deadline()
	d.err, d.value = ctx.Err(), ctx.Value(quotaDeadlineContextKey128{})
	return quotaDeadlineRow128{}
}

func TestQuotaWarning128OriginalOperationIsBoundedBeforeNativeWork(t *testing.T) {
	for _, mode := range []string{"scheduled-background", "earlier-parent-deadline", "parent-canceled"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), quotaDeadlineContextKey128{}, "original-invocation")
			var parentDeadline time.Time
			switch mode {
			case "earlier-parent-deadline":
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 100*time.Millisecond)
				defer cancel()
				parentDeadline, _ = ctx.Deadline()
			case "parent-canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			observed := &quotaDeadlineDB128{}
			w := &worker{queries: generated.New(observed)}
			started := time.Now()
			state := w.sendQuotaWarningObserved(ctx, &generated.ListSubscriptionsOverQuotaWarningRow{OrgID: uuid.New(), DocumentQuotaMonthly: 10, DocumentsUsed: 8})
			if state != flarereport.InvocationPartial || observed.queries != 1 || !observed.bounded || observed.value != "original-invocation" {
				t.Fatal("original producer did not retain bounded invocation at its first query")
			}
			if mode == "earlier-parent-deadline" {
				if !observed.deadline.Equal(parentDeadline) {
					t.Fatal("producer extended the original deadline")
				}
			} else if delta := observed.deadline.Sub(started); delta < 19*time.Second || delta > 21*time.Second {
				t.Fatal("scheduled quota operation did not use its finite20-second convention", delta)
			}
			if mode == "parent-canceled" {
				if !errors.Is(observed.err, context.Canceled) {
					t.Fatal("producer lost original cancellation")
				}
			} else if observed.err != nil {
				t.Fatal("live operation was pre-canceled", observed.err)
			}
		})
	}
}
