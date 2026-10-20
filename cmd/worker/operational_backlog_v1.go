// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/flarereport"
	"time"
)

const operationalBacklogIntervalV1 = 2 * time.Minute
const operationalBacklogQueryBudgetV1 = time.Second

type operationalBacklogCacheV1 struct {
	hasSample bool
	sampledAt time.Time
	data      flarereport.OperationalBacklogDataV1
}
type operationalBacklogReadV1 func(context.Context) (*generated.GetOperationalBacklogV1Row, error)

// Serial owner is the existing telemetry-rollup loop. No raw error is logged
// or retained. A failed read preserves the last GOOD observation and its age;
// no sample is explicitly different from a known empty queue.
func (c *operationalBacklogCacheV1) collectV1(ctx context.Context, read operationalBacklogReadV1, now func() time.Time) (flarereport.OperationalBacklogSnapshotV1, bool) {
	if ctx == nil || ctx.Err() != nil || read == nil {
		return flarereport.OperationalBacklogSnapshotV1{}, false
	}
	started := now()
	queryCtx, cancel := context.WithTimeout(ctx, operationalBacklogQueryBudgetV1)
	row, err := read(queryCtx)
	timedOut := queryCtx.Err() != nil
	cancel()
	finished := now()
	if ctx.Err() != nil {
		return flarereport.OperationalBacklogSnapshotV1{}, false
	}
	unavailable := err != nil || timedOut || row == nil
	if !unavailable {
		d := flarereport.OperationalBacklogDataV1{
			MailCount: row.MailCount, MailDueCount: row.MailDueCount, MailUnknownCreatedCount: row.MailUnknownCreatedCount, MailUnknownDueCount: row.MailUnknownDueCount,
			MailOldestObservedAgeSeconds: row.MailOldestObservedAgeSeconds, MailOldestObservedOverdueSeconds: row.MailOldestObservedOverdueSeconds, MailLimitReached: row.MailLimitReached,
			MailFailedCount: row.MailFailedCount, MailFailedUnknownCreatedCount: row.MailFailedUnknownCreatedCount,
			MailFailedOldestObservedCreationAgeSeconds: row.MailFailedOldestObservedCreationAgeSeconds, MailFailedLimitReached: row.MailFailedLimitReached,
			FinalizingRootCount: row.FinalizingRootCount, FinalizingIntentCount: row.FinalizingIntentCount, FinalizingMissingIntentCount: row.FinalizingMissingIntentCount,
			FinalizingUnknownIntentAgeCount: row.FinalizingUnknownIntentAgeCount, FinalizingOldestObservedIntentAgeSeconds: row.FinalizingOldestObservedIntentAgeSeconds, FinalizingLimitReached: row.FinalizingLimitReached,
		}
		if !d.ValidV1() {
			unavailable = true
		} else {
			c.hasSample = true
			c.sampledAt = finished
			c.data = d
		}
	}
	age := int64(0)
	if c.hasSample && finished.After(c.sampledAt) {
		age = int64(finished.Sub(c.sampledAt) / time.Second)
	}
	duration := finished.Sub(started).Milliseconds()
	if duration < 0 {
		duration = 0
	}
	if duration > 60000 {
		duration = 60000
	}
	return flarereport.OperationalBacklogSnapshotV1{HasSample: c.hasSample, ReadUnavailable: unavailable, SampleAgeSeconds: age, Stale: c.hasSample && age >= 300, ReadDurationMilliseconds: duration, Data: c.data}, true
}
func (w *worker) observeOperationalBacklogV1(ctx context.Context, cache *operationalBacklogCacheV1) {
	if !w.telemetry.OperationalBacklogEnabledV1() {
		return
	}
	if snapshot, ok := cache.collectV1(ctx, w.queries.GetOperationalBacklogV1, time.Now); ok {
		w.telemetry.RecordOperationalBacklogV1(ctx, snapshot)
	}
}
