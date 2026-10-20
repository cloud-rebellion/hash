// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"testing"
	"time"
)

func TestOperationalBacklog426NoSampleEmptyFailureStaleAndRecovery(t *testing.T) {
	var c operationalBacklogCacheV1
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	fail := func(context.Context) (*generated.GetOperationalBacklogV1Row, error) {
		return nil, errors.New("PRIVATE_DB_ERROR_426")
	}
	s, ok := c.collectV1(context.Background(), fail, clock)
	if !ok || s.HasSample || !s.ReadUnavailable || s.Stale {
		t.Fatal("unknown queue became healthy empty", s)
	}
	value := &generated.GetOperationalBacklogV1Row{MailCount: 2, MailDueCount: 1, MailOldestObservedAgeSeconds: 7200, MailOldestObservedOverdueSeconds: 60, FinalizingRootCount: 2, FinalizingIntentCount: 1, FinalizingMissingIntentCount: 1, FinalizingOldestObservedIntentAgeSeconds: 3600}
	read := func(context.Context) (*generated.GetOperationalBacklogV1Row, error) { return value, nil }
	s, ok = c.collectV1(context.Background(), read, clock)
	if !ok || !s.HasSample || s.ReadUnavailable || s.Stale || s.Data.MailCount != 2 || s.Data.FinalizingMissingIntentCount != 1 {
		t.Fatal("real observation lost", s)
	}
	now = now.Add(6 * time.Minute)
	s, _ = c.collectV1(context.Background(), fail, clock)
	if !s.HasSample || !s.ReadUnavailable || !s.Stale || s.SampleAgeSeconds != 360 || s.Data.MailCount != 2 {
		t.Fatal("failure refreshed or erased last-good observation", s)
	}
	value = &generated.GetOperationalBacklogV1Row{}
	s, _ = c.collectV1(context.Background(), read, clock)
	if !s.HasSample || s.ReadUnavailable || s.Stale || s.SampleAgeSeconds != 0 || s.Data.MailCount != 0 {
		t.Fatal("genuine empty recovery not observable", s)
	}
}
func TestOperationalBacklog426ReadBudgetCancellationAndInvalidProjection(t *testing.T) {
	var c operationalBacklogCacheV1
	clock := func() time.Time { return time.Unix(1000, 0) }
	calls := 0
	read := func(ctx context.Context) (*generated.GetOperationalBacklogV1Row, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > operationalBacklogQueryBudgetV1 || ctx.Err() != nil {
			t.Fatal("read escaped finite child budget")
		}
		return &generated.GetOperationalBacklogV1Row{MailCount: 1001}, nil
	}
	s, ok := c.collectV1(context.Background(), read, clock)
	if !ok || s.HasSample || !s.ReadUnavailable || calls != 1 {
		t.Fatal("invalid capped row became valid telemetry", s, calls)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, ok = c.collectV1(ctx, read, clock); ok || calls != 1 {
		t.Fatal("canceled owner started SQL or emitted completed snapshot")
	}
	parent, stop := context.WithCancel(context.Background())
	read = func(context.Context) (*generated.GetOperationalBacklogV1Row, error) {
		stop()
		return &generated.GetOperationalBacklogV1Row{}, nil
	}
	if _, ok = c.collectV1(parent, read, clock); ok || c.hasSample {
		t.Fatal("shutdown became healthy observation")
	}
}

// An empty active queue and successful invocations cannot erase terminal rows.
// The reader represents successive generated-query snapshots, not SMTP delivery.
func TestOperationalBacklog446FailedMailRequiresFreshDurableRemediation(t *testing.T) {
	var c operationalBacklogCacheV1
	now := time.Unix(2000, 0)
	clock := func() time.Time { return now }
	row := &generated.GetOperationalBacklogV1Row{MailFailedCount: 1000, MailFailedUnknownCreatedCount: 1, MailFailedOldestObservedCreationAgeSeconds: 7200, MailFailedLimitReached: true}
	read := func(context.Context) (*generated.GetOperationalBacklogV1Row, error) { return row, nil }
	s, ok := c.collectV1(context.Background(), read, clock)
	if !ok || !s.HasSample || s.ReadUnavailable || s.Data.MailCount != 0 || s.Data.MailFailedCount != 1000 || s.Data.MailFailedUnknownCreatedCount != 1 || s.Data.MailFailedOldestObservedCreationAgeSeconds != 7200 || !s.Data.MailFailedLimitReached {
		t.Fatal("terminal state lost while active queue empty", s)
	}
	// Repeated successful samples preserve the durable failure until rows change.
	now = now.Add(time.Minute)
	s, _ = c.collectV1(context.Background(), read, clock)
	if s.ReadUnavailable || s.Data.MailFailedCount != 1000 || !s.Data.MailFailedLimitReached {
		t.Fatal("healthy poll cleared terminal failures", s)
	}
	lastGood := s.Data
	now = now.Add(6 * time.Minute)
	failedRead := func(context.Context) (*generated.GetOperationalBacklogV1Row, error) {
		return nil, errors.New("PRIVATE_TERMINAL_MAIL_READ_446")
	}
	s, _ = c.collectV1(context.Background(), failedRead, clock)
	if !s.ReadUnavailable || !s.Stale || !s.HasSample || s.SampleAgeSeconds != 360 || s.Data != lastGood {
		t.Fatal("read failure erased or refreshed terminal evidence", s)
	}
	row = &generated.GetOperationalBacklogV1Row{MailFailedCount: 1001}
	s, _ = c.collectV1(context.Background(), read, clock)
	if !s.ReadUnavailable || !s.Stale || s.Data != lastGood || s.SampleAgeSeconds != 360 {
		t.Fatal("invalid terminal projection replaced last good sample", s)
	}
	// Only a successful fresh durable-zero sample can report remediation.
	row = &generated.GetOperationalBacklogV1Row{MailCount: 1}
	s, _ = c.collectV1(context.Background(), read, clock)
	if !s.HasSample || s.ReadUnavailable || s.Stale || s.SampleAgeSeconds != 0 || s.Data.MailFailedCount != 0 || s.Data.MailFailedLimitReached || s.Data.MailFailedOldestObservedCreationAgeSeconds != 0 || s.Data.MailCount != 1 {
		t.Fatal("fresh requeued state did not distinguish remediation", s)
	}
}
