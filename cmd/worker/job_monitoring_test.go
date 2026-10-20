// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package main

import (
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func Test370SelectedAgeIsOnlyFiniteOwnedSampleAndNeverUnknownZero(t *testing.T) {
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	tick := flarereport.JobTick{Job: flarereport.JobFinalizeRetry}
	for _, stamp := range []pgtype.Timestamptz{{}, {Valid: true, InfinityModifier: pgtype.Infinity}, {Valid: true, InfinityModifier: pgtype.NegativeInfinity}, {Valid: true, Time: now.Add(time.Second)}} {
		observeJobAgeAt(&tick, now, stamp)
	}
	if tick.UnknownAges != 4 || tick.OldestSelectedAgeSeconds != 0 {
		t.Fatal("unknown stamps became known empty/young sample", tick)
	}
	observeJobAgeAt(&tick, now, pgtype.Timestamptz{Valid: true, Time: now.Add(-2 * time.Hour)})
	observeJobAgeAt(&tick, now, pgtype.Timestamptz{Valid: true, Time: now.Add(-time.Hour)})
	if tick.OldestSelectedAgeSeconds != 7200 || tick.UnknownAges != 4 {
		t.Fatal("oldest sampled row or unknown observations lost", tick)
	}
	// A valid old timestamp must not overflow time.Duration and look recent.
	old := time.Date(1000, 1, 1, 0, 0, 0, 0, time.UTC)
	observeJobAgeAt(&tick, now, pgtype.Timestamptz{Valid: true, Time: old})
	if tick.OldestSelectedAgeSeconds != now.Unix()-old.Unix() {
		t.Fatal("old timestamp duration saturated", tick)
	}
}

func Test370bRowCreatedAfterEarlierPollStartUsesActualObservationClock(t *testing.T) {
	created := time.Now().Add(-time.Second)
	priorPollStart := created.Add(-25 * time.Minute)
	if !created.After(priorPollStart) {
		t.Fatal("fixture does not represent a later claimed row")
	}
	tick := flarereport.JobTick{Job: flarereport.JobEmailDispatch}
	observeJobAge(&tick, pgtype.Timestamptz{Valid: true, Time: created})
	if tick.UnknownAges != 0 || tick.OldestSelectedAgeSeconds < 1 {
		t.Fatal("later genuine selected timestamp treated as future or aged from prior poll start", tick)
	}
}
