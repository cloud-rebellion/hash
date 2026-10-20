//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"testing"
	"time"
)

// No database, child process or native receipt is fabricated by this test. It
// witnesses actual context ownership: ending migration cannot cancel the pool
// owner's browser lifetime, and cleanup cancels both original fixture roots.
func TestBrowserFixtureBirthContextAndMigrationOwnership368E2E(t *testing.T) {
	var browser, legacy context.Context
	t.Run("browser root owns independent bounded migration phase", func(t *testing.T) {
		before := time.Now()
		browser = browserFixtureContext368(t)
		after := time.Now()
		deadline, ok := browser.Deadline()
		if !ok || browser.Err() != nil {
			t.Fatal("browser fixture must begin with a live bounded owner")
		}
		upper := after.Add(4 * time.Minute)
		lower := before.Add(4 * time.Minute)
		if actual, ok := t.Deadline(); ok {
			reserve := actual.Add(-5 * time.Second)
			if reserve.Before(upper) {
				upper = reserve
			}
			if reserve.Before(lower) {
				lower = reserve
			}
		}
		if deadline.Before(lower) || deadline.After(upper) {
			t.Fatal("browser root changed original240s/test-cleanup bound", deadline, lower, upper)
		}
		phaseBefore := time.Now()
		phase, cancel := browserMigrationPhaseContext368(browser)
		phaseDeadline, ok := phase.Deadline()
		if !ok || phaseDeadline.After(time.Now().Add(90*time.Second)) || phaseDeadline.After(deadline) {
			cancel()
			t.Fatal("migration escaped original90s or its actual browser parent")
		}
		expectedLower := phaseBefore.Add(90 * time.Second)
		if deadline.Before(expectedLower) {
			expectedLower = deadline
		}
		if phaseDeadline.Before(expectedLower) {
			cancel()
			t.Fatal("migration lost its original finite phase budget")
		}
		cancel()
		if phase.Err() != context.Canceled || browser.Err() != nil {
			t.Fatal("migration cancellation consumed the still-owned browser lifetime")
		}
		first, stop := context.WithCancel(browser)
		stop()
		if first.Err() != context.Canceled || browser.Err() != nil {
			t.Fatal("ending one browser borrower cancelled the fixture owner")
		}
	})
	if browser == nil || browser.Err() != context.Canceled {
		t.Fatal("browser owner survived its registered fixture cleanup")
	}
	t.Run("legacy migration fixture keeps original90s owner", func(t *testing.T) {
		before := time.Now()
		legacy = migrationFixtureContext242(t)
		deadline, ok := legacy.Deadline()
		upper := time.Now().Add(90 * time.Second)
		lower := before.Add(90 * time.Second)
		if actual, ok := t.Deadline(); ok {
			reserve := actual.Add(-5 * time.Second)
			if reserve.Before(upper) {
				upper = reserve
			}
			if reserve.Before(lower) {
				lower = reserve
			}
		}
		if !ok || legacy.Err() != nil || deadline.Before(lower) || deadline.After(upper) {
			t.Fatal("legacy fixture90s/test-cleanup contract changed")
		}
	})
	if legacy == nil || legacy.Err() != context.Canceled {
		t.Fatal("legacy owner survived its original registered cleanup")
	}
}
