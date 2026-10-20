// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package chromium

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Real chromiumBrowser state with no native process: health must observe known
// quarantine without attempting lifecycle repair, reconciliation or CDP work.
func hashQuarantineHealthFixture446(t *testing.T) (*hashProcessSupervisor, *chromiumBrowser, func()) {
	t.Helper()
	profile := t.TempDir()
	canary := filepath.Join(profile, "owned-profile-canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	startup := &hashBrowserStartup{done: make(chan struct{})}
	retirement := &hashBrowserRetirement{done: make(chan struct{})}
	lifetime := context.Background()
	lifecycleCalls := 0
	b := &chromiumBrowser{
		ctx: lifetime, startup: startup, retirement: retirement,
		userProfileDirPath: profile, proxyOwned: true,
		closeFunc:      func() error { lifecycleCalls++; return nil },
		cancelFunc:     func() error { lifecycleCalls++; return nil },
		lifetimeCancel: func() { lifecycleCalls++ },
	}
	b.isStarted.Store(true)
	b.hashCleanupUnconfirmed.Store(true)
	logger := slog.New(slog.DiscardHandler)
	s := newHashProcessSupervisor(logger, "chromium", b, 0, 0, 1, 0).(*hashProcessSupervisor)
	s.firstStart.Store(true)
	assertUnchanged := func() {
		t.Helper()
		if lifecycleCalls != 0 || !b.isStarted.Load() || !b.hashCleanupUnconfirmed.Load() || b.ctx != lifetime || b.startup != startup || b.retirement != retirement || b.userProfileDirPath != profile || !b.proxyOwned {
			t.Fatal("health mutated quarantined browser ownership")
		}
		if !s.firstStart.Load() || s.isRestarting.Load() || s.activeTasks.Load() != 0 || s.reqQueueSize.Load() != 0 || s.restartsCounter.Load() != 0 || len(s.semaphore) != 0 || s.idleStopChan != nil {
			t.Fatal("health launched work or changed supervisor ownership")
		}
		if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
			t.Fatal("health retired or changed the original owned profile", err)
		}
	}
	// There is no native command, allocator, proxy or goroutine to retire in
	// this state-only fixture; t.TempDir owns the one actual filesystem resource.
	return s, b, assertUnchanged
}

func TestHashSupervisor446KnownQuarantineOverridesCachedSuccess(t *testing.T) {
	s, b, unchanged := hashQuarantineHealthFixture446(t)
	if b.Healthy(s.logger) {
		t.Fatal("actual browser quarantine did not refuse direct health")
	}
	last := time.Now().UnixNano()
	s.lastHealthyAt.Store(last)
	if !s.recentlyHealthy() {
		t.Fatal("positive-cache precondition unavailable")
	}
	if s.Healthy() {
		t.Fatal("cached success masked known browser quarantine")
	}
	if s.lastHealthyAt.Load() != last || s.consecutiveHealthFailures.Load() != 0 {
		t.Fatal("known quarantine refreshed probe history or used failure tolerance")
	}
	unchanged()
}

func TestHashSupervisor446KnownQuarantineRejectsFirstProbeWithoutCache(t *testing.T) {
	for _, state := range []string{"never_probed", "expired_success"} {
		t.Run(state, func(t *testing.T) {
			s, b, unchanged := hashQuarantineHealthFixture446(t)
			if b.Healthy(s.logger) {
				t.Fatal("actual browser quarantine did not refuse direct health")
			}
			if state == "expired_success" {
				s.lastHealthyAt.Store(time.Now().Add(-2 * healthCheckCacheTTL).UnixNano())
			}
			last := s.lastHealthyAt.Load()
			if s.recentlyHealthy() || s.consecutiveHealthFailures.Load() != 0 {
				t.Fatal("first failed-probe precondition unavailable")
			}
			if s.Healthy() {
				t.Fatal("first-probe tolerance masked known browser quarantine")
			}
			if s.lastHealthyAt.Load() != last || s.consecutiveHealthFailures.Load() != 0 {
				t.Fatal("known quarantine changed generic probe history")
			}
			unchanged()
		})
	}
}
