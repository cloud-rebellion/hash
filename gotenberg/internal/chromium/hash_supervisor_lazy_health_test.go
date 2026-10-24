// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHashSupervisorLazyHealthCleanExecFailureRemainsRetryable(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	logger := slog.New(slog.DiscardHandler)
	b := newChromiumBrowser(browserArguments{
		binPath: filepath.Join(tmp, "missing-browser"), wsUrlReadTimeout: time.Second,
		hyphenDataDirPath: filepath.Join(tmp, "hyphen-data"),
	}).(*chromiumBrowser)
	supervisor := newHashProcessSupervisor(logger, "chromium", b, 0, 0, 1, 0).(*hashProcessSupervisor)
	t.Cleanup(func() { _ = b.Stop(logger) })
	if !supervisor.Healthy() || b.startup != nil || b.userProfileDirPath != "" {
		t.Fatal("pristine health launched or rejected the lazy browser")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var callbacks atomic.Int64
	for range 2 {
		err := supervisor.Run(ctx, logger, func() error { callbacks.Add(1); return nil })
		hashAssertMissingExec(t, err, b.arguments.binPath)
		if supervisor.firstStart.Load() || callbacks.Load() != 0 || !supervisor.Healthy() {
			t.Fatal("clean no-child failure poisoned lazy health or dispatched work")
		}
		if !b.hashCleanupUnconfirmed.Load() || b.ctx != nil || b.startup != nil || b.retirement != nil || b.userProfileDirPath != "" || b.proxyOwned {
			t.Fatal("clean failure retained ownership or did not exercise the old cleanup latch")
		}
		entries, err := os.ReadDir(tmp)
		if err != nil || len(entries) != 0 {
			t.Fatal("clean failed launch leaked profile ownership: ", err)
		}
	}
}

func TestHashSupervisorLazyHealthTracksPendingNoChildRetirement(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	startup := &hashBrowserStartup{done: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { startup.err = context.DeadlineExceeded; close(startup.done) }) }
	profile := t.TempDir()
	canary := filepath.Join(profile, "canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var joins atomic.Int64
	b := &chromiumBrowser{
		ctx: lifetime, startup: startup, userProfileDirPath: profile,
		lifetimeCancel: cancel,
		cancelFunc:     func() error { joins.Add(1); return nil },
		pinningProxy:   newPinningProxy(nil, nil, false, false, false),
	}
	logger := slog.New(slog.DiscardHandler)
	supervisor := newHashProcessSupervisor(logger, "chromium", b, 0, 0, 1, 0).(*hashProcessSupervisor)
	t.Cleanup(func() { release(); _ = b.Stop(logger) })
	b.startMu.Lock()
	b.hashBeginRetirementLocked(logger)
	retirement := b.retirement
	b.startMu.Unlock()
	if supervisor.Healthy() || joins.Load() != 0 || b.retirement != retirement || b.startup != startup {
		t.Fatal("pending retirement reported healthy or health changed ownership before join")
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
		t.Fatal("pending health query removed the owned profile")
	}
	if err := supervisor.Launch(); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("lazy launch overlapped the pending retirement: ", err)
	}
	release()
	hashAwait(t, "no-child retirement published", retirement.done)
	if retirement.err != nil || !supervisor.Healthy() || supervisor.firstStart.Load() || joins.Load() != 1 || b.retirement != retirement || b.startup != startup {
		t.Fatal("completed retryable retirement stayed unhealthy or health reconciled its handles")
	}
	if !b.hashCleanupUnconfirmed.Load() {
		t.Fatal("fixture did not retain the old cleanup latch")
	}
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed no-child retirement retained its profile: ", err)
	}
	// This fixture has no configured startup timeout, so a new attempt must
	// reconcile the old ownership and refuse before acquiring new resources.
	if err := supervisor.Launch(); err == nil || errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("completed retirement did not allow a new clean startup attempt: ", err)
	}
	if joins.Load() != 1 || b.retirement != nil || b.startup != nil || b.ctx != nil || b.userProfileDirPath != "" || !supervisor.Healthy() {
		t.Fatal("retry repeated the waiter, retained handles or poisoned lazy health")
	}
}

func TestHashSupervisorLazyHealthRejectsOwnedFailedChild(t *testing.T) {
	profile := t.TempDir()
	canary := filepath.Join(profile, "canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	helperCtx, cancelHelper := context.WithDeadline(context.Background(), deadline)
	defer cancelHelper()
	requestCtx, cancelRequest := context.WithDeadline(context.Background(), deadline)
	defer cancelRequest()
	cmd := exec.CommandContext(helperCtx, os.Args[0], "-test.run=^TestHashStartupProcessHelper$")
	cmd.Env = []string{"HASH_STARTUP_PROCESS_HELPER=exit-7", "GOMAXPROCS=2", "GOGC=50"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var b *chromiumBrowser
	logger := slog.New(slog.DiscardHandler)
	t.Cleanup(func() {
		cancelHelper()
		if b != nil {
			_ = b.Stop(logger)
			if b.retirement != nil {
				hashAwait(t, "quarantined supervisor root waiter terminal", b.retirement.done)
			}
		}
		if err := hashJoinStartupCommand(cmd); err != nil || cmd.ProcessState == nil {
			t.Error("exact supervisor helper command was not joined: ", err)
		}
	})
	// Construct the existing failed-handshake fixture around a real owned
	// helper command. It exercises actual retirement and supervisor paths;
	// genuine Chromium startup pressure remains a separate qualification.
	startup := &hashBrowserStartup{done: make(chan struct{}), command: cmd, err: context.DeadlineExceeded}
	close(startup.done)
	var joins, callbacks atomic.Int64
	b = &chromiumBrowser{
		ctx: context.Background(), startup: startup, userProfileDirPath: profile,
		lifetimeCancel: cancelHelper,
		cancelFunc:     func() error { joins.Add(1); return startup.join(func() {}, func() {}) },
		pinningProxy:   newPinningProxy(nil, nil, false, false, false),
	}
	b.startMu.Lock()
	err := b.hashFailStartupLocked(logger, context.DeadlineExceeded)
	retirement := b.retirement
	b.startMu.Unlock()
	if !errors.Is(err, errHashBrowserShutdown) || retirement == nil || cmd.ProcessState == nil || joins.Load() != 1 {
		t.Fatal("failed child did not join once and retain quarantine: ", err)
	}
	if helperCtx.Err() == nil || requestCtx.Err() != nil {
		t.Fatal("helper cleanup did not preserve an independent live request context")
	}
	supervisor := newHashProcessSupervisor(logger, "chromium", b, 0, 0, 1, 0).(*hashProcessSupervisor)
	for range 2 {
		if err := supervisor.Launch(); !errors.Is(err, errHashBrowserShutdown) || supervisor.firstStart.Load() {
			t.Fatal("failed first launch admitted a replacement: ", err)
		}
		if supervisor.Healthy() {
			t.Fatal("supervisor reported a quarantined first-start failure healthy")
		}
		if err := supervisor.Run(requestCtx, logger, func() error { callbacks.Add(1); return nil }); !errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("quarantined supervisor accepted work: ", err)
		}
		if callbacks.Load() != 0 || joins.Load() != 1 || b.retirement != retirement || b.startup != startup || !b.hashCleanupUnconfirmed.Load() {
			t.Fatal("failed launch dispatched work, repeated its waiter or lost generation ownership")
		}
		if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
			t.Fatal("quarantined supervisor changed the owned profile")
		}
	}
}
