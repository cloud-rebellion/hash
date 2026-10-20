package chromium

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

func TestHashBrowserRetirementQuarantinesUntilSingleWaiterJoins(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	profile := filepath.Join(t.TempDir(), "owned-profile")
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profile, "canary"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, rawCanceled := make(chan struct{}), make(chan struct{})
	var releaseOnce, rawOnce sync.Once
	var waiterCalls atomic.Int64
	b := &chromiumBrowser{
		ctx: context.Background(), userProfileDirPath: profile,
		pinningProxy:   newPinningProxy(nil, nil, false, false, false),
		closeFunc:      func() error { return nil },
		lifetimeCancel: func() { rawOnce.Do(func() { close(rawCanceled) }) },
		cancelFunc:     func() error { waiterCalls.Add(1); <-release; return nil },
	}
	b.isStarted.Store(true)
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		if err := b.Stop(logger); err != nil {
			t.Error("final retirement: ", err)
		}
	})
	start := time.Now()
	if err := b.Stop(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("unjoined allocator accepted: ", err)
	}
	if elapsed := time.Since(start); elapsed < hashBrowserStopTimeout || elapsed > hashBrowserStopTimeout+2*time.Second {
		t.Fatal("retirement wait bound changed: ", elapsed)
	}
	hashAwait(t, "raw lifetime canceled", rawCanceled)
	if !b.hashCleanupUnconfirmed.Load() || b.Healthy(logger) || b.retirement == nil || b.ctx == nil || b.userProfileDirPath != profile {
		t.Fatal("unknown retirement dropped handles or reported healthy")
	}
	if _, err := os.Stat(profile); err != nil {
		t.Fatal("profile removed before allocator joined: ", err)
	}
	if raw, err := os.ReadFile(filepath.Join(profile, "canary")); err != nil || string(raw) != "owned" {
		t.Fatal("unconfirmed retirement removed or changed owned content")
	}
	if err := b.Start(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("replacement admitted over unjoined generation: ", err)
	}
	if waiterCalls.Load() != 1 {
		t.Fatal("retirement has multiple allocator waiters")
	}
	releaseOnce.Do(func() { close(release) })
	if err := b.Stop(logger); err != nil {
		t.Fatal("confirmed retirement: ", err)
	}
	if waiterCalls.Load() != 1 || b.retirement != nil || b.isStarted.Load() || b.ctx != nil || b.cancelFunc != nil || b.closeFunc != nil || b.userProfileDirPath != "" {
		t.Fatal("confirmed retirement state incomplete")
	}
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned profile retained after join: ", err)
	}
}

func TestHashBrowserRetirementCloseFailureRemainsQuarantined(t *testing.T) {
	profile := t.TempDir()
	canary := filepath.Join(profile, "canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var closes, cancels, joins atomic.Int64
	b := &chromiumBrowser{
		ctx: context.Background(), userProfileDirPath: profile,
		pinningProxy:   newPinningProxy(nil, nil, false, false, false),
		closeFunc:      func() error { closes.Add(1); return context.DeadlineExceeded },
		lifetimeCancel: func() { cancels.Add(1) },
		cancelFunc:     func() error { joins.Add(1); return nil },
	}
	b.isStarted.Store(true)
	logger := slog.New(slog.DiscardHandler)
	for range 2 {
		if err := b.Stop(logger); !errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("unconfirmed graceful close accepted: ", err)
		}
	}
	if err := b.Start(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("replacement after uncertain close: ", err)
	}
	if closes.Load() != 1 || cancels.Load() != 1 || joins.Load() != 1 || b.retirement == nil || b.ctx == nil || b.closeFunc == nil || b.userProfileDirPath != profile || !b.hashCleanupUnconfirmed.Load() || b.Healthy(logger) {
		t.Fatal("uncertain close lost ownership or repeated a waiter")
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
		t.Fatal("uncertain close removed owned profile")
	}
}

func TestHashBrowserStopRefusesInFlightStartup(t *testing.T) {
	b := &chromiumBrowser{}
	b.startMu.Lock()
	err := b.Stop(slog.New(slog.DiscardHandler))
	b.startMu.Unlock()
	if !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("in-flight startup treated as stopped: ", err)
	}
}

func TestHashSupervisorUnconfirmedShutdownNeverLaunchesReplacement(t *testing.T) {
	var starts atomic.Int64
	s := newHashProcessSupervisor(slog.New(slog.DiscardHandler), "chromium", &gotenberg.ProcessMock{
		StartMock:   func(*slog.Logger) error { starts.Add(1); return nil },
		StopMock:    func(*slog.Logger) error { return errHashBrowserShutdown },
		HealthyMock: func(*slog.Logger) bool { return false },
	}, 0, 0, 1, 0).(*hashProcessSupervisor)
	s.firstStart.Store(true)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	invoked := false
	err := s.Run(ctx, slog.New(slog.DiscardHandler), func() error { invoked = true; return nil })
	if !errors.Is(err, errHashBrowserShutdown) || invoked || starts.Load() != 0 || s.RestartsCount() != 0 || s.ReqQueueSize() != 0 || s.ActiveTasksCount() != 0 {
		t.Fatal("unconfirmed shutdown launched or dispatched replacement: ", err)
	}
}
