package chromium

import (
	"bytes"
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

func TestHashStartupWaitHasIndependentDeadline(t *testing.T) {
	lifetime, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &hashBrowserStartup{done: make(chan struct{})}
	if err := hashWaitForStartup(lifetime, s, time.Now().Add(25*time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("startup timeout accepted: ", err)
	}
	if lifetime.Err() != nil {
		t.Fatal("startup wait disposed the permanent lifetime")
	}
	close(s.done) // explicitly synthetic late handshake success
	if err := hashWaitForStartup(lifetime, s, time.Now().Add(-time.Millisecond)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("late nil success accepted: ", err)
	}
	if err := hashWaitForStartup(lifetime, s, time.Now().Add(time.Second)); err != nil {
		t.Fatal("timely completed handshake refused: ", err)
	}
	if lifetime.Err() != nil {
		t.Fatal("successful timer disposal killed the browser lifetime")
	}
	browserContext, cancelBrowser := context.WithCancel(lifetime)
	cancelBrowser() // a browser connection can die while its parent remains live
	if err := hashWaitForStartup(browserContext, s, time.Now().Add(time.Second)); !errors.Is(err, context.Canceled) || lifetime.Err() != nil {
		t.Fatal("dead browser context accepted from its live parent: ", err)
	}
}

func TestHashStartupRetirementJoinsHandshakeAndLazyStartReconciles(t *testing.T) {
	lifetime, rawCancel := context.WithCancel(context.Background())
	defer rawCancel()
	s := &hashBrowserStartup{done: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { s.err = context.DeadlineExceeded; close(s.done) }) }
	profile := t.TempDir()
	canary := filepath.Join(profile, "canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var joins atomic.Int64
	b := &chromiumBrowser{
		ctx: lifetime, startup: s, userProfileDirPath: profile,
		lifetimeCancel: rawCancel,
		cancelFunc:     func() error { joins.Add(1); return nil },
		pinningProxy:   newPinningProxy(nil, nil, false, false, false),
	}
	logger := slog.New(slog.DiscardHandler)
	t.Cleanup(func() { release(); _ = b.Stop(logger) })
	if err := b.Stop(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("incomplete failed startup reported retired: ", err)
	}
	if lifetime.Err() == nil || joins.Load() != 0 || b.retirement == nil || b.startup != s || b.isStarted.Load() {
		t.Fatal("startup cancellation abandoned ownership or joined before handshake")
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
		t.Fatal("profile content removed before handshake joined")
	}
	if err := b.Start(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("replacement admitted while startup still active: ", err)
	}
	release()
	hashAwait(t, "failed-start retirement joined", b.retirement.done)
	// Lazy supervisor retries Start directly; a completed retirement must clear
	// without requiring an intervening Stop. Zero configured timeout prevents
	// this synthetic fixture from acquiring any new resources.
	if err := b.Start(logger); err == nil || errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("completed retirement did not permit a fresh start attempt: ", err)
	}
	if joins.Load() != 1 || b.startup != nil || b.retirement != nil || b.ctx != nil || b.userProfileDirPath != "" {
		t.Fatal("lazy retry left the prior generation or repeated its waiter")
	}
	if _, err := os.Stat(profile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed no-child profile not retired: ", err)
	}
}

func TestHashStartupFailedExecCleansAndRetries(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	b := newChromiumBrowser(browserArguments{
		binPath: filepath.Join(tmp, "missing-browser"), wsUrlReadTimeout: time.Second,
		hyphenDataDirPath: filepath.Join(tmp, "hyphen-data"),
	}).(*chromiumBrowser)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	t.Cleanup(func() { _ = b.Stop(logger) })
	for range 2 {
		hashAssertMissingExec(t, b.Start(logger), b.arguments.binPath)
		if b.ctx != nil || b.startup != nil || b.retirement != nil || b.userProfileDirPath != "" || b.isStarted.Load() || b.proxyOwned {
			t.Fatal("failed exec retained confirmed empty ownership")
		}
		entries, err := os.ReadDir(tmp)
		if err != nil || len(entries) != 0 {
			t.Fatal("failed exec leaked its profile: ", err)
		}
		b.pinningProxy.mu.Lock()
		started := b.pinningProxy.started
		b.pinningProxy.mu.Unlock()
		if started {
			t.Fatal("failed exec leaked its owned proxy listener")
		}
	}
	hashAssertStartupOutcomes(t, logs.Bytes(), 2, true)
}

func hashAssertMissingExec(t *testing.T, err error, path string) {
	t.Helper()
	var pathErr *os.PathError
	if !errors.Is(err, os.ErrNotExist) || errors.Is(err, errHashBrowserShutdown) || !errors.As(err, &pathErr) || pathErr.Op != "fork/exec" || pathErr.Path != path {
		t.Fatal("expected independently retired failure executing the exact missing binary: ", err)
	}
}

func TestHashStartupFailedSetupCleansBeforeRun(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	b := newChromiumBrowser(browserArguments{
		binPath: filepath.Join(tmp, "missing-browser"), wsUrlReadTimeout: time.Second,
		hyphenDataDirPath: "invalid\x00symlink-target",
	}).(*chromiumBrowser)
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	t.Cleanup(func() { _ = b.Stop(logger) })
	for range 2 {
		err := b.Start(logger)
		var linkErr *os.LinkError
		if !errors.As(err, &linkErr) || linkErr.Op != "symlink" || linkErr.Old != b.arguments.hyphenDataDirPath || errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("expected independently retired setup failure before Run: ", err)
		}
		if b.ctx != nil || b.startup != nil || b.retirement != nil || b.userProfileDirPath != "" || b.isStarted.Load() || b.proxyOwned {
			t.Fatal("failed setup retained empty ownership")
		}
		entries, err := os.ReadDir(tmp)
		if err != nil || len(entries) != 0 {
			t.Fatal("failed setup leaked its profile: ", err)
		}
		b.pinningProxy.mu.Lock()
		started := b.pinningProxy.started
		b.pinningProxy.mu.Unlock()
		if started {
			t.Fatal("pre-proxy setup failure acquired a listener")
		}
	}
	hashAssertStartupOutcomes(t, logs.Bytes(), 2, false)
}

func TestHashStartupProcessHelper(t *testing.T) {
	if os.Getenv("HASH_STARTUP_PROCESS_HELPER") == "exit-7" {
		os.Exit(7)
	}
}

func TestHashStartupCommandJoinRepairsOnlyMissingWaiter(t *testing.T) {
	for _, registered := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing-waiter", true: "registered-waiter"}[registered], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHashStartupProcessHelper$")
			cmd.Env = []string{"HASH_STARTUP_PROCESS_HELPER=exit-7", "GOMAXPROCS=2", "GOGC=50"}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			s := &hashBrowserStartup{done: make(chan struct{}), command: cmd}
			close(s.done)
			ownerEntered, releaseOwner := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			finish := make(chan error, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				finish <- s.join(func() {}, func() {
					close(ownerEntered)
					<-releaseOwner
					if registered {
						_ = cmd.Wait() // represents the pinned allocator's sole owner
					}
				})
			}()
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(releaseOwner) })
				cancel()
				hashAwait(t, "helper command waiter terminal", finished)
			})
			hashAwait(t, "allocator owner wait entered", ownerEntered)
			if cmd.ProcessState != nil {
				t.Fatal("fallback waited before allocator ownership ended")
			}
			releaseOnce.Do(func() { close(releaseOwner) })
			select {
			case err := <-finish:
				if err != nil || cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != 7 {
					t.Fatal("exact command not reaped: ", err)
				}
			case <-ctx.Done():
				t.Fatal("command join exceeded helper deadline")
			}
			if err := hashJoinStartupCommand(cmd); err != nil {
				t.Fatal("already-joined command acquired a second waiter: ", err)
			}
			cancel()
		})
	}
}

func TestHashStartupStartedChildRetainsQuarantineAfterRootJoin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHashStartupProcessHelper$")
	cmd.Env = []string{"HASH_STARTUP_PROCESS_HELPER=exit-7", "GOMAXPROCS=2", "GOGC=50"}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var b *chromiumBrowser
	logger := slog.New(slog.DiscardHandler)
	t.Cleanup(func() {
		cancel()
		if b != nil {
			_ = b.Stop(logger)
			if b.retirement != nil {
				hashAwait(t, "quarantined root waiter terminal", b.retirement.done)
			}
		}
		if err := hashJoinStartupCommand(cmd); err != nil || cmd.ProcessState == nil {
			t.Error("exact helper command cleanup was not joined: ", err)
		}
	})
	s := &hashBrowserStartup{done: make(chan struct{}), command: cmd, err: context.DeadlineExceeded}
	close(s.done)
	profile := t.TempDir()
	canary := filepath.Join(profile, "canary")
	if err := os.WriteFile(canary, []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	var joins atomic.Int64
	b = &chromiumBrowser{
		ctx: context.Background(), startup: s, userProfileDirPath: profile,
		lifetimeCancel: cancel,
		cancelFunc: func() error {
			joins.Add(1)
			return s.join(func() {}, func() {})
		},
		pinningProxy: newPinningProxy(nil, nil, false, false, false),
	}
	for range 2 {
		if err := b.Stop(logger); !errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("started failed generation accepted root exit as complete cleanup: ", err)
		}
	}
	if cmd.ProcessState == nil || joins.Load() != 1 || b.startup != s || b.retirement == nil || !b.hashCleanupUnconfirmed.Load() {
		t.Fatal("failed root not joined once or generation handles lost")
	}
	if err := b.Start(logger); !errors.Is(err, errHashBrowserShutdown) {
		t.Fatal("replacement admitted after unconfirmed descendant shutdown: ", err)
	}
	if raw, err := os.ReadFile(canary); err != nil || string(raw) != "owned" {
		t.Fatal("quarantined failed-start profile removed or changed")
	}
}
