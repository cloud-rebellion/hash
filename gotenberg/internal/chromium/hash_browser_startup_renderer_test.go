//go:build renderer_e2e

package chromium

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/gobwas/ws"
)

func TestHashStartupGenuineLifecycle(t *testing.T) {
	t.Run("synthetic-CDP-attachment-timeout-owns-command-and-quarantine", func(t *testing.T) {
		accepted, peerDone, releasePeer := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var requests atomic.Int64
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			first := requests.Add(1) == 1
			if first {
				defer close(peerDone)
			}
			conn, _, _, err := ws.UpgradeHTTP(r, w)
			if err != nil {
				return
			}
			defer conn.Close()
			if !first {
				return
			}
			close(accepted)
			<-releasePeer // explicit synthetic CDP peer: never answer attach commands
		}))
		t.Cleanup(func() {
			close(releasePeer)
			peer.Close()
			if requests.Load() != 0 {
				hashAwait(t, "synthetic CDP peer terminal", peerDone)
			}
		})
		peerURL, err := url.Parse(peer.URL)
		if err != nil {
			t.Fatal(err)
		}
		peerURL.Scheme, peerURL.Path = "ws", "/devtools/browser/hash-startup-fixture"
		helper := filepath.Join(t.TempDir(), "startup-peer-helper")
		// Trusted fixture script execs one harmless sleep process, keeping the
		// exact captured command PID. It is not Chromium or document JavaScript.
		body := fmt.Sprintf("#!/bin/sh\nprintf 'DevTools listening on %s\\n'\nexec /bin/sleep 30\n", peerURL.String())
		if err := os.WriteFile(helper, []byte(body), 0o500); err != nil {
			t.Fatal(err)
		}
		b := hashNewGenuineBrowser(t)
		b.arguments.binPath, b.arguments.wsUrlReadTimeout = helper, 250*time.Millisecond
		logger := slog.New(slog.DiscardHandler)
		t.Cleanup(func() {
			startup := b.startup
			if err := b.Stop(logger); err != nil && !errors.Is(err, errHashBrowserShutdown) {
				t.Error("unexpected stalled fixture retirement error: ", err)
			}
			if b.retirement != nil {
				hashAwait(t, "stalled fixture retirement terminal", b.retirement.done)
			}
			if startup != nil {
				hashAwait(t, "stalled fixture handshake terminal", startup.done)
				if cmd := startup.command; cmd != nil && cmd.Process != nil && cmd.ProcessState == nil {
					t.Error("stalled fixture exact command remained unjoined")
				}
			}
			b.pinningProxy.mu.Lock()
			proxyStarted := b.pinningProxy.started
			b.pinningProxy.mu.Unlock()
			if proxyStarted {
				t.Error("stalled fixture owned proxy remained active")
			}
		})
		started := time.Now()
		if err := b.Start(logger); !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("stalled attachment did not time out and retain quarantine: ", err)
		}
		if elapsed := time.Since(started); elapsed < 150*time.Millisecond || elapsed > hashBrowserStopTimeout+time.Second {
			t.Fatal("whole startup handshake wait escaped its bound: ", elapsed)
		}
		hashAwait(t, "CDP handshake actually accepted before attachment stall", accepted)
		if requests.Load() != 1 || b.isStarted.Load() || b.Healthy(logger) || b.startup == nil || b.retirement == nil {
			t.Fatal("stalled startup was published or lost ownership")
		}
		hashAwait(t, "failed startup root waiter terminal", b.retirement.done)
		observation := b.startup.observation.snapshot()
		if !observation.Finished || !observation.RunJoined || !observation.Failed {
			t.Fatal("stalled startup observation did not retain the original joined failure")
		}
		wantStages := []hashStartupStage{hashStartupCommandPrepared, hashStartupChildOutput, hashStartupDevTools, hashStartupCDPDial}
		for _, stage := range wantStages {
			seen := 0
			for _, record := range observation.Records[:observation.Count] {
				if record.Stage == stage {
					seen++
				}
			}
			if seen != 1 {
				t.Fatalf("stalled startup stage %s observed %d times", stage.label(), seen)
			}
		}
		requestsObserved, repliesObserved := 0, 0
		for _, record := range observation.Records[:observation.Count] {
			if record.Stage == hashStartupRequest && record.Command == hashStartupDiscoverBrowser {
				requestsObserved++
			}
			if record.Stage == hashStartupReply {
				repliesObserved++
			}
		}
		if requestsObserved != 1 || repliesObserved != 0 {
			t.Fatal("stalled peer acquired an invented startup reply")
		}
		cmd := b.startup.command
		if cmd == nil || cmd.Process == nil || cmd.ProcessState == nil || !errors.Is(cmd.Process.Signal(syscall.Signal(0)), os.ErrProcessDone) {
			t.Fatal("stalled startup did not reap its exact captured root")
		}
		profile := b.userProfileDirPath
		if profile == "" || !filepath.IsAbs(profile) {
			t.Fatal("stalled startup discarded the owned profile path")
		}
		canary := filepath.Join(profile, "hash-stalled-startup-canary")
		if err := os.WriteFile(canary, []byte("quarantined"), 0o600); err != nil {
			t.Fatal(err)
		}
		retirement := b.retirement
		if err := b.Stop(logger); !errors.Is(err, errHashBrowserShutdown) {
			t.Fatal("failed startup Stop bypassed descendant quarantine: ", err)
		}
		if err := b.Start(logger); !errors.Is(err, errHashBrowserShutdown) || b.retirement != retirement {
			t.Fatal("failed startup admitted an overlapping replacement: ", err)
		}
		if raw, err := os.ReadFile(canary); err != nil || string(raw) != "quarantined" {
			t.Fatal("failed startup retry removed quarantined profile content")
		}
	})
	t.Run("successful-lifetime-survives-startup-deadline", func(t *testing.T) {
		mod, b := hashPublicFixtureModule(t)
		api, err := mod.Chromium()
		if err != nil {
			t.Fatal(err)
		}
		originalContext := b.ctx
		originalBrowser := chromedp.FromContext(b.ctx).Browser
		originalProcess := originalBrowser.Process()
		if originalProcess == nil || originalProcess.Signal(syscall.Signal(0)) != nil || b.startup == nil || b.startup.command == nil || b.startup.command.Process != originalProcess {
			t.Fatal("successful startup lacks its exact live captured command")
		}
		observation := b.startup.observation.snapshot()
		if !observation.Finished || !observation.RunJoined || observation.Failed {
			t.Fatal("successful startup observation did not freeze its joined Run result")
		}
		canary := filepath.Join(b.userProfileDirPath, "hash-startup-lifetime-canary")
		if err := os.WriteFile(canary, []byte("live"), 0o600); err != nil {
			t.Fatal(err)
		}
		// Deliberately outlive even a timer incorrectly started after publication.
		time.Sleep(b.arguments.wsUrlReadTimeout + 250*time.Millisecond)
		if originalContext.Err() != nil || !b.Healthy(mod.logger) || originalProcess.Signal(syscall.Signal(0)) != nil {
			t.Fatal("startup timer disposal/expiry killed the published browser")
		}
		dir := t.TempDir()
		source := filepath.Join(dir, "index.html")
		if err := os.WriteFile(source, []byte("<!doctype html><p>Hash live after startup cutoff</p>"), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		output := filepath.Join(dir, "after-deadline.pdf")
		if err := api.Pdf(ctx, mod.logger, (&url.URL{Scheme: "file", Path: source}).String(), output, hashGenuinePDFOptions(dir)); err != nil {
			t.Fatal(err)
		}
		hashAssertOutput(t, output, "pdf")
		if !reflect.DeepEqual(observation, b.startup.observation.snapshot()) {
			t.Fatal("post-startup document traffic changed the frozen startup observation")
		}
		if b.ctx != originalContext || chromedp.FromContext(b.ctx).Browser != originalBrowser || mod.supervisor.RestartsCount() != 0 {
			t.Fatal("deadline test silently replaced the successful browser")
		}
		if raw, err := os.ReadFile(canary); err != nil || string(raw) != "live" {
			t.Fatal("startup deadline removed or changed the live profile")
		}
	})
	t.Run("no-child-lazy-retry-preserves-independent-browser", func(t *testing.T) {
		decoy := hashGenuineBrowser(t)
		decoyContext := decoy.ctx
		decoyBrowser := chromedp.FromContext(decoy.ctx).Browser
		canary := filepath.Join(decoy.userProfileDirPath, "hash-startup-decoy-canary")
		if err := os.WriteFile(canary, []byte("independent"), 0o600); err != nil {
			t.Fatal(err)
		}
		b := hashNewGenuineBrowser(t)
		originalPath := b.arguments.binPath
		b.arguments.binPath = filepath.Join(t.TempDir(), "missing-browser")
		logger := slog.New(slog.DiscardHandler)
		s := newHashProcessSupervisor(logger, "chromium", b, 0, 2, 1, 0)
		t.Cleanup(func() {
			if err := s.Shutdown(); err != nil {
				t.Error(err)
			}
		})
		mod := hashPublicModuleWithSupervisor(t, b, s)
		api, err := mod.Chromium()
		if err != nil {
			t.Fatal(err)
		}
		dir := t.TempDir()
		source := filepath.Join(dir, "index.html")
		if err := os.WriteFile(source, []byte("<!doctype html><p>Hash lazy startup retry</p>"), 0o600); err != nil {
			t.Fatal(err)
		}
		sourceURL := (&url.URL{Scheme: "file", Path: source}).String()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		refused := filepath.Join(dir, "failed-start.pdf")
		hashAssertMissingExec(t, api.Pdf(ctx, logger, sourceURL, refused, hashGenuinePDFOptions(dir)), b.arguments.binPath)
		if _, err := os.Stat(refused); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("failed startup produced PDF output")
		}
		if b.ctx != nil || b.startup != nil || b.retirement != nil || b.userProfileDirPath != "" || s.(*hashProcessSupervisor).firstStart.Load() {
			t.Fatal("failed first launch lost lazy-retry semantics")
		}
		b.arguments.binPath = originalPath
		output := filepath.Join(dir, "lazy-retry.pdf")
		if err := api.Pdf(ctx, logger, sourceURL, output, hashGenuinePDFOptions(dir)); err != nil {
			t.Fatal("normal public lazy retry failed: ", err)
		}
		hashAssertOutput(t, output, "pdf")
		if !s.(*hashProcessSupervisor).firstStart.Load() || !b.Healthy(logger) || s.RestartsCount() != 0 || s.ActiveTasksCount() != 0 || s.ReqQueueSize() != 0 {
			t.Fatal("successful lazy retry/accounting not published")
		}
		if decoy.ctx != decoyContext || chromedp.FromContext(decoy.ctx).Browser != decoyBrowser || !decoy.Healthy(logger) {
			t.Fatal("failed startup/retry damaged independent browser")
		}
		if raw, err := os.ReadFile(canary); err != nil || string(raw) != "independent" {
			t.Fatal("failed startup/retry damaged independent profile")
		}
		independent := filepath.Join(dir, "independent.pdf")
		if err := decoy.pdf(ctx, logger, sourceURL, independent, hashGenuinePDFOptions(dir), newNetworkAggregate()); err != nil {
			t.Fatal(err)
		}
		hashAssertOutput(t, independent, "pdf")
	})
}
