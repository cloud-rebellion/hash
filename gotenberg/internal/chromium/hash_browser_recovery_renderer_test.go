//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// Only tests substitute this protocol executor. Target creation/observations
// remain genuine; losing a result or blocking a close is an explicit fault.
type hashFaultExecutor struct {
	cdp.Executor
	loseAllocation bool
	blockClose     bool
	created        target.ID
}

func (e *hashFaultExecutor) Execute(ctx context.Context, method string, params, result any) error {
	if e.blockClose && method == target.CommandCloseTarget {
		return errors.New("injected close transport failure")
	}
	if err := e.Executor.Execute(ctx, method, params, result); err != nil {
		return err
	}
	if e.loseAllocation && method == target.CommandCreateTarget {
		r := result.(*target.CreateTargetReturns)
		e.created = r.TargetID
		r.TargetID = ""
		return errors.New("injected allocation result loss")
	}
	return nil
}

func TestHashBrowserGenuineFaultRecoveryPreservesIndependentBrowser(t *testing.T) {
	for _, fault := range []string{"allocation-result-loss", "cleanup-close-blocked"} {
		t.Run(fault, func(t *testing.T) {
			mod, b := hashPublicFixtureModule(t)
			api, err := mod.Chromium()
			if err != nil {
				t.Fatal(err)
			}
			// This independent browser is outside the retiring generation.
			decoy := hashGenuineBrowser(t)
			decoyContext := decoy.ctx
			decoyBrowser := chromedp.FromContext(decoy.ctx).Browser
			canary := filepath.Join(decoy.userProfileDirPath, "hash-independent-canary")
			if err := os.WriteFile(canary, []byte("independent"), 0o600); err != nil {
				t.Fatal(err)
			}
			oldContext := b.ctx
			oldBrowser := chromedp.FromContext(b.ctx).Browser
			oldProcess := oldBrowser.Process()
			oldProfile := b.userProfileDirPath
			if oldProcess == nil || oldProcess.Signal(syscall.Signal(0)) != nil {
				t.Fatal("fault fixture has no live owned root process")
			}
			if oldProfile == "" || !filepath.IsAbs(oldProfile) || decoy.userProfileDirPath == "" || !filepath.IsAbs(decoy.userProfileDirPath) || oldProfile == decoy.userProfileDirPath {
				t.Fatal("fault fixture profiles are not distinct absolute owned paths")
			}
			if info, err := os.Stat(oldProfile); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
				t.Fatal("fault fixture has no private owned profile")
			}
			ownedCanary := filepath.Join(oldProfile, "hash-owned-canary")
			if err := os.WriteFile(ownedCanary, []byte("owned"), 0o600); err != nil {
				t.Fatal(err)
			}
			phaseCtx, cancelPhase := context.WithTimeout(b.ctx, 2*time.Second)
			var owned target.ID
			if fault == "allocation-result-loss" {
				executor := &hashFaultExecutor{Executor: oldBrowser, loseAllocation: true}
				returned, err := b.hashAllocateTarget(phaseCtx, executor)
				owned = executor.created
				if !errors.Is(err, errHashTabCleanup) || returned != "" || owned == "" {
					t.Fatal("unknown allocation not refused: ", err)
				}
			} else {
				owned, err = b.hashAllocateTarget(phaseCtx, oldBrowser)
				if err != nil {
					t.Fatal(err)
				}
				err = b.hashConfirmTargetCleanup(phaseCtx, owned, &hashFaultExecutor{Executor: oldBrowser, blockClose: true})
				if !errors.Is(err, errHashTabCleanup) {
					t.Fatal("unknown cleanup not refused: ", err)
				}
			}
			cancelPhase()
			if !b.hashCleanupUnconfirmed.Load() || b.Healthy(mod.logger) {
				t.Fatal("faulty owner remained reusable/healthy")
			}
			before, err := hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := before[owned]; !present {
				t.Fatal("fault fixture did not leave a genuine owned target")
			}
			// Refusal must happen before navigation, printing or file writes.
			refused := filepath.Join(t.TempDir(), "refused.pdf")
			if err := b.pdf(context.Background(), mod.logger, "ignored", refused, DefaultPdfOptions(), nil); !errors.Is(err, errHashTabCleanup) {
				t.Fatal(err)
			}
			if _, err := os.Stat(refused); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("quarantined render wrote output")
			}
			if raw, err := os.ReadFile(ownedCanary); err != nil || string(raw) != "owned" {
				t.Fatal("refused conversion removed or changed the owned profile")
			}
			dir := t.TempDir()
			source := filepath.Join(dir, "index.html")
			if err := os.WriteFile(source, []byte("<!doctype html><p>Hash recovered owner</p>"), 0o600); err != nil {
				t.Fatal(err)
			}
			sourceURL := (&url.URL{Scheme: "file", Path: source}).String()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			output := filepath.Join(dir, "recovered.pdf")
			if err := api.Pdf(ctx, mod.logger, sourceURL, output, hashGenuinePDFOptions(dir)); err != nil {
				t.Fatal("public recovery conversion: ", err)
			}
			hashAssertOutput(t, output, "pdf")
			if b.ctx == oldContext || chromedp.FromContext(b.ctx).Browser == oldBrowser || b.hashCleanupUnconfirmed.Load() || !b.Healthy(mod.logger) {
				t.Fatal("public conversion reused faulty owner or failed health recovery")
			}
			select {
			case <-oldContext.Done():
			default:
				t.Fatal("old browser lifetime remains live")
			}
			select {
			case <-oldBrowser.LostConnection:
			default:
				t.Fatal("old browser connection remains live")
			}
			// Allocator owns Wait. Signal(0) on its exact already-reaped handle
			// observes completion without a second waiter or a numeric PID kill.
			if oldProcess == nil || !errors.Is(oldProcess.Signal(syscall.Signal(0)), os.ErrProcessDone) {
				t.Fatal("owned root allocator was not joined")
			}
			if _, err := os.Stat(oldProfile); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("old owned profile not removed: ", err)
			}
			after, err := hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			if _, present := after[owned]; present {
				t.Fatal("unknown old target admitted after recovery")
			}
			if mod.supervisor.RestartsCount() != 1 || mod.supervisor.ActiveTasksCount() != 0 || mod.supervisor.ReqQueueSize() != 0 {
				t.Fatal("recovery accounting incomplete")
			}
			if decoy.ctx != decoyContext || chromedp.FromContext(decoy.ctx).Browser != decoyBrowser || !decoy.Healthy(slog.New(slog.DiscardHandler)) {
				t.Fatal("recovery killed independent browser")
			}
			if raw, err := os.ReadFile(canary); err != nil || string(raw) != "independent" {
				t.Fatal("recovery removed independent profile")
			}
			decoyOutput := filepath.Join(dir, "independent.pdf")
			if err := decoy.pdf(ctx, mod.logger, sourceURL, decoyOutput, hashGenuinePDFOptions(dir), newNetworkAggregate()); err != nil {
				t.Fatal("independent PDF after owner recovery: ", err)
			}
			hashAssertOutput(t, decoyOutput, "pdf")
			image := filepath.Join(dir, "recovered.png")
			if err := api.Screenshot(ctx, mod.logger, sourceURL, image, hashGenuineScreenshotOptions(dir)); err != nil {
				t.Fatal(err)
			}
			hashAssertOutput(t, image, "png")
		})
	}
}
