//go:build renderer_e2e

package chromium

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
)

// Pause only the captured real Chromium root. The original CDP allocation
// loses its response deadline; no executor, lifecycle callback or latch is
// replaced. A genuinely late target is mandatory before public recovery.
func TestHashSupervisorGenuinePausedOwnerQuarantineAndRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	mod, b := hashPublicFixtureModule(t)
	api, err := mod.Chromium()
	if err != nil {
		t.Fatal("public Chromium API unavailable")
	}
	s, ok := mod.supervisor.(*hashProcessSupervisor)
	if !ok || !s.firstStart.Load() || healthCheckCacheTTL != 2*time.Second || hashBrowserCloseTimeout != 2*time.Second || hashBrowserStopTimeout != 5*time.Second {
		t.Fatal("original owned supervisor or lifecycle bounds unavailable")
	}
	oldContext := b.ctx
	oldBrowser := chromedp.FromContext(oldContext).Browser
	oldProcess := oldBrowser.Process()
	oldProfile := b.userProfileDirPath
	if oldProcess == nil || b.startup == nil || b.startup.command == nil || b.startup.command.Process != oldProcess || oldProfile == "" || !filepath.IsAbs(oldProfile) {
		t.Fatal("exact published Chromium owner unavailable")
	}
	if st, err := os.Stat(oldProfile); err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Fatal("original owner profile is not private")
	}
	// /proc stat field22 is the kernel starttime. A retained os.Process handle
	// plus the unchanged starttime guards every nonzero signal against PID reuse.
	readOwnerState := func() (uint64, byte, bool) {
		if oldProcess.Signal(syscall.Signal(0)) != nil {
			return 0, 0, false
		}
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(oldProcess.Pid) + "/stat")
		if err != nil || !strings.HasPrefix(string(raw), strconv.Itoa(oldProcess.Pid)+" (") {
			return 0, 0, false
		}
		end := strings.LastIndex(string(raw), ") ")
		if end < 0 {
			return 0, 0, false
		}
		fields := strings.Fields(string(raw)[end+2:])
		if len(fields) < 20 || len(fields[0]) != 1 {
			return 0, 0, false
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		return start, fields[0][0], err == nil && start != 0
	}
	starttime, state, identityOK := readOwnerState()
	if !identityOK || state == 'T' || state == 't' || state == 'Z' || state == 'X' {
		t.Fatal("original Chromium root is not a live unstopped owner")
	}
	paused := false
	resume := func() bool {
		if !paused {
			return true
		}
		currentStart, _, valid := readOwnerState()
		if !valid || currentStart != starttime {
			return false
		}
		if oldProcess.Signal(syscall.SIGCONT) != nil {
			return false
		}
		paused = false
		return true
	}
	// Goexit runs this defer before either helper's registered Stop cleanup.
	// A failed identity check never signals a replacement numeric PID.
	defer func() {
		if !resume() {
			t.Error("exact paused owner could not be resumed before lifecycle cleanup")
		}
	}()

	// The original two-browser case could not start its second Chromium under
	// the unchanged physical profile. This canary proves only unrelated owned
	// process/filesystem isolation; it is not an independent PDF browser.
	canaryDir, err := os.MkdirTemp(t.TempDir(), "private-canary-")
	if err != nil {
		t.Fatal("private process canary directory creation failed")
	}
	canaryPath := filepath.Join(canaryDir, "hash-independent-process451")
	ownerCanary := filepath.Join(oldProfile, "hash-owner-recovery451")
	if os.WriteFile(ownerCanary, []byte("owned"), 0o600) != nil || os.WriteFile(canaryPath, []byte("independent"), 0o600) != nil {
		t.Fatal("private owner and process canary files unavailable")
	}
	canaryDirInfo, err := os.Stat(canaryDir)
	if err != nil || !canaryDirInfo.IsDir() || canaryDirInfo.Mode().Perm() != 0o700 || canaryDir == oldProfile || !filepath.IsAbs(canaryDir) {
		t.Fatal("separate private process canary directory unavailable")
	}
	canaryFileInfo, err := os.Stat(canaryPath)
	if err != nil || !canaryFileInfo.Mode().IsRegular() || canaryFileInfo.Mode().Perm() != 0o600 {
		t.Fatal("private process canary file unavailable")
	}
	canary := exec.Command("/bin/sleep", "90")
	if canary.Start() != nil || canary.Process == nil {
		t.Fatal("owned independent canary process failed to start")
	}
	canaryProcess := canary.Process
	// This private command has no other waiter. Always attempt Wait even when
	// Kill fails; no process-group/prefix signal or second wait is introduced.
	defer func() {
		killErr := canaryProcess.Kill()
		waitErr := canary.Wait()
		if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
			t.Error("owned canary exact-child cleanup signal failed")
		}
		if waitErr != nil {
			var exitErr *exec.ExitError
			if !errors.As(waitErr, &exitErr) {
				t.Error("owned canary exact-child wait failed")
			} else if status, ok := exitErr.Sys().(syscall.WaitStatus); !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Error("owned canary cleanup returned an unexpected child outcome")
			}
		}
		if canary.Process != canaryProcess || canary.ProcessState == nil || !errors.Is(canaryProcess.Signal(syscall.Signal(0)), os.ErrProcessDone) {
			t.Error("owned canary exact child was not joined")
		}
	}()
	readCanaryState := func() (uint64, byte, bool) {
		if canaryProcess.Signal(syscall.Signal(0)) != nil {
			return 0, 0, false
		}
		raw, err := os.ReadFile("/proc/" + strconv.Itoa(canaryProcess.Pid) + "/stat")
		if err != nil || !strings.HasPrefix(string(raw), strconv.Itoa(canaryProcess.Pid)+" (") {
			return 0, 0, false
		}
		end := strings.LastIndex(string(raw), ") ")
		if end < 0 {
			return 0, 0, false
		}
		fields := strings.Fields(string(raw)[end+2:])
		if len(fields) < 20 || len(fields[0]) != 1 {
			return 0, 0, false
		}
		start, err := strconv.ParseUint(fields[19], 10, 64)
		return start, fields[0][0], err == nil && start != 0
	}
	canaryStart, _, validCanary := readCanaryState()
	canaryIntact := func() bool {
		currentStart, currentState, live := readCanaryState()
		dirInfo, dirErr := os.Stat(canaryDir)
		fileInfo, fileErr := os.Stat(canaryPath)
		raw, readErr := os.ReadFile(canaryPath)
		return validCanary && live && currentStart == canaryStart && currentState != 'Z' && currentState != 'X' && currentState != 'T' && currentState != 't' &&
			canary.Process == canaryProcess && canary.ProcessState == nil && canaryProcess != oldProcess &&
			dirErr == nil && os.SameFile(canaryDirInfo, dirInfo) && dirInfo.IsDir() && dirInfo.Mode().Perm() == 0o700 && dirInfo.ModTime().Equal(canaryDirInfo.ModTime()) &&
			fileErr == nil && os.SameFile(canaryFileInfo, fileInfo) && fileInfo.Mode().IsRegular() && fileInfo.Mode().Perm() == 0o600 && fileInfo.ModTime().Equal(canaryFileInfo.ModTime()) &&
			readErr == nil && string(raw) == "independent"
	}
	if !canaryIntact() {
		t.Fatal("unrelated process and private file canary not initially live and exact")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "index.html")
	if os.WriteFile(source, []byte("<!doctype html><meta charset=utf-8><p>Hash genuine owner recovery451</p>"), 0o600) != nil {
		t.Fatal("owned local conversion source unavailable")
	}
	sourceURL := (&url.URL{Scheme: "file", Path: source}).String()
	initial := filepath.Join(dir, "initial.pdf")
	if api.Pdf(ctx, mod.logger, sourceURL, initial, hashGenuinePDFOptions(dir)) != nil {
		t.Fatal("initial public PDF conversion failed")
	}
	hashAssertOutput(t, initial, "pdf")
	baseline, err := hashTargetSnapshot(b)
	if err != nil || b.ctx != oldContext || chromedp.FromContext(b.ctx).Browser != oldBrowser || s.RestartsCount() != 0 || s.lastHealthyAt.Load() != 0 {
		t.Fatal("initial real owner or uncached-probe precondition changed")
	}
	if !s.Healthy() || !s.recentlyHealthy() || s.lastHealthyAt.Load() == 0 || s.consecutiveHealthFailures.Load() != 0 {
		t.Fatal("genuine successful health probe did not prime original cache")
	}
	healthStamp := s.lastHealthyAt.Load()
	currentStart, currentState, valid := readOwnerState()
	if !valid || currentStart != starttime || currentState == 'T' || currentState == 't' || currentState == 'Z' || currentState == 'X' {
		t.Fatal("owned root identity changed before pause")
	}
	if oldProcess.Signal(syscall.SIGSTOP) != nil {
		t.Fatal("exact owned Chromium pause failed")
	}
	paused = true
	// Signal delivery is asynchronous. Observe the one requested stop within
	// 250ms; this never repeats the signal, allocation or conversion.
	stopObservedBy := time.Now().Add(250 * time.Millisecond)
	for {
		currentStart, currentState, valid = readOwnerState()
		if !valid || currentStart != starttime || currentState == 'Z' || currentState == 'X' {
			t.Fatal("real owned Chromium identity changed during stop observation")
		}
		if currentState == 'T' {
			break
		}
		if !time.Now().Before(stopObservedBy) || !s.recentlyHealthy() {
			t.Fatal("real owned Chromium stop was not observed within original cache window")
		}
		time.Sleep(time.Millisecond)
	}
	allocationCtx, stopAllocation := context.WithTimeout(oldContext, 250*time.Millisecond)
	if allocationCtx.Err() != nil || ctx.Err() != nil {
		stopAllocation()
		t.Fatal("allocation caller deadline was not initially valid")
	}
	returned, allocationErr := b.hashAllocateTarget(allocationCtx, oldBrowser, mod.logger)
	allocationOutcome := allocationCtx.Err()
	stopAllocation()
	if returned != "" || !errors.Is(allocationErr, errHashTabCleanup) || !errors.Is(allocationOutcome, context.DeadlineExceeded) || !b.hashCleanupUnconfirmed.Load() {
		t.Fatal("real paused allocation did not retain unknown target ownership")
	}
	// No timestamp/latch is written by the test. Missing fresh-cache overlap
	// fails this one case; neither the fault nor its deadline is retried.
	if !s.recentlyHealthy() || s.lastHealthyAt.Load() != healthStamp || s.Healthy() || !s.recentlyHealthy() || s.lastHealthyAt.Load() != healthStamp || s.consecutiveHealthFailures.Load() != 0 {
		t.Fatal("known actual quarantine did not override still-fresh cached success")
	}
	if !resume() {
		t.Fatal("exact real owner could not resume after allocation deadline")
	}
	// One genuine snapshot, not a retry/polling allowance. The command must
	// have reached Chromium and created exactly one previously unknown page.
	lateSnapshot, err := hashTargetSnapshot(b)
	if err != nil || len(lateSnapshot) != len(baseline)+1 {
		t.Fatal("one genuinely late target was not observed")
	}
	for id, oldURL := range baseline {
		if currentURL, found := lateSnapshot[id]; !found || currentURL != oldURL {
			t.Fatal("fault changed a pre-existing owned target")
		}
	}
	var late target.ID
	for id, targetURL := range lateSnapshot {
		if _, present := baseline[id]; !present {
			if late != "" || targetURL != "about:blank" {
				t.Fatal("late allocation identity was not one real blank page")
			}
			late = id
		}
	}
	if late == "" || oldContext.Err() != nil || oldProcess.Signal(syscall.Signal(0)) != nil {
		t.Fatal("late target did not belong to the still-live original generation")
	}
	refused := filepath.Join(dir, "must-not-exist.pdf")
	if err := b.pdf(ctx, mod.logger, sourceURL, refused, hashGenuinePDFOptions(dir), newNetworkAggregate()); !errors.Is(err, errHashTabCleanup) {
		t.Fatal("quarantined original browser accepted a conversion")
	}
	if _, err := os.Stat(refused); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("quarantined original conversion wrote output")
	}
	if raw, err := os.ReadFile(ownerCanary); err != nil || string(raw) != "owned" {
		t.Fatal("refusal removed the original generation profile")
	}
	output := filepath.Join(dir, "recovered.pdf")
	if api.Pdf(ctx, mod.logger, sourceURL, output, hashGenuinePDFOptions(dir)) != nil {
		t.Fatal("public PDF API failed confirmed retirement and fresh conversion")
	}
	hashAssertOutput(t, output, "pdf")
	newBrowser := chromedp.FromContext(b.ctx).Browser
	if b.ctx == oldContext || newBrowser == oldBrowser || newBrowser.Process() == nil || newBrowser.Process() == oldProcess || b.userProfileDirPath == oldProfile || b.hashCleanupUnconfirmed.Load() || !b.Healthy(mod.logger) || !s.Healthy() {
		t.Fatal("public recovery did not publish a distinct healthy generation")
	}
	select {
	case <-oldContext.Done():
	default:
		t.Fatal("old browser lifetime remains live")
	}
	select {
	case <-oldBrowser.LostConnection:
	default:
		t.Fatal("old browser transport remains live")
	}
	if !errors.Is(oldProcess.Signal(syscall.Signal(0)), os.ErrProcessDone) {
		t.Fatal("original allocator did not join its exact root handle")
	}
	if _, err := os.Stat(oldProfile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("confirmed retirement retained original owned profile")
	}
	after, err := hashTargetSnapshot(b)
	if err != nil {
		t.Fatal("new generation target snapshot failed")
	}
	if _, exists := after[late]; exists || s.RestartsCount() != 1 || s.ActiveTasksCount() != 0 || s.ReqQueueSize() != 0 || len(s.semaphore) != 0 {
		t.Fatal("recovery retained late target or incomplete supervisor accounting")
	}
	if !canaryIntact() {
		t.Fatal("real owner recovery changed unrelated canary process, directory or file")
	}
	if ctx.Err() != nil {
		t.Fatal("recovery assertions exceeded original finite case budget")
	}
}
