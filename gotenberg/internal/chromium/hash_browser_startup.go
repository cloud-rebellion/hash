package chromium

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"time"
)

// The initial Run owns command registration and writes only this attempt.
// Closing done publishes those fields; command process state is inspected only
// after the allocator joins. No startup timer is a parent of the browser.
type hashBrowserStartup struct {
	done        chan struct{}
	err         error
	command     *exec.Cmd
	observation *hashStartupObserver
}

// hashLazyStartHealthy observes the published retirement result without starting
// a browser, waiting for cleanup or reconciling generation ownership.
func (b *chromiumBrowser) hashLazyStartHealthy() bool {
	b.ctxMu.RLock()
	retirement := b.retirement
	b.ctxMu.RUnlock()
	if retirement == nil {
		return true
	}
	select {
	case <-retirement.done:
		return retirement.err == nil
	default:
		return false
	}
}

func (s *hashBrowserStartup) captureCommand(cmd *exec.Cmd) {
	hashAllocateCommandOptions(cmd)
	s.command = cmd
	s.observation.commandPrepared()
}

func hashWaitForStartup(lifetime context.Context, s *hashBrowserStartup, deadline time.Time) error {
	if !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.done:
		if s.err != nil {
			return s.err
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		return lifetime.Err()
	case <-lifetime.Done():
		return lifetime.Err()
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func (s *hashBrowserStartup) join(cancelWait, allocatorWait context.CancelFunc) error {
	// Run may register allocator workers after cancellation. Never race that
	// registration with Wait or inspect exec.Cmd while Start is in progress.
	<-s.done
	cancelWait()
	allocatorWait()
	return hashJoinStartupCommand(s.command)
}

func hashJoinStartupCommand(cmd *exec.Cmd) error {
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return nil
	}
	// Pinned chromedp v0.14.2 can cancel after cmd.Start but before registering
	// its waiter. All registered workers have now joined; only that missing
	// waiter case needs a fallback on this exact command, never a PID scan.
	_ = cmd.Wait()
	if cmd.ProcessState == nil {
		return errHashBrowserShutdown
	}
	return nil // a killed child's ExitError still carries its joined exit state
}

func (b *chromiumBrowser) hashFailSetupLocked(logger *slog.Logger, cause error) error {
	b.startup.err = cause
	b.startup.observation.finish(false, true)
	close(b.startup.done) // no Run was launched for a setup failure
	return b.hashFailStartupLocked(logger, cause)
}

func (b *chromiumBrowser) hashFailStartupLocked(logger *slog.Logger, cause error) error {
	var observation *hashStartupObserver
	if b.startup != nil {
		observation = b.startup.observation
	}
	b.hashBeginRetirementLocked(logger)
	retired := b.hashAwaitRetirementLocked()
	observation.reportOutcome(false)
	return errors.Join(cause, retired)
}

// All lifecycle helpers require startMu. Workers capture immutable generation
// handles and publish their result by closing done; workers hold no lock over joins.
func (b *chromiumBrowser) hashBeginRetirementLocked(logger *slog.Logger) {
	b.ctxMu.Lock()
	defer b.ctxMu.Unlock()
	if b.retirement != nil {
		return
	}
	b.hashCleanupUnconfirmed.Store(true)
	r := &hashBrowserRetirement{done: make(chan struct{})}
	b.retirement = r
	startup, failed := b.startup, !b.isStarted.Load()
	ownedClose, ownedJoin := b.closeFunc, b.cancelFunc
	ownedCancel, ownedContext := b.lifetimeCancel, b.ctx
	ownedProfile, ownedProxy, ownsProxy := b.userProfileDirPath, b.pinningProxy, b.proxyOwned
	go func() {
		defer close(r.done)
		var closeErr, joinErr, proxyErr error
		if failed {
			if ownedCancel != nil {
				ownedCancel() // unblock Run; never invoke graceful Cancel before allocation
			}
		} else if ownedClose == nil || ownedCancel == nil || ownedJoin == nil {
			closeErr = errHashBrowserShutdown
		} else {
			closeErr = ownedClose() // exactly one graceful close per successful generation
			ownedCancel()
		}
		if startup != nil {
			<-startup.done
		}
		if ownedJoin != nil {
			joinErr = ownedJoin()
		} else if ownedContext != nil {
			joinErr = errHashBrowserShutdown
		}
		if ownsProxy {
			proxyErr = ownedProxy.Stop(logger)
		}
		// Reaping an abruptly canceled startup root does not prove descendant
		// quiescence. Preserve its profile and quarantine rather than admitting
		// another generation over possible late profile writers.
		startedFailedChild := failed && startup != nil && startup.command != nil && startup.command.Process != nil
		if closeErr != nil || joinErr != nil || proxyErr != nil || startedFailedChild {
			r.err = errHashBrowserShutdown
			return
		}
		if ownedProfile != "" {
			if err := os.RemoveAll(ownedProfile); err != nil {
				r.err = errHashBrowserShutdown
			}
		}
	}()
}

func (b *chromiumBrowser) hashAwaitRetirementLocked() error {
	timer := time.NewTimer(hashBrowserStopTimeout)
	defer timer.Stop()
	select {
	case <-b.retirement.done:
		return b.hashReconcileRetirementLocked()
	case <-timer.C:
		return errHashBrowserShutdown
	}
}

func (b *chromiumBrowser) hashReconcileRetirementLocked() error {
	select {
	case <-b.retirement.done:
	default:
		return errHashBrowserShutdown
	}
	if b.retirement.err != nil {
		return errHashBrowserShutdown
	}
	b.ctxMu.Lock()
	defer b.ctxMu.Unlock()
	b.ctx, b.cancelFunc, b.closeFunc, b.lifetimeCancel = nil, nil, nil, nil
	b.userProfileDirPath = ""
	b.startup, b.retirement, b.proxyOwned = nil, nil, false
	b.isStarted.Store(false)
	return nil
}
