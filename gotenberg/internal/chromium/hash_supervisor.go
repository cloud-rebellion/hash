// Pinned Gotenberg v8.36.0 supervisor, adapted only for Hash-owned Chromium.
// Original source hashes and MIT license are recorded in UPSTREAM.json/LICENSE.
// Conversion callbacks retain admission until browser cleanup and callback-owned
// reports finish. Lifecycle deadline wrappers remain upstream; unconfirmed browser retirement refuses restart.
package chromium

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// healthCheckCacheTTL caches successful health probe results so kubelet-
// style probes (liveness + readiness, every few seconds each) do not
// hammer the underlying process with CDP roundtrips on every call.
// Tuned to bridge typical probe periods while still catching outages
// quickly: a real outage surfaces on the next probe after the TTL
// elapses.
const healthCheckCacheTTL = 2 * time.Second

// healthFailureThreshold is the number of consecutive Healthy() failures
// the supervisor tolerates before reporting unhealthy. Absorbs single-
// probe blips of transient CDP latency (for example a slow
// Browser.getVersion roundtrip when several conversion slots are
// simultaneously stuck), without delaying detection of a real outage.
// The container orchestrator's own failureThreshold stacks on top of
// this. See https://github.com/gotenberg/gotenberg/issues/1561.
const healthFailureThreshold = 2

type hashProcessSupervisor struct {
	logger         *slog.Logger
	engine         string
	process        gotenberg.Process
	maxReqLimit    int64
	maxQueueSize   int64
	maxConcurrency int64
	semaphore      chan struct{}
	firstStart     atomic.Bool
	// firstStartMu serializes lazy-launch attempts so concurrent callers do
	// not all spawn Launch() simultaneously. Using a mutex (instead of
	// sync.Once) lets a failed launch be retried by the next caller, since a
	// transient failure (such as a cold-start timeout) must not poison the
	// supervisor for the rest of the container's lifetime. See
	// https://github.com/gotenberg/gotenberg/issues/1538.
	firstStartMu        sync.Mutex
	reqCounter          atomic.Int64
	reqQueueSize        atomic.Int64
	restartsCounter     atomic.Int64
	isRestarting        atomic.Bool
	activeTasks         atomic.Int64
	restartMutex        sync.Mutex
	idleShutdownTimeout time.Duration
	lastActivity        atomic.Int64 // unix nano timestamp of last completed task
	// healthMu serializes Healthy() probes so concurrent callers do not
	// all issue a CDP roundtrip; the second caller hits the refreshed
	// cache instead.
	healthMu                  sync.Mutex
	lastHealthyAt             atomic.Int64  // unix nano of last successful probe; 0 means never
	consecutiveHealthFailures atomic.Int64  // reset to 0 on every successful probe
	idleMu                    sync.Mutex    // protects idleStopChan
	idleStopChan              chan struct{} // signal to stop the idle ticker goroutine
}

// newHashProcessSupervisor initializes a new [gotenberg.ProcessSupervisor]. engine names the
// managed process (for example "chromium" or "libreoffice") and prefixes the
// telemetry sub-spans; an empty engine falls back to "process".
func newHashProcessSupervisor(logger *slog.Logger, engine string, process gotenberg.Process, maxReqLimit, maxQueueSize, maxConcurrency int64, idleShutdownTimeout time.Duration) gotenberg.ProcessSupervisor {
	if maxConcurrency < 1 {
		maxConcurrency = 1
	}

	if engine == "" {
		engine = "process"
	}

	b := &hashProcessSupervisor{
		logger:              logger,
		engine:              engine,
		process:             process,
		semaphore:           make(chan struct{}, maxConcurrency),
		maxReqLimit:         maxReqLimit,
		maxQueueSize:        maxQueueSize,
		maxConcurrency:      maxConcurrency,
		idleShutdownTimeout: idleShutdownTimeout,
	}
	b.reqCounter.Store(0)
	b.reqQueueSize.Store(0)
	b.restartsCounter.Store(0)
	b.isRestarting.Store(false)
	b.activeTasks.Store(0)

	return b
}

func (s *hashProcessSupervisor) Launch() error {
	s.logger.DebugContext(context.Background(), "start process")
	err := s.process.Start(s.logger)
	if err != nil {
		return fmt.Errorf("start process: %w", err)
	}

	s.firstStart.Store(true)

	if s.idleShutdownTimeout > 0 {
		s.lastActivity.Store(time.Now().UnixNano())
		s.startIdleTicker()
	}

	s.logger.DebugContext(context.Background(), "process successfully started")

	return nil
}

func (s *hashProcessSupervisor) Shutdown() error {
	s.logger.DebugContext(context.Background(), "shutdown process")

	s.stopIdleTicker()

	err := s.process.Stop(s.logger)
	if err != nil {
		return fmt.Errorf("shutdown process: %w", err)
	}

	s.logger.DebugContext(context.Background(), "process successfully shutdown")

	return nil
}

func (s *hashProcessSupervisor) restart() error {
	s.logger.DebugContext(context.Background(), "restart process")

	err := s.Shutdown()
	if errors.Is(err, errHashBrowserShutdown) {
		// Never launch over an unjoined old browser generation.
		return err
	}
	if err != nil {
		// Not necessarily critical, chances are the process is already stopped,
		// but worth flagging in case it indicates a real issue.
		s.logger.WarnContext(context.Background(), fmt.Sprintf("stop process before restart: %s", err))
	}

	err = s.Launch()
	if err != nil {
		return fmt.Errorf("restart process: %w", err)
	}

	s.reqCounter.Store(0)
	s.restartsCounter.Add(1)
	s.logger.DebugContext(context.Background(), "process successfully restarted")

	return nil
}

func (s *hashProcessSupervisor) Healthy() bool {
	if !s.firstStart.Load() {
		// A non-started process is considered healthy: Gotenberg defers
		// process startup until the first request to keep resource usage low.
		// Reporting unhealthy here would cause container orchestrators to
		// restart the pod before any request arrives.
		// Owned Chromium may have attempted startup and retained an unconfirmed
		// retirement even though no launch has succeeded yet.
		if process, ok := s.process.(interface {
			hashLazyStartHealthy() bool
		}); ok {
			return process.hashLazyStartHealthy()
		}
		return true
	}

	// Explicit owned-browser quarantine is not a transient CDP probe failure.
	// This optional observation applies only after a successful first start;
	// the lazy branch above retains clean no-child retry semantics.
	knownUnavailable := func() bool {
		process, ok := s.process.(interface {
			hashReadinessUnavailable() bool
		})
		return ok && process.hashReadinessUnavailable()
	}
	if knownUnavailable() {
		return false
	}

	if s.isRestarting.Load() {
		// A restarting process is not yet healthy. This gives load balancers
		// honest information so they can avoid routing traffic to this node.
		return false
	}

	// Cache hit: a recent probe succeeded. Skip the CDP roundtrip so probe
	// spam does not pile commands onto a busy websocket.
	if s.recentlyHealthy() {
		return !knownUnavailable()
	}

	// Serialize probes so concurrent callers do not all roundtrip. The
	// second caller will see the refreshed cache (or counter) and return
	// without re-probing.
	s.healthMu.Lock()
	defer s.healthMu.Unlock()

	if knownUnavailable() {
		return false
	}
	if s.recentlyHealthy() {
		return !knownUnavailable()
	}

	if s.process.Healthy(s.logger) {
		if knownUnavailable() {
			return false
		}
		s.lastHealthyAt.Store(time.Now().UnixNano())
		s.consecutiveHealthFailures.Store(0)
		return true
	}

	if knownUnavailable() {
		return false
	}
	if s.consecutiveHealthFailures.Add(1) < healthFailureThreshold {
		// First failure: tolerate it. Under load, a single blown CDP
		// timeout is more likely transient pressure than a dead process.
		// A genuinely dead process will fail the next probe as well and
		// flip us unhealthy then.
		return !knownUnavailable()
	}
	return false
}

// recentlyHealthy reports whether a successful probe landed within
// [healthCheckCacheTTL]. Negative results are never cached so recovery
// from a real outage is observable on the very next probe.
func (s *hashProcessSupervisor) recentlyHealthy() bool {
	last := s.lastHealthyAt.Load()
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) < healthCheckCacheTTL
}

func (s *hashProcessSupervisor) Run(ctx context.Context, logger *slog.Logger, task func() error) error {
	// Time spent before the task body runs: queueing, slot acquisition, lazy
	// launch, and health checks. Ended once, when the task is about to execute.
	_, queueSpan := gotenberg.Tracer().Start(ctx, s.engine+".queue.wait",
		trace.WithSpanKind(trace.SpanKindInternal),
	)
	queueWaitDone := false
	endQueueWait := func() {
		if !queueWaitDone {
			queueWaitDone = true
			queueSpan.End()
		}
	}
	defer endQueueWait()

	// Atomically check and increment the queue size to avoid the TOCTOU race
	// originally reported in https://github.com/gotenberg/gotenberg/issues/951.
	for {
		current := s.reqQueueSize.Load()
		if s.maxQueueSize > 0 && current >= s.maxQueueSize {
			return gotenberg.ErrMaximumQueueSizeExceeded
		}
		if s.reqQueueSize.CompareAndSwap(current, current+1) {
			break
		}
	}

	// Decrement when Run() returns, regardless of which path is taken
	// (context timeout, task completion, error, etc.). This ensures the
	// request is counted as "in the queue" for the entire duration of Run(),
	// preventing new requests from entering while one is being processed.
	// See https://github.com/gotenberg/gotenberg/issues/1502.
	defer s.reqQueueSize.Add(-1)

	for {
		err := func() error {
			if err := s.acquireSlot(ctx, logger); err != nil {
				return err
			}

			s.reqCounter.Add(1)
			s.activeTasks.Add(1)
			semaphoreOwned := true

			defer func() {
				s.activeTasks.Add(-1)
				if s.idleShutdownTimeout > 0 {
					s.lastActivity.Store(time.Now().UnixNano())
				}
				if semaphoreOwned {
					logger.DebugContext(ctx, "process lock released")
					<-s.semaphore
				}
			}()

			if err := s.ensureStarted(ctx); err != nil {
				return err
			}

			if err := s.ensureHealthy(ctx); err != nil {
				return err
			}

			endQueueWait()
			err := s.runConversion(ctx, task)

			if s.maybeRestartAfterTask(logger) {
				semaphoreOwned = false
			}

			// Note: no error wrapping because it leaks on Chromium console exceptions output.
			return err
		}()

		if errors.Is(err, gotenberg.ErrProcessAlreadyRestarting) {
			logger.DebugContext(ctx, "process is already restarting, trying to acquire process lock again...")
			time.Sleep(10 * time.Millisecond)
			continue
		}

		// Note: no error wrapping because it leaks on Chromium console exceptions output.
		return err
	}
}

// startIdleTicker starts a background goroutine that periodically checks
// whether the process has been idle long enough to shut down.
func (s *hashProcessSupervisor) startIdleTicker() {
	stopChan := make(chan struct{})

	s.idleMu.Lock()
	s.idleStopChan = stopChan
	s.idleMu.Unlock()

	go func() {
		ticker := time.NewTicker(s.idleShutdownTimeout)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.maybeIdleShutdown()
			case <-stopChan:
				return
			}
		}
	}()
}

// stopIdleTicker signals the idle ticker goroutine to exit, if one is running.
func (s *hashProcessSupervisor) stopIdleTicker() {
	s.idleMu.Lock()
	defer s.idleMu.Unlock()

	if s.idleStopChan != nil {
		close(s.idleStopChan)
		s.idleStopChan = nil
	}
}

// maybeIdleShutdown stops the process if it has been idle for longer than
// the configured timeout. It is safe to call concurrently with Run and
// restart.
func (s *hashProcessSupervisor) maybeIdleShutdown() {
	if !s.firstStart.Load() || s.isRestarting.Load() {
		return
	}

	if s.activeTasks.Load() > 0 || s.reqQueueSize.Load() > 0 {
		return
	}

	lastNano := s.lastActivity.Load()
	if lastNano == 0 || time.Since(time.Unix(0, lastNano)) < s.idleShutdownTimeout {
		return
	}

	if !s.restartMutex.TryLock() {
		return
	}
	defer s.restartMutex.Unlock()

	// Double-check after acquiring the lock.
	if s.activeTasks.Load() > 0 || s.reqQueueSize.Load() > 0 {
		return
	}

	s.logger.DebugContext(context.Background(), "idle shutdown timeout reached, stopping process")

	// Stop the ticker, it will be restarted on the next Launch().
	s.stopIdleTicker()

	err := s.process.Stop(s.logger)
	if err != nil {
		s.logger.WarnContext(context.Background(), fmt.Sprintf("idle shutdown: %s", err))
		return
	}

	// Reset state so ensureStarted() re-launches on next request.
	s.firstStart.Store(false)
	s.reqCounter.Store(0)

	s.logger.DebugContext(context.Background(), "process stopped due to idle timeout")
}

// acquireSlot attempts to acquire a semaphore slot, yielding it back if a
// restart drain is in progress.
func (s *hashProcessSupervisor) acquireSlot(ctx context.Context, logger *slog.Logger) error {
	select {
	case s.semaphore <- struct{}{}:
		// If a restart drain is in progress, release the slot
		// immediately so the drain can acquire it instead.
		if s.isRestarting.Load() {
			<-s.semaphore
			return gotenberg.ErrProcessAlreadyRestarting
		}

		logger.DebugContext(ctx, "process lock acquired")

		return nil
	case <-ctx.Done():
		logger.DebugContext(ctx, "failed to acquire process lock before deadline")

		return fmt.Errorf("acquire process lock: %w", ctx.Err())
	}
}

// ensureStarted performs a lazy launch of the process on its first use.
// Concurrent callers serialize on firstStartMu; once the launch succeeds,
// subsequent calls short-circuit on the firstStart flag. A failed launch
// leaves firstStart unset, so the next caller retries the launch.
func (s *hashProcessSupervisor) ensureStarted(ctx context.Context) error {
	if s.firstStart.Load() {
		return nil
	}

	s.firstStartMu.Lock()
	defer s.firstStartMu.Unlock()

	if s.firstStart.Load() {
		return nil
	}

	err := s.tracedLaunch(ctx, "first_start", func() error {
		return s.runWithDeadline(ctx, s.Launch)
	})
	if err != nil {
		return fmt.Errorf("process first start: %w", err)
	}

	return nil
}

// tracedLaunch wraps a process (re)start in an <engine>.process.start span,
// tagged with the reason that triggered it. The eager restart after the maximum
// request limit runs on a background context, so its span is a detached root.
func (s *hashProcessSupervisor) tracedLaunch(ctx context.Context, reason string, launch func() error) error {
	_, span := gotenberg.Tracer().Start(ctx, s.engine+".process.start",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(attribute.String("gotenberg.process.start.reason", reason)),
	)
	defer span.End()

	err := launch()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return err
	}

	span.SetStatus(codes.Ok, "")
	return nil
}

// ensureHealthy checks the underlying process health and triggers a
// synchronous restart if the process is unhealthy. Skips the check if a
// restart is already in progress.
func (s *hashProcessSupervisor) ensureHealthy(ctx context.Context) error {
	if s.isRestarting.Load() || s.process.Healthy(s.logger) {
		return nil
	}

	s.logger.DebugContext(context.Background(), "process is unhealthy, cannot handle task, restarting...")

	if err := s.doRestart(ctx, "unhealthy"); err != nil {
		return fmt.Errorf("process restart before task: %w", err)
	}

	return nil
}

// maybeRestartAfterTask checks if the maximum request limit has been reached
// and, if so, triggers an asynchronous restart. If a restart is initiated, it
// takes ownership of the caller's semaphore slot (the caller must not release
// it). Returns true if ownership was taken.
func (s *hashProcessSupervisor) maybeRestartAfterTask(logger *slog.Logger) bool {
	if s.maxReqLimit <= 0 || s.reqCounter.Load() < s.maxReqLimit {
		return false
	}

	if !s.restartMutex.TryLock() {
		return false
	}

	s.logger.DebugContext(context.Background(), "max request limit reached, restarting eagerly...")

	go func() {
		restartErr := s.doRestartLocked(context.Background(), "max_requests")
		s.restartMutex.Unlock()
		if restartErr != nil {
			s.logger.ErrorContext(context.Background(), fmt.Sprintf("process restart after task: %v", restartErr))
		}
		logger.DebugContext(context.Background(), "process lock released")
		<-s.semaphore
	}()

	return true
}

// doRestart coordinates a process restart, draining all active concurrent
// tasks before stopping and restarting the process.
func (s *hashProcessSupervisor) doRestart(ctx context.Context, reason string) error {
	s.restartMutex.Lock()
	defer s.restartMutex.Unlock()

	return s.doRestartLocked(ctx, reason)
}

// doRestartLocked performs the restart drain logic. The caller must hold restartMutex.
func (s *hashProcessSupervisor) doRestartLocked(ctx context.Context, reason string) error {
	s.isRestarting.Store(true)
	defer s.isRestarting.Store(false)

	// Drain all other active semaphore slots so no other tasks are running during the restart.
	slotsToAcquire := s.maxConcurrency - 1
	acquired := make([]struct{}, 0, slotsToAcquire)

	for range slotsToAcquire {
		select {
		case s.semaphore <- struct{}{}:
			acquired = append(acquired, struct{}{})
		case <-ctx.Done():
			for range acquired {
				<-s.semaphore
			}
			return fmt.Errorf("drain active tasks before restart: %w", ctx.Err())
		}
	}

	err := s.tracedLaunch(ctx, reason, func() error {
		return s.runWithDeadline(ctx, s.restart)
	})

	for range acquired {
		<-s.semaphore
	}

	return err
}

func (s *hashProcessSupervisor) runWithDeadline(ctx context.Context, task func() error) error {
	runChan := make(chan error, 1)
	go func() {
		runChan <- task()
	}()

	for {
		select {
		case err := <-runChan:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s *hashProcessSupervisor) ReqQueueSize() int64 {
	return s.reqQueueSize.Load()
}

func (s *hashProcessSupervisor) RestartsCount() int64 {
	return s.restartsCounter.Load()
}

func (s *hashProcessSupervisor) ActiveTasksCount() int64 {
	return s.activeTasks.Load()
}

// ConversionsSinceRestart returns the number of tasks handled since the last
// process (re)start. reqCounter is reset to zero on every restart and idle
// shutdown.
func (s *hashProcessSupervisor) ConversionsSinceRestart() int64 {
	return s.reqCounter.Load()
}

// Interface guards.
var (
	_ gotenberg.ProcessSupervisor = (*hashProcessSupervisor)(nil)
)

// runConversion is deliberately synchronous. The only production callers are
// Chromium.Pdf/Screenshot, whose browser work uses the request deadline and
// independently bounded allocation/cleanup. A cancellation must never abandon
// that callback and release its slot while it still owns a tab or report.
func (s *hashProcessSupervisor) runConversion(ctx context.Context, task func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := task()
	if canceled := ctx.Err(); canceled != nil {
		return errors.Join(err, canceled)
	}
	return err
}
