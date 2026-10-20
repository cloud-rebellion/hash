package chromium

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// Retained pinned upstream cmd_test.go helper, namespaced for this module.
func hashTestSpanRecorder(t *testing.T) *tracetest.SpanRecorder {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	previous := otel.GetTracerProvider()
	otel.SetTracerProvider(provider)
	t.Cleanup(func() { otel.SetTracerProvider(previous) })
	return recorder
}

func hashWait(t *testing.T, description string, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for !predicate() {
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("timed out: ", description)
		}
	}
}

func hashAwait(t *testing.T, description string, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out: ", description)
	}
}

func hashMockSupervisor(maxQueue int64) *hashProcessSupervisor {
	s := newHashProcessSupervisor(slog.New(slog.DiscardHandler), "chromium", &gotenberg.ProcessMock{
		StartMock:   func(*slog.Logger) error { return nil },
		StopMock:    func(*slog.Logger) error { return nil },
		HealthyMock: func(*slog.Logger) bool { return true },
	}, 0, maxQueue, 1, 0).(*hashProcessSupervisor)
	_ = s.Launch() // finite mock lifecycle, before any canceled caller is tested
	return s
}

func TestHashSupervisorCancellationOwnsCallback(t *testing.T) {
	for _, mode := range []string{"caller-cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			s := hashMockSupervisor(2)
			logger := slog.New(slog.DiscardHandler)
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 500*time.Millisecond)
				want = context.DeadlineExceeded
			}
			secondCtx, cancelSecond := context.WithTimeout(context.Background(), 5*time.Second)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			entered, draining := make(chan struct{}), make(chan struct{})
			firstDone, secondDone := make(chan struct{}), make(chan struct{})
			firstResult, secondResult := make(chan error, 1), make(chan error, 1)
			var metadata atomic.Int64
			var secondEntered atomic.Bool
			t.Cleanup(func() {
				cancel()
				cancelSecond()
				releaseGate()
				hashAwait(t, "first caller joined", firstDone)
				hashAwait(t, "second caller joined", secondDone)
			})
			go func() {
				defer close(firstDone)
				firstResult <- s.Run(ctx, logger, func() error {
					close(entered)
					<-ctx.Done()
					close(draining)
					select {
					case <-release:
					case <-time.After(4 * time.Second):
						return errors.New("test cleanup barrier expired")
					}
					metadata.Store(42)
					return nil
				})
			}()
			go func() {
				defer close(secondDone)
				select {
				case <-entered:
				case <-secondCtx.Done():
					secondResult <- secondCtx.Err()
					return
				}
				secondResult <- s.Run(secondCtx, logger, func() error {
					secondEntered.Store(true)
					if metadata.Load() != 42 {
						return errors.New("second task admitted before callback metadata completed")
					}
					return nil
				})
			}()
			hashAwait(t, "first conversion entered", entered)
			hashWait(t, "second conversion queued", func() bool { return s.ActiveTasksCount() == 1 && s.ReqQueueSize() == 2 })
			if mode == "caller-cancel" {
				cancel()
			}
			hashAwait(t, "callback cancellation observed", draining)
			queueErr := s.Run(context.Background(), logger, func() error { return errors.New("queue limit admitted a third task") })
			if !errors.Is(queueErr, gotenberg.ErrMaximumQueueSizeExceeded) {
				t.Fatal("upstream queue sentinel lost: ", queueErr)
			}
			select {
			case <-firstDone:
				t.Fatal("canceled Run returned before callback cleanup")
			case <-secondDone:
				t.Fatal("queued Run entered before callback cleanup")
			case <-time.After(100 * time.Millisecond):
			}
			if secondEntered.Load() || s.ActiveTasksCount() != 1 || s.ReqQueueSize() != 2 {
				t.Fatal("conversion slot or queue released during cleanup")
			}
			releaseGate()
			hashAwait(t, "first completion", firstDone)
			hashAwait(t, "second completion", secondDone)
			if err := <-firstResult; !errors.Is(err, want) {
				t.Fatal("cancellation classification lost: ", err)
			}
			if err := <-secondResult; err != nil {
				t.Fatal(err)
			}
			if s.ActiveTasksCount() != 0 || s.ReqQueueSize() != 0 || metadata.Load() != 42 {
				t.Fatal("completed callbacks leave accounting or metadata incomplete")
			}
		})
	}
}

func TestHashSupervisorQueuedCancellationNeverDispatches(t *testing.T) {
	s := hashMockSupervisor(2)
	logger := slog.New(slog.DiscardHandler)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once sync.Once
	releaseGate := func() { once.Do(func() { close(release) }) }
	t.Cleanup(func() { releaseGate(); cancel(); hashAwait(t, "active caller joined", done) })
	go func() {
		defer close(done)
		_ = s.Run(ctx, logger, func() error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil
		})
	}()
	hashAwait(t, "active callback", entered)
	queuedCtx, cancelQueued := context.WithCancel(context.Background())
	defer cancelQueued()
	result := make(chan error, 1)
	queuedDone := make(chan struct{})
	var invoked atomic.Bool
	t.Cleanup(func() { cancelQueued(); hashAwait(t, "queued caller joined", queuedDone) })
	go func() {
		defer close(queuedDone)
		result <- s.Run(queuedCtx, logger, func() error { invoked.Store(true); return nil })
	}()
	hashWait(t, "cancellable caller queued", func() bool { return s.ReqQueueSize() == 2 })
	cancelQueued()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) || invoked.Load() {
			t.Fatal("canceled queued task dispatched or lost cancellation: ", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("queued cancellation did not return")
	}
	if s.ReqQueueSize() != 1 || s.ActiveTasksCount() != 1 {
		t.Fatal("queued cancellation affected active ownership")
	}
	releaseGate()
	hashAwait(t, "active completion", done)
	if s.ReqQueueSize() != 0 || s.ActiveTasksCount() != 0 {
		t.Fatal("accounting remains after completion")
	}
}

func TestHashSupervisorCancellationClassification(t *testing.T) {
	taskErr := errors.New("conversion refused")
	for _, tc := range []struct {
		name      string
		cancelPre bool
		taskErr   error
	}{
		{"already-canceled-refuses-dispatch", true, nil},
		{"late-nil-success-is-canceled", false, nil},
		{"task-and-cancellation-errors-retained", false, taskErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := hashMockSupervisor(0)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelPre {
				cancel()
			}
			invoked := false
			err := s.Run(ctx, slog.New(slog.DiscardHandler), func() error {
				invoked = true
				cancel()
				return tc.taskErr
			})
			if !errors.Is(err, context.Canceled) || invoked == tc.cancelPre || (tc.taskErr != nil && !errors.Is(err, taskErr)) {
				t.Fatal("dispatch or cancellation classification changed: ", err)
			}
			if s.ReqQueueSize() != 0 || s.ActiveTasksCount() != 0 {
				t.Fatal("canceled conversion retained accounting")
			}
		})
	}
}
