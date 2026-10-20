//go:build renderer_e2e

package chromium

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
	"github.com/chromedp/chromedp"
	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

// This observer wraps the actual public conversion closure and delegates to the
// production-owned supervisor. The finite tail gate is a synthetic scheduling
// witness; all browser work and target observations use genuine Chromium.
type hashSupervisorObserver struct {
	gotenberg.ProcessSupervisor
	sequence      atomic.Int64
	firstComplete atomic.Bool
	firstDrained  chan struct{}
	secondEntered chan struct{}
	release       <-chan struct{}
	firstError    error // published by closing firstDrained
	beforeSecond  func() error
}

func (o *hashSupervisorObserver) Run(ctx context.Context, logger *slog.Logger, task func() error) error {
	return o.ProcessSupervisor.Run(ctx, logger, func() error {
		switch o.sequence.Add(1) {
		case 1:
			err := task()
			o.firstError = err
			close(o.firstDrained)
			select {
			case <-o.release:
			case <-time.After(5 * time.Second):
				return errors.New("public conversion tail gate expired")
			}
			o.firstComplete.Store(true)
			return err
		case 2:
			close(o.secondEntered)
			if !o.firstComplete.Load() {
				return errors.New("public conversion admitted before prior callback completion")
			}
			if err := o.beforeSecond(); err != nil {
				return err
			}
		}
		return task()
	})
}

func hashTargetSnapshot(b *chromiumBrowser) (map[target.ID]string, error) {
	return hashTargetSnapshotUntil(b, time.Now().Add(2*time.Second))
}

func hashTargetSnapshotUntil(b *chromiumBrowser, deadline time.Time) (map[target.ID]string, error) {
	ctx, cancel := context.WithDeadline(b.ctx, deadline)
	defer cancel()
	ctx = cdp.WithExecutor(ctx, chromedp.FromContext(b.ctx).Browser)
	infos, err := target.GetTargets().Do(ctx)
	if err != nil {
		return nil, err
	}
	ids := make(map[target.ID]string)
	for _, info := range infos {
		if info.Type == "page" {
			ids[info.TargetID] = info.URL
		}
	}
	return ids, nil
}

func hashPublicFixtureModule(t *testing.T) (*Chromium, *chromiumBrowser) {
	t.Helper()
	b := hashNewGenuineBrowser(t)
	logger := slog.New(slog.DiscardHandler)
	s := newHashProcessSupervisor(logger, "chromium", b, 0, 2, 1, 0)
	if err := s.Launch(); err != nil {
		t.Fatal("launch actual supervisor/browser: ", err)
	}
	t.Cleanup(func() {
		if err := s.Shutdown(); err != nil {
			t.Error("shutdown actual supervisor/browser: ", err)
		}
	})
	return hashPublicModuleWithSupervisor(t, b, s), b
}

func hashPublicModuleWithSupervisor(t *testing.T, b *chromiumBrowser, s gotenberg.ProcessSupervisor) *Chromium {
	t.Helper()
	logger := slog.New(slog.DiscardHandler)
	mod := &Chromium{args: b.arguments, logger: logger, browser: b, supervisor: s, maxConcurrency: 1}
	meter := metricnoop.NewMeterProvider().Meter("hash-public-renderer-fixture")
	var err error
	mod.reqsCounter, err = meter.Int64Counter("requests")
	if err != nil {
		t.Fatal(err)
	}
	mod.errsCounter, err = meter.Int64Counter("errors")
	if err != nil {
		t.Fatal(err)
	}
	mod.networkRequestsCounter, err = meter.Int64Counter("network_requests")
	if err != nil {
		t.Fatal(err)
	}
	mod.conversionDurationCounter, err = meter.Float64Histogram("conversion_duration")
	if err != nil {
		t.Fatal(err)
	}
	mod.queueWaitDurationCounter, err = meter.Float64Histogram("queue_wait")
	if err != nil {
		t.Fatal(err)
	}
	mod.pdfOutputSizeCounter, err = meter.Int64Histogram("pdf_output_size")
	if err != nil {
		t.Fatal(err)
	}
	mod.imageOutputSizeCounter, err = meter.Int64Histogram("image_output_size")
	if err != nil {
		t.Fatal(err)
	}
	mod.networkBytesCounter, err = meter.Int64Histogram("network_bytes")
	if err != nil {
		t.Fatal(err)
	}
	return mod
}

func hashPublicConvert(api Api, ctx context.Context, logger *slog.Logger, kind, sourceURL, output, sourceDir string, wait bool) error {
	if kind == "pdf" {
		options := hashGenuinePDFOptions(sourceDir)
		if wait {
			options.WaitForSelector = "#hash-supervisor-never-present"
		}
		return api.Pdf(ctx, logger, sourceURL, output, options)
	}
	options := hashGenuineScreenshotOptions(sourceDir)
	if wait {
		options.WaitForSelector = "#hash-supervisor-never-present"
	}
	return api.Screenshot(ctx, logger, sourceURL, output, options)
}

func hashAssertOutput(t *testing.T, path, kind string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("ordinary public output: ", err)
	}
	prefix := []byte("%PDF-")
	if kind == "png" {
		prefix = []byte{137, 80, 78, 71, 13, 10, 26, 10}
	}
	if len(raw) <= len(prefix) || !bytes.HasPrefix(raw, prefix) {
		t.Fatal("invalid ordinary public output")
	}
}

func TestHashSupervisorGenuinePublicConversions(t *testing.T) {
	for _, pair := range []struct{ first, second string }{{"pdf", "png"}, {"png", "pdf"}} {
		t.Run(pair.first+"-cancel-then-"+pair.second, func(t *testing.T) {
			mod, b := hashPublicFixtureModule(t)
			api, err := mod.Chromium()
			if err != nil {
				t.Fatal(err)
			}
			baseline, err := hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			source := filepath.Join(dir, "index.html")
			if err := os.WriteFile(source, []byte("<!doctype html><meta charset=utf-8><p>Hash public queue fixture</p>"), 0o600); err != nil {
				t.Fatal(err)
			}
			sourceURL := (&url.URL{Scheme: "file", Path: source}).String()
			firstOutput, secondOutput := filepath.Join(dir, "first."+pair.first), filepath.Join(dir, "second."+pair.second)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			secondCtx, cancelSecond := context.WithTimeout(context.Background(), 30*time.Second)
			release := make(chan struct{})
			var releaseOnce sync.Once
			releaseGate := func() { releaseOnce.Do(func() { close(release) }) }
			observer := &hashSupervisorObserver{ProcessSupervisor: mod.supervisor, firstDrained: make(chan struct{}), secondEntered: make(chan struct{}), release: release}
			mod.supervisor = observer
			var owned target.ID
			observer.beforeSecond = func() error {
				current, err := hashTargetSnapshot(b)
				if err != nil {
					return err
				}
				if owned == "" {
					return errors.New("first target was not observed")
				}
				if _, present := current[owned]; present {
					return errors.New("prior exact target remains at public admission")
				}
				return nil
			}
			firstDone, secondDone := make(chan struct{}), make(chan struct{})
			firstResult, secondResult := make(chan error, 1), make(chan error, 1)
			secondStarted := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				cancelSecond()
				releaseGate()
				// Cleanup ordering joins callers before the earlier browser shutdown.
				hashAwait(t, "first public caller joined", firstDone)
				hashAwait(t, "second public caller joined", secondDone)
			})
			go func() {
				defer close(firstDone)
				firstResult <- hashPublicConvert(api, ctx, mod.logger, pair.first, sourceURL, firstOutput, dir, true)
			}()
			go func() {
				defer close(secondDone)
				select {
				case <-secondStarted:
				case <-secondCtx.Done():
					secondResult <- secondCtx.Err()
					return
				}
				secondResult <- hashPublicConvert(api, secondCtx, mod.logger, pair.second, sourceURL, secondOutput, dir, false)
			}()
			// Real startup/first-call work is distinct from the deterministic
			// three-second mock witnesses. Keep a local finite observation budget
			// and expose early callback failures instead of disguising them as a
			// missing target. Production/caller/queue/tail deadlines are unchanged.
			witnessDeadline := time.Now().Add(10 * time.Second)
			var lastTargets map[target.ID]string
			for owned == "" {
				select {
				case <-observer.firstDrained:
					t.Fatal("first public callback ended before target observation: ", observer.firstError)
				default:
				}
				observationDeadline := time.Now().Add(2 * time.Second)
				if witnessDeadline.Before(observationDeadline) {
					observationDeadline = witnessDeadline
				}
				current, err := hashTargetSnapshotUntil(b, observationDeadline)
				if err != nil {
					t.Fatalf("observe first public target: %v; sequence=%d active=%d queued=%d lastTargets=%v", err, observer.sequence.Load(), observer.ActiveTasksCount(), observer.ReqQueueSize(), lastTargets)
				}
				lastTargets = current
				for id, targetURL := range current {
					if _, old := baseline[id]; !old && targetURL == sourceURL {
						owned = id
						break
					}
				}
				if owned != "" {
					break
				}
				remaining := time.Until(witnessDeadline)
				if remaining <= 0 {
					t.Fatalf("timed out observing first public target: sequence=%d active=%d queued=%d lastTargets=%v", observer.sequence.Load(), observer.ActiveTasksCount(), observer.ReqQueueSize(), lastTargets)
				}
				pause := 20 * time.Millisecond
				if remaining < pause {
					pause = remaining
				}
				timer := time.NewTimer(pause)
				select {
				case <-observer.firstDrained:
					timer.Stop()
					t.Fatal("first public callback ended before target observation: ", observer.firstError)
				case <-timer.C:
				}
			}
			close(secondStarted)
			hashWait(t, "actual public second request queued", func() bool { return observer.ActiveTasksCount() == 1 && observer.ReqQueueSize() == 2 })
			cancel()
			hashAwait(t, "genuine browser callback drained", observer.firstDrained)
			if !errors.Is(observer.firstError, context.Canceled) {
				t.Fatal("actual browser cancellation missing: ", observer.firstError)
			}
			current, err := hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(current, baseline) {
				t.Fatal("exact first target cleanup did not restore baseline")
			}
			queueCtx, cancelQueue := context.WithTimeout(context.Background(), 2*time.Second)
			queueErr := api.Pdf(queueCtx, mod.logger, sourceURL, filepath.Join(dir, "queue-full.pdf"), hashGenuinePDFOptions(dir))
			cancelQueue()
			if !errors.Is(queueErr, gotenberg.ErrMaximumQueueSizeExceeded) {
				t.Fatal("public queue sentinel changed: ", queueErr)
			}
			select {
			case <-firstDone:
				t.Fatal("public caller returned before conversion callback completed")
			case <-observer.secondEntered:
				t.Fatal("second public callback admitted before prior callback completed")
			case <-time.After(100 * time.Millisecond):
			}
			if observer.ActiveTasksCount() != 1 || observer.ReqQueueSize() != 2 {
				t.Fatal("public slot released during callback tail")
			}
			for _, output := range []string{firstOutput, secondOutput, filepath.Join(dir, "queue-full.pdf")} {
				if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused or queued conversion produced output: ", output)
				}
			}
			releaseGate()
			hashAwait(t, "first public completion", firstDone)
			hashAwait(t, "second public completion", secondDone)
			if err := <-firstResult; !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if err := <-secondResult; err != nil {
				t.Fatal(err)
			}
			hashAssertOutput(t, secondOutput, pair.second)
			finalCtx, cancelFinal := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancelFinal()
			finalOutput := filepath.Join(dir, "after.pdf")
			if err := api.Pdf(finalCtx, mod.logger, sourceURL, finalOutput, hashGenuinePDFOptions(dir)); err != nil {
				t.Fatal("ordinary public PDF after cancellation: ", err)
			}
			hashAssertOutput(t, finalOutput, "pdf")
			current, err = hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(current, baseline) || observer.ActiveTasksCount() != 0 || observer.ReqQueueSize() != 0 || observer.RestartsCount() != 0 {
				t.Fatal(fmt.Sprintf("public renderer state not restored: active=%d queue=%d restarts=%d", observer.ActiveTasksCount(), observer.ReqQueueSize(), observer.RestartsCount()))
			}
		})
	}
}
