//go:build renderer_e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package chromium

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/target"
	"github.com/gotenberg/gotenberg/v8/pkg/gotenberg"
)

func TestHashPublicPDFQueueAdmissionV1(t *testing.T) {
	for _, pair := range []struct{ first, second string }{{"pdf", "pdf"}} {
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
			// Real queued cancellation must refund without dispatch or a new target.
			queuedCtx, cancelQueued := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancelQueued()
			queuedDone, queuedResult := make(chan struct{}), make(chan error, 1)
			queuedOutput := filepath.Join(dir, "canceled-queued.pdf")
			beforeQueued, err := hashTargetSnapshot(b)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { cancelQueued(); hashAwait(t, "canceled queued caller joined", queuedDone) })
			go func() {
				defer close(queuedDone)
				queuedResult <- api.Pdf(queuedCtx, mod.logger, sourceURL, queuedOutput, hashGenuinePDFOptions(dir))
			}()
			hashWait(t, "cancellable public request actually queued", func() bool { return observer.ActiveTasksCount() == 1 && observer.ReqQueueSize() == 2 })
			cancelQueued()
			hashAwait(t, "queued cancellation physically joined", queuedDone)
			if err := <-queuedResult; !errors.Is(err, context.Canceled) {
				t.Fatal("queued cancellation missing: ", err)
			}
			afterQueued, err := hashTargetSnapshot(b)
			if err != nil || !reflect.DeepEqual(beforeQueued, afterQueued) || observer.sequence.Load() != 1 || observer.ActiveTasksCount() != 1 || observer.ReqQueueSize() != 1 {
				t.Fatal("canceled queued work dispatched, changed targets or retained admission: ", err)
			}
			if _, err := os.Stat(queuedOutput); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("canceled queued conversion produced output")
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
			t.Log("HASH_ADMISSION208_V1 active_limit=1 admitted_limit=2 queued_cancel_joined=true overflow_refused=true target_absence_before_refund=true queued_pdf=true canary_pdf=true final_active=0 final_queue=0 restarts=0")
		})
	}
}
