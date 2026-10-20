// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPDFWorkerObservationTypedInvalidProducerV1(t *testing.T) {
	w := workerTestHelper(t, "protocol")
	var seen []PDFWorkerObservationV1
	var slotHeld bool
	w.observer = func(observation PDFWorkerObservationV1) {
		seen = append(seen, observation)
		slotHeld = len(w.slots) != 0
	}
	result, err := w.clean(context.Background(), "PRIVATE_ASSET_374", "application/pdf", []byte("invalid"))
	if !errors.Is(err, ErrPDFInvalid) || err.Error() != "sanitize: invalid PDF" || len(result.Bytes) != 0 {
		t.Fatalf("coherent invalid input lost typed refusal or returned output: %v", err)
	}
	if len(seen) != 1 || seen[0].Operation != PDFWorkerOperationCleanV1 || seen[0].Outcome != PDFWorkerOutcomeRejectedV1 || seen[0].Elapsed < 0 || slotHeld {
		t.Fatal("observation preceded runner cleanup or lost fixed refusal", seen)
	}
	if strings.Contains(fmt.Sprint(seen), "PRIVATE_ASSET_374") {
		t.Fatal("asset crossed closed observation boundary")
	}
}

func TestPDFWorkerObservationBrokenProtocolIsUnavailableV1(t *testing.T) {
	w := workerTestHelper(t, "broken")
	var seen []PDFWorkerObservationV1
	w.observer = func(observation PDFWorkerObservationV1) {
		if len(w.slots) != 0 {
			t.Error("callback ran while its runner slot remained held")
		}
		seen = append(seen, observation)
	}
	_, body, err := w.run(context.Background(), pdfWorkerRequest{Operation: "clean", Length: 7}, []byte("invalid"))
	if !errors.Is(err, ErrPDFWorkerUnavailable) || errors.Is(err, ErrPDFInvalid) || len(body) != 0 || len(seen) != 1 || seen[0].Outcome != PDFWorkerOutcomeUnavailableV1 {
		t.Fatal("corrupt protocol was mislabeled as expected input refusal")
	}
}

func TestPDFWorkerObservationCancellationAfterActualReapV1(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	w := &pdfWorker{path: workerTestScript(t, "echo $$ > "+shellTestQuote(pidFile)+"\nexec /bin/sleep 60"), slots: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type witness struct {
		observation   PDFWorkerObservationV1
		slotReleased  bool
		processAbsent bool
	}
	observed := make(chan witness, 1)
	w.observer = func(observation PDFWorkerObservationV1) {
		raw, err := os.ReadFile(pidFile)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		observed <- witness{observation, len(w.slots) == 0, err == nil && parseErr == nil && errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)}
	}
	done := make(chan error, 1)
	finished := make(chan struct{})
	// TempDir registered its cleanup above; this later cleanup joins first.
	// The normal path may consume done, so cleanup waits a separate close-only
	// signal and never tries to receive the error value a second time.
	t.Cleanup(func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(3 * time.Second):
			t.Error("actual worker goroutine did not join before fixture cleanup")
		}
	})
	go func() {
		defer close(finished)
		_, _, err := w.run(ctx, pdfWorkerRequest{Operation: "pages"}, nil)
		done <- err
	}()
	limit := time.Now().Add(3 * time.Second)
	for {
		raw, _ := os.ReadFile(pidFile)
		if len(raw) != 0 {
			break
		}
		if time.Now().After(limit) {
			t.Fatal("actual child did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("cancellation semantics changed", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runner cancellation failed to join")
	}
	select {
	case seen := <-observed:
		if seen.observation.Outcome != PDFWorkerOutcomeCanceledV1 || !seen.slotReleased || !seen.processAbsent {
			t.Fatal("observer preceded actual wait/slot release", seen)
		}
	default:
		t.Fatal("missing joined runner observation")
	}
}

func TestPDFWorkerObservationPreflightHasNoExecutionClaimV1(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "unexpected-child")
	w := &pdfWorker{path: workerTestScript(t, "echo started > "+shellTestQuote(marker)), slots: make(chan struct{}, 2)}
	w.slots <- struct{}{}
	w.slots <- struct{}{}
	var seen []PDFWorkerObservationV1
	w.observer = func(observation PDFWorkerObservationV1) { seen = append(seen, observation) }
	if _, _, err := w.run(context.Background(), pdfWorkerRequest{Operation: "clean"}, nil); !errors.Is(err, ErrPDFWorkerCapacity) {
		t.Fatal("capacity admission changed", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := w.run(ctx, pdfWorkerRequest{Operation: "clean"}, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled caller was not refused before capacity", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) || len(w.slots) != 2 || len(seen) != 2 || seen[0].Outcome != PDFWorkerOutcomeCapacityV1 || seen[1].Outcome != PDFWorkerOutcomeCanceledV1 {
		t.Fatal("preflight attempt falsely launched/refunded another owner or changed outcome")
	}
}

func TestPDFWorkerObservationFixedOperationAndOutcomeMatrixV1(t *testing.T) {
	operations := []struct {
		raw  string
		want PDFWorkerOperationV1
	}{
		{"probe", PDFWorkerOperationProbeV1}, {"clean", PDFWorkerOperationCleanV1}, {"pages", PDFWorkerOperationPagesV1},
		{pdfComposeSigningPageOperation, PDFWorkerOperationComposeV1}, {pdfProviderOverlayOperation, PDFWorkerOperationProviderOverlayV1},
		{pdfManualInspectOperation, PDFWorkerOperationManualInspectV1}, {pdfManualOverlayOperation, PDFWorkerOperationManualOverlayV1},
		{pdfManualLayersOperation, PDFWorkerOperationManualLayersV1}, {pdfManualFragmentOperation, PDFWorkerOperationManualFragmentV1},
		{"PRIVATE_UNKNOWN_OPERATION", PDFWorkerOperationUnknownV1},
	}
	for _, item := range operations {
		if pdfWorkerOperationV1(item.raw) != item.want {
			t.Fatal("operation mapping differs")
		}
	}
	parent := context.Background()
	for _, err := range []error{ErrPDFTooLarge, ErrTooManyPages, ErrActivePDFContent, ErrPDFInvalid, ErrPDFProviderOverlay, ErrPDFSigningPageInvalid, ErrPDFManualOverlay, ErrPDFManualLayers, ErrPDFManualFragment} {
		if pdfWorkerOutcomeV1(parent, fmt.Errorf("PRIVATE_WRAPPER: %w", err)) != PDFWorkerOutcomeRejectedV1 {
			t.Fatal("typed refusal became pageable")
		}
	}
	if pdfWorkerOutcomeV1(parent, nil) != PDFWorkerOutcomeSuccessV1 || pdfWorkerOutcomeV1(parent, ErrPDFWorkerCapacity) != PDFWorkerOutcomeCapacityV1 || pdfWorkerOutcomeV1(parent, ErrPDFWorkerUnavailable) != PDFWorkerOutcomeUnavailableV1 || pdfWorkerOutcomeV1(parent, context.DeadlineExceeded) != PDFWorkerOutcomeTimeoutV1 || pdfWorkerOutcomeV1(parent, errors.New("PRIVATE_INTERNAL")) != PDFWorkerOutcomeInternalV1 {
		t.Fatal("fixed terminal error mapping differs")
	}
	canceled, stop := context.WithCancel(parent)
	stop()
	expired, stopDeadline := context.WithDeadline(parent, time.Now().Add(-time.Second))
	defer stopDeadline()
	for _, ctx := range []context.Context{canceled, expired} {
		if pdfWorkerOutcomeV1(ctx, context.DeadlineExceeded) != PDFWorkerOutcomeCanceledV1 || pdfWorkerOutcomeV1(ctx, ErrPDFWorkerUnavailable) != PDFWorkerOutcomeCanceledV1 || pdfWorkerOutcomeV1(ctx, nil) != PDFWorkerOutcomeSuccessV1 {
			t.Fatal("original caller state or successful result precedence changed")
		}
	}
}

func TestPDFWorkerObservationPanicDoesNotChangeProcessingResultV1(t *testing.T) {
	w := workerTestHelper(t, "protocol")
	w.observer = func(PDFWorkerObservationV1) { panic("PRIVATE_OBSERVER_FAILURE") }
	before := PDFWorkerObserverPanicsV1()
	response, body, err := w.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil)
	if err != nil || response.Pages != 1 || len(body) != 0 || len(w.slots) != 0 || PDFWorkerObserverPanicsV1() != before+1 {
		t.Fatal("observer failure changed actual processing or leaked its runner slot")
	}
}

func TestPDFWorkerObservationInnerDeadlineJoinsBeforeTimeoutV1(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	w := &pdfWorker{path: workerTestScript(t, "echo $$ > "+shellTestQuote(pidFile)+"\nexec /bin/sleep 60"), slots: make(chan struct{}, 2)}
	parent := context.Background()
	var seen PDFWorkerObservationV1
	var calls int
	var reaped, slotReleased bool
	w.observer = func(observation PDFWorkerObservationV1) {
		seen, calls = observation, calls+1
		raw, err := os.ReadFile(pidFile)
		pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
		reaped = err == nil && parseErr == nil && errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
		slotReleased = len(w.slots) == 0
	}
	_, body, err := w.run(parent, pdfWorkerRequest{Operation: "pages"}, nil)
	if !errors.Is(err, context.DeadlineExceeded) || parent.Err() != nil || len(body) != 0 || calls != 1 || seen.Outcome != PDFWorkerOutcomeTimeoutV1 || seen.Elapsed < pdfWorkerTimeout || seen.Elapsed > pdfWorkerTimeout+3*time.Second || !reaped || !slotReleased {
		t.Fatal("real unchanged inner deadline was not joined/classified honestly")
	}
}

func TestPDFWorkerObservationInstalledBeforeStartupProbeV1(t *testing.T) {
	previous := activePDFWorker.Load()
	t.Cleanup(func() { activePDFWorker.Store(previous) })
	helper := workerTestHelper(t, "protocol")
	var seen []PDFWorkerObservationV1
	observer := func(observation PDFWorkerObservationV1) { seen = append(seen, observation) }
	if err := ConfigurePDFWorkerWithObserverV1(context.Background(), helper.path, "production", observer); err != nil {
		t.Fatal("actual observed constructor failed", err)
	}
	if len(seen) != 1 || seen[0].Operation != PDFWorkerOperationProbeV1 || seen[0].Outcome != PDFWorkerOutcomeSuccessV1 {
		t.Fatal("observer was not attached at actual startup birth")
	}
	if pages, err := PageCountWithContext(context.Background(), buildTestPDF(t, 1)); err != nil || pages != 1 {
		t.Fatal("published observed worker failed original public operation", err)
	}
	if len(seen) != 2 || seen[1].Operation != PDFWorkerOperationPagesV1 || seen[1].Outcome != PDFWorkerOutcomeSuccessV1 {
		t.Fatal("published instance lost its immutable observer")
	}
}
