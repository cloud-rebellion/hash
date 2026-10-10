// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sanitize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// A real child executes the one-shot protocol. It deliberately does not install
// Linux limits: cmd/pdfworker's Linux tests cover that separate boundary.
func TestPDFWorkerChildHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--hash-pdf-test" {
		return
	}
	if os.Getenv("HASH_PRIVATE_SYNTHETIC_SECRET") != "" {
		os.Exit(2)
	}
	switch os.Args[len(os.Args)-1] {
	case "protocol":
		if ServePDFWorker(os.Stdin, os.Stdout) != nil {
			os.Exit(3)
		}
	case "broken":
		os.Stdout.WriteString("{not-json}\n")
	case "short":
		os.Stdout.WriteString("{\"protocol_version\":2,\"length\":4}\nabc")
	case "extra":
		os.Stdout.WriteString("{\"protocol_version\":2,\"length\":1}\nab")
	case "too-many-pages":
		os.Stdout.WriteString("{\"protocol_version\":2,\"length\":0,\"pages\":501}\n")
	case "oversized-header":
		os.Stdout.WriteString(strings.Repeat("x", pdfWorkerHeaderLimit+1))
	case "exit":
		os.Exit(4)
	case "overflow":
		chunk := make([]byte, 1<<20)
		for i := 0; i < 60; i++ {
			if _, err := os.Stdout.Write(chunk); err != nil {
				os.Exit(0)
			}
		}
	case "composition-wrong-input", "composition-wrong-output", "composition-wrong-report", "composition-missing-report", "composition-missing-manifest", "composition-extra-key", "composition-wrong-geometry":
		if serveMalformedCompositionForTest(os.Args[len(os.Args)-1]) != nil {
			os.Exit(6)
		}
	default:
		os.Exit(5)
	}
	os.Exit(0)
}

func workerTestScript(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "worker")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+text+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func shellTestQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func workerTestHelper(t *testing.T, mode string) *pdfWorker {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path := workerTestScript(t, "exec "+shellTestQuote(binary)+" -test.run='^TestPDFWorkerChildHelper$' -- --hash-pdf-test "+shellTestQuote(mode))
	return &pdfWorker{path: path, slots: make(chan struct{}, 2)}
}

func TestPDFWorkerRealProtocolAndCredentialIsolation(t *testing.T) {
	raw := buildTestPDF(t, 3)
	t.Setenv("HASH_PRIVATE_SYNTHETIC_SECRET", "never-pass-to-parser")
	w := workerTestHelper(t, "protocol")
	result, err := w.clean(context.Background(), "template-pdf", "application/pdf", raw)
	if err != nil || len(result.Bytes) == 0 || result.Report.BytesBefore != int64(len(raw)) {
		t.Fatalf("clean: %v", err)
	}
	response, body, err := w.run(context.Background(), pdfWorkerRequest{Operation: "pages", Length: len(result.Bytes)}, result.Bytes)
	if err != nil || response.Pages != 3 || len(body) != 0 {
		t.Fatalf("count: pages=%d err=%v", response.Pages, err)
	}
	_, output, err := w.run(context.Background(), pdfWorkerRequest{Operation: "clean", Length: 7, Asset: "upload"}, []byte("invalid"))
	if err == nil || len(output) != 0 {
		t.Fatal("malformed PDF returned usable output")
	}
}

func TestPDFWorkerRejectsBrokenOutputAndExit(t *testing.T) {
	for _, mode := range []string{"broken", "short", "extra", "oversized-header", "exit", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			w := workerTestHelper(t, mode)
			_, body, err := w.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil)
			if !errors.Is(err, ErrPDFWorkerUnavailable) || len(body) != 0 || len(w.slots) != 0 {
				t.Fatalf("err=%v bytes=%d slots=%d", err, len(body), len(w.slots))
			}
		})
	}
}

func TestPDFWorkerCancellationReapsProcessAndReleasesCapacity(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	path := workerTestScript(t, "echo $$ > "+shellTestQuote(pidFile)+"\nexec /bin/sleep 60")
	w := &pdfWorker{path: path, slots: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, _, err := w.run(ctx, pdfWorkerRequest{Operation: "probe"}, nil); done <- err }()
	var encoded []byte
	deadline := time.Now().Add(3 * time.Second)
	for {
		encoded, _ = os.ReadFile(pidFile)
		if len(encoded) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	start := time.Now()
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) || len(w.slots) != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("cancellation not bounded: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("worker process was not reaped: %v", err)
	}
	w.path = workerTestHelper(t, "protocol").path
	if _, _, err := w.run(context.Background(), pdfWorkerRequest{Operation: "probe"}, nil); err != nil {
		t.Fatal("capacity not reusable", err)
	}
}

func TestPDFWorkerCapacityIsBoundedBeforeLaunching(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pids")
	w := &pdfWorker{path: workerTestScript(t, "echo $$ >> "+shellTestQuote(pidFile)+"\nexec /bin/sleep 60"), slots: make(chan struct{}, 2)}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { _, _, err := w.run(ctx, pdfWorkerRequest{Operation: "probe"}, nil); done <- err }()
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, _ := os.ReadFile(pidFile)
		if strings.Count(string(b), "\n") == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("workers did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, err := w.run(ctx, pdfWorkerRequest{Operation: "probe"}, nil); !errors.Is(err, ErrPDFWorkerCapacity) {
		t.Fatalf("third job admitted: %v", err)
	}
	cancel()
	for i := 0; i < 2; i++ {
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if len(w.slots) != 0 {
		t.Fatal("slots retained after cancellation")
	}
}

func TestPDFWorkerConfigurationFailsClosed(t *testing.T) {
	t.Cleanup(func() { ConfigurePDFWorker(context.Background(), "", "development") })
	if err := ConfigurePDFWorker(context.Background(), "relative", "production"); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal(err)
	}
	if _, err := PageCount(buildTestPDF(t, 1)); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("failed configuration fell back to in-process parser", err)
	}
	if err := CheckPDFWorker(context.Background()); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatal("health accepted failed configuration", err)
	}
	w := workerTestHelper(t, "protocol")
	if err := ConfigurePDFWorker(context.Background(), w.path, "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := PageCountWithContext(context.Background(), buildTestPDF(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := CheckPDFWorker(context.Background()); err != nil {
		t.Fatal("health rejected configured parser", err)
	}
	configured := activePDFWorker.Load()
	configured.slots <- struct{}{}
	configured.slots <- struct{}{}
	configured.readinessMu.Lock()
	configured.readinessUntil = time.Time{}
	configured.readinessMu.Unlock()
	if err := CheckPDFWorker(context.Background()); err != nil {
		t.Fatal("busy parser reported missing dependency", err)
	}
	<-configured.slots
	<-configured.slots
	if err := ConfigurePDFWorker(context.Background(), "", "development"); err != nil || activePDFWorker.Load() != nil {
		t.Fatal("development opt-out failed", err)
	}
}

func TestPDFWorkerReadinessCoalescesAndCachesWithoutCallerCancellation(t *testing.T) {
	t.Cleanup(func() { activePDFWorker.Store(nil) })
	countFile := filepath.Join(t.TempDir(), "probes")
	path := workerTestScript(t, "echo probe >> "+shellTestQuote(countFile)+"\n/bin/sleep 0.2\nprintf '%s\\n' '{\"protocol_version\":2,\"length\":0,\"pages\":1}'")
	w := &pdfWorker{path: path, slots: make(chan struct{}, 2)}
	activePDFWorker.Store(w)
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { first <- CheckPDFWorker(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if b, _ := os.ReadFile(countFile); len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("readiness probe did not start")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation was not respected: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := CheckPDFWorker(context.Background()); err != nil {
				t.Errorf("canceled caller poisoned shared readiness: %v", err)
			}
		}()
	}
	wg.Wait()
	for i := 0; i < 24; i++ {
		if err := CheckPDFWorker(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if b, _ := os.ReadFile(countFile); strings.Count(string(b), "probe") != 1 {
		t.Fatalf("health traffic launched multiple parser processes: %q", b)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	w.readinessMu.Lock()
	w.readinessUntil = time.Time{}
	w.readinessMu.Unlock()
	if err := CheckPDFWorker(context.Background()); !errors.Is(err, ErrPDFWorkerUnavailable) {
		t.Fatalf("expired cached readiness hid missing worker: %v", err)
	}
	w.readinessMu.Lock()
	until := w.readinessUntil
	w.readinessMu.Unlock()
	for i := 0; i < 24; i++ {
		if err := CheckPDFWorker(context.Background()); !errors.Is(err, ErrPDFWorkerUnavailable) {
			t.Fatalf("failure cache accepted missing worker: %v", err)
		}
	}
	w.readinessMu.Lock()
	defer w.readinessMu.Unlock()
	if w.readinessUntil != until || w.readinessDone != nil {
		t.Fatal("health traffic retried cached worker failure")
	}
}

func TestPDFWorkerProtocolInputIsBounded(t *testing.T) {
	for _, text := range []string{
		`{"protocol_version":2,"operation":"probe","length":1}` + "\nx",
		`{"protocol_version":2,"operation":"exec","length":0}` + "\n",
		`{"protocol_version":2,"operation":"clean","length":52428801}` + "\n",
		`{"protocol_version":2,"operation":"probe","length":0,"extra":true}` + "\n",
		`{"protocol_version":2,"operation":"clean","length":3}` + "\nabcd",
	} {
		var out bytes.Buffer
		if err := ServePDFWorker(strings.NewReader(text), &out); err == nil || out.Len() != 0 {
			t.Fatal("invalid request returned output")
		}
	}
	var out bytes.Buffer
	if err := ServePDFWorker(strings.NewReader("{\"protocol_version\":2,\"operation\":\"probe\",\"length\":0}\n"), &out); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&out)
	var response pdfWorkerResponse
	if err := decoder.Decode(&response); err != nil || response.Length != 0 {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(&out); err != nil {
		t.Fatal(err)
	}
}
