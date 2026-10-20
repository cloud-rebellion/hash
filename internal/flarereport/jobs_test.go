// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

type jobWire370 struct {
	path string
	body []byte
}

func jobReceiver370(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*httptest.Server, *sentry.Client, string) {
	t.Helper()
	peer := httptest.NewServer(http.HandlerFunc(handler))
	t.Cleanup(peer.Close)
	dsn := strings.Replace(peer.URL, "://", "://fixture-public@", 1) + "/prefix/1"
	t.Setenv("FLARE_DSN", dsn)
	t.Setenv("HASH_FLARE_MONITOR_PREFIX", strings.Repeat("x", 40))
	t.Setenv("FLARE_HEARTBEAT", "off")
	t.Setenv("HASH_FLARE_EMAIL_SAMPLE_MAX_AGE_SECONDS", "")
	t.Setenv("HASH_FLARE_FINALIZE_SAMPLE_MAX_AGE_SECONDS", "")
	options := sdkClientOptions(dsn, "hash-worker", strings.Repeat("a", 40), "development")
	options.TracesSampleRate = 0
	client, err := sentry.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	return peer, client, strings.Repeat("x", 40) + "-hash-worker"
}
func waitJobWire370(t *testing.T, ctx context.Context, ch <-chan jobWire370, match func(jobWire370) bool) jobWire370 {
	t.Helper()
	for {
		select {
		case got := <-ch:
			if match(got) {
				return got
			}
		case <-ctx.Done():
			t.Fatal("actual collector receipt not observed before owner deadline")
			return jobWire370{}
		}
	}
}

func Test370CompletedJobUsesActualJoinedSenderAndPrivateFreeNativeWire(t *testing.T) {
	var mu sync.Mutex
	var wires []jobWire370
	arrived := make(chan jobWire370, 32)
	_, client, slug := jobReceiver370(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
			return
		}
		wire := jobWire370{r.URL.RequestURI(), append([]byte(nil), raw...)}
		mu.Lock()
		wires = append(wires, wire)
		mu.Unlock()
		select {
		case arrived <- wire:
		default:
			t.Error("test receiver observation queue overflow")
		}
		if strings.HasSuffix(r.URL.Path, "/logs") {
			var lines []nativeLogLine
			if err := json.Unmarshal(raw, &lines); err != nil {
				t.Error(err)
			}
			json.NewEncoder(w).Encode(map[string]int{"accepted": len(lines)})
		} else {
			io.WriteString(w, `{}`)
		}
	})
	defer client.Close()
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	ready := make(chan struct{})
	owner := newLifecycle(budget, ready, "hash-worker", client)
	endpoint, key, _ := parseDSNForLogs(client.Options().Dsn)
	logctx, cancel := context.WithCancel(owner.ctx)
	sh := &logShipper{ctx: logctx, cancel: cancel, done: make(chan struct{}), endpoint: endpoint, key: key, service: "hash-worker", release: strings.Repeat("a", 40), environment: "development", ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Timeout: time.Second}}
	owner.shipper = sh
	go sh.run()
	defer owner.Close(budget)
	// No private data is representable in the report; the original caller's
	// context may still contain it and must not be retained/projected.
	type privateKey struct{}
	caller := context.WithValue(budget, privateKey{}, "PRIVATE_370_CONTRACT_AND_TOKEN")
	owner.RecordJobTick(caller, JobTick{Job: JobEmailDispatch, Selected: 1, Attempted: 1, Returned: 1, RetryScheduled: 1, OldestSelectedAgeSeconds: 60, Duration: time.Second})
	select {
	case <-arrived:
		t.Fatal("not-ready lifecycle emitted a job checkin")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == "/prefix/api/1/checkins/"+slug+"-mail?status=ok" })
	// A nil finalizer return is represented as returned, never finalized.
	owner.RecordJobTick(caller, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1, Duration: time.Second})
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == "/prefix/api/1/checkins/"+slug+"-finalize?status=ok" })
	waitCheckinResponses376(t, budget, owner, 3)
	if err := owner.Close(budget); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("lifecycle sender not joined")
	}
	select {
	case <-sh.done:
	default:
		t.Fatal("native log sender not joined")
	}
	mu.Lock()
	snapshot := append([]jobWire370(nil), wires...)
	mu.Unlock()
	var logs []nativeLogLine
	var encoded strings.Builder
	var smtpIssue bool
	for _, wire := range snapshot {
		encoded.Write(wire.body)
		if strings.HasSuffix(wire.path, "/logs") {
			var batch []nativeLogLine
			if err := json.Unmarshal(wire.body, &batch); err != nil {
				t.Fatal(err)
			}
			logs = append(logs, batch...)
		}
		if strings.Contains(string(wire.body), `"operation":"smtp"`) && strings.Contains(string(wire.body), `"failure_category":"dependency"`) {
			smtpIssue = true
		}
	}
	if len(logs) != 2 || !smtpIssue {
		t.Fatal("missing real typed summary or separate SMTP failure issue", len(logs), smtpIssue)
	}
	if strings.Contains(encoded.String(), "PRIVATE_370") || strings.Contains(encoded.String(), "finalized") {
		t.Fatal("private content or false finalized claim in actual wire", encoded.String())
	}
	for _, line := range logs {
		var attrs map[string]any
		if err := json.Unmarshal(line.Attributes, &attrs); err != nil {
			t.Fatal(err)
		}
		if attrs["service"] != "hash-worker" || attrs["release"] != strings.Repeat("a", 40) || attrs["environment"] != "development" || attrs["max_selected_sample"] != float64(1) || attrs["returned"] != float64(1) {
			t.Fatal("fixed identity/sample lost", attrs)
		}
	}
	if len(slug+"-finalize") > 64 || owner.Diagnostics().CheckinFailures != 0 {
		t.Fatal("checkin contract or delivery differs")
	}
}

func Test370JobReportNonblockingWhileActualCheckinIsHeldAndCloseJoins(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	retired := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	_, client, _ := jobReceiver370(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "-mail") {
			close(entered)
			defer close(retired)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		io.WriteString(w, `{}`)
	})
	defer client.Close()
	defer unblock()
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	ready := make(chan struct{})
	close(ready)
	owner := newLifecycle(budget, ready, "hash-worker", client)
	defer owner.Close(budget)
	owner.RecordJobTick(budget, JobTick{Job: JobEmailDispatch})
	select {
	case <-entered:
	case <-budget.Done():
		t.Fatal("actual job checkin did not enter")
	}
	returned := make(chan struct{})
	go func() {
		owner.RecordJobTick(budget, JobTick{Job: JobEmailDispatch, Unavailable: true})
		close(returned)
	}()
	select {
	case <-returned:
	case <-budget.Done():
		t.Fatal("job enqueue waited on collector HTTP")
	}
	if err := owner.Close(budget); err != nil {
		t.Fatal(err)
	}
	select {
	case <-retired:
	case <-budget.Done():
		t.Fatal("actual HTTP request did not cancel/join receiver")
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("job sender still owned after close")
	}
}

func Test370JobWindowsBoundQueueAndRefuseForeignCanceledOrInvalidTicks(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &Lifecycle{ctx: ctx, service: "hash-worker", jobQueue: make(chan jobReport, 16)}
	for i := 0; i < 18; i++ {
		owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch, Unavailable: i%2 == 0})
	}
	if len(owner.jobQueue) != 16 || owner.Diagnostics().JobDropped != 2 {
		t.Fatal("fixed queue/drop accounting changed", len(owner.jobQueue), owner.Diagnostics())
	}
	bad := []JobTick{{Job: "PRIVATE_NAME"}, {Job: JobEmailDispatch, Selected: 51}, {Job: JobEmailDispatch, Selected: 1, Attempted: 1, Returned: 1}, {Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1, SentAcknowledged: 1}}
	for _, tick := range bad {
		owner.RecordJobTick(ctx, tick)
	}
	if owner.Diagnostics().JobRejected != uint64(len(bad)) {
		t.Fatal("invalid scalar reports accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	owner.RecordJobTick(canceled, JobTick{Job: JobFinalizeRetry})
	if len(owner.jobQueue) != 16 {
		t.Fatal("canceled tick entered queue")
	}
	other := &Lifecycle{ctx: ctx, service: "hash", jobQueue: make(chan jobReport, 16)}
	other.RecordJobTick(ctx, JobTick{Job: JobFinalizeRetry})
	if other.Diagnostics().JobRejected != 1 || len(other.jobQueue) != 0 {
		t.Fatal("server role impersonated worker tick")
	}
}

func Test370SamplingRetainsFailuresAndExplicitStaleSamplePolicy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &Lifecycle{ctx: ctx, service: "hash-worker", jobQueue: make(chan jobReport, 16)}
	owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch})
	<-owner.jobQueue
	// A real retry is urgent and cannot disappear inside an info-only window.
	owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch, Selected: 1, Attempted: 1, Returned: 1, RetryScheduled: 1})
	if len(owner.jobQueue) != 1 {
		t.Fatal("actual SMTP failure was hidden by sampling")
	}
	report := <-owner.jobQueue
	if report.tick.RetryScheduled != 1 || report.ticks != 1 {
		t.Fatal("retry attribution changed", report)
	}
	owner.jobMaxAge[1] = 60
	owner.RecordJobTick(ctx, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1, OldestSelectedAgeSeconds: 61})
	if report := <-owner.jobQueue; !report.stale {
		t.Fatal("explicit sample-age threshold was ignored")
	}
	owner.jobWindows[1] = jobWindow{}
	owner.RecordJobTick(ctx, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1, UnknownAges: 1})
	if report := <-owner.jobQueue; !report.policyUnobservable {
		t.Fatal("configured age policy falsely treated unknown timestamps as young")
	}
	owner.jobMaxAge[1] = 0
	owner.jobWindows[1] = jobWindow{}
	owner.RecordJobTick(ctx, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1, OldestSelectedAgeSeconds: 999})
	if report := <-owner.jobQueue; report.stale {
		t.Fatal("invented a default business SLA")
	}
}

func Test370ActualErrorCheckinAndLaterReturnedInvocationRecovery(t *testing.T) {
	arrived := make(chan jobWire370, 16)
	_, client, slug := jobReceiver370(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/checkins/") && r.Header.Get("X-Flare-Key") != "fixture-public" {
			t.Error("configured fixed ingest key missing")
		}
		select {
		case arrived <- jobWire370{path: r.URL.RequestURI()}:
		default:
			t.Error("test receipt overflow")
		}
		io.Copy(io.Discard, io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		io.WriteString(w, `{}`)
	})
	defer client.Close()
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	ready := make(chan struct{})
	close(ready)
	owner := newLifecycle(budget, ready, "hash-worker", client)
	defer owner.Close(budget)
	owner.RecordJobTick(budget, JobTick{Job: JobFinalizeRetry, Unavailable: true})
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == "/prefix/api/1/checkins/"+slug+"-finalize?status=error" })
	owner.RecordJobTick(budget, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1})
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == "/prefix/api/1/checkins/"+slug+"-finalize?status=ok" })
	waitCheckinResponses376(t, budget, owner, 3)
	if err := owner.Close(budget); err != nil {
		t.Fatal(err)
	}
	if owner.Diagnostics().CheckinFailures != 0 {
		t.Fatal("checkin local response handling failed", owner.Diagnostics())
	}
}

func Test370bFailureWindowCannotContaminateRealNextTickRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &Lifecycle{ctx: ctx, service: "hash-worker", jobQueue: make(chan jobReport, 16)}
	fail := JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Failed: 1}
	owner.RecordJobTick(ctx, fail)
	first := <-owner.jobQueue
	if first.tick.Failed != 1 {
		t.Fatal("first actual invocation failure missing")
	}
	owner.RecordJobTick(ctx, fail)
	if len(owner.jobQueue) != 0 {
		t.Fatal("same problem did not coalesce within30s")
	}
	// Preserve one pending failed attempt, then fresh success, in that order.
	owner.RecordJobTick(ctx, JobTick{Job: JobFinalizeRetry, Selected: 1, Attempted: 1, Returned: 1})
	if len(owner.jobQueue) != 2 {
		t.Fatal("old error and real recovery were not both queued")
	}
	old, recovery := <-owner.jobQueue, <-owner.jobQueue
	if old.tick.Failed != 1 || old.tick.Returned != 0 || recovery.tick.Failed != 0 || recovery.tick.Returned != 1 || old.ticks != 1 || recovery.ticks != 1 || old.completedAt.After(recovery.completedAt) {
		t.Fatal("historical failure contaminated fresh actual recovery", old, recovery)
	}
}

func Test370bRecoveredPersistenceIsNotHeldByDifferentSMTPProblem(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &Lifecycle{ctx: ctx, service: "hash-worker", jobQueue: make(chan jobReport, 16)}
	owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch, Unavailable: true})
	<-owner.jobQueue
	owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch, Unavailable: true})
	owner.RecordJobTick(ctx, JobTick{Job: JobEmailDispatch, Selected: 1, Attempted: 1, Returned: 1, RetryScheduled: 1})
	if len(owner.jobQueue) != 2 {
		t.Fatal("distinct persistence recovery/SMTP failure transition was hidden")
	}
	old, current := <-owner.jobQueue, <-owner.jobQueue
	if !old.tick.Unavailable || current.tick.Unavailable || current.tick.RetryScheduled != 1 || current.tick.Returned != 1 {
		t.Fatal("old persistence error contaminated current durable SMTP retry", old, current)
	}
}
