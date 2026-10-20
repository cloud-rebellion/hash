// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func Test385CompleteClosedJobInventoryHasUniqueBoundedStableSlugs(t *testing.T) {
	expected := []CriticalJob{JobEmailDispatch, JobFinalizeRetry, JobReminders, JobExpirations, JobWebhookRedrive, JobTelemetryRollup, JobQuotaWarnings, JobSoftDeletePurge, JobCollabArchivePurge, JobSendSealing, JobPackageSendRecovery, JobComplianceRollup}
	if len(expected) != criticalJobCount {
		t.Fatal("inventory omitted an enabled loop or package phase")
	}
	names := map[CriticalJob]bool{}
	suffixes := map[string]bool{}
	for _, job := range expected {
		suffix := jobSuffix(job)
		slug := strings.Repeat("p", 40) + "-hash-worker-" + suffix
		if jobIndex(job) < 0 || names[job] || suffix == "" || suffixes[suffix] || len(slug) > 64 {
			t.Fatal("invalid,duplicate,or oversized monitor identity", job, suffix, len(slug))
		}
		names[job] = true
		suffixes[suffix] = true
	}
	if jobSuffix(JobEmailDispatch) != "mail" || jobSuffix(JobFinalizeRetry) != "finalize" {
		t.Fatal("existing monitor identities changed")
	}
	if jobIndex(CriticalJob("PRIVATE_UNKNOWN")) >= 0 || jobSuffix(CriticalJob("PRIVATE_UNKNOWN")) != "" {
		t.Fatal("arbitrary job name admitted")
	}
}

func Test385InvocationStatesAreSeparateFromOriginalSelectionContract(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner := &Lifecycle{ctx: ctx, service: "hash-worker", jobQueue: make(chan jobReport, 16)}
	owner.RecordJobInvocation(ctx, JobInvocation{Job: JobReminders, State: InvocationPartial})
	owner.RecordJobInvocation(ctx, JobInvocation{Job: JobExpirations, State: InvocationReturned})
	first, second := <-owner.jobQueue, <-owner.jobQueue
	if first.tick.InvocationState != InvocationPartial || second.tick.InvocationState != InvocationReturned || first.tick.Selected != 0 || second.tick.Attempted != 0 {
		t.Fatal("independent invocation states or zero-selection boundary changed")
	}
	for _, tick := range []JobTick{
		{Job: JobEmailDispatch, Selected: 51}, {Job: JobFinalizeRetry, InvocationState: InvocationReturned},
		{Job: JobReminders, InvocationState: InvocationReturned, Selected: 100},
		{Job: JobReminders, InvocationState: "PRIVATE_STATUS"},
	} {
		owner.RecordJobTick(ctx, tick)
	}
	owner.RecordJobInvocation(ctx, JobInvocation{Job: JobEmailDispatch, State: InvocationReturned})
	if owner.Diagnostics().JobRejected != 5 || len(owner.jobQueue) != 0 {
		t.Fatal("old50 cap weakened or new invocation invented selection", owner.Diagnostics())
	}
	stopped, stop := context.WithCancel(ctx)
	stop()
	owner.RecordJobInvocation(stopped, JobInvocation{Job: JobComplianceRollup, State: InvocationReturned})
	if len(owner.jobQueue) != 0 {
		t.Fatal("canceled job fabricated a completed tick")
	}
	// Same-job partial→partial→returned must retain the pending historical error,
	// then the fresh completion, just as original370b's selection windows do.
	owner.RecordJobInvocation(ctx, JobInvocation{Job: JobReminders, State: InvocationPartial})
	owner.RecordJobInvocation(ctx, JobInvocation{Job: JobReminders, State: InvocationReturned})
	if len(owner.jobQueue) != 2 {
		t.Fatal("new state recovery was hidden in error coalescing")
	}
	old, current := <-owner.jobQueue, <-owner.jobQueue
	if old.tick.InvocationState != InvocationPartial || current.tick.InvocationState != InvocationReturned {
		t.Fatal("historical error contaminated invocation recovery")
	}
}

func Test385AllAdditionalJobStatesReachActualBoundedCollectorWithSafeMetadata(t *testing.T) {
	var mu sync.Mutex
	var wires []jobWire370
	_, client, slug := jobReceiver370(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
			return
		}
		mu.Lock()
		wires = append(wires, jobWire370{path: r.URL.RequestURI(), body: append([]byte(nil), raw...)})
		mu.Unlock()
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
	type privateKey struct{}
	caller := context.WithValue(budget, privateKey{}, "PRIVATE_385_CONTRACT_TOKEN_ERROR")
	states := []JobInvocationState{InvocationReturned, InvocationPending, InvocationPartial, InvocationUnavailable, InvocationUnobservable}
	expected := map[string]string{}
	for i, job := range criticalJobNames[2:] {
		state := states[i%len(states)]
		status := "ok"
		if invocationStateError(state) {
			status = "error"
		}
		expected["/prefix/api/1/checkins/"+slug+"-"+jobSuffix(job)+"?status="+status] = string(state)
		owner.RecordJobInvocation(caller, JobInvocation{Job: job, State: state, Duration: time.Second})
	}
	mu.Lock()
	before := len(wires)
	mu.Unlock()
	if before != 0 {
		t.Fatal("not-ready lifecycle emitted job health")
	}
	close(ready)
	// Role plus ten additional job responses, after actual bounded client handling.
	waitCheckinResponses376(t, budget, owner, 11)
	if err := owner.Close(budget); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	snapshot := append([]jobWire370(nil), wires...)
	mu.Unlock()
	seen := map[string]bool{}
	native := 0
	for _, wire := range snapshot {
		if _, ok := expected[wire.path]; ok {
			seen[wire.path] = true
		}
		if strings.Contains(string(wire.body), "PRIVATE_385") {
			t.Fatal("private caller context entered collector wire")
		}
		if !strings.HasSuffix(wire.path, "/logs") {
			continue
		}
		var lines []nativeLogLine
		if err := json.Unmarshal(wire.body, &lines); err != nil {
			t.Fatal(err)
		}
		for _, line := range lines {
			native++
			var attrs map[string]any
			if err := json.Unmarshal(line.Attributes, &attrs); err != nil {
				t.Fatal(err)
			}
			if attrs["observation_kind"] != "invocation" || attrs["selected_observations"] != float64(0) || attrs["attempted"] != float64(0) || attrs["service"] != "hash-worker" || attrs["release"] != strings.Repeat("a", 40) || attrs["environment"] != "development" {
				t.Fatal("false throughput or missing safe identity", attrs)
			}
			if !validInvocationState(JobInvocationState(attrs["invocation_state"].(string))) {
				t.Fatal("unknown state escaped fixed schema")
			}
		}
	}
	if len(seen) != 10 || native != 10 || owner.Diagnostics().CheckinFailures != 0 {
		t.Fatal("actual additional job receipts incomplete", len(seen), native, owner.Diagnostics())
	}
}
