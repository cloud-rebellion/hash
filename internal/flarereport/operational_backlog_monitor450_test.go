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

// The existing receiver/client fixture keeps the real native HTTP checkin
// implementation, ready owner, queue16, response handling and joined Close.
func backlogReceiver450(t *testing.T, handler func(http.ResponseWriter, *http.Request)) (*Lifecycle, *logShipper, chan struct{}, string, context.Context) {
	t.Helper()
	_, client, slug := jobReceiver370(t, handler)
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	ready := make(chan struct{})
	owner := newLifecycle(budget, ready, "hash-worker", client)
	endpoint, key, ok := parseDSNForLogs(client.Options().Dsn)
	if !ok {
		t.Fatal("native fixture DSN refused")
	}
	logctx, cancel := context.WithCancel(owner.ctx)
	sh := &logShipper{ctx: logctx, cancel: cancel, done: make(chan struct{}), endpoint: endpoint, key: key, service: "hash-worker", release: strings.Repeat("a", 40), environment: "development", ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Timeout: time.Second}}
	owner.shipper = sh
	go sh.run()
	t.Cleanup(func() {
		cleanup, cancelCleanup := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancelCleanup()
		if err := owner.Close(cleanup); err != nil {
			t.Error("native sampler sender cleanup did not join", err)
		}
		stop()
		client.Close()
	})
	return owner, sh, ready, slug, budget
}

func TestBacklogMonitor450ActualReadySenderFailureAndFreshRemediationPrivacy(t *testing.T) {
	arrived := make(chan jobWire370, 32)
	checkinArrived := make(chan struct{}, 1)
	var mu sync.Mutex
	var wires []jobWire370
	owner, sh, ready, slug, budget := backlogReceiver450(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
			return
		}
		wire := jobWire370{path: r.URL.RequestURI(), body: append([]byte(nil), raw...)}
		if strings.Contains(r.URL.Path, "/checkins/") && (r.Method != http.MethodPost || len(raw) != 0) {
			t.Error("checkin gained a method/body payload")
		}
		if strings.Contains(r.URL.Path, "/checkins/") {
			select {
			case checkinArrived <- struct{}{}:
			default:
			}
		}
		if !strings.Contains(r.URL.Path, "/checkins/") && !strings.HasSuffix(r.URL.Path, "/logs") && r.URL.Path != "/prefix/api/1/metrics" {
			t.Error("sampler unexpectedly emitted an SDK exception/event")
		}
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
		} else if r.URL.Path == "/prefix/api/1/metrics" {
			var points []nativeOperationalMetricV1
			if err := json.Unmarshal(raw, &points); err != nil || len(points) != 23 {
				t.Error("invalid fixed operational metric projection", err)
			}
			json.NewEncoder(w).Encode(map[string]any{"accepted": len(points), "rejected": 0, "dropped": 0, "receipt_id": "fixture-metrics450"})
		} else {
			io.WriteString(w, `{}`)
		}
	})
	type privateKey450 struct{}
	caller := context.WithValue(budget, privateKey450{}, "PRIVATE_BACKLOG450_CONTRACT_TOKEN")
	owner.RecordOperationalBacklogV1(caller, OperationalBacklogSnapshotV1{ReadUnavailable: true})
	select {
	case <-checkinArrived:
		t.Fatal("not-ready lifecycle emitted sampler or process status")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	prefix := "/prefix/api/1/checkins/" + slug + "-backlog?status="
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == prefix+"error" })
	// Saturating the existing native-log admission must not suppress the
	// separate failed/remediation checkins through the actual ready sender.
	sh.mu.Lock()
	sh.windowStart, sh.windowCount = time.Now(), logShipMaxPerMin
	sh.mu.Unlock()
	for _, snapshot := range []OperationalBacklogSnapshotV1{
		// A same-second failed cached read may retain age0 and zero failed mail.
		// ReadUnavailable alone must still force the actual ERROR checkin.
		{HasSample: true, ReadUnavailable: true},
		{HasSample: true, Data: OperationalBacklogDataV1{MailFailedCount: 2}},
		{HasSample: true, ReadUnavailable: true, SampleAgeSeconds: 360, Stale: true, Data: OperationalBacklogDataV1{MailFailedCount: 2}},
		{HasSample: true, SampleAgeSeconds: 1, Data: OperationalBacklogDataV1{MailCount: 2}},
	} {
		owner.RecordOperationalBacklogV1(caller, snapshot)
		waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == prefix+"error" })
	}
	// This is the successful durable-read shape, not an invocation or process
	// heartbeat. The real worker cache tests separately bind its provenance.
	owner.RecordOperationalBacklogV1(caller, OperationalBacklogSnapshotV1{HasSample: true, Data: OperationalBacklogDataV1{MailCount: 2}})
	waitJobWire370(t, budget, arrived, func(w jobWire370) bool { return w.path == prefix+"ok" })
	waitCheckinResponses376(t, budget, owner, 7) // one process-ready + six sampler observations
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := owner.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("ready sender not physically joined")
	}
	select {
	case <-sh.done:
	default:
		t.Fatal("native log sender not physically joined")
	}
	if sh.failed.Load() != 0 || sh.rejected.Load() != 0 || sh.dropped.Load() != 5 {
		t.Fatal("native-log admission/response accounting or independent checkins changed", sh.dropped.Load())
	}
	if owner.Diagnostics().MetricAcknowledgedBatches != 1 || owner.Diagnostics().MetricFailures != 0 {
		t.Fatal("initial fixed metrics were not independently acknowledged")
	}
	mu.Lock()
	defer mu.Unlock()
	var statuses []string
	for _, wire := range wires {
		if strings.HasPrefix(wire.path, prefix) {
			statuses = append(statuses, strings.TrimPrefix(wire.path, prefix))
		}
		for _, marker := range []string{"PRIVATE_BACKLOG450", "fixture-public", "document_id", "org_id", "recipient_id"} {
			if strings.Contains(string(wire.body), marker) {
				t.Fatal("private marker crossed sampler wire", marker)
			}
		}
	}
	if strings.Join(statuses, ",") != "error,error,error,error,error,ok" {
		t.Fatal("durable failure/recovery order or separate fixed monitor lost", statuses)
	}
}

func TestBacklogMonitor450OffRoleCancelValidationAndOriginalQueueBound(t *testing.T) {
	ctx := context.Background()
	owner, sh := diagnosticFixture409(ctx)
	owner.jobQueue = make(chan jobReport, 16)
	good := OperationalBacklogSnapshotV1{ReadUnavailable: true}
	var nilOwner *Lifecycle
	nilOwner.RecordOperationalBacklogV1(ctx, good)
	owner.shipper = nil
	owner.RecordOperationalBacklogV1(ctx, good)
	owner.shipper = sh
	owner.service = "hash"
	owner.RecordOperationalBacklogV1(ctx, good)
	owner.service = "hash-worker"
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	owner.RecordOperationalBacklogV1(canceled, good)
	owner.RecordOperationalBacklogV1(ctx, OperationalBacklogSnapshotV1{})
	url := owner.checkinURL
	owner.checkinURL = ""
	owner.RecordOperationalBacklogV1(ctx, good)
	owner.checkinURL = url
	if len(owner.jobQueue) != 0 || sh.rejected.Load() != 1 {
		t.Fatal("refused/unconfigured snapshot became healthy or queued", len(owner.jobQueue))
	}
	for i := 0; i < 16; i++ {
		owner.jobQueue <- jobReport{ticks: int64(i + 1)}
	}
	owner.RecordOperationalBacklogV1(ctx, good)
	if cap(owner.jobQueue) != 16 || len(owner.jobQueue) != 16 || owner.jobDropped.Load() != 1 {
		t.Fatal("sampler widened/blocked/displaced the original queue16")
	}
	for i := 0; i < 16; i++ {
		report := <-owner.jobQueue
		if report.ticks != int64(i+1) || report.backlogHealth {
			t.Fatal("sampler displaced an existing job report")
		}
	}
	lifecycleContext, stopLifecycle := context.WithCancel(context.Background())
	owner.ctx = lifecycleContext
	stopLifecycle()
	owner.RecordOperationalBacklogV1(ctx, good)
	if len(owner.jobQueue) != 0 {
		t.Fatal("canceled lifecycle queued a sampler status")
	}
}

func TestBacklogMonitor450OldHealthySuppressedButUnhealthyStillPosted(t *testing.T) {
	arrived := make(chan jobWire370, 4)
	peer, client, slug := jobReceiver370(t, func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, io.LimitReader(r.Body, 4096))
		r.Body.Close()
		arrived <- jobWire370{path: r.URL.RequestURI()}
		io.WriteString(w, `{}`)
	})
	defer client.Close()
	ctx, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	owner := &Lifecycle{ctx: ctx, checkinURL: peer.URL + "/prefix/api/1/checkins/" + slug, checkinKey: "fixture-public", checkinProgress: make(chan struct{}, 1)}
	old := jobReport{backlogHealth: true, completedAt: time.Now().Add(-jobReportInterval - time.Second)}
	owner.sendOperationalBacklogHealthV1(old)
	select {
	case <-arrived:
		t.Fatal("old healthy queue item revived sampler")
	default:
	}
	old.backlogUnhealthy = true
	owner.sendOperationalBacklogHealthV1(old)
	waitJobWire370(t, ctx, arrived, func(w jobWire370) bool { return w.path == "/prefix/api/1/checkins/"+slug+"-backlog?status=error" })
	if owner.jobDropped.Load() != 1 || owner.checkinResponses.Load() != 1 || owner.checkinFailures.Load() != 0 {
		t.Fatal("old unhealthy report was dropped as healthy or response not completed")
	}
}

func TestBacklogMonitor450BlockedHTTPIsCanceledAndExistingOwnersJoin(t *testing.T) {
	started, retired := make(chan struct{}), make(chan struct{})
	var once sync.Once
	handlerBudget, stopHandler := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopHandler()
	owner, sh, ready, _, budget := backlogReceiver450(t, func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
			return
		}
		if strings.HasSuffix(r.URL.Path, "-backlog") {
			once.Do(func() { close(started) })
			select {
			case <-r.Context().Done():
				close(retired)
			case <-handlerBudget.Done():
				// Finite failed-test cleanup is not a retirement witness.
			}
			return
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
	close(ready)
	owner.RecordOperationalBacklogV1(budget, OperationalBacklogSnapshotV1{ReadUnavailable: true})
	select {
	case <-started:
	case <-budget.Done():
		t.Fatal("actual sampler HTTP phase did not start")
	}
	cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := owner.Close(cleanup); err != nil {
		t.Fatal("blocked native checkin did not cancel and join", err)
	}
	select {
	case <-retired:
	case <-cleanup.Done():
		t.Fatal("actual receiver request context did not retire")
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("ready sender remains active")
	}
	select {
	case <-sh.done:
	default:
		t.Fatal("native log sender remains active")
	}
}
