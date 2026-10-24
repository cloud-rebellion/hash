// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

func diagnosticFixture409(ctx context.Context) (*Lifecycle, *logShipper) {
	sh := &logShipper{ctx: ctx, ch: make(chan nativeLogLine, 2), service: "hash-worker", release: strings.Repeat("a", 40), environment: "test", key: "PRIVATE_INGEST_KEY_409", endpoint: "https://PRIVATE_ENDPOINT_409/logs"}
	l := &Lifecycle{ctx: ctx, shipper: sh, service: sh.service, diagnosticsEpoch: time.Date(2026, 10, 19, 12, 0, 0, 1, time.UTC), checkinURL: "https://PRIVATE_MONITOR_409/secret"}
	return l, sh
}

func TestDeliveryDiagnostics409FixedCountersPrivacyAndResetEpoch(t *testing.T) {
	l, sh := diagnosticFixture409(context.Background())
	sh.dropped.Store(math.MaxInt64)
	sh.failed.Store(2)
	sh.rejected.Store(3)
	l.checkinFailures.Store(math.MaxUint64)
	l.checkinResponses.Store(5)
	l.jobDropped.Store(6)
	l.jobRejected.Store(7)
	l.metricAcknowledged.Store(8)
	l.metricFailures.Store(9)
	l.emitDeliveryDiagnostics409()
	line := <-sh.ch
	if line.Body != "Hash telemetry delivery diagnostics" || line.Severity != "info" || len(line.Attributes) > logShipMaxAttrs {
		t.Fatal("fixed diagnostic envelope/bound changed")
	}
	var attrs map[string]any
	if err := json.Unmarshal(line.Attributes, &attrs); err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 17 || attrs["schema"] != "hash-delivery-diagnostics-v1" || attrs["counter_scope"] != "process_local" || attrs["counter_epoch"] != l.diagnosticsEpoch.Format(time.RFC3339Nano) || attrs["log_dropped"] != "9223372036854775807" || attrs["checkin_failures"] != "18446744073709551615" || attrs["checkin_responses"] != "5" || attrs["job_dropped"] != "6" || attrs["metric_acknowledged_batches"] != "8" || attrs["metric_failures"] != "9" || attrs["sdk_delivery_accounted"] != false || attrs["checkins_configured"] != true {
		t.Fatal("counter precision/reset/response-only semantics changed", attrs)
	}
	for _, key := range []string{"PRIVATE_INGEST_KEY_409", "PRIVATE_ENDPOINT_409", "PRIVATE_MONITOR_409", "https://"} {
		if strings.Contains(string(line.Attributes), key) {
			t.Fatal("private transport state exported")
		}
	}
	l.diagnosticsEpoch = l.diagnosticsEpoch.Add(time.Second)
	l.checkinResponses.Store(0)
	l.emitDeliveryDiagnostics409()
	second := <-sh.ch
	if string(second.Attributes) == string(line.Attributes) || !strings.Contains(string(second.Attributes), `"checkin_responses":"0"`) {
		t.Fatal("owner reset epoch/counters were hidden")
	}
}

func TestDeliveryDiagnostics409RateQueueCancelRecursionAndIdentityRefusals(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	l, sh := diagnosticFixture409(ctx)
	l.diagnosticsBusy.Store(true)
	l.emitDeliveryDiagnostics409()
	if len(sh.ch) != 0 {
		t.Fatal("reentrant snapshot enqueued")
	}
	l.diagnosticsBusy.Store(false)
	sh.windowStart, sh.windowCount = time.Now(), logShipMaxPerMin
	l.emitDeliveryDiagnostics409()
	if sh.dropped.Load() != 1 || len(sh.ch) != 0 {
		t.Fatal("diagnostic bypassed original rate bound")
	}
	sh.windowCount = 0
	sh.ch <- nativeLogLine{Body: "original1"}
	sh.ch <- nativeLogLine{Body: "original2"}
	l.emitDeliveryDiagnostics409()
	if sh.dropped.Load() != 2 || len(sh.ch) != 2 || (<-sh.ch).Body != "original1" || (<-sh.ch).Body != "original2" {
		t.Fatal("full diagnostic queue blocked/displaced original records")
	}
	sh.release = strings.Repeat("x", 1<<20)
	l.emitDeliveryDiagnostics409()
	if sh.rejected.Load() != 1 || len(sh.ch) != 0 {
		t.Fatal("oversized identity copied into diagnostic envelope")
	}
	cancel()
	l.emitDeliveryDiagnostics409()
	if sh.rejected.Load() != 1 || len(sh.ch) != 0 {
		t.Fatal("canceled owner emitted/re-entered projection")
	}
}

func TestDeliveryDiagnostics409ExistingReadyOwnerAndJoinedClose(t *testing.T) {
	t.Setenv("FLARE_DSN", "")
	t.Setenv("HASH_FLARE_MONITOR_PREFIX", "")
	t.Setenv("FLARE_HEARTBEAT", "off")
	budget, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	ready := make(chan struct{})
	var sh *logShipper
	owner := newLifecycleWithShipper(budget, ready, "hash-worker", nil, func(owned context.Context) *logShipper {
		_, sh = diagnosticFixture409(owned)
		sh.done = make(chan struct{})
		close(sh.done) // no fake log worker; only the original lifecycle owner runs
		return sh
	})
	select {
	case <-sh.ch:
		t.Fatal("snapshot preceded original ready signal")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	select {
	case line := <-sh.ch:
		if line.Body != "Hash telemetry delivery diagnostics" {
			t.Fatal("wrong ready-owner signal")
		}
	case <-budget.Done():
		t.Fatal("existing ready owner did not emit diagnostic snapshot")
	}
	if err := owner.Close(budget); err != nil {
		t.Fatal("existing owner failed joined close", err)
	}
	owner.emitDeliveryDiagnostics409()
	if len(sh.ch) != 0 {
		t.Fatal("post-close diagnostic producer survived")
	}
}
