// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package flarereport

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const fullMetricAck498 = `{"accepted":23,"rejected":0,"dropped":0,"receipt_id":"receipt498"}`

type metricTransport498 func(*http.Request) (*http.Response, error)

func (f metricTransport498) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type metricBody498 struct {
	io.Reader
	closeErr error
	closed   atomic.Int32
}

func (b *metricBody498) Close() error { b.closed.Add(1); return b.closeErr }

type metricReadError498 struct{}

func (metricReadError498) Read([]byte) (int, error) { return 0, errors.New("synthetic read failure") }

func directMetricLifecycle498(ctx context.Context, transport http.RoundTripper) (*Lifecycle, *logShipper) {
	sh := &logShipper{ctx: ctx, service: "hash-worker", release: "release498", environment: "test", endpoint: "https://collector.invalid/prefix/api/1/logs", key: "PRIVATE_METRIC_KEY498", ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Transport: transport}}
	return &Lifecycle{ctx: ctx, service: "hash-worker", shipper: sh}, sh
}

func readyMetricLifecycle498(t *testing.T, endpoint string, transport http.RoundTripper) (*Lifecycle, *logShipper, chan struct{}, context.Context) {
	t.Helper()
	t.Setenv("FLARE_LOG_LEVEL", "info")
	t.Setenv("FLARE_HEARTBEAT", "off")
	t.Setenv("HASH_FLARE_MONITOR_PREFIX", "")
	t.Setenv("FLARE_DSN", "")
	budget, stop := context.WithTimeout(context.Background(), 3*time.Second)
	ready := make(chan struct{})
	var sh *logShipper
	l := newLifecycleWithShipper(budget, ready, "hash-worker", nil, func(owned context.Context) *logShipper {
		_, sh = directMetricLifecycle498(owned, transport)
		sh.endpoint = endpoint
		sh.done = make(chan struct{})
		close(sh.done) // no additional test log worker; the actual ready owner runs
		return sh
	})
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := l.Close(cleanup); err != nil {
			t.Error("metrics owner cleanup failed", err)
		}
		stop()
	})
	return l, sh, ready, budget
}

func waitMetricAck498(t *testing.T, budget context.Context, l *Lifecycle) {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if l.Diagnostics().MetricAcknowledgedBatches == 1 {
			return
		}
		select {
		case <-tick.C:
		case <-budget.Done():
			t.Fatal("native metric acknowledgement did not finish", l.Diagnostics())
		}
	}
}

func TestOperationalMetrics498ActualReadyWirePrivacyAndLogAdmissionIndependence(t *testing.T) {
	type observed struct {
		path, method, key, contentType, cookie string
		body                                   []byte
	}
	wire := make(chan observed, 2)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<10+1))
		r.Body.Close()
		if err != nil {
			t.Error(err)
		}
		wire <- observed{r.URL.RequestURI(), r.Method, r.Header.Get("X-Flare-Key"), r.Header.Get("Content-Type"), r.Header.Get("Cookie"), raw}
		io.WriteString(w, fullMetricAck498)
	}))
	defer peer.Close()
	l, sh, ready, budget := readyMetricLifecycle498(t, peer.URL+"/prefix/api/1/logs", peer.Client().Transport)
	sh.mu.Lock()
	sh.windowStart, sh.windowCount = time.Now(), logShipMaxPerMin
	sh.mu.Unlock()
	sh.ch = make(chan nativeLogLine, 1)
	sh.ch <- nativeLogLine{Body: "PRIVATE_ORIGINAL_LOG498"}
	type privateContext498 struct{}
	caller := context.WithValue(budget, privateContext498{}, "PRIVATE_CONTRACT498")
	l.RecordOperationalBacklogV1(caller, OperationalBacklogSnapshotV1{HasSample: true, SampleAgeSeconds: 299, ReadDurationMilliseconds: 12, Data: OperationalBacklogDataV1{MailCount: 3, MailDueCount: 2, MailFailedCount: 1, MailFailedOldestObservedCreationAgeSeconds: 9, FinalizingRootCount: 2, FinalizingIntentCount: 1, FinalizingMissingIntentCount: 1}})
	stored := l.operationalMetrics.Load()
	if stored == nil {
		t.Fatal("valid observation lost behind full native log admission")
	}
	aged := *stored
	aged.recordedAt = time.Now().Add(-2 * time.Second)
	l.operationalMetrics.Store(&aged)
	select {
	case <-wire:
		t.Fatal("metrics escaped before readiness")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	var got observed
	select {
	case got = <-wire:
	case <-budget.Done():
		t.Fatal("actual ready sender did not reach native metrics receiver")
	}
	waitMetricAck498(t, budget, l)
	if got.path != "/prefix/api/1/metrics" || got.method != http.MethodPost || got.key != "PRIVATE_METRIC_KEY498" || got.contentType != "application/json" || got.cookie != "" {
		t.Fatal("native endpoint/authentication or cookie boundary changed")
	}
	for _, private := range []string{"PRIVATE_", peer.URL, "document_id", "org_id", "recipient", "mail_body", "last_error", "https://"} {
		if strings.Contains(string(got.body), private) {
			t.Fatal("private material crossed metric wire", private)
		}
	}
	var rows []map[string]json.RawMessage
	if err := json.Unmarshal(got.body, &rows); err != nil || len(rows) != 23 {
		t.Fatal("fixed wire size/shape changed", err)
	}
	wantSuffixes := strings.Fields("has_sample read_unavailable sample_age_seconds stale read_duration_ms observed_row_limit mail_count mail_due_count mail_unknown_created_count mail_unknown_due_count mail_oldest_observed_age_seconds mail_oldest_observed_overdue_seconds mail_limit_reached mail_failed_count mail_failed_unknown_created_count mail_failed_oldest_observed_creation_age_seconds mail_failed_limit_reached finalizing_root_count finalizing_intent_count finalizing_missing_intent_count finalizing_unknown_intent_age_count finalizing_oldest_observed_intent_age_seconds finalizing_limit_reached")
	want := make(map[string]bool, len(wantSuffixes))
	for _, suffix := range wantSuffixes {
		want["hash.operational_backlog."+suffix] = true
	}
	values := make(map[string]int64, len(rows))
	for _, row := range rows {
		if len(row) != 5 {
			t.Fatal("metric row widened")
		}
		var name, kind, stamp string
		if json.Unmarshal(row["name"], &name) != nil || !want[name] {
			t.Fatal("unknown or duplicate metric", name)
		}
		delete(want, name)
		if json.Unmarshal(row["kind"], &kind) != nil || kind != "gauge" {
			t.Fatal("backlog state lost gauge semantics")
		}
		var value int64
		if err := json.Unmarshal(row["value"], &value); err != nil || value < 0 || value > 1<<53-1 {
			t.Fatal("wire value was not an exact nonnegative integer", err)
		}
		values[name] = value
		if json.Unmarshal(row["timestamp"], &stamp) != nil {
			t.Fatal("invalid metric timestamp")
		}
		at, err := time.Parse(time.RFC3339Nano, stamp)
		if err != nil || time.Since(at) < 0 || time.Since(at) > time.Second {
			t.Fatal("metric export timestamp was not current UTC", err)
		}
		var labels map[string]string
		if json.Unmarshal(row["labels"], &labels) != nil || len(labels) != 4 || labels["schema"] != "hash-operational-backlog-v1" || labels["service"] != "hash-worker" || labels["release"] != "release498" || labels["environment"] != "test" {
			t.Fatal("metric labels escaped the fixed process identity")
		}
	}
	if len(want) != 0 || values["hash.operational_backlog.has_sample"] != 1 || values["hash.operational_backlog.stale"] != 1 || values["hash.operational_backlog.sample_age_seconds"] < 301 || values["hash.operational_backlog.mail_due_count"] != 2 || values["hash.operational_backlog.mail_failed_count"] != 1 || values["hash.operational_backlog.observed_row_limit"] != 1000 {
		t.Fatal("cached age, explicit booleans or durable values changed", values)
	}
	if sh.dropped.Load() != 2 || len(sh.ch) != 1 || (<-sh.ch).Body != "PRIVATE_ORIGINAL_LOG498" || l.Diagnostics().MetricFailures != 0 || l.Diagnostics().CheckinResponses != 0 {
		t.Fatal("metrics displaced logs or relabeled checkin/local failure accounting", l.Diagnostics())
	}
	if err := l.Close(budget); err != nil {
		t.Fatal("ready metric owner did not join", err)
	}
	l.emitOperationalMetricsV1()
	select {
	case <-wire:
		t.Fatal("post-close metrics escaped")
	default:
	}
}

func TestOperationalMetrics498StrictAcknowledgementReadAndCloseFailures(t *testing.T) {
	t.Setenv("FLARE_LOG_LEVEL", "info")
	cases := []struct {
		name, body                     string
		status                         int
		readError, closeError, wantAck bool
	}{
		{"full", fullMetricAck498, 200, false, false, true},
		{"partial", `{"accepted":22,"rejected":1,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"dropped", `{"accepted":23,"rejected":0,"dropped":1,"receipt_id":"r"}`, 200, false, false, false},
		{"too_many", `{"accepted":24,"rejected":0,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"missing", `{"accepted":23,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"null_count", `{"accepted":23,"rejected":null,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"fraction", `{"accepted":23.0,"rejected":0,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"string", `{"accepted":"23","rejected":0,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"empty_receipt", `{"accepted":23,"rejected":0,"dropped":0,"receipt_id":""}`, 200, false, false, false},
		{"duplicate", `{"accepted":22,"accepted":23,"rejected":0,"dropped":0,"receipt_id":"r"}`, 200, false, false, false},
		{"unknown", `{"accepted":23,"rejected":0,"dropped":0,"receipt_id":"r","other":0}`, 200, false, false, false},
		{"trailing", fullMetricAck498 + ` {}`, 200, false, false, false},
		{"malformed", `{"accepted":23`, 200, false, false, false},
		{"oversize", fullMetricAck498 + strings.Repeat(" ", 4096), 200, false, false, false},
		{"read", fullMetricAck498, 200, true, false, false},
		{"close", fullMetricAck498, 200, false, true, false},
		{"uncommitted_status", fullMetricAck498, 202, false, false, false},
		{"failed_status", fullMetricAck498, 503, false, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := &metricBody498{Reader: strings.NewReader(tc.body)}
			if tc.readError {
				body.Reader = io.MultiReader(body.Reader, metricReadError498{})
			}
			if tc.closeError {
				body.closeErr = errors.New("synthetic close failure")
			}
			var requests int
			l, _ := directMetricLifecycle498(context.Background(), metricTransport498(func(r *http.Request) (*http.Response, error) {
				requests++
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Second {
					t.Error("metric request lost its finite deadline")
				}
				io.Copy(io.Discard, r.Body)
				r.Body.Close()
				return &http.Response{StatusCode: tc.status, Body: body, Header: make(http.Header)}, nil
			}))
			l.RecordOperationalBacklogV1(context.Background(), OperationalBacklogSnapshotV1{HasSample: true})
			l.emitOperationalMetricsV1()
			if requests != 1 || body.closed.Load() != 1 {
				t.Fatal("metric sender retried or did not complete Close")
			}
			d := l.Diagnostics()
			if tc.wantAck && (d.MetricAcknowledgedBatches != 1 || d.MetricFailures != 0) || !tc.wantAck && (d.MetricAcknowledgedBatches != 0 || d.MetricFailures != 1) || d.CheckinResponses != 0 || d.CheckinFailures != 0 {
				t.Fatal("strict receiver acknowledgement/accounting changed", d)
			}
		})
	}
}

func TestOperationalMetrics498NativeOffRoleInvalidInputAndIntegerRange(t *testing.T) {
	t.Setenv("FLARE_LOG_LEVEL", "info")
	var requests atomic.Int32
	transport := metricTransport498(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, errors.New("unexpected egress")
	})
	l, sh := directMetricLifecycle498(context.Background(), transport)
	l.emitOperationalMetricsV1()
	if requests.Load() != 0 {
		t.Fatal("no-sample owner emitted")
	}
	for _, change := range []func(*Lifecycle, *logShipper){
		func(l *Lifecycle, _ *logShipper) { l.shipper = nil },
		func(l *Lifecycle, _ *logShipper) { l.service = "hash" },
		func(_ *Lifecycle, s *logShipper) { s.service = "hash" },
		func(_ *Lifecycle, s *logShipper) { s.release = "PRIVATE CONTRACT" },
		func(_ *Lifecycle, s *logShipper) { s.environment = "unconfigured" },
	} {
		x, native := directMetricLifecycle498(context.Background(), transport)
		change(x, native)
		x.RecordOperationalBacklogV1(context.Background(), OperationalBacklogSnapshotV1{HasSample: true})
		x.emitOperationalMetricsV1()
		if x.operationalMetrics.Load() != nil {
			t.Fatal("off/invalid role or identity retained a metric sample")
		}
	}
	for _, off := range []string{"off", " OFF "} {
		t.Setenv("FLARE_LOG_LEVEL", off)
		l.RecordOperationalBacklogV1(context.Background(), OperationalBacklogSnapshotV1{HasSample: true})
		l.emitOperationalMetricsV1()
		if l.operationalMetrics.Load() != nil {
			t.Fatal("native-off acquired an alternate metric path")
		}
	}
	t.Setenv("FLARE_LOG_LEVEL", "info")
	for _, bad := range []OperationalBacklogSnapshotV1{{}, {HasSample: true, SampleAgeSeconds: -1}, {HasSample: true, SampleAgeSeconds: 300}, {HasSample: true, Data: OperationalBacklogDataV1{MailCount: 1001}}} {
		l.RecordOperationalBacklogV1(context.Background(), bad)
	}
	if l.operationalMetrics.Load() != nil {
		t.Fatal("invalid backlog became a metric observation")
	}
	valid := OperationalBacklogSnapshotV1{HasSample: true, Data: OperationalBacklogDataV1{MailCount: 1, MailOldestObservedAgeSeconds: 1<<53 - 1}}
	l.RecordOperationalBacklogV1(context.Background(), valid)
	prior := l.operationalMetrics.Load()
	if prior == nil {
		t.Fatal("largest exact integer was refused")
	}
	valid.Data.MailOldestObservedAgeSeconds++
	l.RecordOperationalBacklogV1(context.Background(), valid)
	if l.operationalMetrics.Load() != prior || l.Diagnostics().MetricFailures != 1 {
		t.Fatal("rounded integer overwrote the last exact observation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	x, _ := directMetricLifecycle498(ctx, transport)
	x.RecordOperationalBacklogV1(context.Background(), OperationalBacklogSnapshotV1{HasSample: true})
	x.emitOperationalMetricsV1()
	l.RecordOperationalBacklogV1(ctx, OperationalBacklogSnapshotV1{ReadUnavailable: true})
	if x.operationalMetrics.Load() != nil || l.operationalMetrics.Load() != prior || requests.Load() != 0 {
		t.Fatal("canceled owner/caller produced metrics")
	}
	if sh.rejected.Load() != 4 {
		t.Fatal("existing invalid-backlog refusals changed")
	}
}

func TestOperationalMetrics498CachedAgeStaleUnknownAndOverflow(t *testing.T) {
	base := time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)
	labels := operationalMetricLabelsV1{"hash-operational-backlog-v1", "hash-worker", "r", "test"}
	sample := &operationalMetricSampleV1{snapshot: OperationalBacklogSnapshotV1{HasSample: true, SampleAgeSeconds: 299}, recordedAt: base}
	points, ok := projectOperationalMetricsV1(sample, base.Add(2*time.Second), labels)
	if !ok {
		t.Fatal("cached observation was refused")
	}
	values := make(map[string]int64)
	for _, point := range points {
		values[point.Name] = point.Value
	}
	if values["hash.operational_backlog.sample_age_seconds"] != 301 || values["hash.operational_backlog.stale"] != 1 || values["hash.operational_backlog.has_sample"] != 1 || sample.snapshot.SampleAgeSeconds != 299 || sample.snapshot.Stale {
		t.Fatal("cache age did not advance honestly or mutated the retained sample")
	}
	sample.snapshot = OperationalBacklogSnapshotV1{ReadUnavailable: true}
	points, ok = projectOperationalMetricsV1(sample, base.Add(time.Hour), labels)
	if !ok {
		t.Fatal("unknown observation was not representable")
	}
	for _, point := range points {
		if point.Name == "hash.operational_backlog.has_sample" && point.Value != 0 || point.Name == "hash.operational_backlog.read_unavailable" && point.Value != 1 {
			t.Fatal("cached unknown state became healthy")
		}
	}
	sample.snapshot = OperationalBacklogSnapshotV1{HasSample: true, SampleAgeSeconds: 1<<53 - 1, Stale: true}
	if _, ok := projectOperationalMetricsV1(sample, base.Add(time.Second), labels); ok {
		t.Fatal("elapsed age rounded past the exact integer range")
	}
	sample.snapshot.SampleAgeSeconds = math.MaxInt64
	if _, ok := projectOperationalMetricsV1(sample, base, labels); ok {
		t.Fatal("out-of-range integer was accepted")
	}
	if _, ok := projectOperationalMetricsV1(sample, base.Add(-time.Second), labels); ok {
		t.Fatal("clock reversal made a cached observation fresh")
	}
}

type metricBlockedClose498 struct {
	io.Reader
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *metricBlockedClose498) Close() error {
	b.once.Do(func() { close(b.started) })
	<-b.release
	return nil
}

func TestOperationalMetrics498ExistingOwnerWaitsForActualResponseClose(t *testing.T) {
	body := &metricBlockedClose498{Reader: strings.NewReader(fullMetricAck498), started: make(chan struct{}), release: make(chan struct{})}
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(body.release) })
	l, _, ready, budget := readyMetricLifecycle498(t, "https://collector.invalid/api/1/logs", metricTransport498(func(r *http.Request) (*http.Response, error) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: body}, nil
	}))
	l.RecordOperationalBacklogV1(budget, OperationalBacklogSnapshotV1{HasSample: true})
	close(ready)
	select {
	case <-body.started:
	case <-budget.Done():
		t.Fatal("actual response Close did not begin")
	}
	cleanup, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer stop()
	if err := l.Close(cleanup); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("blocked response Close was falsely reported joined", err)
	}
	select {
	case <-l.done:
		t.Fatal("owner retired while response Close remained active")
	default:
	}
	if l.Diagnostics().MetricAcknowledgedBatches != 0 {
		t.Fatal("acknowledgement preceded successful Close")
	}
	releaseOnce.Do(func() { close(body.release) })
	if err := l.Close(budget); err != nil {
		t.Fatal("owner did not join after response Close finished", err)
	}
	select {
	case <-l.done:
	default:
		t.Fatal("existing ready owner survived joined close")
	}
}

func TestOperationalMetrics498CancellationRetiresInFlightTransportBeforeJoin(t *testing.T) {
	started, retired := make(chan struct{}), make(chan struct{})
	l, _, ready, budget := readyMetricLifecycle498(t, "https://collector.invalid/api/1/logs", metricTransport498(func(r *http.Request) (*http.Response, error) {
		defer close(retired)
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	l.RecordOperationalBacklogV1(budget, OperationalBacklogSnapshotV1{HasSample: true})
	close(ready)
	select {
	case <-started:
	case <-budget.Done():
		t.Fatal("metric transport did not start")
	}
	if err := l.Close(budget); err != nil {
		t.Fatal("canceled metric owner did not join", err)
	}
	select {
	case <-retired:
	default:
		t.Fatal("joined lifecycle left an active metric request phase")
	}
	if l.Diagnostics().MetricAcknowledgedBatches != 0 || l.Diagnostics().MetricFailures != 1 {
		t.Fatal("canceled request became a receipt", l.Diagnostics())
	}
}

func TestOperationalMetrics498RedirectIsNotFollowed(t *testing.T) {
	t.Setenv("FLARE_LOG_LEVEL", "info")
	var followed atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed.Add(1); io.WriteString(w, fullMetricAck498) }))
	defer target.Close()
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer peer.Close()
	l, sh := directMetricLifecycle498(context.Background(), peer.Client().Transport)
	sh.endpoint = peer.URL + "/api/1/logs"
	l.RecordOperationalBacklogV1(context.Background(), OperationalBacklogSnapshotV1{HasSample: true})
	l.emitOperationalMetricsV1()
	if followed.Load() != 0 || l.Diagnostics().MetricFailures != 1 || l.Diagnostics().MetricAcknowledgedBatches != 0 {
		t.Fatal("redirect leaked ingest credentials or became an acknowledgement")
	}
}
