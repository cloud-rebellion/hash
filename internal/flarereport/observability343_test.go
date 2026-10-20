// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

type wire343 struct {
	mu      sync.Mutex
	bodies  [][]byte
	paths   []string
	arrived chan struct{}
}

func newWire343(t *testing.T) (*wire343, *httptest.Server, *sentry.Hub) {
	t.Helper()
	wire := &wire343{arrived: make(chan struct{}, 16)}
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body.Close()
		if err != nil {
			t.Error(err)
		}
		wire.mu.Lock()
		wire.bodies = append(wire.bodies, append([]byte(nil), raw...))
		wire.paths = append(wire.paths, r.URL.Path)
		wire.mu.Unlock()
		select {
		case wire.arrived <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/logs") {
			var logs []nativeLogLine
			if err := json.Unmarshal(raw, &logs); err != nil {
				t.Error(err)
			}
			json.NewEncoder(w).Encode(map[string]int{"accepted": len(logs)})
		} else {
			io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(peer.Close)
	options := sdkClientOptions(strings.Replace(peer.URL, "://", "://fixture-public@", 1)+"/1", "hash", strings.Repeat("a", 40), "development")
	options.TracesSampleRate = 1
	client, err := sentry.NewClient(options)
	if err != nil {
		t.Fatal(err)
	}
	return wire, peer, sentry.NewHub(client, sentry.NewScope())
}
func flush343(t *testing.T, hub *sentry.Hub) {
	t.Helper()
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if !hub.Client().FlushWithContext(ctx) {
		t.Fatal("actual local receiver did not join SDK flush")
	}
}
func (w *wire343) all() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out strings.Builder
	for _, body := range w.bodies {
		out.Write(body)
	}
	return out.String()
}
func (w *wire343) events(t *testing.T) []map[string]any {
	t.Helper()
	w.mu.Lock()
	defer w.mu.Unlock()
	out := []map[string]any{}
	for _, body := range w.bodies {
		for _, line := range strings.Split(string(body), "\n") {
			var event map[string]any
			if json.Unmarshal([]byte(line), &event) == nil && event["event_id"] != nil && event["platform"] != nil {
				out = append(out, event)
			}
		}
	}
	return out
}
func Test343RuntimePublicConfigDoesNotExposePrivateDSNOrGeneralEnvironment(t *testing.T) {
	t.Setenv("FLARE_DSN", "https://fixture-public:PRIVATE_DSNPASSWORD@flare.example.test/1")
	cfg := BrowserConfiguration(strings.Repeat("a", 40), "production")
	raw, _ := json.Marshal(cfg)
	if !cfg.Enabled || cfg.Service != "hash-browser" || cfg.DSN != "https://fixture-public@flare.example.test/1" || strings.Contains(string(raw), "PRIVATE_DSNPASSWORD") || BrowserIngestOrigin(cfg.Release, cfg.Environment) != "https://flare.example.test" {
		t.Fatal("runtime public config differs", string(raw))
	}
	for _, bad := range []string{"https://key@flare.example.test/1?secret=private", "https://key@flare.example.test/1#private", "https://key@flare.example.test/../1", "javascript:private", "http://key@flare.example.test/1", "https://key@flare.example.test;/1", "https://key@flare.example.test:0/1", "https://key@flare.example.test:65536/1", "https://key@flare.example.test:/1", "https://key@flare.example.test/1?", "https://key@bad_host/1"} {
		t.Setenv("FLARE_DSN", bad)
		if BrowserConfiguration("release", "production").Enabled || BrowserIngestOrigin("release", "production") != "" {
			t.Fatal("invalid runtime ingest authority enabled", bad)
		}
	}
	t.Setenv("FLARE_DSN", "http://fixture-public@127.0.0.1:1234/1")
	if !BrowserConfiguration("release", "development").Enabled || BrowserConfiguration("release", "production").Enabled {
		t.Fatal("local receiver exception escaped development")
	}
}
func Test343FixedFailureUsesContextHubAndExcludesInheritedPrivateMaterial(t *testing.T) {
	wire, _, hub := newWire343(t)
	const marker = "PRIVATE_CONTRACT_PROMPT_MAIL_343"
	hub.Scope().SetTag("private", marker)
	hub.Scope().SetContext("customer", sentry.Context{"body": marker})
	hub.Scope().SetRequest(httptest.NewRequest(http.MethodPost, "https://hash.example/sign/"+marker+"?code="+marker, strings.NewReader(marker)))
	ctx := sentry.SetHubOnContext(context.Background(), hub)
	CaptureOperationFailure(ctx, OperationMCP, FailureInternal)
	flush343(t, hub)
	encoded := wire.all()
	if strings.Contains(encoded, marker) || !strings.Contains(encoded, `"operation":"mcp"`) || !strings.Contains(encoded, `"failure_category":"internal"`) || !strings.Contains(encoded, "Hash operational failure") {
		t.Fatal("fixed failure wire lost identity or exported private data", encoded)
	}
	if len(wire.events(t)) != 1 {
		t.Fatal("failure did not reach actual local receiver exactly once")
	}
}
func Test343ActualHTTPStatusTraceIdentityAndTypedFailureDedup(t *testing.T) {
	t.Setenv("FLARE_TRACES_SAMPLE_RATE", "1")
	wire, _, hub := newWire343(t)
	previous := currentIdentity.Load()
	currentIdentity.Store(&processIdentity{service: "hash", release: strings.Repeat("a", 40), environment: "development"})
	t.Cleanup(func() { currentIdentity.Store(previous) })
	var marshaled atomic.Int32
	hub.Scope().SetUser(sentry.User{Email: "PRIVATE_INHERITED_SCOPE"})
	hub.Scope().SetTag("private", "PRIVATE_INHERITED_SCOPE")
	hub.Scope().SetContext("private", sentry.Context{"body": "PRIVATE_INHERITED_SCOPE"})
	parent := sentry.StartTransaction(sentry.SetHubOnContext(context.Background(), hub), "PRIVATE_PARENT_TRANSACTION")
	parent.Description = "PRIVATE_PARENT_DESCRIPTION"
	parent.SetData("private", forbiddenJSON343{called: &marshaled})
	r := httptest.NewRequest(http.MethodGet, "https://hash.example/api/v1/documents/PRIVATE_URL", nil).WithContext(parent.Context())
	r.Header.Set("baggage", "sentry-user_segment=PRIVATE_BAGGAGE_343")
	r.Header.Set("sentry-trace", strings.Repeat("1", 32)+"-"+strings.Repeat("2", 16)+"-1")
	r, finish := BeginHTTPRequest(r)
	ObserveOperation(r.Context(), OperationCRM, OutcomeDependency, 17*time.Millisecond)
	finish(503, "/api/v1/documents/{id}")
	flush343(t, hub)
	events := wire.events(t)
	var failures, transactions int
	var failureTrace, transactionTrace string
	for _, event := range events {
		if event["type"] == "transaction" {
			transactions++
			contexts := event["contexts"].(map[string]any)
			trace := contexts["trace"].(map[string]any)
			transactionTrace, _ = trace["trace_id"].(string)
			data := trace["data"].(map[string]any)
			if trace["status"] != "internal_error" || data["http.response.status_code"] != float64(503) || data["service.name"] != "hash" || data["release"] != strings.Repeat("a", 40) || data["environment"] != "development" || event["transaction"] != "GET /api/v1/documents/{id}" {
				t.Fatal("actual trace receiver fields differ", event)
			}
		} else {
			failures++
			contexts := event["contexts"].(map[string]any)
			trace := contexts["trace"].(map[string]any)
			failureTrace, _ = trace["trace_id"].(string)
		}
	}
	if failures != 1 || transactions != 1 || failureTrace != strings.Repeat("1", 32) || transactionTrace != failureTrace || strings.Contains(wire.all(), "PRIVATE_") || marshaled.Load() != 0 {
		t.Fatal("typed error/generic5xx duplicate or missing safe trace", failures, transactions, wire.all())
	}
}
func Test343ExpectedOutcomesAggregateWithoutPageAndUnknownCategoriesRefuse(t *testing.T) {
	wire, _, hub := newWire343(t)
	ctx := sentry.SetHubOnContext(context.Background(), hub)
	ObserveOperation(ctx, OperationImport, OutcomeRejected, time.Millisecond)
	ObserveOperation(ctx, OperationAuthentication, OutcomeCanceled, time.Millisecond)
	CaptureOperationFailure(ctx, Operation("PRIVATE_TEXT"), FailureInternal)
	CaptureOperationFailure(ctx, OperationHTTP, FailureCategory("PRIVATE_TEXT"))
	flush343(t, hub)
	if len(wire.events(t)) != 0 {
		t.Fatal("expected/unknown outcome created pageable event", wire.all())
	}
	var found bool
	for _, row := range SnapshotOperations() {
		if row.Operation == OperationImport && row.Outcome == OutcomeRejected && row.Count > 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("expected outcome was silently discarded instead of counted")
	}
}
func Test343NativeLogWireIsBoundedFixedAndFiniteCloseJoins(t *testing.T) {
	wire, peer, _ := newWire343(t)
	ctx, cancel := context.WithCancel(context.Background())
	sh := &logShipper{endpoint: peer.URL + "/api/1/logs", key: "fixture-public", service: "hash-worker", release: strings.Repeat("b", 40), environment: "production", ctx: ctx, cancel: cancel, done: make(chan struct{}), ch: make(chan nativeLogLine, logShipBuffer), client: &http.Client{Timeout: 5 * time.Second}}
	go sh.run()
	h := &flareSlogHandler{next: slog.NewTextHandler(io.Discard, nil), shipper: sh, minLvl: slog.LevelWarn}
	const marker = "PRIVATE_CONTRACT_PROMPT_MAIL_343"
	record := slog.NewRecord(time.Now(), slog.LevelError, marker, 0)
	record.AddAttrs(slog.Any("nested", map[string]any{"body": marker, "prompt": marker}), slog.String("error", marker), slog.String("trace_id", marker), slog.Int64("duration_ms", 42))
	if err := h.Handle(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	sh.beginClose(cleanup)
	select {
	case <-sh.done:
	case <-cleanup.Done():
		t.Fatal("native log sender did not actually join")
	}
	encoded := wire.all()
	for _, value := range []string{marker, "nested", "prompt"} {
		if strings.Contains(encoded, value) {
			t.Fatal("arbitrary log content survived fixed schema", encoded)
		}
	}
	if !strings.Contains(encoded, `"service":"hash-worker"`) || !strings.Contains(encoded, `"environment":"production"`) || !strings.Contains(encoded, strings.Repeat("b", 40)) || !strings.Contains(encoded, `"duration_ms":42`) {
		t.Fatal("native log lost useful fixed metadata", encoded)
	}
	if sh.failed.Load() != 0 || sh.rejected.Load() != 0 {
		t.Fatal("local accepted wire counted as failed", sh.failed.Load(), sh.rejected.Load())
	}
}
func Test343ReadySenderDoesNotPingBeforeReadyOrAfterFiniteClose(t *testing.T) {
	wire, peer, hub := newWire343(t)
	t.Setenv("FLARE_DSN", strings.Replace(peer.URL, "://", "://fixture-public@", 1)+"/1")
	t.Setenv("HASH_FLARE_MONITOR_PREFIX", "fixture343")
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	ready := make(chan struct{})
	owner := newLifecycle(cleanup, ready, "hash-worker", hub.Client())
	defer owner.Close(cleanup)
	select {
	case <-wire.arrived:
		t.Fatal("booting role emitted healthy signal before ready")
	case <-time.After(20 * time.Millisecond):
	}
	close(ready)
	// There are two real sends: SDK service-up and direct role checkin.
	// Cancellation can return from HTTP.Do before an already-dispatched peer
	// handler records its body. Observe BOTH real signals before checking close;
	// a late remote arrival alone does not prove a new detached local send.
	for {
		events := wire.events(t)
		role := false
		wire.mu.Lock()
		for _, path := range wire.paths {
			if path == "/api/1/checkins/fixture343-hash-worker" {
				role = true
			}
		}
		wire.mu.Unlock()
		if len(events) == 1 && events[0]["message"] == "service-up:hash-worker" && role {
			break
		}
		select {
		case <-wire.arrived:
		case <-cleanup.Done():
			t.Fatal("both actual SDK and role ready signals did not reach the local receiver")
		}
	}
	if err := owner.Close(cleanup); err != nil {
		t.Fatal("ready owner did not join", err)
	}
	select {
	case <-owner.done:
	default:
		t.Fatal("role sender did not finish")
	}
	if owner.ctx.Err() != context.Canceled {
		t.Fatal("role context remained live after close")
	}
	wire.mu.Lock()
	count := len(wire.bodies)
	wire.mu.Unlock()
	secondReady := make(chan struct{})
	second := newLifecycle(cleanup, secondReady, "hash-worker", hub.Client())
	if err := second.Close(cleanup); err != nil {
		t.Fatal(err)
	}
	select {
	case <-second.done:
	default:
		t.Fatal("cancel-before-ready sender did not finish")
	}
	if second.ctx.Err() != context.Canceled {
		t.Fatal("cancel-before-ready context remained live")
	}
	close(secondReady)
	wire.mu.Lock()
	after := len(wire.bodies)
	wire.mu.Unlock()
	if after != count {
		t.Fatal("closed role emitted another signal")
	}
}

type forbiddenJSON343 struct{ called *atomic.Int32 }

func (f forbiddenJSON343) MarshalJSON() ([]byte, error) {
	f.called.Add(1)
	return []byte(`"PRIVATE_PARENT_DATA"`), nil
}
func Test343DSNBasePathMatchesNativeAndBrowserAuthority(t *testing.T) {
	dsn := "https://fixture-public:PRIVATE_PASSWORD@flare.example.test/prefix/1"
	endpoint, key, ok := parseDSNForLogs(dsn)
	if !ok || endpoint != "https://flare.example.test/prefix/api/1/logs" || key != "fixture-public" {
		t.Fatal("native endpoint disagrees with SDK/browser base path", endpoint, key, ok)
	}
	for _, environment := range []string{"customer secret", "custom"} {
		t.Setenv("FLARE_DSN", dsn)
		if BrowserConfiguration("release", environment).Enabled {
			t.Fatal("unsupported browser environment enabled")
		}
	}
}
