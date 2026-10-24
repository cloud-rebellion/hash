// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package chromium

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/target"
)

// This protocol seam exercises the real allocation helper. It does not claim
// a live Chromium process, physical target retirement or image acceptance.
type hashAllocationExecutor444 struct {
	t       *testing.T
	result  target.ID
	failure error
	calls   int
}

var _ cdp.Executor = (*hashAllocationExecutor444)(nil)

func (e *hashAllocationExecutor444) Execute(_ context.Context, method string, params, result any) error {
	e.t.Helper()
	e.calls++
	if e.calls != 1 || method != target.CommandCreateTarget {
		e.t.Fatal("allocation performed an extra or different protocol command")
	}
	input, ok := params.(*target.CreateTargetParams)
	if !ok || input.URL != "about:blank" || *input != *target.CreateTarget("about:blank") {
		e.t.Fatal("allocation changed its original private blank-target command")
	}
	output, ok := result.(*target.CreateTargetReturns)
	if !ok {
		e.t.Fatal("allocation lost the native typed reply")
	}
	output.TargetID = e.result
	return e.failure
}

func hashAllocationContext444(t *testing.T, state string) context.Context {
	t.Helper()
	switch state {
	case "live":
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		return ctx
	case "canceled":
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		return ctx
	case "deadline":
		ctx, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
		t.Cleanup(cancel)
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal("deterministic expired context unavailable")
		}
		return ctx
	default:
		t.Fatal("unsupported controlled context state")
		return nil
	}
}

const hashPrivateAllocationTarget444 = target.ID("private-target444-never-log")
const hashPrivateAllocationError444 = "private-error444 https://private.invalid/doc/private-document444?token=private-token444 hash_session=private-cookie444"

func hashReadAllocationLog444(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	if len(raw) == 0 || len(raw) > 1024 {
		t.Fatal("expected one bounded native diagnostic record")
	}
	for _, marker := range []string{string(hashPrivateAllocationTarget444), "private-error444", "private.invalid", "private-document444", "private-token444", "private-cookie444", "private-profile444", "hash_session", "about:blank"} {
		if bytes.Contains(raw, []byte(marker)) {
			t.Fatal("native diagnostic leaked private error, target, URL or auth data")
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		t.Fatal("native diagnostic is not one JSON object")
	}
	record := make(map[string]any)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			t.Fatal("native diagnostic key is invalid")
		}
		if _, exists := record[key]; exists {
			t.Fatal("native diagnostic duplicated a field")
		}
		var value any
		if decoder.Decode(&value) != nil {
			t.Fatal("native diagnostic value is invalid")
		}
		record[key] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		t.Fatal("native diagnostic object is incomplete")
	}
	if decoder.Decode(new(any)) != io.EOF {
		t.Fatal("allocation emitted more than one diagnostic record")
	}
	keys := []string{"time", "level", "msg", "schema", "reason", "command_error", "empty_target_id", "context_deadline", "context_canceled"}
	if len(record) != len(keys) {
		t.Fatal("native diagnostic added or omitted fields")
	}
	for _, key := range keys {
		if _, ok := record[key]; !ok {
			t.Fatal("native diagnostic omitted a closed field")
		}
	}
	stamp, ok := record["time"].(string)
	if !ok {
		t.Fatal("native timestamp type differs")
	}
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		t.Fatal("native timestamp is invalid")
	}
	if record["level"] != "ERROR" || record["msg"] != "hash chromium tab allocation unconfirmed" || record["schema"] != float64(1) {
		t.Fatal("native diagnostic identity differs")
	}
	return record
}

func TestHashTabAllocationDiagnostic444PreservesFailureAuthorityAndClosedEvidence(t *testing.T) {
	privateFailure := errors.New(hashPrivateAllocationError444)
	cases := []struct {
		name         string
		contextState string
		failure      error
		result       target.ID
		reason       string
	}{
		{"deadline error with live context", "live", context.DeadlineExceeded, hashPrivateAllocationTarget444, "allocation_deadline"},
		{"canceled error with live context", "live", context.Canceled, hashPrivateAllocationTarget444, "allocation_canceled"},
		{"protocol error with live context", "live", privateFailure, hashPrivateAllocationTarget444, "allocation_protocol"},
		{"empty successful reply", "live", nil, "", "allocation_empty"},
		{"protocol error with canceled context", "canceled", privateFailure, hashPrivateAllocationTarget444, "allocation_protocol"},
		{"protocol error with deadline context", "deadline", privateFailure, hashPrivateAllocationTarget444, "allocation_protocol"},
		{"deadline error with canceled context", "canceled", context.DeadlineExceeded, hashPrivateAllocationTarget444, "allocation_deadline"},
		{"canceled error with deadline context", "deadline", context.Canceled, hashPrivateAllocationTarget444, "allocation_canceled"},
		{"wrapped deadline omits private error", "live", errors.Join(privateFailure, context.DeadlineExceeded), hashPrivateAllocationTarget444, "allocation_deadline"},
		{"wrapped cancel omits private error", "live", errors.Join(privateFailure, context.Canceled), hashPrivateAllocationTarget444, "allocation_canceled"},
		{"empty reply with canceled context", "canceled", nil, "", "allocation_empty"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := hashAllocationContext444(t, tt.contextState)
			browser := &chromiumBrowser{ctx: ctx, userProfileDirPath: "private-profile444-never-log"}
			executor := &hashAllocationExecutor444{t: t, result: tt.result, failure: tt.failure}
			var logs bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&logs, nil))
			id, err := browser.hashAllocateTarget(ctx, executor, logger)
			if err != errHashTabCleanup || !errors.Is(err, errHashTabCleanup) || id != "" || !browser.hashCleanupUnconfirmed.Load() {
				t.Fatal("failed allocation changed its exact sentinel, opaque ownership or quarantine")
			}
			if executor.calls != 1 || browser.ctx != ctx || browser.userProfileDirPath != "private-profile444-never-log" || browser.retirement != nil || browser.startup != nil || browser.isStarted.Load() || browser.closeFunc != nil || browser.cancelFunc != nil || browser.lifetimeCancel != nil || browser.proxyOwned {
				t.Fatal("diagnostic changed lifetime, profile, startup or physical ownership")
			}
			record := hashReadAllocationLog444(t, logs.Bytes())
			// Generated CreateTarget.Do discards its reply ID on any command
			// error. The helper must not reconstruct or disclose that lost ID.
			if record["reason"] != tt.reason || record["command_error"] != (tt.failure != nil) || record["empty_target_id"] != true || record["context_deadline"] != (tt.contextState == "deadline") || record["context_canceled"] != (tt.contextState == "canceled") {
				t.Fatal("actual command classification was confused with separate context state")
			}
		})
	}
}

func TestHashTabAllocationDiagnostic444SuccessfulTargetIsQuiet(t *testing.T) {
	ctx := hashAllocationContext444(t, "live")
	browser := &chromiumBrowser{ctx: ctx}
	executor := &hashAllocationExecutor444{t: t, result: hashPrivateAllocationTarget444}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	id, err := browser.hashAllocateTarget(ctx, executor, logger)
	if err != nil || id != hashPrivateAllocationTarget444 || browser.hashCleanupUnconfirmed.Load() || executor.calls != 1 || logs.Len() != 0 || browser.ctx != ctx || browser.retirement != nil || browser.startup != nil {
		t.Fatal("successful allocation was refused, changed ownership or emitted a failure signal")
	}
}

func TestHashTabAllocationDiagnostic444OriginalTwoArgumentCallerAndNilLogger(t *testing.T) {
	for _, style := range []string{"original two arguments", "explicit nil logger"} {
		for _, outcome := range []string{"success", "protocol failure", "empty reply"} {
			t.Run(style+"/"+outcome, func(t *testing.T) {
				ctx := hashAllocationContext444(t, "live")
				browser := &chromiumBrowser{ctx: ctx}
				executor := &hashAllocationExecutor444{t: t, result: hashPrivateAllocationTarget444}
				if outcome == "protocol failure" {
					executor.failure = errors.New(hashPrivateAllocationError444)
				}
				if outcome == "empty reply" {
					executor.result = ""
				}
				var id target.ID
				var err error
				if style == "original two arguments" {
					id, err = browser.hashAllocateTarget(ctx, executor)
				} else {
					id, err = browser.hashAllocateTarget(ctx, executor, nil)
				}
				if executor.calls != 1 || browser.ctx != ctx || browser.retirement != nil || browser.startup != nil {
					t.Fatal("original caller or nil logger changed command/lifetime ownership")
				}
				if outcome == "success" {
					if err != nil || id != hashPrivateAllocationTarget444 || browser.hashCleanupUnconfirmed.Load() {
						t.Fatal("original successful caller changed")
					}
				} else if err != errHashTabCleanup || id != "" || !browser.hashCleanupUnconfirmed.Load() {
					t.Fatal("original failed caller lost exact sentinel/quarantine")
				}
			})
		}
	}
}

// A native slog handler is external code: publish quarantine before it can
// inspect or reenter the owner. This callback needs no goroutine or timing.
type hashAllocationCallbackHandler444 struct {
	next    slog.Handler
	observe func(slog.Record)
}

func (h *hashAllocationCallbackHandler444) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}
func (h *hashAllocationCallbackHandler444) Handle(ctx context.Context, record slog.Record) error {
	if h.observe != nil {
		h.observe(record)
	}
	return h.next.Handle(ctx, record)
}
func (h *hashAllocationCallbackHandler444) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &hashAllocationCallbackHandler444{next: h.next.WithAttrs(attrs), observe: h.observe}
}
func (h *hashAllocationCallbackHandler444) WithGroup(name string) slog.Handler {
	return &hashAllocationCallbackHandler444{next: h.next.WithGroup(name), observe: h.observe}
}

func TestHashTabAllocationDiagnostic444PublishesQuarantineBeforeHandlerEntry(t *testing.T) {
	ctx := hashAllocationContext444(t, "live")
	browser := &chromiumBrowser{ctx: ctx}
	executor := &hashAllocationExecutor444{t: t, result: hashPrivateAllocationTarget444, failure: errors.New(hashPrivateAllocationError444)}
	var logs bytes.Buffer
	observations := 0
	handler := &hashAllocationCallbackHandler444{
		next: slog.NewJSONHandler(&logs, nil),
		observe: func(record slog.Record) {
			observations++
			if observations != 1 || !browser.hashCleanupUnconfirmed.Load() {
				t.Fatal("external logger observed a failed allocation before quarantine publication")
			}
			if record.Message != "hash chromium tab allocation unconfirmed" || executor.calls != 1 {
				t.Fatal("external logger ran before the one original allocation outcome")
			}
		},
	}
	id, err := browser.hashAllocateTarget(ctx, executor, slog.New(handler))
	if observations != 1 || executor.calls != 1 || id != "" || err != errHashTabCleanup || !errors.Is(err, errHashTabCleanup) || !browser.hashCleanupUnconfirmed.Load() {
		t.Fatal("observer changed exact allocation failure authority or callback cardinality")
	}
	record := hashReadAllocationLog444(t, logs.Bytes())
	if record["reason"] != "allocation_protocol" || record["command_error"] != true || record["empty_target_id"] != true || record["context_deadline"] != false || record["context_canceled"] != false {
		t.Fatal("callback changed the closed causal observation")
	}
}
