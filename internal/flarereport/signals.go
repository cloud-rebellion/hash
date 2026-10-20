// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"

	sentry "github.com/getsentry/sentry-go"
)

type Operation string

const (
	OperationHTTP   Operation = "http"
	OperationMCP    Operation = "mcp"
	OperationWorker Operation = "worker"
	OperationMail   Operation = "email_dispatch"
)

type FailureCategory string

const (
	FailureInternal    FailureCategory = "internal"
	FailureDependency  FailureCategory = "dependency"
	FailureUnavailable FailureCategory = "unavailable"
	FailurePanic       FailureCategory = "panic"
)

func validOperation(op Operation) bool { return operationIndex(op) >= 0 }
func validFailure(category FailureCategory) bool {
	switch category {
	case FailureInternal, FailureDependency, FailureUnavailable, FailurePanic, FailureTimeout:
		return true
	}
	return false
}

type processIdentity struct{ service, release, environment string }

var currentIdentity atomic.Pointer[processIdentity]

func signalHub(ctx context.Context) *sentry.Hub {
	if ctx != nil {
		if hub := sentry.GetHubFromContext(ctx); hub != nil {
			return hub
		}
	}
	return sentry.CurrentHub()
}

// CaptureOperationFailure accepts only closed operational categories. Raw
// errors, panic values, input arguments and private outputs have no API slot.
func CaptureOperationFailure(ctx context.Context, operation Operation, category FailureCategory) {
	if !validOperation(operation) || !validFailure(category) {
		return
	}
	if ctx != nil {
		if observation, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok && !observation.reported.CompareAndSwap(false, true) {
			return
		}
	}
	hub := signalHub(ctx).Clone()
	hub.WithScope(func(scope *sentry.Scope) {
		scope.Clear()
		scope.SetLevel(sentry.LevelError)
		scope.SetTag("operation", string(operation))
		scope.SetTag("failure_category", string(category))
		scope.SetFingerprint([]string{"hash", string(operation), string(category)})
		if id := currentIdentity.Load(); id != nil {
			scope.SetTag("service", id.service)
			scope.SetTag("release", id.release)
			scope.SetTag("environment", id.environment)
		}
		if ctx != nil {
			if span := contextSpan(ctx); span != nil {
				scope.SetPropagationContext(sentry.PropagationContext{TraceID: span.TraceID, SpanID: span.SpanID})
			}
		}
		event := sentry.NewEvent()
		event.Message = "Hash operational failure"
		event.Exception = []sentry.Exception{{Type: "HashOperationFailure", Value: string(operation) + ":" + string(category), Stacktrace: safeStack(sentry.NewStacktrace())}}
		hub.CaptureEvent(event)
	})
}
func safeStack(stack *sentry.Stacktrace) *sentry.Stacktrace {
	if stack == nil {
		return nil
	}
	frames := stack.Frames
	if len(frames) > 32 {
		frames = frames[len(frames)-32:]
	}
	out := &sentry.Stacktrace{Frames: make([]sentry.Frame, 0, len(frames))}
	for _, frame := range frames {
		// Only compiled code location, never source snippets, locals or absolute
		// paths. Function/module names come from the runtime, not user content.
		name := filepath.Base(frame.Filename)
		if len(name) > 128 {
			name = "source"
		}
		fn, module := frame.Function, frame.Module
		if len(fn) > 256 {
			fn = ""
		}
		if len(module) > 256 {
			module = ""
		}
		out.Frames = append(out.Frames, sentry.Frame{Filename: name, Function: fn, Module: module, Lineno: frame.Lineno, Colno: frame.Colno, InApp: frame.InApp})
	}
	return out
}
func requestMethod(method string) string {
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE":
		return method
	}
	return "OTHER"
}
func routeTemplate(route string) string {
	if len(route) == 0 || len(route) > 256 || strings.ContainsAny(route, "?\r\n#") {
		return "/unmatched"
	}
	return route
}

type httpObservation struct {
	span     *sentry.Span
	panicked atomic.Bool
	aborted  atomic.Bool
	reported atomic.Bool
}
type httpObservationKey struct{}

// BeginHTTPRequest is used by the existing chi response wrapper. Its finish
// sees the actual final status without introducing a writer that loses SSE or
// hijacking support. The inner recovery marks panics to avoid duplicate5xx.
func BeginHTTPRequest(r *http.Request) (*http.Request, func(int, string)) {
	hub := sentry.NewHub(signalHub(r.Context()).Client(), sentry.NewScope())
	ctx := sentry.SetHubOnContext(r.Context(), hub)
	observation := &httpObservation{}
	if tracesSampleRate() > 0 && !isUntraceable(r.URL.Path) {
		traceContext := sentry.SetHubOnContext(context.Background(), hub)
		observation.span = sentry.StartTransaction(traceContext, "HTTP request", sentry.ContinueFromTrace(safeIncomingTrace(r.Header.Get("sentry-trace"))), sentry.WithOpName("http.server"), sentry.WithTransactionSource(sentry.SourceRoute))
		if id := currentIdentity.Load(); id != nil {
			observation.span.SetData("service.name", id.service)
			observation.span.SetData("release", id.release)
			observation.span.SetData("environment", id.environment)
		}
	}
	ctx = context.WithValue(ctx, httpObservationKey{}, observation)
	return r.WithContext(ctx), func(status int, route string) {
		if observation.span != nil {
			observation.span.Name = requestMethod(r.Method) + " " + routeTemplate(route)
			observation.span.SetData("http.response.status_code", status)
			switch {
			case observation.aborted.Load():
				observation.span.Status = sentry.SpanStatusAborted
			case status >= 500:
				observation.span.Status = sentry.SpanStatusInternalError
			case status == 429:
				observation.span.Status = sentry.SpanStatusResourceExhausted
			case status >= 400:
				observation.span.Status = sentry.SpanStatusInvalidArgument
			default:
				observation.span.Status = sentry.SpanStatusOK
			}
			defer observation.span.Finish()
		}
		if status >= 500 && !observation.panicked.Load() && !observation.aborted.Load() {
			CaptureOperationFailure(ctx, OperationHTTP, FailureInternal)
		}
	}
}

func contextSpan(ctx context.Context) *sentry.Span {
	if ctx == nil {
		return nil
	}
	if observation, ok := ctx.Value(httpObservationKey{}).(*httpObservation); ok && observation.span != nil {
		return observation.span
	}
	return sentry.SpanFromContext(ctx)
}
func safeIncomingTrace(value string) string {
	if len(value) != 49 && len(value) != 51 {
		return ""
	}
	if value[32] != '-' || !validHexID(value[:32], 32) || !validHexID(value[33:49], 16) {
		return ""
	}
	if len(value) == 51 && (value[49] != '-' || (value[50] != '0' && value[50] != '1')) {
		return ""
	}
	return value[:49]
}
