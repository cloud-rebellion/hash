// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package flarereport

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

// credentialPathPatterns match credentials/high-cardinality authentication
// handles carried in URL paths so they can be redacted before an event leaves
// the process. Query strings are removed wholesale below.
var credentialPathPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(/sign/)[^/?#]+`),
	regexp.MustCompile(`(/completed/)[^/?#]+`),
	regexp.MustCompile(`(/e/o/)[^/?#]+`),
	regexp.MustCompile(`(/webhooks/billing/)[^/?#]+`),
	regexp.MustCompile(`(/qes/callback/)[^/?#]+`),
}

func redactCredentialPath(raw string) string {
	for _, pattern := range credentialPathPatterns {
		raw = pattern.ReplaceAllString(raw, "${1}[redacted]")
	}
	return raw
}

// scrubSensitive removes request material that must never leave Hash. The SDK
// buffers up to 10 KiB of request bodies independently of SendDefaultPII; that
// can contain contract text, comments, typed names, identity data, API-key
// creation inputs, or webhook payloads. Non-sensitive headers can still carry
// customer-specific metadata and forwarding IPs, so retain only the redacted
// method/URL needed to diagnose a failing route. Applied to errors and traces.
func scrubSensitive(event *sentry.Event, _ *sentry.EventHint) *sentry.Event {
	if event != nil {
		event.Message = scrubLogText(event.Message)
		for i := range event.Exception {
			event.Exception[i].Value = scrubLogText(event.Exception[i].Value)
		}
	}
	if event != nil && event.Request != nil {
		event.Request.QueryString = ""
		if at := strings.IndexAny(event.Request.URL, "?#"); at >= 0 {
			event.Request.URL = event.Request.URL[:at]
		}
		event.Request.URL = redactCredentialPath(event.Request.URL)
		event.Request.Data = ""
		event.Request.Cookies = ""
		event.Request.Headers = nil
		event.Request.Env = nil
	}
	return event
}

// InitFlare wires error reporting to the house Flare instance (Sentry-wire
// protocol) when FLARE_DSN is set in the environment. release and environment
// identify the exact deployed artifact and tier in every event. The DSN is
// injected by the deploy pipeline's flare-provision step; without it this is a
// no-op so dev runs and self-hosts boot unchanged.
func InitFlare(service, release, environment string) bool {
	ready := make(chan struct{})
	close(ready)
	return InitFlareWithContext(context.Background(), ready, service, release, environment) != nil
}

// InitFlareWithContext installs capture before dependencies but starts healthy
// role signals only after actual readiness. The caller owns finite Close.
func InitFlareWithContext(ctx context.Context, ready <-chan struct{}, service, release, environment string) *Lifecycle {
	dsn := os.Getenv("FLARE_DSN")
	if dsn == "" || ctx == nil || ready == nil {
		return nil
	}
	if service != "hash" && service != "hash-worker" {
		return nil
	}
	release, environment = identityValue(release), identityValue(environment)
	if release == "" || environment == "" {
		return nil
	}
	if _, _, valid := publicDSN(dsn, environment); !valid {
		return nil
	}
	err := sentry.Init(sdkClientOptions(dsn, service, release, environment))
	if err != nil {
		slog.Warn("flare: error reporting disabled", "category", "invalid_configuration")
		return nil
	}
	currentIdentity.Store(&processIdentity{service: service, release: release, environment: environment})
	return newLifecycleWithShipper(ctx, ready, service, sentry.CurrentHub().Client(), func(owned context.Context) *logShipper {
		return installLogShipperWithContext(owned, service, release, environment)
	})
}

// sdkClientOptions keeps capture asynchronous and bounded while enqueuing each
// error/transaction before capture returns. SDK v0.47's default telemetry
// scheduler can remove an item before enqueueing it to the transport, allowing
// a simultaneous Flush to finish before that item reaches the transport.
// Use the supported HTTP transport's synchronous enqueue/batch-drain barrier;
// network I/O still runs on its bounded background worker. Hash ships its own
// fixed-schema logs and has no SDK log/metric producers.
func sdkClientOptions(dsn, service, release, environment string) sentry.ClientOptions {
	transport := sentry.NewHTTPTransport()
	transport.BufferSize = 30
	transport.Timeout = 3 * time.Second
	return sentry.ClientOptions{
		Dsn: dsn, Release: release, Environment: environment, ServerName: service,
		Transport: transport, DisableLogs: true, DisableMetrics: true,
		HTTPClient:    &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		EnableTracing: true, TracesSampleRate: tracesSampleRate(),
		BeforeSend: scrubSensitive, BeforeSendTransaction: scrubSensitive,
	}
}

// FlareRecoverer captures panics to Flare and re-panics so the existing
// sanitized outer recovery middleware still renders the 500. Mount it AFTER
// Recoverer in the chain so it sees the panic first. Safe to mount when
// InitFlare was a no-op: capture calls on an uninitialized hub do nothing.
func FlareRecoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				observation, _ := r.Context().Value(httpObservationKey{}).(*httpObservation)
				if asError(rec) == http.ErrAbortHandler {
					if observation != nil {
						observation.aborted.Store(true)
					}
					panic(rec)
				}
				if observation != nil {
					observation.panicked.Store(true)
				}
				CaptureOperationFailure(r.Context(), OperationHTTP, FailurePanic)
				// Re-panic the original value for existing recovery behavior;
				// only the fixed signal and safe code stack leave this process.
				panic(rec)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// CaptureErr reports a non-panic error to Flare. No-op when reporting is
// disabled. Use for errors that are handled but should page someone.
func CaptureErr(err error) {
	if err == nil {
		return
	}
	CaptureOperationFailure(context.Background(), OperationMail, FailureUnavailable)
}

// CaptureWorkerFatal emits a deliberately data-free fatal signal and waits for
// the Sentry transport before a worker supervisor terminates the process. The
// native slog shipper is asynchronous, so a log followed by os.Exit cannot be
// relied on to leave the process. Never accept the recovered panic value here:
// panic payloads can contain contract data or credentials.
func CaptureWorkerFatal(loop string, panicked bool) {
	failure := "unexpected_return"
	if panicked {
		failure = "panic"
	}
	hub := sentry.CurrentHub().Clone()
	hub.WithScope(func(scope *sentry.Scope) {
		scope.Clear()
		scope.SetLevel(sentry.LevelFatal)
		if id := currentIdentity.Load(); id != nil {
			scope.SetTag("service", id.service)
			scope.SetTag("release", id.release)
			scope.SetTag("environment", id.environment)
		}
		scope.SetTag("worker_loop", loop)
		scope.SetTag("worker_failure", failure)
		scope.SetFingerprint([]string{"hash-worker-fatal", loop, failure})
		hub.CaptureMessage("critical Hash worker loop stopped")
	})
	// No configured client returns immediately. A configured asynchronous
	// transport gets a bounded chance to deliver before os.Exit skips defers.
	hub.Flush(2 * time.Second)
}

func asError(value any) error { err, _ := value.(error); return err }
