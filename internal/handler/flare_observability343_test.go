// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	sentry "github.com/getsentry/sentry-go"
	"github.com/go-chi/chi/v5"
)

func Test343ActualRecoveryChainCapturesHandledFailureAndPanicOnceButNotAbort(t *testing.T) {
	t.Setenv("FLARE_TRACES_SAMPLE_RATE", "0")
	for _, kind := range []string{"handled", "typed", "panic", "wrapped_abort", "abort"} {
		t.Run(kind, func(t *testing.T) {
			const private = "PRIVATE_CONTRACT_TOKEN_PROMPT_343"
			var mu sync.Mutex
			var wire strings.Builder
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				r.Body.Close()
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				wire.Write(raw)
				mu.Unlock()
				w.WriteHeader(http.StatusOK)
			}))
			defer receiver.Close()
			transport := sentry.NewHTTPTransport()
			transport.BufferSize = 30
			transport.Timeout = 3 * time.Second
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: strings.Replace(receiver.URL, "://", "://fixture-public@", 1) + "/1", Release: "343-handler", Environment: "test", Transport: transport, DisableLogs: true, DisableMetrics: true, HTTPClient: &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
			if err != nil {
				t.Fatal(err)
			}
			hub := sentry.NewHub(client, sentry.NewScope())
			hub.Scope().SetUser(sentry.User{Email: private})
			hub.Scope().SetContext("private", sentry.Context{"value": private})
			router := chi.NewRouter()
			router.Use(safeAccessLogger)
			router.Use(hashRecoverer)
			router.Use(panicMiddleware)
			router.Use(flarereport.FlareRecoverer)
			router.Post("/sign/{token}", func(w http.ResponseWriter, r *http.Request) {
				switch kind {
				case "handled":
					w.WriteHeader(http.StatusInternalServerError)
				case "typed":
					flarereport.CaptureOperationFailure(r.Context(), flarereport.OperationMCP, flarereport.FailureDependency)
					w.WriteHeader(http.StatusServiceUnavailable)
				case "panic":
					panic(private)
				case "wrapped_abort":
					panic(fmt.Errorf("private wrapped abort: %w", http.ErrAbortHandler))
				case "abort":
					panic(http.ErrAbortHandler)
				}
			})
			req := httptest.NewRequest(http.MethodPost, "https://hash.example/sign/"+private+"?code="+private, strings.NewReader(private))
			req.Header.Set("Authorization", "Bearer "+private)
			req.Header.Set("Cookie", "hash_sess="+private)
			req.Header.Set("baggage", "sentry-user_segment="+private)
			req = req.WithContext(sentry.SetHubOnContext(req.Context(), hub))
			recorder := httptest.NewRecorder()
			var recovered any
			func() { defer func() { recovered = recover() }(); router.ServeHTTP(recorder, req) }()
			if kind == "abort" {
				if recovered != http.ErrAbortHandler {
					t.Fatal("intentional abort was swallowed or replaced", recovered)
				}
			} else {
				wantStatus := http.StatusInternalServerError
				if kind == "typed" {
					wantStatus = http.StatusServiceUnavailable
				}
				if recovered != nil || recorder.Code != wantStatus {
					t.Fatal("actual recovery status differs", recovered, recorder.Code)
				}
			}
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if !client.FlushWithContext(cleanup) {
				t.Fatal("actual receiver flush did not join")
			}
			mu.Lock()
			encoded := wire.String()
			mu.Unlock()
			var eventCount int
			for _, line := range strings.Split(encoded, "\n") {
				var event map[string]any
				if json.Unmarshal([]byte(line), &event) == nil && event["platform"] != nil && event["event_id"] != nil {
					eventCount++
				}
			}
			wantCount := 1
			if kind == "abort" {
				wantCount = 0
			}
			if eventCount != wantCount || strings.Contains(encoded, private) {
				t.Fatal("actual handler telemetry count/privacy differs", eventCount, encoded)
			}
			if (kind == "panic" || kind == "wrapped_abort") && !strings.Contains(encoded, `"failure_category":"panic"`) {
				t.Fatal("panic lost fixed classification", encoded)
			}
			if kind == "typed" && !strings.Contains(encoded, `"operation":"mcp"`) {
				t.Fatal("typed failure was replaced by genericHTTP500", encoded)
			}
		})
	}
}

type streamWriter343 struct {
	*httptest.ResponseRecorder
	hijacked bool
}

func (w *streamWriter343) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, errors.New("fixture hijack witness")
}
func Test343AccessObservationPreservesFlushAndHijackInterfaces(t *testing.T) {
	t.Setenv("FLARE_TRACES_SAMPLE_RATE", "0")
	router := chi.NewRouter()
	router.Use(safeAccessLogger)
	router.Get("/stream", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Fatal("existing streaming interface lost")
		}
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("existing hijack interface lost")
		}
		flusher.Flush()
		_, _, _ = hijacker.Hijack()
	})
	writer := &streamWriter343{ResponseRecorder: httptest.NewRecorder()}
	router.ServeHTTP(writer, httptest.NewRequest(http.MethodGet, "https://hash.example/stream", nil))
	if !writer.Flushed || !writer.hijacked {
		t.Fatal("wrapper failed to forward actual streaming calls")
	}
}
func Test343PublicConfigAndCSPShareOnlyValidatedIngestOrigin(t *testing.T) {
	t.Setenv("FLARE_DSN", "https://public-key:PRIVATE_PASSWORD@flare.example.test/prefix/1")
	t.Setenv("UNRELATED_PRIVATE_CONFIG", "PRIVATE_GENERAL_CONFIG")
	server := &Server{Release: "343-release", Environment: "production"}
	router := chi.NewRouter()
	router.Use(server.securityHeaders)
	router.Get("/api/telemetry/config", server.handleFlareConfiguration)
	req := httptest.NewRequest(http.MethodGet, "https://hash.example/api/telemetry/config?target=https://attacker.invalid", nil)
	out := httptest.NewRecorder()
	router.ServeHTTP(out, req)
	var cfg flarereport.BrowserConfig
	if err := json.Unmarshal(out.Body.Bytes(), &cfg); err != nil {
		t.Fatal(err)
	}
	csp := out.Header().Get("Content-Security-Policy")
	if out.Code != 200 || out.Header().Get("Cache-Control") != "no-store" || !cfg.Enabled || cfg.Service != "hash-browser" || cfg.DSN != "https://public-key@flare.example.test/prefix/1" || !strings.Contains(csp, "connect-src 'self' https://flare.example.test;") || strings.Contains(out.Body.String()+csp, "PRIVATE_") || strings.Contains(csp, "attacker.invalid") {
		t.Fatal("public config/CSP contract differs", out.Code, out.Body.String(), csp)
	}
	t.Setenv("FLARE_DSN", "https://public-key@flare.example.test;/1")
	bad := httptest.NewRecorder()
	// Header policy is fixed at middleware construction, as process config is.
	server.securityHeaders(http.HandlerFunc(server.handleFlareConfiguration)).ServeHTTP(bad, req)
	if bad.Body.String() != "{\"enabled\":false}\n" || strings.Contains(bad.Header().Get("Content-Security-Policy"), "flare.example.test") {
		t.Fatal("invalid ingest authority enabled public browser config/CSP", bad.Body.String(), bad.Header())
	}
}
