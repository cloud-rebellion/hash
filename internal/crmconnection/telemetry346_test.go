// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

type crmTelemetryDoer346 func(*http.Request) (*http.Response, error)

func (f crmTelemetryDoer346) Do(r *http.Request) (*http.Response, error) { return f(r) }

type crmClosedBody346 struct {
	io.Reader
	closed *atomic.Bool
}

func (b crmClosedBody346) Close() error { b.closed.Store(true); return nil }

type crmTelemetryTransport346 struct {
	mu     sync.Mutex
	rows   [][]byte
	closed *atomic.Bool
	t      *testing.T
}

func (*crmTelemetryTransport346) Configure(sentry.ClientOptions)        {}
func (*crmTelemetryTransport346) Flush(time.Duration) bool              { return true }
func (*crmTelemetryTransport346) FlushWithContext(context.Context) bool { return true }
func (*crmTelemetryTransport346) Close()                                {}
func (s *crmTelemetryTransport346) SendEvent(e *sentry.Event) {
	if !s.closed.Load() {
		s.t.Error("telemetry ran before actual response body closed")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		s.t.Error(err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, raw)
}

func TestCRMTransportOutcomeTelemetryPreservesPrivateBoundaries346(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		signal bool
	}{
		{"upstream failure", http.StatusBadGateway, "private-contract-346@example.test Bearer private-token-346", true},
		{"malformed success", http.StatusOK, "private-contract-346@example.test", true},
		{"credential denial", http.StatusUnauthorized, "private-contract-346@example.test", false},
		{"record absence", http.StatusNotFound, "private-contract-346@example.test", false},
		{"rate limit", http.StatusTooManyRequests, "private-contract-346@example.test", false},
		{"success", http.StatusOK, `{"note":"private-contract-346@example.test"}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var closed atomic.Bool
			transport := &crmTelemetryTransport346{closed: &closed, t: t}
			client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://public@flare.invalid/1", Transport: transport})
			if err != nil {
				t.Fatal(err)
			}
			ctx := sentry.SetHubOnContext(context.Background(), sentry.NewHub(client, sentry.NewScope()))
			c := &Client{origin: "https://crm.invalid", now: time.Now, doer: crmTelemetryDoer346(func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer private-token-346" {
					t.Fatal("original credential path changed")
				}
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: crmClosedBody346{Reader: strings.NewReader(tc.body), closed: &closed}}, nil
			})}
			budget := MaxResponseBytes
			_, _, callErr := c.get(ctx, "/private-customer-346", "private-token-346", &budget)
			if tc.name == "success" && callErr != nil || tc.name != "success" && callErr == nil {
				t.Fatal("actual CRM outcome changed", callErr)
			}
			if !closed.Load() {
				t.Fatal("actual body not closed")
			}
			transport.mu.Lock()
			defer transport.mu.Unlock()
			want := 0
			if tc.signal {
				want = 1
			}
			if len(transport.rows) != want {
				t.Fatalf("signals=%d want=%d", len(transport.rows), want)
			}
			for _, raw := range transport.rows {
				for _, private := range []string{"private-contract-346", "private-token-346", "private-customer-346", "crm.invalid"} {
					if strings.Contains(string(raw), private) {
						t.Fatal("private CRM context reached telemetry")
					}
				}
				var event sentry.Event
				if json.Unmarshal(raw, &event) != nil || event.Tags["operation"] != "crm" || event.Tags["failure_category"] != "dependency" {
					t.Fatal("missing fixed CRM failure context", string(raw))
				}
			}
		})
	}
}
