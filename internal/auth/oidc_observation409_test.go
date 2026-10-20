// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/flarereport"
	coreoidc "github.com/coreos/go-oidc/v3/oidc"
	sentry "github.com/getsentry/sentry-go"
	"golang.org/x/oauth2"
)

type oidcPrivateError409 struct{}

func (oidcPrivateError409) Error() string { panic("observer read private error text") }

type oidcEvents409 struct {
	mu     sync.Mutex
	events [][]byte
}

func (*oidcEvents409) Configure(sentry.ClientOptions)            {}
func (*oidcEvents409) Flush(time.Duration) bool                  { return true }
func (*oidcEvents409) FlushWithContext(ctx context.Context) bool { return ctx.Err() == nil }
func (*oidcEvents409) Close()                                    {}
func (m *oidcEvents409) SendEvent(event *sentry.Event) {
	raw, _ := json.Marshal(event)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, raw)
}
func (m *oidcEvents409) snapshot() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.events...)
}
func oidcContext409(t *testing.T) (context.Context, *oidcEvents409) {
	t.Helper()
	transport := &oidcEvents409{}
	client, err := sentry.NewClient(sentry.ClientOptions{Dsn: "https://fixture@flare.example/1", Transport: transport, ServerName: "hash", Release: strings.Repeat("a", 40), Environment: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return sentry.SetHubOnContext(context.Background(), sentry.NewHub(client, sentry.NewScope())), transport
}

func TestOIDCProvider409TypedOutcomesWithoutErrorText(t *testing.T) {
	retrieve := func(status int, code string) error {
		return &oauth2.RetrieveError{Response: &http.Response{StatusCode: status}, ErrorCode: code, Body: []byte("PRIVATE_BODY_409")}
	}
	for _, tc := range []struct {
		name      string
		operation flarereport.Operation
		err       error
		want      flarereport.Outcome
	}{
		{"success", flarereport.OperationOIDCTokenExchange, nil, flarereport.OutcomeSuccess},
		{"cancel", flarereport.OperationOIDCTokenExchange, context.Canceled, flarereport.OutcomeCanceled},
		{"deadline", flarereport.OperationOIDCDiscovery, context.DeadlineExceeded, flarereport.OutcomeTimeout},
		{"invalid-grant", flarereport.OperationOIDCTokenExchange, retrieve(400, "invalid_grant"), flarereport.OutcomeRejected},
		{"access-denied", flarereport.OperationOIDCTokenExchange, retrieve(403, "access_denied"), flarereport.OutcomeRejected},
		{"bad-client", flarereport.OperationOIDCTokenExchange, retrieve(400, "invalid_client"), flarereport.OutcomeDependency},
		{"unknown-client-auth", flarereport.OperationOIDCTokenExchange, retrieve(401, ""), flarereport.OutcomeDependency},
		{"wrong-endpoint", flarereport.OperationOIDCTokenExchange, retrieve(404, ""), flarereport.OutcomeDependency},
		{"empty400", flarereport.OperationOIDCTokenExchange, retrieve(400, ""), flarereport.OutcomeDependency},
		{"unknown400", flarereport.OperationOIDCTokenExchange, retrieve(400, "PRIVATE_UNKNOWN_PROTOCOL_409"), flarereport.OutcomeDependency},
		{"invalid-scope", flarereport.OperationOIDCTokenExchange, retrieve(400, "invalid_scope"), flarereport.OutcomeDependency},
		{"invalid-request", flarereport.OperationOIDCTokenExchange, retrieve(400, "invalid_request"), flarereport.OutcomeDependency},
		{"unsupported-grant", flarereport.OperationOIDCTokenExchange, retrieve(400, "unsupported_grant_type"), flarereport.OutcomeDependency},
		{"provider-rate", flarereport.OperationOIDCTokenExchange, retrieve(429, "invalid_grant"), flarereport.OutcomeDependency},
		{"provider-unavailable", flarereport.OperationOIDCTokenExchange, retrieve(503, "invalid_grant"), flarereport.OutcomeDependency},
		{"private-error", flarereport.OperationOIDCDiscovery, oidcPrivateError409{}, flarereport.OutcomeDependency},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := oidcProviderOutcome409(tc.operation, tc.err); got != tc.want {
				t.Fatal("typed outcome mismatch", got, tc.want)
			}
		})
	}
}

type oidcBody409 struct {
	io.Reader
	closed *int
}

func (b *oidcBody409) Close() error { (*b.closed)++; return nil }

func TestOIDCProvider409ActualCallbackFailureBoundaryAndPrivacy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		code   string
		issues int
	}{
		{"outage", 503, "temporarily_unavailable", 1},
		{"bad-grant", 400, "invalid_grant", 0},
		{"bad-client", 400, "invalid_client", 1},
		{"consent-denial", 403, "access_denied", 0},
		{"unknown400", 400, "", 1},
		{"invalid-scope", 400, "invalid_scope", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, captured := oidcContext409(t)
			calls, closed := 0, 0
			peer := &http.Client{Transport: callbackTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if deadline, ok := r.Context().Deadline(); !ok || time.Until(deadline) > 30*time.Second {
					t.Fatal("original callback deadline changed")
				}
				raw := `{"error":"` + tc.code + `","error_description":"PRIVATE_TOKEN_BODY_409"}`
				return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: &oidcBody409{Reader: strings.NewReader(raw), closed: &closed}, Request: r}, nil
			})}
			ctx = context.WithValue(ctx, oauth2.HTTPClient, peer)
			o := &OIDC{oauth2: &oauth2.Config{ClientID: "PRIVATE_CLIENT_409", ClientSecret: "PRIVATE_SECRET_409", Endpoint: oauth2.Endpoint{TokenURL: "https://PRIVATE_IDP_409/token"}}}
			r := httptest.NewRequest(http.MethodGet, "https://hash.example/auth/callback?state=s&code=PRIVATE_CODE_409", nil)
			r.Header.Set("Cookie", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v")
			_, _, _, _, err := o.Callback(ctx, r)
			if err == nil || calls == 0 || closed != calls {
				t.Fatal("original exchange failure/body-close behavior changed")
			}
			events := captured.snapshot()
			if len(events) != tc.issues {
				t.Fatal("provider outage/refusal issue classification changed", len(events))
			}
			for _, raw := range events {
				if strings.Contains(string(raw), "PRIVATE_") {
					t.Fatal("provider credentials/body/code exported")
				}
				var event map[string]any
				if json.Unmarshal(raw, &event) != nil {
					t.Fatal("invalid fixed event")
				}
				tags, _ := event["tags"].(map[string]any)
				if tags["operation"] != string(flarereport.OperationOIDCTokenExchange) || tags["failure_category"] != "dependency" {
					t.Fatal("fixed provider stage missing")
				}
			}
		})
	}
}

func TestOIDCProvider409InvalidStatePrecedesAllProviderCallsAndIssues(t *testing.T) {
	ctx, captured := oidcContext409(t)
	calls := 0
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: callbackTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("PRIVATE_SHOULD_NOT_RUN_409")
	})})
	o := &OIDC{cfg: OIDCConfig{IssuerURL: "https://PRIVATE_ISSUER_409"}}
	r := httptest.NewRequest(http.MethodGet, "https://hash.example/auth/callback?state=wrong&code=PRIVATE_CODE_409", nil)
	r.Header.Set("Cookie", "hash_oauth_state=s; hash_oauth_nonce=n; hash_oauth_verifier=v")
	if _, _, _, _, err := o.Callback(ctx, r); err == nil || calls != 0 || len(captured.snapshot()) != 0 {
		t.Fatal("invalid state became a provider attempt/pageable failure")
	}
}

func TestOIDCProvider409DiscoveryFailureAndCacheAreActualBoundaries(t *testing.T) {
	ctx, captured := oidcContext409(t)
	calls := 0
	peer := &http.Client{Transport: callbackTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("PRIVATE_DISCOVERY_409")), Header: http.Header{}, Request: r}, nil
	})}
	o := &OIDC{cfg: OIDCConfig{IssuerURL: "https://idp.example", DiscoveryTimeout: time.Second}}
	if _, _, err := o.resolve(coreoidc.ClientContext(ctx, peer)); err == nil || calls != 1 || len(captured.snapshot()) != 1 {
		t.Fatal("actual discovery failure missing or duplicated")
	}
	for _, raw := range captured.snapshot() {
		if strings.Contains(string(raw), "PRIVATE_DISCOVERY_409") {
			t.Fatal("private discovery response exported")
		}
	}
	ctx, captured = oidcContext409(t)
	calls = 0
	peer = &http.Client{Transport: callbackTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		raw := `{"issuer":"https://idp.example","authorization_endpoint":"https://idp.example/auth","token_endpoint":"https://idp.example/token","jwks_uri":"https://idp.example/keys"}`
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw)), Header: http.Header{"Content-Type": []string{"application/json"}}, Request: r}, nil
	})}
	o = &OIDC{cfg: OIDCConfig{IssuerURL: "https://idp.example", ClientID: "fixture", DiscoveryTimeout: time.Second}}
	ctx = coreoidc.ClientContext(ctx, peer)
	first, verifier, err := o.resolve(ctx)
	if err != nil || first == nil || verifier == nil {
		t.Fatal("successful original discovery failed")
	}
	second, _, err := o.resolve(ctx)
	if err != nil || second != first || calls != 1 || len(captured.snapshot()) != 0 {
		t.Fatal("cached discovery became new provider work/error")
	}
}
