// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type sessionLookupDiagnosticOpaqueError struct{}

func (sessionLookupDiagnosticOpaqueError) Error() string { panic("raw error must never be formatted") }

type sessionLookupDiagnosticTimeout struct{}

func (sessionLookupDiagnosticTimeout) Error() string   { return "PRIVATE_CONNECTION_DETAIL" }
func (sessionLookupDiagnosticTimeout) Timeout() bool   { return true }
func (sessionLookupDiagnosticTimeout) Temporary() bool { return true }

// Exercise the real middleware and JSON logger: secrets in error messages,
// PostgreSQL details/codes, session values and URL must not cross the log boundary.
func TestSessionLookupFailureDiagnosticPreservesRefusalAndPrivacy(t *testing.T) {
	config, err := pgconn.ParseConfig("postgres://private_user:private_password@127.0.0.1/private_database?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	dialCalls := 0
	config.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		dialCalls++
		return nil, sessionLookupDiagnosticTimeout{}
	}
	_, dialErr := pgconn.ConnectConfig(context.Background(), config)
	if dialErr == nil || dialCalls != 1 || !pgconn.Timeout(dialErr) {
		t.Fatal("actual pgconn timeout fixture did not exercise one denied dial")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	deadline, end := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer end()
	postgres := func(code string) error {
		return &pgconn.PgError{Code: code, Message: "PRIVATE_SQL", Detail: "PRIVATE_IDENTITY", Where: "PRIVATE_QUERY"}
	}
	tests := []struct {
		name                                 string
		ctx                                  context.Context
		err                                  error
		request, postgres                    string
		canceled, deadline, timeout, connect bool
	}{
		{name: "opaque_error", ctx: context.Background(), err: sessionLookupDiagnosticOpaqueError{}, request: "active", postgres: "none"},
		{name: "request_canceled", ctx: canceled, err: errors.New("PRIVATE_SQL"), request: "canceled", postgres: "none"},
		{name: "request_deadline", ctx: deadline, err: errors.New("PRIVATE_SQL"), request: "deadline", postgres: "none"},
		{name: "wrapped_canceled", ctx: context.Background(), err: fmt.Errorf("PRIVATE_DETAIL: %w", context.Canceled), request: "active", postgres: "none", canceled: true},
		{name: "bare_deadline_is_not_pgconn_timeout", ctx: context.Background(), err: context.DeadlineExceeded, request: "active", postgres: "none", deadline: true},
		{name: "actual_pgconn_dial_timeout", ctx: context.Background(), err: dialErr, request: "active", postgres: "none", timeout: true, connect: true},
		{name: "query_cancel", ctx: context.Background(), err: postgres("57014"), request: "active", postgres: "query_canceled"},
		{name: "lock_refusal", ctx: context.Background(), err: postgres("55P03"), request: "active", postgres: "lock_unavailable"},
		{name: "connection_limit", ctx: context.Background(), err: postgres("53300"), request: "active", postgres: "connection_limit"},
		{name: "server_unavailable", ctx: context.Background(), err: postgres("57P03"), request: "active", postgres: "server_unavailable"},
		{name: "connection_exception", ctx: context.Background(), err: postgres("08006"), request: "active", postgres: "connection_exception"},
		{name: "arbitrary_code_redacted", ctx: context.Background(), err: postgres("PRIVATE_CODE"), request: "active", postgres: "other"},
		{name: "joined_causes", ctx: canceled, err: errors.Join(postgres("57014"), context.Canceled, context.DeadlineExceeded), request: "canceled", postgres: "query_canceled", canceled: true, deadline: true},
	}
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	cookies, err := NewSignedCookie(strings.Repeat("a", 64))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var output bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
			store := &sessionUserStoreStub{err: test.err}
			userID := uuid.New()
			req := signedSessionRequest(t, cookies, SessionPayload{UserID: userID, OrgID: uuid.New(), Role: "owner", Email: "PRIVATE_EMAIL"})
			req = req.WithContext(test.ctx)
			req.URL.Path = "/PRIVATE_PATH"
			h := RequireSession(cookies, "hash_session", store)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("lookup error reached protected handler") }))
			response := httptest.NewRecorder()
			h.ServeHTTP(response, req)
			if response.Code != http.StatusServiceUnavailable || response.Body.String() != "session authorization unavailable\n" || len(response.Result().Cookies()) != 0 || store.requested != userID {
				t.Fatal("diagnostic changed authorization refusal/body/cookie/lookup behavior")
			}
			var record map[string]any
			decoder := json.NewDecoder(&output)
			if err := decoder.Decode(&record); err != nil {
				t.Fatal(err)
			}
			if decoder.Decode(new(any)) != io.EOF {
				t.Fatal("more than one diagnostic record")
			}
			want := map[string]any{
				"level": "WARN", "msg": "session authorization lookup failed", "operation": "get_user",
				"request_context": test.request, "lookup_error_canceled": test.canceled, "lookup_error_deadline": test.deadline,
				"pgconn_timeout": test.timeout, "connect_error": test.connect, "postgres_class": test.postgres,
			}
			if _, ok := record["time"]; !ok {
				t.Fatal("missing log timestamp")
			}
			delete(record, "time")
			if len(record) != len(want) {
				t.Fatal("diagnostic contains unexpected fields")
			}
			for key, value := range want {
				if record[key] != value {
					t.Fatalf("closed diagnostic field %s differs", key)
				}
			}
			encoded, _ := json.Marshal(record)
			if bytes.Contains(encoded, []byte("PRIVATE_")) || bytes.Contains(encoded, []byte("private_")) || bytes.Contains(encoded, []byte(userID.String())) {
				t.Fatal("private error or request data leaked")
			}
		})
	}
	// Deletion is an authorization denial, not an operational lookup failure.
	var output bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	h := RequireSession(cookies, "hash_session", &sessionUserStoreStub{err: pgx.ErrNoRows})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("deleted user reached protected handler") }))
	response := httptest.NewRecorder()
	h.ServeHTTP(response, signedSessionRequest(t, cookies, SessionPayload{UserID: uuid.New()}))
	if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 1 || output.Len() != 0 {
		t.Fatal("deleted-user semantics or diagnostic scope changed")
	}
}
