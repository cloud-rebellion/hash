// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// L2 and N3: a deadlock, a serialization failure or a lock wait that outlived the
// transaction deadline (context deadline or 57014) is a retryable 503 with
// Retry-After. writeDSRRetryableV1 maps nothing else: 55P03 is a 409 and goes
// through writeDSRPrivacyContentionV1, and both are reached via
// classifyDSRDBErrorV1.
func TestWriteDSRRetryableMapsLockConflictsAndDeadlinesOnlyV1(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"deadlock", &pgconn.PgError{Code: "40P01"}, true},
		{"serialization", &pgconn.PgError{Code: "40001"}, true},
		{"wrapped deadlock", fmt.Errorf("gate: %w", fmt.Errorf("lock document: %w", &pgconn.PgError{Code: "40P01"})), true},
		{"query canceled", &pgconn.PgError{Code: "57014"}, true},
		{"context deadline", context.DeadlineExceeded, true},
		{"wrapped context deadline", fmt.Errorf("serialize erasure fulfilment: %w", context.DeadlineExceeded), true},
		{"client gone", context.Canceled, false},
		{"lock not available", &pgconn.PgError{Code: "55P03"}, false},
		{"unique violation", &pgconn.PgError{Code: "23505"}, false},
		{"plain error", errors.New("boom"), false},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			got := writeDSRRetryableV1(w, tc.err)
			if got != tc.want {
				t.Fatalf("handled=%v, want %v", got, tc.want)
			}
			if tc.want {
				if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
					t.Fatalf("status=%d Retry-After=%q", w.Code, w.Header().Get("Retry-After"))
				}
			} else if w.Body.Len() != 0 || w.Code != http.StatusOK || w.Header().Get("Retry-After") != "" {
				t.Fatalf("a non-retryable error wrote a response: %d %q", w.Code, w.Body.String())
			}
		})
	}
}

// N2 and N3: the single classifier behind fail() answers every contention shape
// with a retryable status instead of a 500, and leaves other errors alone.
func TestClassifyDSRDBErrorMapsEveryContentionShapeV1(t *testing.T) {
	for _, tc := range []struct {
		name       string
		err        error
		want       bool
		status     int
		retryAfter bool
	}{
		{"fence contention", &pgconn.PgError{Code: "55P03"}, true, http.StatusConflict, false},
		{"wrapped fence contention", fmt.Errorf("redact: %w", &pgconn.PgError{Code: "55P03"}), true, http.StatusConflict, false},
		{"deadlock", &pgconn.PgError{Code: "40P01"}, true, http.StatusServiceUnavailable, true},
		{"serialization", &pgconn.PgError{Code: "40001"}, true, http.StatusServiceUnavailable, true},
		{"statement canceled", &pgconn.PgError{Code: "57014"}, true, http.StatusServiceUnavailable, true},
		{"deadline", fmt.Errorf("lock: %w", context.DeadlineExceeded), true, http.StatusServiceUnavailable, true},
		{"unique violation", &pgconn.PgError{Code: "23505"}, false, http.StatusOK, false},
		{"plain error", errors.New("boom"), false, http.StatusOK, false},
		{"nil", nil, false, http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			if got := classifyDSRDBErrorV1(w, tc.err); got != tc.want {
				t.Fatalf("handled=%v, want %v", got, tc.want)
			}
			if w.Code != tc.status || (w.Header().Get("Retry-After") != "") != tc.retryAfter {
				t.Fatalf("status=%d Retry-After=%q, want %d retryAfter=%v", w.Code, w.Header().Get("Retry-After"), tc.status, tc.retryAfter)
			}
			if !tc.want && w.Body.Len() != 0 {
				t.Fatalf("an unclassified error wrote a response: %q", w.Body.String())
			}
		})
	}
}
