// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestSendReviewGateMapsDatabaseRefusalsToConflict(t *testing.T) {
	for name, msg := range map[string]string{
		"replaced PDF": "Replaced PDF requires review before sending",
		"agent-review": "Signing document requires a fresh human review before sending",
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Server{}).writeSendError(w, fmt.Errorf("send: %w", &pgconn.PgError{Code: "23514", Message: msg}))
			if w.Code != http.StatusConflict || w.Body.Len() == 0 {
				t.Fatalf("status %d body %q", w.Code, w.Body.String())
			}
		})
	}
	w := httptest.NewRecorder()
	(&Server{}).writeSendError(w, &pgconn.PgError{Code: "23514", Message: "some other check"})
	if w.Code == http.StatusConflict {
		t.Fatal("unrelated check violation became a review conflict")
	}
}
