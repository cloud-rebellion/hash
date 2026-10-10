// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/jackc/pgx/v5"
)

func assertCRMErrorResponse(t *testing.T, recorder *httptest.ResponseRecorder, status int, useful string) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d want=%d body=%s", recorder.Code, status, recorder.Body.String())
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil || len(body) != 1 || body["error"] == "" {
		t.Fatalf("expected a bounded error-only JSON response: %s", recorder.Body.String())
	}
	if !strings.Contains(strings.ToLower(body["error"]), useful) || strings.Contains(recorder.Body.String(), "synthetic-private-crm-marker") {
		t.Fatalf("error must explain the next step without leaking upstream data: %s", recorder.Body.String())
	}
}

func TestCRMConnectionErrorsKeepOriginalSessionStatusAndRedactProviderDetails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		useful string
	}{
		{"expired original session", auth.ErrMutationCredentialExpired, http.StatusUnauthorized, "session"},
		{"revoked owner", auth.ErrMutationPermissionRevoked, http.StatusForbidden, "owner"},
		{"invalid input", errOwnerMutationInput, http.StatusBadRequest, "input"},
		{"changed generation", errCRMConnectionChanged, http.StatusConflict, "refresh"},
		{"missing audit row", pgx.ErrNoRows, http.StatusServiceUnavailable, "unavailable"},
		{"provider failure", errors.New("provider credential=synthetic-private-crm-marker"), http.StatusServiceUnavailable, "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			(&Server{}).writeCRMConnectionError(recorder, fmt.Errorf("synthetic-private-crm-marker: %w", tc.err))
			assertCRMErrorResponse(t, recorder, tc.status, tc.useful)
		})
	}
}

func TestCRMSendErrorsDistinguishChangedContentFromUnavailableConnection(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
		useful string
	}{
		{"changed reviewed information", resolver.ErrCRMReviewRequired, http.StatusConflict, "review"},
		{"missing connection", resolver.ErrNotConfigured, http.StatusServiceUnavailable, "owner"},
		{"failed source observation", resolver.ErrSourceFreshness, http.StatusServiceUnavailable, "connection"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			(&Server{}).writeSendError(recorder, fmt.Errorf("upstream bearer=synthetic-private-crm-marker: %w", tc.err))
			assertCRMErrorResponse(t, recorder, tc.status, tc.useful)
		})
	}
}

func TestCRMConnectionRoutesRequireOwnerForReadAndEveryMutation(t *testing.T) {
	// Exercise real Routes + signed session/live canonical user admission using
	// the existing native fixture. No DB mutation or remote client is available;
	// a missing owner guard would reach input/store errors instead of 403.
	for _, role := range []string{"viewer", "sender"} {
		for _, route := range []struct{ method, path string }{
			{http.MethodGet, "/api/v1/settings/crm/connection"},
			{http.MethodPut, "/api/v1/settings/crm/connection"},
			{http.MethodDelete, "/api/v1/settings/crm/connection"},
			{http.MethodPost, "/api/v1/settings/crm/connection/enable"},
		} {
			t.Run(role+" "+route.method+" "+route.path, func(t *testing.T) {
				if got := authorizedRouteStatus(t, role, route.method, route.path); got != http.StatusForbidden {
					t.Fatalf("non-owner reached CRM owner route: status=%d want=403", got)
				}
			})
		}
	}
}
