// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/google/uuid"
)

func branding769Request(method, body string) *http.Request {
	ctx := context.WithValue(context.Background(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	return httptest.NewRequest(method, "/api/v1/branding", strings.NewReader(body)).WithContext(ctx)
}

func TestBranding769ConfigurationReportsEnforcedLogoCapability(t *testing.T) {
	for _, environment := range []string{"production", " PRODUCTION ", "development", "staging"} {
		t.Run(environment, func(t *testing.T) {
			response := httptest.NewRecorder()
			(&Server{Environment: environment}).handleGetOrgBranding(response, branding769Request(http.MethodGet, ""))
			if response.Code != http.StatusOK {
				t.Fatalf("GET status=%d", response.Code)
			}
			var result struct {
				branding.Branding
				Supported *bool `json:"logo_url_supported"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			allowed := branding.ValidateLogoURLForEnvironment(environment, "https://example.test/logo.png") == nil
			if result.Supported == nil || *result.Supported != allowed || result.Branding != branding.DefaultBranding() {
				t.Fatal("capability must match existing validation and preserve the full theme")
			}
		})
	}
	response := httptest.NewRecorder()
	(&Server{Environment: "production"}).handleGetOrgBranding(response, httptest.NewRequest(http.MethodGet, "/api/v1/branding", nil))
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "logo_url_supported") {
		t.Fatal("unauthenticated request exposed branding configuration")
	}
}

func TestBranding769LogoOmissionAndExplicitClearPreserveTheme(t *testing.T) {
	base := branding.DefaultBranding()
	base.LogoURL, base.LogoAlt = "https://legacy.example.test/logo.png", "Legacy company"
	for _, test := range []struct {
		name, input string
		clear       bool
	}{
		{"absent", `{}`, false},
		{"null-preserves", `{"logo_url":null,"logo_alt":null}`, false},
		{"explicit-empty-clears", `{"logo_url":"","logo_alt":""}`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var input brandingInput
			if err := json.Unmarshal([]byte(test.input), &input); err != nil {
				t.Fatal(err)
			}
			want := base
			if test.clear {
				want.LogoURL, want.LogoAlt = "", ""
			}
			got := mergeBrandingInput(base, input)
			if got != want {
				t.Fatal("logo clear changed other theme fields or omission lost the legacy value")
			}
			allowed := branding.ValidateLogoURLForEnvironment("production", got.LogoURL) == nil
			if allowed != test.clear {
				t.Fatal("only an explicit clear may make a legacy logo valid in production")
			}
		})
	}
}

func TestBranding769ProductionRejectsNewLogoBeforeMutation(t *testing.T) {
	for _, input := range []string{
		`{"logo_url":" https://example.test/new.png "}`,
		`{"logo_url":"https://example.test/new.png","logo_url_supported":true}`,
	} {
		response := httptest.NewRecorder()
		// A nil pool must stay unreachable; read-only capability metadata cannot
		// turn on production logo writes or bypass the existing validation.
		(&Server{Environment: "production"}).handleUpsertOrgBranding(response, branding769Request(http.MethodPut, input))
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "exact version") {
			t.Fatalf("new production logo reached mutation or lost the existing refusal: status=%d", response.Code)
		}
	}
}
