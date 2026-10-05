// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"strings"

	"context"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
)

type unreadImportBody struct{ reads int }

func (b *unreadImportBody) Read([]byte) (int, error) {
	b.reads++
	panic("overloaded upload body was read")
}
func (*unreadImportBody) Close() error { return nil }

func TestTemplateCapacityRejectedBeforeBodyRead(t *testing.T) {
	org := uuid.New()
	release, err := importguard.Shared.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	body := &unreadImportBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates", nil)
	req.Body = body
	response := httptest.NewRecorder()
	(&Server{}).createPDFTemplate(response, req, uuid.New(), org)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" || body.reads != 0 {
		t.Fatalf("admission failed: %d reads=%d", response.Code, body.reads)
	}
}

func TestReplacementImportCapacityRejectedBeforeBodyRead(t *testing.T) {
	org, user := uuid.New(), uuid.New()
	release, err := importguard.Shared.Acquire(org)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, path := range []string{"html", "md"} {
		body := &unreadImportBody{}
		req := httptest.NewRequest(http.MethodPost, "/"+uuid.New().String(), nil)
		ctx := context.WithValue(req.Context(), auth.UserIDKey, user)
		ctx = context.WithValue(ctx, auth.OrgIDKey, org)
		ctx = context.WithValue(ctx, auth.RoleKey, "owner")
		req = req.WithContext(ctx)
		req.Body = body
		router := chi.NewRouter()
		if path == "html" {
			router.Post("/{id}", (&Server{}).handleImportHTML)
		} else {
			router.Post("/{id}", (&Server{}).handleImportMarkdown)
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != 429 || response.Header().Get("Retry-After") == "" || body.reads != 0 {
			t.Fatalf("%s admission: %d reads=%d", path, response.Code, body.reads)
		}
	}
}

func TestReplacementImportScannerUnavailableBeforePersistence(t *testing.T) {
	ctx := context.Background()
	defer malwarescan.Configure(ctx, "", "development")
	if err := malwarescan.Configure(ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
		t.Fatal(err)
	}
	org := uuid.New()
	ctx = context.WithValue(ctx, auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	for _, input := range []struct{ kind, body string }{{"html", `{"html":"<p>content</p>","expected_updated_at":"2026-10-05T00:00:00Z"}`}, {"md", `{"markdown":"content","expected_updated_at":"2026-10-05T00:00:00Z"}`}} {
		router := chi.NewRouter()
		if input.kind == "html" {
			router.Post("/{id}", (&Server{}).handleImportHTML)
		} else {
			router.Post("/{id}", (&Server{}).handleImportMarkdown)
		}
		req := httptest.NewRequest(http.MethodPost, "/"+uuid.New().String(), strings.NewReader(input.body)).WithContext(ctx)
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)
		if response.Code != 503 || !strings.Contains(response.Body.String(), "upload scanning unavailable") {
			t.Fatalf("%s scanner gate: %d %s", input.kind, response.Code, response.Body.String())
		}
		release, err := importguard.Shared.Acquire(org)
		if err != nil {
			t.Fatal("rejection leaked admission", err)
		}
		release()
	}
}
