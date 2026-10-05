// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func TestCollabPendingCapacityRejectsBeforeDatabaseOrUpgrade(t *testing.T) {
	s := &Server{Collab: collab.NewHub(nil)}
	releases := make([]func(), 0, maxPendingCollabHandshakes)
	for i := 0; i < maxPendingCollabHandshakes; i++ {
		release, ok := s.collabHandshakes.acquire()
		if !ok {
			t.Fatal("early refusal")
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()
	r := httptest.NewRequest(http.MethodGet, "/"+uuid.New().String(), nil)
	ctx := context.WithValue(r.Context(), auth.UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	router := chi.NewRouter()
	router.Get("/{id}", s.handleCollabSocket)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, r.WithContext(ctx))
	if response.Code != 429 || response.Header().Get("Retry-After") == "" {
		t.Fatalf("response=%d", response.Code)
	}
	// Queries is nil: reaching database access would panic instead of returning 429.
	releases[0]()
	releases[0]()
	release, ok := s.collabHandshakes.acquire()
	if !ok {
		t.Fatal("capacity not released")
	}
	release()
}

func TestCollabPendingAdmissionConcurrentBound(t *testing.T) {
	var gate collabHandshakeGate
	var wg sync.WaitGroup
	results := make(chan func(), 128)
	for i := 0; i < 128; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, ok := gate.acquire()
			if ok {
				results <- release
			}
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for release := range results {
		accepted++
		release()
		release()
	}
	if accepted != maxPendingCollabHandshakes || gate.active.Load() != 0 {
		t.Fatalf("accepted=%d active=%d", accepted, gate.active.Load())
	}
}
