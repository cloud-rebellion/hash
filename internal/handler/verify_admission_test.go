// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"net/http"
	"net/http/httptest"
	"testing"
)

type unreadBody struct{ t *testing.T }

func (b unreadBody) Read([]byte) (int, error) {
	b.t.Fatal("busy verification read request body")
	return 0, nil
}
func (unreadBody) Close() error { return nil }

func TestVerifyBundleRejectsBeforeBodyWhenBusy(t *testing.T) {
	release, err := importguard.Shared.AcquireAnonymous()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	req := httptest.NewRequest(http.MethodPost, "/api/verify-bundle", nil)
	req.Body = unreadBody{t}
	w := httptest.NewRecorder()
	(&Server{}).handleVerifyBundle(w, req)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d headers %v", w.Code, w.Header())
	}
}

func TestVerifyBundleReleasesAdmissionAfterBadMultipart(t *testing.T) {
	w := httptest.NewRecorder()
	(&Server{}).handleVerifyBundle(w, httptest.NewRequest(http.MethodPost, "/api/verify-bundle", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	release, err := importguard.Shared.AcquireAnonymous()
	if err != nil {
		t.Fatal("failed request leaked admission", err)
	}
	release()
}

func TestScannerAcceptsVerifierSizeContract(t *testing.T) {
	if malwarescan.MaxBytes < maxVerifyBundleSize {
		t.Fatalf("scanner limit %d below verifier limit %d", malwarescan.MaxBytes, maxVerifyBundleSize)
	}
}
