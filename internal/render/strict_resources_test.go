// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestContractRenderRequiresAllResourcesAndDoesNotRetryRefusal(t *testing.T) {
	var attempts atomic.Int32
	var strict atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/forms/chromium/convert/html" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "invalid multipart", http.StatusBadRequest)
			return
		}
		defer r.MultipartForm.RemoveAll()
		strict.Store(len(r.MultipartForm.Value["failOnResourceLoadingFailed"]) == 1 && r.FormValue("failOnResourceLoadingFailed") == "true")
		http.Error(w, "Chromium failed to load resources", http.StatusConflict)
	}))
	defer server.Close()
	pdf, err := NewGotenberg(server.URL).HTMLToPDF(context.Background(), "<p>Contract</p>", PDFOptions{Assets: []FontAsset{}})
	if err == nil || !strings.Contains(err.Error(), "409") || len(pdf) != 0 || !strict.Load() || attempts.Load() != 1 {
		t.Fatalf("partial output or refusal policy lost: bytes=%d err=%v strict=%v attempts=%d", len(pdf), err, strict.Load(), attempts.Load())
	}
}

func TestOwnedContractRenderResourceRefusalRetiresAdmission(t *testing.T) {
	ctx, coordinator, org := htmlLocalTestAdmissionV1(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		reader, err := r.MultipartReader()
		strict := false
		if err == nil {
			for {
				part, nextErr := reader.NextPart()
				if nextErr == io.EOF {
					break
				}
				if nextErr != nil {
					break
				}
				value, readErr := io.ReadAll(io.LimitReader(part, 1<<20))
				_ = part.Close()
				if readErr == nil && part.FormName() == "failOnResourceLoadingFailed" && string(value) == "true" {
					strict = true
				}
			}
		}
		if !strict {
			http.Error(w, "strict policy missing", http.StatusBadRequest)
			return
		}
		http.Error(w, "resource unavailable", http.StatusConflict)
	}))
	defer server.Close()
	result, err := NewGotenberg(server.URL).HTMLToPDFLocalOwnedV1(ctx, "<p>Contract</p>", PDFOptions{Assets: []FontAsset{}, MaxResponseBytes: 16384}, coordinator, org)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if result == nil || err == nil || !strings.Contains(err.Error(), "409") || calls.Load() != 1 {
		t.Fatalf("owned refusal changed: result=%v err=%v calls=%d", result != nil, err, calls.Load())
	}
	consumed := false
	if accessErr := result.WithPDFV1(func([]byte) error { consumed = true; return nil }); accessErr == nil || consumed {
		t.Fatal("refused render exposed a partial PDF to a consumer")
	}
	// This API deliberately returns a closable ownership handle on errors.
	// Release its consumer only after proving that it exposes no PDF bytes.
	result.CloseConsumerV1()
	if got := coordinator.SnapshotV1(org); got.Global.ProviderStreams != 0 || got.Global.ParentBytes != 0 || got.GlobalGrants != 0 {
		t.Fatal("refused resource retained actual local admission", got)
	}
}
