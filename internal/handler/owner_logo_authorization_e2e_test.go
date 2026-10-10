//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func submitOwnerLogoE2E(f lifecycleAuthorizationFixture, ctx context.Context, cookie string) *httptest.ResponseRecorder {
	var body, raw bytes.Buffer
	canvas := image.NewRGBA(image.Rect(0, 0, 3, 3))
	canvas.Set(1, 1, color.RGBA{R: 255, A: 255})
	_ = png.Encode(&raw, canvas)
	form := multipart.NewWriter(&body)
	part, _ := form.CreateFormFile("logo", "brand.png")
	_, _ = part.Write(raw.Bytes())
	_ = form.Close()
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/branding/logo", &body).WithContext(ctx)
	r.Header.Set("Content-Type", form.FormDataContentType())
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func TestOwnerOrgLogoUploadRetainsAuthorizationAndCompensatesE2E(t *testing.T) {
	for _, failure := range []string{"demotion", "expiry", "cancellation", "audit-error", "audit-no-row"} {
		t.Run(failure, func(t *testing.T) {
			f, peer := setupImportAuthorizationE2E(t)
			if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "owner"}); err != nil {
				t.Fatal(err)
			}
			f.s.Environment = "development"
			originalKey := "branding/" + f.org.String() + "/logo.png"
			original := []byte("synthetic historical logo")
			peer.mu.Lock()
			peer.objects[originalKey] = original
			peer.mu.Unlock()
			of := ownerOrgMutationFixture{lifecycleAuthorizationFixture: f}
			var blocked interface{ Commit(context.Context) error }
			var drop func()
			if strings.HasPrefix(failure, "audit-") {
				drop = ownerOrgAuditFaultE2E(t, of, failure == "audit-no-row")
			} else {
				blocked = ownerOrgLockE2E(t, of, failure != "demotion")
			}
			ttl := time.Hour
			if failure == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, ttl)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitOwnerLogoE2E(f, ctx, cookie) }()
			if failure == "demotion" {
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetOrgForOwnerMutation", "transactionid")
				if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
					t.Fatal(err)
				}
			} else if drop == nil {
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			}
			var w *httptest.ResponseRecorder
			if failure == "expiry" {
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
			} else if failure == "cancellation" {
				cancel()
				w = receiveSessionOperationE2E(t, result)
			}
			if blocked != nil {
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
			}
			if w == nil {
				w = receiveSessionOperationE2E(t, result)
			}
			want := http.StatusInternalServerError
			if failure == "demotion" {
				want = http.StatusForbidden
			}
			if failure == "expiry" {
				want = http.StatusUnauthorized
			}
			if w.Code != want {
				t.Fatalf("logo refusal=%d want=%d %s", w.Code, want, w.Body.String())
			}
			peer.mu.Lock()
			puts, deletes, objects := peer.puts, peer.deletes, len(peer.objects)
			old := append([]byte(nil), peer.objects[originalKey]...)
			peer.mu.Unlock()
			wantWrites := 1
			if failure == "demotion" {
				wantWrites = 0
			}
			if puts != wantWrites || deletes != wantWrites || objects != 1 || !bytes.Equal(original, old) {
				t.Fatalf("logo compensation puts=%d deletes=%d objects=%d old=%q", puts, deletes, objects, old)
			}
			var audits int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind='branding.logo_uploaded'`, f.org).Scan(&audits); err != nil || audits != 0 {
				t.Fatalf("rejected logo audit=%d err=%v", audits, err)
			} //nolint:rawsql
			if drop != nil {
				drop()
			}
		})
	}
}

func TestOwnerOrgLogoUploadUniqueURLsAndLegacyReadE2E(t *testing.T) {
	f, peer := setupImportAuthorizationE2E(t)
	if _, err := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	f.s.Environment = "development"
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, 0, time.Hour)
	var first string
	for i := 0; i < 2; i++ {
		w := submitOwnerLogoE2E(f, f.ctx, cookie)
		if w.Code != http.StatusOK {
			t.Fatalf("logo upload=%d %s", w.Code, w.Body.String())
		}
		var out struct {
			URL string `json:"logo_url"`
			Key string `json:"key"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = out.URL
		} else if out.URL == first {
			t.Fatal("logo edit reused an old document asset URL")
		}
		req := httptest.NewRequest(http.MethodGet, out.URL, nil)
		res := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(res, req)
		if res.Code != http.StatusOK || !bytes.HasPrefix(res.Body.Bytes(), []byte("\x89PNG")) {
			t.Fatalf("new logo URL unavailable=%d %s", res.Code, res.Body.String())
		}
	}
	peer.mu.Lock()
	peer.objects["branding/"+f.org.String()+"/logo.png"] = []byte("legacy-logo")
	peer.mu.Unlock()
	res := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(res, httptest.NewRequest(http.MethodGet, f.s.PublicURL+"/branding/logo/"+f.org.String()+".png", nil))
	if res.Code != http.StatusOK || res.Body.String() != "legacy-logo" {
		t.Fatalf("legacy logo URL changed=%d %s", res.Code, res.Body.String())
	}
}
