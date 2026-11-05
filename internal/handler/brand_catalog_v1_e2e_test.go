//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	brandcatalog "github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These fixtures retain catalog history in the caller's disposable database.
// They deliberately do not delete the organization: immutable catalog rows
// must continue to prevent an accidental cascading deletion.
func brandCatalogFixture783(t *testing.T) folderFixture695 {
	t.Helper()
	ctx, pool, q, s, org, userID := setupDSRE2E(t)
	u, err := q.GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	return folderFixture695{lifecycleAuthorizationFixture: lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: u}, cookie: dsrSessionCookieE2E(t, s, userID, u.SessionGeneration, time.Hour)}
}

func brandCatalogJSON783(t *testing.T, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}

func brandCatalogProfile783(t *testing.T, f folderFixture695, in brandcatalog.ProfileInputV1) brandcatalog.ProfileV1 {
	t.Helper()
	w := f.request(http.MethodPost, "/api/v1/brand-profiles", brandCatalogJSON783(t, in))
	var p brandcatalog.ProfileV1
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.ProfileID == uuid.Nil || p.Revision != 1 || len(p.ContentSHA256) != 64 {
		t.Fatalf("create catalog profile: %d %s", w.Code, w.Body.String())
	}
	return p
}

func TestBrandCatalog783ProfilesCASDefaultProjectionAndTenantE2E(t *testing.T) {
	f := brandCatalogFixture783(t)
	p := brandcatalog.DefaultProfileDataV1()
	p.Guidance = "Keep supplied proportions and declared spacing."
	p.Palette.Colors["accessible_accent"] = "#222222"
	p.Palette.Roles.AccentText = "accessible_accent"
	first := brandCatalogProfile783(t, f, brandcatalog.ProfileInputV1{Name: "Example complete profile", Profile: p})
	path := "/api/v1/brand-profiles/" + first.ProfileID.String()
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	for _, name := range []string{"First competing revision", "Second competing revision"} {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			codes <- f.request(http.MethodPost, path+"/revisions", brandCatalogJSON783(t, brandcatalog.ProfileInputV1{Name: name, ExpectedRevision: 1, Profile: p})).Code
		}(name)
	}
	wg.Wait()
	close(codes)
	ok, conflict := 0, 0
	for c := range codes {
		switch c {
		case 200:
			ok++
		case 409:
			conflict++
		default:
			t.Fatal("unexpected profile CAS result", c)
		}
	}
	if ok != 1 || conflict != 1 {
		t.Fatal("profile CAS admitted more than one successor", ok, conflict)
	}
	var current brandcatalog.ProfileV1
	w := f.request(http.MethodGet, path, "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.Revision != 2 {
		t.Fatal("profile successor missing", w.Code)
	}
	var old brandcatalog.ProfileV1
	w = f.request(http.MethodGet, path+"?revision=1", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &old) != nil || old.ContentSHA256 != first.ContentSHA256 || old.Name != first.Name {
		t.Fatal("profile revision was rewritten")
	}
	selection := map[string]any{"profile_id": first.ProfileID, "revision": 1, "content_sha256": first.ContentSHA256, "expected_selection_revision": 0}
	w = f.request(http.MethodPut, "/api/v1/branding/default-profile", brandCatalogJSON783(t, selection))
	if w.Code != 200 {
		t.Fatal("select exact older revision", w.Code, w.Body.String())
	}
	if w = f.request(http.MethodPut, "/api/v1/branding/default-profile", brandCatalogJSON783(t, selection)); w.Code != 409 {
		t.Fatal("selection CAS did not refuse stale revision", w.Code)
	}
	// The legacy adapter must append to the same profile, retaining the full
	// selected palette/guidance while updating its scalar projection atomically.
	w = f.request(http.MethodPut, "/api/v1/branding", `{"primary_hex":"#334455"}`)
	if w.Code != 200 {
		t.Fatal("legacy projection join failed", w.Code, w.Body.String())
	}
	var selected brandcatalog.DefaultSelectionV1
	w = f.request(http.MethodGet, "/api/v1/branding/default-profile", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &selected) != nil || !selected.Configured || selected.Revision != 3 || selected.SelectionRevision != 2 {
		t.Fatal("legacy mutation lost catalog revision or selection", w.Code)
	}
	w = f.request(http.MethodGet, path+"?revision=3", "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &current) != nil || current.Profile.Guidance != p.Guidance || current.Profile.Palette.Colors["accessible_accent"] != "#222222" || current.Profile.Palette.Colors[current.Profile.Palette.Roles.Primary] != "#334455" {
		t.Fatal("legacy projection erased extended profile data")
	}
	if _, e := f.pool.Exec(f.ctx, `UPDATE org_branding SET primary_hex='#000000' WHERE org_id=$1`, f.org); e == nil {
		t.Fatal("unbound legacy SQL bypassed selected profile")
	}
	if _, e := f.pool.Exec(f.ctx, `UPDATE brand_profile_revisions_v1 SET name='mutated' WHERE org_id=$1 AND profile_id=$2 AND revision=1`, f.org, first.ProfileID); e == nil {
		t.Fatal("retained profile revision was mutable")
	}
	other := brandCatalogFixture783(t)
	if w = other.request(http.MethodGet, path, ""); w.Code != 404 {
		t.Fatal("cross-tenant profile disclosed", w.Code)
	}
	if _, e := f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); e != nil {
		t.Fatal(e)
	}
	if w = f.request(http.MethodPost, path+"/revisions", brandCatalogJSON783(t, brandcatalog.ProfileInputV1{Name: "Revoked write", ExpectedRevision: 3, Profile: p})); w.Code != 403 {
		t.Fatal("revoked owner wrote catalog", w.Code)
	}
	if w = f.request(http.MethodGet, path, ""); w.Code != 200 {
		t.Fatal("current viewer cannot read own catalog", w.Code)
	}
}

func TestBrandCatalog783OriginalAssetVersionsReplayAndScopeE2E(t *testing.T) {
	f := brandCatalogFixture783(t)
	peer := &importStoragePeer{objects: map[string][]byte{}}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	f.s.Storage, err = storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-brand-catalog", SecretKey: "synthetic-brand-catalog-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	var pngBytes bytes.Buffer
	if e := png.Encode(&pngBytes, image.NewRGBA(image.Rect(0, 0, 2, 2))); e != nil {
		t.Fatal(e)
	}
	original := []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Example symbol" viewBox="0 0 32 32"><title>Exact supplied original</title><path fill="#223344" d="M0 0H32V32H0Z"/></svg>`)
	in := brandcatalog.AssetUploadV1{RequestID: uuid.New(), Name: "Example exact vector", MediaType: "image/svg+xml", OriginalBase64: base64.StdEncoding.EncodeToString(original), RenderPNGBase64: base64.StdEncoding.EncodeToString(pngBytes.Bytes())}
	upload := func(v brandcatalog.AssetUploadV1, want int) brandcatalog.AssetV1 {
		t.Helper()
		w := f.request(http.MethodPost, "/api/v1/brand-assets", brandCatalogJSON783(t, v))
		var a brandcatalog.AssetV1
		if w.Code != want {
			t.Fatalf("asset upload: %d %s", w.Code, w.Body.String())
		}
		if want == 201 && json.Unmarshal(w.Body.Bytes(), &a) != nil {
			t.Fatal("invalid asset DTO")
		}
		return a
	}
	a := upload(in, 201)
	sum := sha256.Sum256(original)
	if a.AssetID == uuid.Nil || a.Revision != 1 || a.Original.SHA256 != hex.EncodeToString(sum[:]) || a.RenderMethod != "provided_png_v1" {
		t.Fatal("asset lost original/variant identity")
	}
	peer.mu.Lock()
	puts := peer.puts
	peer.mu.Unlock()
	again := upload(in, 201)
	peer.mu.Lock()
	replayPuts := peer.puts
	peer.mu.Unlock()
	if again.AssetID != a.AssetID || again.Revision != a.Revision || puts != 2 || replayPuts != puts {
		t.Fatal("same durable request re-uploaded or duplicated asset", puts, replayPuts)
	}
	// The bounded machine import is independent of the MCP envelope and uses
	// the SAME original API-key receipt/scopes through final owner commit.
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	machineKey := func(scopes []string) string {
		t.Helper()
		k, e := auth.MintAPIKey()
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, KeyPrefix: k.Prefix, KeyHash: k.Hash, Name: "Synthetic catalog import", Scopes: scopes, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); e != nil {
			t.Fatal(e)
		}
		return k.Plaintext
	}
	key := machineKey([]string{"read", "write:authoring"})
	readOnly := machineKey([]string{"read"})
	machine := func(credential, method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, f.s.PublicURL+path, strings.NewReader(body)).WithContext(f.ctx)
		r.Header.Set("Authorization", "Bearer "+credential)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		return w
	}
	if w := machine(key, http.MethodPost, "/api/automation/v1/brand-assets", brandCatalogJSON783(t, in)); w.Code != 201 {
		t.Fatal("same organization API key import refused", w.Code, w.Body.String())
	}
	if w := machine(readOnly, http.MethodPost, "/api/automation/v1/brand-assets", brandCatalogJSON783(t, in)); w.Code != 403 {
		t.Fatal("read-only API key imported catalog asset", w.Code)
	}
	doc, err := f.q.CreateBlocksDocument(f.ctx, generated.CreateBlocksDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Synthetic document-key scope", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	docKey, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: doc.ID, OrgID: f.org, Name: "Synthetic document credential", Prefix: docKey.Prefix, KeyHash: docKey.Hash, Scopes: []string{"read", "write:authoring"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}}); err != nil {
		t.Fatal(err)
	}
	if w := machine(docKey.Plaintext, http.MethodPost, "/api/automation/v1/brand-assets", brandCatalogJSON783(t, in)); w.Code != 403 {
		t.Fatal("document credential acquired organization catalog", w.Code)
	}
	changed := in
	changed.Name = "Same request different intent"
	upload(changed, 409)
	path := fmt.Sprintf("/api/v1/brand-assets/%s/revisions/1/content", a.AssetID)
	w := f.request(http.MethodGet, path, "")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), original) || w.Header().Get("Content-Type") != "image/svg+xml" || w.Header().Get("X-Content-Type-Options") != "nosniff" || !strings.HasPrefix(w.Header().Get("Content-Disposition"), "attachment;") {
		t.Fatal("exact original attachment differs", w.Code)
	}
	w = f.request(http.MethodGet, path+"?representation=render", "")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), pngBytes.Bytes()) {
		t.Fatal("provided render was modified or lost", w.Code)
	}
	var status brandcatalog.UploadStatusV1
	w = f.request(http.MethodGet, "/api/v1/brand-assets/uploads/"+in.RequestID.String(), "")
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.State != "committed" || status.AssetID != a.AssetID {
		t.Fatal("durable publication not observable", w.Code)
	}
	profile := brandcatalog.DefaultProfileDataV1()
	profile.Assets = []brandcatalog.AssetRefV1{{Slot: "logo_primary", AssetID: a.AssetID, Revision: 1, Alt: "Example logo", Usage: brandcatalog.LogoUsageV1{MinimumWidthPX: 180, ClearSpace: "Half the symbol width", AllowedBackgrounds: []string{"surface"}}}}
	p := brandCatalogProfile783(t, f, brandcatalog.ProfileInputV1{Name: "Exact linked assets", Profile: profile})
	if p.Profile.Assets[0].AssetID != a.AssetID {
		t.Fatal("profile lost stable asset reference")
	}
	in.RequestID = uuid.New()
	in.AssetID = a.AssetID
	in.ExpectedRevision = 1
	in.Name = "Example asset second revision"
	second := upload(in, 201)
	if second.Revision != 2 {
		t.Fatal("asset head failed to advance")
	}
	w = f.request(http.MethodGet, path, "")
	if w.Code != 200 || !bytes.Equal(w.Body.Bytes(), original) {
		t.Fatal("asset revision update rewrote original")
	}
	if _, e := f.pool.Exec(f.ctx, `UPDATE brand_asset_revisions_v1 SET original_sha256=decode(repeat('00',32),'hex') WHERE org_id=$1 AND asset_id=$2 AND revision=1`, f.org, a.AssetID); e == nil {
		t.Fatal("asset revision permitted overwrite")
	}
	other := brandCatalogFixture783(t)
	other.s.Storage = f.s.Storage
	if w = other.request(http.MethodGet, path, ""); w.Code != 404 {
		t.Fatal("cross-tenant original disclosed", w.Code)
	}
	profile.Assets[0].AssetID = uuid.New()
	w = f.request(http.MethodPost, "/api/v1/brand-profiles", brandCatalogJSON783(t, brandcatalog.ProfileInputV1{Name: "Missing asset", Profile: profile}))
	if w.Code != 404 {
		t.Fatal("unresolved asset reference admitted", w.Code)
	}
	var pending int
	err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM brand_asset_uploads_v1 WHERE org_id=$1 AND state<>'committed'`, f.org).Scan(&pending)
	if err != nil || pending != 0 {
		t.Fatal("successful asset publication left unresolved intent", pending, err)
	}
}
