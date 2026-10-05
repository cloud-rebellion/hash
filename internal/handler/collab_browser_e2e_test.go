//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/google/uuid"
)

func TestRenderedCollabCanonicalSaveAndReloadE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, _, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{29}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer s.Collab.Shutdown(context.Background())
	root, err := filepath.Abs("../../frontend/build")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, "index.html")); err != nil {
		t.Fatal("build frontend before browser test")
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal(err)
	}
	s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	s.PublicURL = "https://" + server.Listener.Addr().String()
	server.Config.Handler = s.Routes()
	server.StartTLS()
	defer server.Close()
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Hour)
	sender, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Email: uuid.NewString() + "@sender.test", Name: "Browser sender", Role: "sender"})
	if err != nil {
		t.Fatal(err)
	}
	senderPayload, _ := json.Marshal(auth.SessionPayload{UserID: sender.ID})
	senderCookie := s.Cookies.Mint(senderPayload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, Name: "Browser collaboration fixture", SenderID: user, BlocksJson: json.RawMessage(`{"version":1,"blocks":[{"id":"seed","type":"paragraph","text":"Initial contract"}]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	fixture, _ := json.Marshal(map[string]any{"base": server.URL, "documentID": doc.ID.String(), "cookieName": SessionCookieName, "cookies": []string{cookie, senderCookie}, "userIDs": []string{user.String(), sender.ID.String()}})
	runCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-browser-collaboration.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	t.Log(string(output))
	if err != nil {
		t.Fatalf("rendered collaboration acceptance: %v", err)
	}
	saved, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(saved.BlocksJson), "Replacement contract") || strings.Contains(string(saved.BlocksJson), "Initial contract") {
		t.Fatalf("canonical content missing: %s", saved.BlocksJson)
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := q.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: doc.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Generation.Valid || state.Generation.Int64 != generation || len(state.YdocState) == 0 {
		t.Fatal("rendered canonical/history association missing")
	}
	t.Logf("BROWSER_CANONICAL_GENERATION=%d", generation)
}
