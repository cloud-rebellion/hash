//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/google/uuid"
)

// The host browser is orchestrated separately from this Linux test process so
// PDF processing uses the actual isolated worker. Only a task-owned loopback
// HTTPS port is published; PostgreSQL, renderer and S3 remain private synthetic
// peers. This is local built-UI/API acceptance, not production signing/delivery.
func TestRenderedHTMLDocumentRevisionWithExternalBrowserE2E(t *testing.T) {
	if os.Getenv("HASH_HTML_REVISION_BROWSER_E2E") != "1" {
		t.Skip("explicit external browser fixture required")
	}
	base, err := url.Parse(os.Getenv("HASH_HTML_REVISION_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("browser fixture requires an exact loopback HTTPS origin")
	}
	root := os.Getenv("HASH_HTML_REVISION_BROWSER_FRONTEND")
	inputPath := os.Getenv("HASH_HTML_REVISION_BROWSER_INPUT")
	donePath := os.Getenv("HASH_HTML_REVISION_BROWSER_DONE")
	if !filepath.IsAbs(root) || !filepath.IsAbs(inputPath) || !filepath.IsAbs(donePath) || inputPath == donePath {
		t.Fatal("browser fixture requires separate absolute task artifact paths")
	}
	if os.Getenv("HASH_E2E_PDF_WORKER_PATH") == "" {
		t.Fatal("browser fixture requires the source-built isolated PDF worker")
	}
	f, _, _, original, cookie := setupHTMLRevisionE2E(t)
	partyResponse := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/recipients", `{"email":"synthetic-customer@html-revision.test","name":"Named customer","role":"signer","locale":"en"}`, cookie)
	if partyResponse.Code != http.StatusCreated {
		t.Fatalf("browser named party setup status=%d", partyResponse.Code)
	}
	var party recipientResponse
	if json.Unmarshal(partyResponse.Body.Bytes(), &party) != nil || party.ID == uuid.Nil || party.DocumentID != original.ID {
		t.Fatal("browser named party setup lost document identity")
	}
	originalCommitment, err := htmlsource.Commitment(original)
	if err != nil {
		t.Fatal("browser original source commitment unavailable")
	}
	fieldBody, err := json.Marshal(map[string]any{
		"type": "signature", "recipient_id": party.ID, "page": 1,
		"x_pct": 10, "y_pct": 70, "w_pct": 30, "h_pct": 8, "required": true,
		"label":                           "Original placement before revision",
		"expected_pdf_sha256":             hex.EncodeToString(original.PdfSha256),
		"expected_html_source_commitment": originalCommitment,
	})
	if err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/fields", string(fieldBody), cookie); w.Code != http.StatusCreated {
		t.Fatalf("browser original pinned field setup status=%d", w.Code)
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("browser requires current built frontend")
	}
	f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("task browser fixture listener unavailable")
	}
	f.s.PublicURL = base.String()
	f.s.OperatorName = "Synthetic Hash operator"
	f.s.PrivacyContact = "privacy@hash.example.test"
	f.s.SupervisoryAuthority = "Synthetic authority"
	f.s.PrivacyPolicyURL = base.String() + "/legal/privacy"
	server.Config.Handler = f.s.Routes()
	server.StartTLS()
	defer server.Close()
	packet, err := json.Marshal(map[string]any{"base": base.String(), "documentID": original.ID.String(), "cookieName": SessionCookieName, "cookie": cookie})
	if err != nil {
		t.Fatal(err)
	}
	// Never place the original session credential in logs or receipts.
	if _, err := os.Stat(inputPath); !os.IsNotExist(err) {
		t.Fatal("browser input path is not fresh")
	}
	if err := os.WriteFile(inputPath, packet, 0600); err != nil {
		t.Fatal("write private browser input")
	}
	defer os.Remove(inputPath)
	deadline := time.Now().Add(150 * time.Second)
	var done struct {
		ExitCode int  `json:"exit_code"`
		Verified bool `json:"verified"`
	}
	for {
		body, err := os.ReadFile(donePath)
		if err == nil {
			if json.Unmarshal(body, &done) != nil || done.ExitCode != 0 || !done.Verified {
				t.Fatal("external browser did not accept revised contract workflow")
			}
			break
		}
		if !os.IsNotExist(err) || time.Now().After(deadline) {
			t.Fatal("external browser acceptance timed out")
		}
		time.Sleep(100 * time.Millisecond)
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.ID, OrgID: f.org})
	if err != nil || !bytes.Equal(current.HtmlSourceJson, original.HtmlSourceJson) || !current.HtmlCurrentMaterializationSequence.Valid || current.HtmlCurrentMaterializationSequence.Int32 != 2 || current.Status != "draft" {
		t.Fatal("browser lost original source or current revision identity")
	}
	if err := htmlsource.Validate(current, true); err != nil {
		t.Fatal("browser did not record exact revised PDF/source review")
	}
	if _, err := htmlmaterialization.Current(f.ctx, f.q, current); err != nil {
		t.Fatal("browser current immutable row differs from document")
	}
	fields, err := f.q.ListFieldsByDocument(f.ctx, current.ID)
	if err != nil || len(fields) != 1 || fields[0].Type != "signature" || !fields[0].RecipientID.Valid {
		t.Fatal("browser did not persist exactly one named-party signature placement")
	}
	input, err := htmlsource.InputForCurrent(current)
	if err != nil || !strings.Contains(input.Values["customer"], "Negotiated") || input.Sections["scope"] == "" || input.Sections["scope"] == "Approved scope" {
		t.Fatal("browser did not persist declared value and plain-text wording")
	}
	t.Log("built UI + real HTTPS/PG + actual isolated PDF worker accepted immutable revision/history/fresh review/named-party placement; synthetic renderer/S3, no signing/SMTP/provider/recovery claim")
}
