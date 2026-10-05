//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestRenderedSenderPanelRecipientDraftsStayScopedE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, pool, q, s, org, owner := setupDSRE2E(t)
	const textA, textB = "Sender A draft text", "Sender B draft text"
	seed := func(name, text string) *generated.Document {
		tree, err := json.Marshal(map[string]any{"version": 1, "blocks": []map[string]any{{"id": "text", "type": "paragraph", "text": text}}})
		if err != nil {
			t.Fatal(err)
		}
		doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: owner, Name: name + uuid.NewString(), BlocksJson: tree, VariablesJson: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	a, b := seed("Sender A ", textA), seed("Sender B ", textB)
	_, hash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	original, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: a.ID, Role: "signer", Name: "Original A recipient", Email: uuid.NewString() + "@sender-panel.test", Locale: "en", MagicTokenHash: hash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.Collab.Shutdown(shutdownCtx)
	}()
	root, err := filepath.Abs("../../frontend/build")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("build frontend before browser fixture")
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
	user, err := q.GetUser(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: owner, Generation: user.SessionGeneration})
	cookie := s.Cookies.Mint(payload, time.Hour)
	createdAName, createdBName, editedBName := "Submitted A recipient", "New B recipient", "Edited B recipient"
	createdAEmail, createdBEmail := uuid.NewString()+"@sender-panel.test", uuid.NewString()+"@sender-panel.test"
	fixture, _ := json.Marshal(map[string]any{
		"base": server.URL, "cookieName": SessionCookieName, "cookie": cookie,
		"documentAID": a.ID.String(), "documentBID": b.ID.String(), "documentAName": a.Name, "documentBName": b.Name,
		"documentAText": textA, "documentBText": textB,
		"recipientAID": original.ID.String(), "recipientAName": original.Name, "recipientAEmail": original.Email,
		"createdAName": createdAName, "createdAEmail": createdAEmail, "createdBName": createdBName, "createdBEmail": createdBEmail, "editedBName": editedBName,
	})
	runCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-browser-sender-panel.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	t.Log(strings.ReplaceAll(string(output), cookie, "[redacted-session]"))
	if err != nil {
		t.Fatalf("rendered recipient forms: %v", err)
	}
	rowsA, err := q.ListRecipientsByDocument(ctx, a.ID)
	if err != nil || len(rowsA) != 2 {
		t.Fatalf("A recipient count=%d err=%v", len(rowsA), err)
	}
	var originalFound, submittedFound bool
	for _, row := range rowsA {
		if row.ID == original.ID {
			originalFound = row.Name == original.Name && row.Email == original.Email && bytes.Equal(row.MagicTokenHash, original.MagicTokenHash)
		}
		if row.Name == createdAName && row.Email == createdAEmail {
			submittedFound = true
		}
	}
	if !originalFound || !submittedFound {
		t.Fatal("cancelled A edit escaped or submitted A snapshot changed")
	}
	rowsB, err := q.ListRecipientsByDocument(ctx, b.ID)
	if err != nil || len(rowsB) != 1 || rowsB[0].Name != editedBName || rowsB[0].Email != createdBEmail {
		t.Fatalf("B recipient result count=%d err=%v", len(rowsB), err)
	}
	receiptBytes, err := os.ReadFile("/private/tmp/hash-browser-sender-panel-receipt.json")
	if err != nil {
		t.Fatal(err)
	}
	var receipt struct {
		RecipientBID        uuid.UUID `json:"recipientBID"`
		DeletedRecipientBID uuid.UUID `json:"deletedRecipientBID"`
		DeleteVerified      bool      `json:"currentDocumentDeleteAndRecreateVerified"`
	}
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.DeleteVerified || receipt.DeletedRecipientBID == uuid.Nil || receipt.RecipientBID != rowsB[0].ID {
		t.Fatal("rendered recipient deletion/recreation receipt does not match persisted B")
	}
	if _, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: receipt.DeletedRecipientBID, OrgID: org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("deleted B recipient survived: %v", err)
	}
	var deletionEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND document_id=$2 AND recipient_id=$3 AND kind='recipient.deleted'`, org, b.ID, receipt.DeletedRecipientBID).Scan(&deletionEvents); err != nil || deletionEvents != 1 {
		t.Fatalf("deleted B immutable audit count=%d err=%v", deletionEvents, err)
	}
	for _, doc := range []*generated.Document{a, b} {
		current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org})
		if err != nil || current.Status != "draft" || !bytes.Equal(current.BlocksJson, doc.BlocksJson) {
			t.Fatalf("recipient forms changed draft content/state: %v", err)
		}
	}
	var deliveries, intents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM email_deliveries WHERE to_email=ANY($1::text[])`, []string{original.Email, createdAEmail, createdBEmail}).Scan(&deliveries); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM send_sealing_intents WHERE org_id=$1`, org).Scan(&intents); err != nil {
		t.Fatal(err)
	}
	if deliveries != 0 || intents != 0 {
		t.Fatal("recipient form acceptance dispatched a lifecycle operation")
	}
}
