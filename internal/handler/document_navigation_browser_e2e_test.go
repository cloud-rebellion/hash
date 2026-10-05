//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Delayed reads use actual Go responses. The browser injects only one explicit
// proposal-refresh 503 to prove that previously loaded requests remain visible.
// Sealing receipts are synthetic; this does not verify storage or SMTP.
func TestRenderedDocumentNavigationKeepsNegotiationsScopedE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, pool, q, s, org, ownerID := setupDSRE2E(t)
	owner, err := q.GetUser(ctx, ownerID)
	if err != nil {
		t.Fatal(err)
	}
	const (
		documentAText   = "Document A existing terms"
		documentBText   = "Document B existing terms"
		commentAText    = "Document A retained conversation"
		commentBText    = "Document B retained conversation"
		changeAMessage  = "Please revise document A delivery terms."
		changeBMessage  = "Please revise document B delivery terms."
		newCommentBText = "Current B negotiation reply"
	)
	type negotiation struct {
		document  *generated.Document
		recipient *generated.Recipient
		request   *generated.ChangeRequest
		comment   *generated.DocumentComment
	}
	seed := func(name, text, commentBody, requestMessage string) negotiation {
		blocksJSON, marshalErr := json.Marshal(map[string]any{
			"version": 1, "blocks": []map[string]any{{"id": "terms", "type": "paragraph", "text": text}},
		})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		doc, createErr := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
			OrgID: org, SenderID: ownerID, Name: name + uuid.NewString(), BlocksJson: blocksJSON, VariablesJson: json.RawMessage(`{}`),
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		_, tokenHash, mintErr := auth.MintMagicToken()
		if mintErr != nil {
			t.Fatal(mintErr)
		}
		recipient, createErr := q.CreateRecipient(ctx, generated.CreateRecipientParams{
			DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@navigation.test", Name: name + "signer",
			MagicTokenHash: tokenHash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		if _, createErr = q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
			DocumentID: doc.ID, OrgID: org, LawfulBasis: "contract", Via: "test",
			ConfirmedBy: pgtype.UUID{Bytes: ownerID, Valid: true},
		}); createErr != nil {
			t.Fatal(createErr)
		}
		doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)
		doc, createErr = q.RequestChangesOnDocument(ctx, generated.RequestChangesOnDocumentParams{ID: doc.ID, OrgID: org})
		if createErr != nil {
			t.Fatal(createErr)
		}
		request, createErr := q.CreateChangeRequest(ctx, generated.CreateChangeRequestParams{
			DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, Message: requestMessage,
			BlockID: "terms", Quote: text, Proposed: "Proposed " + text,
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		comment, createErr := q.CreateComment(ctx, generated.CreateCommentParams{
			DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
			AuthorName: recipient.Name, AuthorSide: "signer", Body: commentBody,
		})
		if createErr != nil {
			t.Fatal(createErr)
		}
		return negotiation{doc, recipient, request, comment}
	}
	a := seed("Negotiation A ", documentAText, commentAText, changeAMessage)
	b := seed("Negotiation B ", documentBText, commentBText, changeBMessage)

	root, err := filepath.Abs("../../frontend/build")
	if err != nil {
		t.Fatal(err)
	}
	shell, err := os.ReadFile(filepath.Join(root, "index.html"))
	if err != nil {
		t.Fatal("build frontend before browser test")
	}
	s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(root))
	s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if info, statErr := os.Stat(filepath.Join(root, clean)); statErr == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	s.PublicURL = "https://" + server.Listener.Addr().String()
	s.Sign = &sign.Engine{Pool: pool, Queries: q, Audit: s.Audit, Mailer: dispatch.QueueingMailer{Q: q}, OrgName: "Navigation fixture", BaseURL: s.PublicURL}
	server.Config.Handler = s.Routes()
	server.StartTLS()
	defer server.Close()
	payload, err := json.Marshal(auth.SessionPayload{UserID: ownerID, Generation: owner.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	cookie := s.Cookies.Mint(payload, time.Hour)
	foreignOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "Foreign navigation fixture " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignOwner, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: foreignOrg.ID, Email: uuid.NewString() + "@navigation.test", Name: "Foreign navigation owner", Role: "owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	foreignPayload, err := json.Marshal(auth.SessionPayload{UserID: foreignOwner.ID, Generation: foreignOwner.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path          string
		cookie        string
		status        int
		staticPreview bool
	}{
		{"/api/v1/documents/" + b.document.ID.String() + "/preview", cookie, http.StatusOK, true},
		{"/api/v1/me", cookie, http.StatusOK, false},
		{"/api/v1/documents/" + b.document.ID.String() + "/preview", "", http.StatusUnauthorized, false},
		{"/api/v1/documents/" + b.document.ID.String() + "/preview", s.Cookies.Mint(foreignPayload, time.Hour), http.StatusNotFound, false},
	} {
		requestCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		req, requestErr := http.NewRequestWithContext(requestCtx, http.MethodGet, server.URL+check.path, nil)
		if requestErr != nil {
			stop()
			t.Fatal(requestErr)
		}
		if check.cookie != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: check.cookie})
		}
		response, requestErr := server.Client().Do(req)
		if requestErr != nil {
			stop()
			t.Fatal(requestErr)
		}
		body, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
		_ = response.Body.Close()
		stop()
		if readErr != nil || response.StatusCode != check.status {
			t.Fatalf("actual preview/header boundary status=%d want=%d err=%v", response.StatusCode, check.status, readErr)
		}
		csp := response.Header.Get("Content-Security-Policy")
		if check.staticPreview {
			if response.Header.Get("X-Frame-Options") != "SAMEORIGIN" || !bytes.Contains(body, []byte(documentBText)) {
				t.Fatal("authorized preview lost same-origin framing or actual document text")
			}
			for _, directive := range []string{"frame-ancestors 'self'", "script-src 'none'", "form-action 'none'", "connect-src 'none'", "sandbox allow-same-origin"} {
				if !strings.Contains(csp, directive) {
					t.Fatalf("authorized static preview is missing %q", directive)
				}
			}
		} else if response.Header.Get("X-Frame-Options") != "DENY" || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatal("default API or refused preview weakened frame protection")
		}
	}
	fixture, err := json.Marshal(map[string]any{
		"base": server.URL, "cookieName": SessionCookieName, "cookie": cookie,
		"documentAID": a.document.ID.String(), "documentBID": b.document.ID.String(),
		"documentAName": a.document.Name, "documentBName": b.document.Name,
		"changeAID": a.request.ID.String(), "changeBID": b.request.ID.String(),
		"documentAText": documentAText, "documentBText": documentBText,
		"commentAText": commentAText, "commentBText": commentBText,
		"changeAMessage": changeAMessage, "changeBMessage": changeBMessage, "newCommentBText": newCommentBText,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-browser-document-navigation.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	t.Log(strings.ReplaceAll(string(output), cookie, "[redacted-session]"))
	if err != nil {
		t.Fatalf("rendered document navigation acceptance: %v", err)
	}
	for _, item := range []negotiation{a, b} {
		current, readErr := q.GetDocumentByID(ctx, item.document.ID)
		if readErr != nil || current.Status != "changes_requested" || current.SenderID != ownerID || !bytes.Equal(current.BlocksJson, item.document.BlocksJson) {
			t.Fatalf("navigation changed paused document identity/content: err=%v", readErr)
		}
		comments, readErr := q.ListComments(ctx, item.document.ID)
		wantCount := 1
		if item.document.ID == b.document.ID {
			wantCount = 2
		}
		if readErr != nil || len(comments) != wantCount || comments[0].ID != item.comment.ID {
			t.Fatalf("navigation changed the wrong conversation: count=%d want=%d err=%v", len(comments), wantCount, readErr)
		}
		if wantCount == 2 && (comments[1].Body != newCommentBText || comments[1].AuthorSide != "sender" || !comments[1].UserID.Valid || uuid.UUID(comments[1].UserID.Bytes) != ownerID || comments[1].RecipientID.Valid) {
			t.Fatal("current B comment lost its actual cookie sender identity")
		}
		request, readErr := q.GetChangeRequest(ctx, generated.GetChangeRequestParams{ID: item.request.ID, OrgID: org})
		if readErr != nil {
			t.Fatal(readErr)
		}
		if item.document.ID == a.document.ID {
			if request.Status != "open" || request.Resolution.Valid || request.ResolvedAt.Valid {
				t.Fatal("late A responses redirected the current B resolution to A")
			}
		} else if request.Status != "resolved" || !request.Resolution.Valid || request.Resolution.String != "denied" || !request.ResolvedAt.Valid {
			t.Fatal("current B proposal was not denied")
		}
		var commentsAudit, resolutionAudit, signingAudit int
		if readErr = pool.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE kind=$2),
			count(*) FILTER (WHERE kind=$3 AND payload_json->>'change_request'=$4),
			count(*) FILTER (WHERE kind IN ($5,$6,$7,$8)) FROM events WHERE document_id=$1`,
			item.document.ID, audit.KindCommentPosted, audit.KindChangesRequested, item.request.ID.String(),
			audit.KindDocumentSigned, audit.KindDocumentAccepted, audit.KindDocumentFieldFill, audit.KindDocumentCompleted).
			Scan(&commentsAudit, &resolutionAudit, &signingAudit); readErr != nil { //nolint:rawsql
			t.Fatal(readErr)
		}
		wantMutations := 0
		if wantCount == 2 {
			wantMutations = 1
		}
		if commentsAudit != wantMutations || resolutionAudit != wantMutations || signingAudit != 0 {
			t.Fatalf("navigation mutation audit mismatch: comments=%d resolutions=%d signing=%d", commentsAudit, resolutionAudit, signingAudit)
		}
	}
	var aDeliveries, bDeliveries int
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE to_email=$1),
		count(*) FILTER (WHERE to_email=$2 AND status='pending' AND attempts=0 AND sent_at IS NULL
		AND strpos(text_body,$3)>0) FROM email_deliveries`, a.recipient.Email, b.recipient.Email, newCommentBText).
		Scan(&aDeliveries, &bDeliveries); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if aDeliveries != 0 || bDeliveries != 1 {
		t.Fatalf("navigation notified the wrong conversation: A=%d B=%d", aDeliveries, bDeliveries)
	}
	t.Log("verified A retained its original request/comment; only B received the authenticated comment, denied resolution, committed audits and pending notification; synthetic sealing, no SMTP/storage verification")
}
