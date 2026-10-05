//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

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

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This fixture exercises the built portal, real HTTPS handlers, current
// Article 13 evidence, and a durable transactional mail outbox. Send-sealing
// receipts are synthetic: it does not verify immutable storage or SMTP.
func TestRenderedNegotiationConversationE2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("set HASH_BROWSER_E2E=1 with built frontend and cached Chromium")
	}
	ctx, pool, q, s, org, decoyOwnerID := setupDSRE2E(t)
	decoyOwner, err := q.GetUser(ctx, decoyOwnerID)
	if err != nil {
		t.Fatal(err)
	}
	// The first org owner is deliberately unrelated to this document. Every
	// negotiation notification must follow the document's actual SenderID.
	sender, err := q.CreateUser(ctx, generated.CreateUserParams{
		OrgID: org, Email: uuid.NewString() + "@negotiation.test", Name: "Negotiation owner", Role: "owner",
		ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	const (
		documentText     = "Negotiation contract text remains readable"
		requestMessage   = "Please revise the payment schedule before I sign."
		signerFollowup   = "Could the first payment be due after delivery?"
		senderReply      = "Yes. I will prepare a revised payment schedule."
		signerFinalReply = "Thank you. Please include the revised schedule in the next document."
	)
	blocksJSON, err := json.Marshal(map[string]any{
		"version": 1,
		"blocks":  []map[string]any{{"id": "negotiation-text", "type": "paragraph", "text": documentText}},
	})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org, SenderID: sender.ID, Name: "Negotiation browser fixture " + uuid.NewString(),
		BlocksJson: blocksJSON, VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	token, tokenHash, err := auth.MintMagicToken()
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{
		DocumentID: doc.ID, Role: "signer", Email: uuid.NewString() + "@negotiation.test", Name: "Negotiation signer",
		MagicTokenHash: tokenHash, MagicTokenExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, Locale: "en",
	})
	if err != nil {
		t.Fatal(err)
	}
	var fieldID uuid.UUID
	if err = pool.QueryRow(ctx, `INSERT INTO document_fields
		(document_id,recipient_id,type,page,x_pct,y_pct,w_pct,h_pct,required,label,options_json)
		VALUES($1,$2,'text',1,0,0,20,5,true,'Negotiation reference','[]'::jsonb) RETURNING id`,
		doc.ID, recipient.ID).Scan(&fieldID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if _, err = q.ConfirmDocumentLawfulBasis(ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: doc.ID, OrgID: org, LawfulBasis: "contract", Via: "test",
		ConfirmedBy: pgtype.UUID{Bytes: sender.ID, Valid: true},
	}); err != nil {
		t.Fatal(err)
	}
	doc = sendDSRDocumentE2E(t, ctx, pool, q, doc, recipient)

	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{43}, 32)))
	if err != nil {
		t.Fatal(err)
	}
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
		if info, err := os.Stat(filepath.Join(root, clean)); err == nil && !info.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(root, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	s.PublicURL = "https://" + server.Listener.Addr().String()
	s.OperatorName = "Hash negotiation fixture operator"
	s.PrivacyContact = "privacy@hash.example.test"
	s.SupervisoryAuthority = "Fixture supervisory authority"
	s.PrivacyPolicyURL = s.PublicURL + "/legal/privacy"
	s.Sign = &sign.Engine{
		Pool: pool, Queries: q, Audit: s.Audit, Mailer: dispatch.QueueingMailer{Q: q},
		OrgName: "Negotiation fixture", BaseURL: s.PublicURL,
	}
	server.Config.Handler = s.Routes()
	server.StartTLS()
	defer server.Close()
	payload, err := json.Marshal(auth.SessionPayload{UserID: sender.ID, Generation: sender.SessionGeneration})
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := json.Marshal(map[string]any{
		"base": server.URL, "token": token, "documentID": doc.ID.String(), "fieldID": fieldID.String(),
		"cookieName": SessionCookieName, "cookie": s.Cookies.Mint(payload, time.Hour),
		"documentText": documentText, "requestMessage": requestMessage, "signerFollowup": signerFollowup,
		"senderReply": senderReply, "signerFinalReply": signerFinalReply,
	})
	if err != nil {
		t.Fatal(err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "bun", "scripts/verify-browser-negotiation.ts")
	cmd.Dir = "../../frontend"
	cmd.Stdin = bytes.NewReader(fixture)
	output, err := cmd.CombinedOutput()
	// Credentials are passed only on stdin, and never included in test logs.
	redactedOutput := strings.ReplaceAll(string(output), token, "[redacted-magic-token]")
	var fixtureSecrets struct {
		Cookie string `json:"cookie"`
	}
	if json.Unmarshal(fixture, &fixtureSecrets) == nil && fixtureSecrets.Cookie != "" {
		redactedOutput = strings.ReplaceAll(redactedOutput, fixtureSecrets.Cookie, "[redacted-session]")
	}
	t.Log(redactedOutput)
	if err != nil {
		t.Fatalf("rendered negotiation acceptance: %v", err)
	}

	current, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || current.Status != "changes_requested" || current.SenderID != sender.ID {
		t.Fatalf("negotiation lost paused document identity: err=%v", err)
	}
	var originalBlocks, currentBlocks any
	if json.Unmarshal(doc.BlocksJson, &originalBlocks) != nil || json.Unmarshal(current.BlocksJson, &currentBlocks) != nil {
		t.Fatal("invalid fixture block document")
	}
	originalCanonical, _ := json.Marshal(originalBlocks)
	currentCanonical, _ := json.Marshal(currentBlocks)
	if !bytes.Equal(originalCanonical, currentCanonical) {
		t.Fatal("negotiation mutated the sent document")
	}
	requests, err := q.ListChangeRequests(ctx, doc.ID)
	if err != nil || len(requests) != 1 || requests[0].Message != requestMessage || requests[0].Status != "open" {
		t.Fatalf("expected one retained open change request: err=%v", err)
	}
	comments, err := q.ListComments(ctx, doc.ID)
	if err != nil || len(comments) != 3 {
		t.Fatalf("expected three persisted negotiation comments: count=%d err=%v", len(comments), err)
	}
	for i, want := range []struct{ body, side string }{
		{signerFollowup, "signer"}, {senderReply, "sender"}, {signerFinalReply, "signer"},
	} {
		comment := comments[i]
		if comment.Body != want.body || comment.AuthorSide != want.side || comment.DocumentID != doc.ID {
			t.Fatalf("comment %d lost its body, side, or document", i)
		}
		if want.side == "sender" {
			if !comment.UserID.Valid || uuid.UUID(comment.UserID.Bytes) != sender.ID || comment.RecipientID.Valid {
				t.Fatal("owner HTTP comment lost its authenticated sender identity")
			}
		} else if !comment.RecipientID.Valid || uuid.UUID(comment.RecipientID.Bytes) != recipient.ID || comment.UserID.Valid {
			t.Fatal("magic-link comment lost its recipient identity")
		}
	}
	for _, notification := range []struct{ message, target string }{
		{requestMessage, sender.Email}, {signerFollowup, sender.Email},
		{senderReply, recipient.Email}, {signerFinalReply, sender.Email},
	} {
		var count int
		if err = pool.QueryRow(ctx, `SELECT count(*) FROM email_deliveries
			WHERE to_email=$1 AND strpos(text_body,$2)>0 AND strpos(subject,$3)>0
			AND status='pending' AND attempts=0 AND sent_at IS NULL`,
			notification.target, notification.message, doc.Name).Scan(&count); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if count != 1 {
			t.Fatalf("negotiation notification missing or duplicated: expected one pending delivery, got %d", count)
		}
	}
	var actualDeliveries, decoyDeliveries int
	if err = pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE to_email IN ($1,$2)),
		count(*) FILTER (WHERE to_email=$3) FROM email_deliveries`, sender.Email, recipient.Email, decoyOwner.Email).
		Scan(&actualDeliveries, &decoyDeliveries); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if actualDeliveries != 4 || decoyDeliveries != 0 {
		t.Fatalf("notification ownership mismatch: actual=%d unrelated-owner=%d", actualDeliveries, decoyDeliveries)
	}
	fields, err := q.ListFieldsByDocument(ctx, doc.ID)
	if err != nil || len(fields) != 1 || fields[0].ID != fieldID || fields[0].Value.Valid || fields[0].CompletedAt.Valid {
		t.Fatalf("paused negotiation changed an assigned field: err=%v", err)
	}
	freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: org})
	if err != nil || freshRecipient.SignedAt.Valid || freshRecipient.Status == "signed" || freshRecipient.Status == "accepted" {
		t.Fatalf("paused negotiation captured recipient consent: err=%v", err)
	}
	var signatures, finalizations, signingEvents int
	if err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM signatures WHERE document_id=$1),
		(SELECT count(*) FROM document_finalization_intents WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND kind IN ($2,$3,$4,$5))`,
		doc.ID, audit.KindDocumentSigned, audit.KindDocumentAccepted, audit.KindDocumentFieldFill, audit.KindDocumentCompleted).
		Scan(&signatures, &finalizations, &signingEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if signatures != 0 || finalizations != 0 || signingEvents != 0 {
		t.Fatalf("negotiation produced consent artifacts: signatures=%d finalizations=%d events=%d", signatures, finalizations, signingEvents)
	}
	rows, err := pool.Query(ctx, `SELECT payload_json FROM events
		WHERE document_id=$1 AND recipient_id=$2 AND kind IN ($3,$4) ORDER BY created_at`,
		doc.ID, recipient.ID, audit.KindChangesRequested, audit.KindCommentPosted) //nolint:rawsql
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var evidenceCount int
	for rows.Next() {
		var raw json.RawMessage
		if err = rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var eventPayload map[string]json.RawMessage
		if json.Unmarshal(raw, &eventPayload) != nil || len(eventPayload[article13.AuditNoticeSnapshotKey]) == 0 {
			t.Fatal("negotiation response lost current notice evidence")
		}
		if err = article13.ValidateAuditPayload(raw, org, doc.ID, recipient.ID); err != nil {
			t.Fatalf("negotiation response notice evidence: %v", err)
		}
		evidenceCount++
	}
	if err = rows.Err(); err != nil || evidenceCount != 3 {
		t.Fatalf("expected notice-bound request and two signer comments: count=%d err=%v", evidenceCount, err)
	}
	t.Log("verified paused conversation, actual sender notification ownership, four pending outbox deliveries, and three valid notice-bound responses; synthetic sealing, no SMTP/storage verification")
}
