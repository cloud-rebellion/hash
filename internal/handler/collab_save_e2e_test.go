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
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type canonicalSavePeer struct {
	id   string
	user uuid.UUID
}

func (p canonicalSavePeer) ID() string                         { return p.id }
func (p canonicalSavePeer) UserID() uuid.UUID                  { return p.user }
func (p canonicalSavePeer) DisplayName() string                { return "save fixture" }
func (p canonicalSavePeer) Send(context.Context, []byte) error { return nil }

func TestCollabSaveAuthenticatedAtomicReceiptE2E(t *testing.T) {
	ctx, _, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{27}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer s.Collab.Shutdown(ctx)
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, Name: "coordinated save", SenderID: user, BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	peer := canonicalSavePeer{id: "fixture-peer", user: user}
	joined, err := s.Collab.Join(ctx, doc.ID, org, peer)
	if err != nil {
		t.Fatal(err)
	}
	if err := joined.Room.HandleFrame(ctx, peer, []byte{0, 2, 1, 42}); err != nil {
		t.Fatal(err)
	}
	cp, err := joined.Room.CaptureSaveCheckpoint(peer.ID())
	if err != nil {
		t.Fatal(err)
	}
	input := collabSaveInput{PeerID: peer.ID(), Checkpoint: hex.EncodeToString(cp.Token[:]), Generation: "1", ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), BlocksJSON: doc.BlocksJson}
	routes := s.Routes()
	submit := func(in collabSaveInput, cookieValue string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPost, s.PublicURL+"/api/v1/documents/"+doc.ID.String()+"/collab/save", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.PublicURL)
		if cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieValue})
		}
		res := httptest.NewRecorder()
		routes.ServeHTTP(res, req)
		return res
	}
	if res := submit(input, ""); res.Code != 401 {
		t.Fatalf("anonymous: %d %s", res.Code, res.Body.String())
	}
	res := submit(input, cookie)
	if res.Code != 200 {
		t.Fatalf("save: %d %s", res.Code, res.Body.String())
	}
	var receipt struct {
		Document   documentResponse `json:"document"`
		Generation string           `json:"generation"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Generation != "2" || receipt.Document.UpdatedAt == input.ExpectedUpdatedAt {
		t.Fatal("missing advanced receipt")
	}
	if err := joined.Room.CheckGeneration(2); err != nil {
		t.Fatal(err)
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation.Int64 != 2 || !bytes.Equal(state.YdocState, []byte{1, 42}) {
		t.Fatal("content/history receipt not associated")
	}
	if res := submit(input, cookie); res.Code != 409 {
		t.Fatalf("replayed checkpoint: %d", res.Code)
	}
	// The copied cookie remains cryptographically valid after role demotion.
	cp, err = joined.Room.CaptureSaveCheckpoint(peer.ID())
	if err != nil {
		t.Fatal(err)
	}
	input.Checkpoint = hex.EncodeToString(cp.Token[:])
	input.Generation = "2"
	if res := submit(input, cookie); res.Code != 412 {
		t.Fatalf("stale document observation with fresh checkpoint: %d %s", res.Code, res.Body.String())
	}
	input.ExpectedUpdatedAt = receipt.Document.UpdatedAt
	if _, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if res := submit(input, cookie); res.Code != 403 {
		t.Fatalf("demoted save: %d %s", res.Code, res.Body.String())
	}
	state, err = q.GetCollabDocStateWithGeneration(ctx, doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation.Int64 != 2 {
		t.Fatal("refusal changed history")
	}
}
