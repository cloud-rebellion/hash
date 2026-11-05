// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
)

type designKey783 struct {
	key           *auth.MintedKey
	id, user, org uuid.UUID
}

func (v *designKey783) LookupByPrefix(_ context.Context, p string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	if p != v.key.Prefix {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("unknown synthetic key")
	}
	return v.id, v.user, v.org, "owner", "owner@example.invalid", v.key.Hash, uuid.Nil, []string{"read", "write:authoring"}, nil
}
func (v *designKey783) Claim(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func designActor783(t *testing.T, user, org uuid.UUID) (context.Context, mcp.DesignActorV1) {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &designKey783{key: key, id: uuid.New(), user: user, org: org}
	var ctx context.Context
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+key.Plaintext)
	w := httptest.NewRecorder()
	auth.RequireAPIKey(v)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { ctx = r.Context() })).ServeHTTP(w, r)
	if ctx == nil {
		t.Fatal("real API key admission refused", w.Code)
	}
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, uuid.Nil, "write:authoring")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, mcp.DesignActorV1{Actor: authoring.Actor{OrgID: org, UserID: user, Authorize: authorize}, KeyID: v.id}
}
func TestMCPDesign783PreviewExactKeyActorPinsAndPurpose(t *testing.T) {
	user, org := uuid.New(), uuid.New()
	ctx, a := designActor783(t, user, org)
	cookies, err := auth.NewSignedCookie(strings.Repeat("14", 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Cookies: cookies}
	now := time.Now().UTC()
	p := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: org, ReviewerID: user, CredentialID: a.KeyID, TemplateID: uuid.New(), Version: 3, TemplateContentSHA256: strings.Repeat("a", 64), MaterializationSHA256: strings.Repeat("b", 64), PDFSHA256: strings.Repeat("c", 64), PageCount: 2, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	token, err := s.mintMCPDesignPreviewV1(p)
	if err != nil {
		t.Fatal(err)
	}
	in := mcp.DesignApprovalInputV1{ExpectedVersion: p.Version, ExpectedContentSHA256: p.TemplateContentSHA256, ExpectedPreviewPDFSHA256: p.PDFSHA256, PreviewReceipt: token}
	if _, err = s.validateMCPDesignPreviewV1(ctx, a, p.TemplateID, in); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"key", "actor", "org", "template", "version", "content", "pdf", "no-live-auth", "wrong-purpose", "expired"} {
		t.Run(kind, func(t *testing.T) {
			call, actor, id, args := ctx, a, p.TemplateID, in
			switch kind {
			case "key":
				call, actor = designActor783(t, user, org)
			case "actor":
				actor.UserID = uuid.New()
			case "org":
				actor.OrgID = uuid.New()
			case "template":
				id = uuid.New()
			case "version":
				args.ExpectedVersion++
			case "content":
				args.ExpectedContentSHA256 = strings.Repeat("d", 64)
			case "pdf":
				args.ExpectedPreviewPDFSHA256 = strings.Repeat("d", 64)
			case "no-live-auth":
				actor.Authorize = nil
			case "wrong-purpose":
				raw, _ := json.Marshal(p)
				args.PreviewReceipt, err = s.Cookies.MintPurpose(htmlTemplatePreviewPurpose, raw, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
			case "expired":
				old := p
				old.IssuedAt = now.Add(-6 * time.Minute)
				old.ExpiresAt = now.Add(-time.Minute)
				raw, _ := json.Marshal(old)
				args.PreviewReceipt, err = s.Cookies.MintPurpose(mcpDesignPreviewPurposeV1, raw, time.Minute)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err = s.validateMCPDesignPreviewV1(call, actor, id, args); err == nil {
				t.Fatal("foreign/stale receipt accepted")
			}
		})
	}
	if _, err = s.mintHTMLTemplatePreviewReceipt(p); err == nil {
		t.Fatal("API credential receipt minted under cookie purpose")
	}
	p.SessionSHA256 = strings.Repeat("e", 64)
	if p.validate(now) == nil {
		t.Fatal("receipt accepted both cookie and API-key identities")
	}
}
func TestMCPDesign783UnverifiedContextCannotSelectActor(t *testing.T) {
	_, a := designActor783(t, uuid.New(), uuid.New())
	if validMCPDesignActorV1(context.Background(), a) == nil {
		t.Fatal("caller actor substituted for verified API admission")
	}
	ctx := context.WithValue(context.Background(), auth.UserIDKey, a.UserID)
	ctx = context.WithValue(ctx, auth.OrgIDKey, a.OrgID)
	ctx = context.WithValue(ctx, auth.RoleKey, "owner")
	if validMCPDesignActorV1(ctx, a) == nil {
		t.Fatal("public identity context forged private credential admission")
	}
}
