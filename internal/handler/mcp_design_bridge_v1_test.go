// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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

// An API-credential preview identity must never become a staff approval
// receipt: template approval is human-only, through a staff session.
func TestMCPDesign783CredentialPreviewCannotMintStaffReceipt(t *testing.T) {
	user, org := uuid.New(), uuid.New()
	_, a := designActor783(t, user, org)
	cookies, err := auth.NewSignedCookie(strings.Repeat("14", 32))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Cookies: cookies}
	now := time.Now().UTC()
	p := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: org, ReviewerID: user, CredentialID: a.KeyID, TemplateID: uuid.New(), Version: 3, TemplateContentSHA256: strings.Repeat("a", 64), MaterializationSHA256: strings.Repeat("b", 64), PDFSHA256: strings.Repeat("c", 64), PageCount: 2, IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
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

// validate is the refusal that holds when verify is not in front of it: a
// credential-bound receipt with no session hash must be refused by validate and
// by the authorization wrapper, which calls validate alone.
func TestHTMLTemplatePreviewReceiptValidateRefusesAnyCredential(t *testing.T) {
	now := time.Now().UTC()
	p := htmlTemplatePreviewReceipt{SchemaVersion: 1, PreviewID: uuid.New(), OrgID: uuid.New(), ReviewerID: uuid.New(), TemplateID: uuid.New(), Version: 3, TemplateContentSHA256: strings.Repeat("a", 64), MaterializationSHA256: strings.Repeat("b", 64), PDFSHA256: strings.Repeat("c", 64), PageCount: 2, SessionSHA256: strings.Repeat("e", 64), IssuedAt: now, ExpiresAt: now.Add(5 * time.Minute)}
	if err := p.validate(now); err != nil {
		t.Fatalf("session receipt must stay valid: %v", err)
	}
	p.CredentialID = uuid.New()
	p.SessionSHA256 = ""
	if p.validate(now) == nil {
		t.Fatal("validate accepted a credential-bound receipt")
	}
	authz := htmlTemplatePreviewReceiptAuthorization(func(context.Context, pgx.Tx, *generated.User) error { return nil }, p)
	if authz(context.Background(), nil, nil) == nil {
		t.Fatal("authorization wrapper accepted a credential-bound receipt")
	}
}
