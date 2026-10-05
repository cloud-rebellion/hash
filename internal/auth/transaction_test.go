// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

func TestSessionTransactionAuthorizationBindsSignedIdentity(t *testing.T) {
	cookies, err := NewSignedCookie("2424242424242424242424242424242424242424242424242424242424242424")
	if err != nil {
		t.Fatal(err)
	}
	user := &generated.User{ID: uuid.New(), OrgID: uuid.New(), SessionGeneration: 4}
	session := SessionPayload{UserID: user.ID, Generation: 4}
	payload, _ := json.Marshal(session)
	cookie := cookies.Mint(payload, time.Hour)
	guard := SessionTransactionAuthorization(cookies, cookie, session, user.OrgID)
	if err := guard(context.Background(), nil, user); err != nil {
		t.Fatal(err)
	}
	changed := *user
	changed.SessionGeneration++
	if err := guard(context.Background(), nil, &changed); !errors.Is(err, ErrMutationPermissionRevoked) {
		t.Fatalf("changed generation: %v", err)
	}
	forged := session
	forged.Generation++
	if err := SessionTransactionAuthorization(cookies, cookie, forged, user.OrgID)(context.Background(), nil, &changed); !errors.Is(err, ErrMutationPermissionRevoked) {
		t.Fatalf("cookie identity mismatch: %v", err)
	}
	expired := cookies.Mint(payload, -time.Second)
	if err := SessionTransactionAuthorization(cookies, expired, session, user.OrgID)(context.Background(), nil, user); !errors.Is(err, ErrMutationCredentialExpired) {
		t.Fatalf("expired cookie: %v", err)
	}
	changed = *user
	changed.OrgID = uuid.New()
	if err := guard(context.Background(), nil, &changed); !errors.Is(err, ErrMutationPermissionRevoked) {
		t.Fatalf("changed tenant: %v", err)
	}
}

func TestAPITransactionAuthorizationRequiresVerifiedAdmission(t *testing.T) {
	ctx := context.WithValue(context.Background(), UserIDKey, uuid.New())
	ctx = context.WithValue(ctx, OrgIDKey, uuid.New())
	ctx = context.WithValue(ctx, TokenScopesKey, []string{"admin"})
	if _, err := APIKeyTransactionAuthorization(ctx, uuid.New(), "write:workflow"); !errors.Is(err, ErrMutationPermissionRevoked) {
		t.Fatalf("fabricated public identity: %v", err)
	}
}

func TestMiddlewareCredentialReceiptPreservesOriginalScopeAndDocument(t *testing.T) {
	key, err := MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	documentID := uuid.New()
	verifier := apiKeyVerifierStub{id: uuid.New(), userID: uuid.New(), orgID: uuid.New(), docScope: documentID, hash: key.Hash, scopes: []string{"write:workflow"}}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Authorization", "Bearer "+key.Plaintext)
	RequireAPIKey(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A downstream mutation of the public scope slice cannot widen the
		// credential rights captured when the secret was actually admitted.
		scopes, _ := TokenScopesFromContext(r.Context())
		scopes[0] = "admin"
		if _, err := APIKeyTransactionAuthorization(r.Context(), documentID, "write:authoring"); !errors.Is(err, ErrMutationPermissionRevoked) {
			t.Errorf("scope escalation: %v", err)
		}
		if _, err := APIKeyTransactionAuthorization(r.Context(), uuid.New(), "write:workflow"); !errors.Is(err, ErrMutationPermissionRevoked) {
			t.Errorf("scope escape: %v", err)
		}
		if _, err := APIKeyTransactionAuthorization(r.Context(), documentID, "write:workflow"); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("middleware admission status=%d", response.Code)
	}
}
