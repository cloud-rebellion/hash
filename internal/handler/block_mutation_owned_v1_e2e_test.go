//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func ownedBlockTestDocumentV1(t *testing.T, w *httptest.ResponseRecorder, transport string) *generated.Document {
	t.Helper()
	var doc generated.Document
	if transport == "rest" {
		if w.Code != http.StatusCreated && w.Code != http.StatusOK {
			t.Fatalf("actual block route=%d %s", w.Code, w.Body.String())
		}
		if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
	} else {
		var rpc struct {
			Result struct {
				Content []struct{ Text string }
				IsError bool
			}
		}
		if err := json.Unmarshal(w.Body.Bytes(), &rpc); err != nil || rpc.Result.IsError || len(rpc.Result.Content) != 1 {
			t.Fatalf("actual MCP block result %v %s", err, w.Body.String())
		}
		if err := json.Unmarshal([]byte(rpc.Result.Content[0].Text), &doc); err != nil {
			t.Fatal(err)
		}
	}
	if doc.ID == uuid.Nil {
		t.Fatal("actual block result has no document ID")
	}
	return &doc
}
func ownedBlockAppendV1(t *testing.T, f lifecycleAuthorizationFixture, transport, credential string, id uuid.UUID, stamp string) *httptest.ResponseRecorder {
	t.Helper()
	block := json.RawMessage("{\"type\":\"paragraph\",\"text\":\"Negotiated extra clause\"}")
	if transport == "mcp" {
		return submitRecipientMCPE2E(f, "append_block", credential, map[string]any{"document_id": id, "expected_updated_at": stamp, "block": block})
	}
	body, _ := json.Marshal(map[string]any{"expected_updated_at": stamp, "block": block})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/v1/documents/"+id.String()+"/blocks", bytes.NewReader(body)).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}
func ownedBlockCacheStateV1(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, "SELECT jsonb_build_array((SELECT row_to_json(m) FROM document_signing_policy_sizes_v1 m WHERE document_id=$1),(SELECT row_to_json(m) FROM html_creation_response_sizes_v1 m WHERE document_id=$1),(SELECT row_to_json(m) FROM document_read_report_sizes_v1 m WHERE document_id=$1))::text", id).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// This real operation test creates its own native measured source, appends via
// the actual authenticated REST/MCP tool, and observes actual old/new rows and
// linear versions. Direct SQL below is only the independent finite test oracle
// or intentional missing-cache/revocation stimulus, never application repair.
func TestOwnedBlocksMutationActualCASVersionsAndAuthorizationE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			var keyID uuid.UUID
			if transport == "mcp" {
				f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
				f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
				key, id := mintRecipientMCPKeyE2E(t, f, false, 0)
				credential, keyID = key.Plaintext, id
			}
			args := map[string]any{"name": "Measured draft for actual edit", "source_kind": "blocks", "blocks_json": json.RawMessage("{\"version\":0,\"blocks\":[{\"type\":\"paragraph\",\"text\":\"Original exact clause\"}]}"), "variables_json": map[string]string{"customer": "Exact original customer"}}
			created := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, transport, credential, args), transport)
			old, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			oldTree, err := blocks.ParseCanonicalTree(old.BlocksJson)
			if err != nil {
				t.Fatal(err)
			}
			var parent uuid.UUID
			if transport == "mcp" {
				previous, err := f.q.GetLatestDocumentVersion(f.ctx, old.ID)
				if err != nil {
					t.Fatal(err)
				}
				parent = previous.ID
			}
			response := ownedBlockAppendV1(t, f, transport, credential, old.ID, old.UpdatedAt.Time.UTC().Format(time.RFC3339Nano))
			updated := ownedBlockTestDocumentV1(t, response, transport)
			stored, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: old.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			tree, err := blocks.ParseCanonicalTree(stored.BlocksJson)
			if err != nil || len(tree.Blocks) != 2 || tree.Version != blocks.SchemaVersion || tree.Blocks[0].ID != oldTree.Blocks[0].ID || tree.Blocks[0].Text != oldTree.Blocks[0].Text || tree.Blocks[1].ID == "" || tree.Blocks[1].ID == tree.Blocks[0].ID || updated.ID != old.ID {
				t.Fatalf("actual normalization/persisted identity changed: %v", err)
			}
			if string(stored.VariablesJson) != string(old.VariablesJson) {
				t.Fatal("block edit changed original variables")
			}
			latest, err := f.q.GetLatestDocumentVersion(f.ctx, old.ID)
			if err != nil {
				t.Fatal(err)
			}
			wantVersion := int32(1)
			if transport == "mcp" {
				wantVersion = 2
			}
			if latest.VersionNo != wantVersion || latest.ParentID.Valid != (parent != uuid.Nil) || (latest.ParentID.Valid && uuid.UUID(latest.ParentID.Bytes) != parent) || string(latest.BlockTreeJson) != string(stored.BlocksJson) || string(latest.VariablesJson) != string(stored.VariablesJson) {
				t.Fatal("actual original linear version chain/source not preserved")
			}
			cacheBefore := ownedBlockCacheStateV1(t, f, old.ID)
			before := f.snapshot(t)
			stale := ownedBlockAppendV1(t, f, transport, credential, old.ID, old.UpdatedAt.Time.UTC().Format(time.RFC3339Nano))
			if transport == "rest" {
				if stale.Code != http.StatusPreconditionFailed {
					t.Fatalf("stale=%d %s", stale.Code, stale.Body.String())
				}
			} else {
				assertLifecycleMCPResultE2E(t, stale, true)
				if !strings.Contains(stale.Body.String(), "changed since observation") {
					t.Fatal(stale.Body.String())
				}
			}
			if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, old.ID) != cacheBefore {
				t.Fatal("stale CAS changed source, version, audit, or any genuine measurement")
			}
			// The actual live role and original credential must refuse with the old
			// source and measurements intact; the original role is restored only by
			// the independent fixture before the following corruption stimulus.
			if _, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"}); err != nil {
				t.Fatal(err)
			}
			before = f.snapshot(t)
			denied := ownedBlockAppendV1(t, f, transport, credential, old.ID, stored.UpdatedAt.Time.UTC().Format(time.RFC3339Nano))
			if transport == "rest" {
				if denied.Code != http.StatusForbidden {
					t.Fatalf("role=%d %s", denied.Code, denied.Body.String())
				}
			} else {
				assertLifecycleMCPResultE2E(t, denied, true)
			}
			if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, old.ID) != cacheBefore {
				t.Fatal("wrong role changed the instrument or measurements")
			}
			if _, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
				t.Fatal(err)
			}
			if _, err = f.pool.Exec(f.ctx, "DELETE FROM html_creation_response_sizes_v1 WHERE document_id=$1", old.ID); err != nil {
				t.Fatal(err)
			}
			cacheBefore = ownedBlockCacheStateV1(t, f, old.ID)
			before = f.snapshot(t)
			missing := ownedBlockAppendV1(t, f, transport, credential, old.ID, stored.UpdatedAt.Time.UTC().Format(time.RFC3339Nano))
			if transport == "rest" {
				if missing.Code != http.StatusServiceUnavailable {
					t.Fatalf("missing cache=%d %s", missing.Code, missing.Body.String())
				}
			} else {
				assertLifecycleMCPResultE2E(t, missing, true)
			}
			if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, old.ID) != cacheBefore {
				t.Fatal("missing old cache caused read repair or instrument changes")
			}
			if transport == "rest" {
				if _, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration}); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = f.pool.Exec(f.ctx, "DELETE FROM api_keys WHERE id=$1", keyID); err != nil {
					t.Fatal(err)
				}
			}
			before = f.snapshot(t)
			revoked := ownedBlockAppendV1(t, f, transport, credential, old.ID, stored.UpdatedAt.Time.UTC().Format(time.RFC3339Nano))
			if revoked.Code != http.StatusUnauthorized {
				t.Fatalf("revoked credential did not win missing cache: %d %s", revoked.Code, revoked.Body.String())
			}
			if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, old.ID) != cacheBefore {
				t.Fatal("revoked credential changed instrument or measurements")
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
