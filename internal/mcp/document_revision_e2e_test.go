// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestMCPReplacementRevisionEvidenceE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*cfg.ConnConfig)
	if err := mdb.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	db.Close()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "MCP revision", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@mcp.test", Name: "Owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	tree := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "MCP", BlocksJson: tree, VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	target, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: org.ID, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: tree, VariablesJS: doc.VariablesJson, CreatedBy: &user.ID, Via: versions.ViaHuman})
	if err != nil {
		t.Fatal(err)
	}
	old := doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	if _, err := q.UpdateDocumentBlocks(ctx, generated.UpdateDocumentBlocksParams{ID: doc.ID, OrgID: org.ID, BlocksJson: tree, VariablesJson: json.RawMessage(`{"state":"new"}`)}); err != nil {
		t.Fatal(err)
	}
	server := NewServer()
	deps := Deps{Pool: pool, Queries: q, Audit: audit.New(q, pool), Versions: versions.New(q)}
	registerAuthoringTools(server, deps)
	registerVersionTools(server, deps)
	mint, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{OrgID: org.ID, UserID: user.ID, Name: "Revision fixture key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:authoring"}}); err != nil {
		t.Fatal(err)
	}
	// Admit through genuine PgVerifier middleware. Public context identity is
	// insufficient for the original transaction receipt required by authoring.
	admitted := auth.RequireAPIKey(&auth.PgVerifier{Queries: q})(server.Handler())
	call := func(t *testing.T, name string, args map[string]any, wantError bool) {
		t.Helper()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(body))).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mint.Plaintext)
		response := httptest.NewRecorder()
		admitted.ServeHTTP(response, req)
		var reply struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reply) != nil || len(reply.Error) != 0 || reply.Result.IsError != wantError {
			t.Fatalf("tool %s status=%d wantError=%v %s", name, response.Code, wantError, response.Body.String())
		}
	}
	cases := map[string]map[string]any{
		"append_block":             {"block": map[string]string{"id": "q", "type": "paragraph", "text": "appended"}},
		"reorder_blocks":           {"block_ids": []string{"q", "p"}},
		"add_signature_field":      {"recipient_role": "client"},
		"delete_block":             {"block_id": "q"},
		"update_block":             {"block_id": "p", "block": map[string]string{"id": "p", "type": "paragraph", "text": "replacement"}},
		"set_document_blocks":      {"blocks_json": tree},
		"import_html":              {"html": "<p>Imported</p>"},
		"import_markdown":          {"markdown": "Imported"},
		"set_variables":            {"variables": map[string]string{"state": "replacement"}},
		"restore_document_version": {"target_version": target.VersionNo},
	}
	for _, name := range []string{"set_document_blocks", "import_html", "import_markdown", "set_variables", "restore_document_version", "update_block", "append_block", "reorder_blocks", "add_signature_field", "delete_block"} {
		args := cases[name]
		t.Run(name, func(t *testing.T) {
			current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
			if err != nil {
				t.Fatal(err)
			}
			counts := func() (int, int) {
				var v, e int
				if err := pool.QueryRow(ctx, "SELECT (SELECT count(*) FROM document_versions WHERE document_id=$1),(SELECT count(*) FROM events WHERE document_id=$1)", doc.ID).Scan(&v, &e); err != nil {
					t.Fatal(err)
				}
				return v, e
			}
			v, e := counts()
			args["document_id"] = doc.ID.String()
			args["expected_updated_at"] = old
			call(t, name, args, true)
			after, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
			if err != nil {
				t.Fatal(err)
			}
			av, ae := counts()
			if av != v || ae != e || string(after.BlocksJson) != string(current.BlocksJson) || string(after.VariablesJson) != string(current.VariablesJson) || !after.UpdatedAt.Time.Equal(current.UpdatedAt.Time) {
				t.Fatal("stale tool mutated content/evidence")
			}
			args["expected_updated_at"] = current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
			call(t, name, args, false)
			av, ae = counts()
			if av <= v || ae <= e {
				t.Fatal("fresh tool missing evidence")
			}
		})
	}
}
