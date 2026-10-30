// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMCPReplacementRevisionEvidenceE2E(t *testing.T) {
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Every case still owns a complete independent estate. Only the closed,
	// fully migrated empty seed is reused; source/history assertions are unchanged.
	database := revisionDatabasesE2E.Clone(t, "hash_mcp_revision_e2e_")
	cfg.ConnConfig.Database = database
	cfg.ConnConfig.RuntimeParams["application_name"] = "hash_mcp_revision_" + uuid.NewString()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	q := generated.New(pool)
	org, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "MCP revision", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@mcp.test", Name: "Owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 8}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, SQLSessions: 4}, MaxGrants: 128, MaxOrganisationGrants: 64}
	runtime, err := pdfadmission.NewWorkRuntimeV1(pool, limits, int64(pool.Config().MaxConns)+8)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		observers := runtime.SessionsV1().PendingV1().ObserverSessions
		err := runtime.CloseV1(cleanup)
		pending := runtime.SessionsV1().PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 || pending.HTMLCanonicalConsumers != 0 || pending.CatalogMaintenance != 0 || pending.ObserverSessions != observers {
			t.Errorf("revision runtime retained work: %+v", pending)
		}
		if observers > 0 && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			t.Errorf("revision observer cleanup debt falsely resolved: %v", err)
		} else if observers == 0 && err != nil {
			t.Error(err)
		}
		snapshot, snapshotErr := runtime.SnapshotV1(org.ID)
		if snapshotErr != nil || snapshot.Global != (workguard.VectorV1{SQLSessions: int64(observers)}) || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("revision work leaked or observer debt lost: %+v err=%v", snapshot, snapshotErr)
		}
	})
	// Explicitly prepare only the seeded operator plan through its real M95
	// producer. No fixture inserts or repairs measurement/authority rows.
	var plan uuid.UUID
	var serverVersion int32
	if err := pool.QueryRow(ctx, "SELECT id,current_setting('server_version_num')::integer FROM billing_plans WHERE slug='pro'").Scan(&plan, &serverVersion); err != nil {
		t.Fatal(err)
	}
	owner, err := runtime.SessionsV1().ControlledMeasurePlanSourceV1(ctx, plan)
	if owner != nil {
		t.Cleanup(func() {
			owner.CloseConsumerV1()
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if err := owner.CloseV1(cleanup); err != nil {
				t.Error("revision plan source cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("actual revision plan preparation", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != plan || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != serverVersion || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("actual revision plan measurement receipt", err)
	}
	owner.CloseConsumerV1()
	if err := owner.CloseV1(ctx); err != nil {
		t.Fatal("actual revision plan owner close", err)
	}
	deps := Deps{Pool: pool, Queries: q, Audit: audit.New(q, pool), Versions: versions.New(q), PDFCreationSessions: runtime.SessionsV1(), Billing: billing.NewOperator(q, []config.OperatorEntitlement{{OrgID: org.ID, PlanSlug: "pro", ReviewRef: "synthetic revision qualification"}})}
	server := New(deps)
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
	call := func(t *testing.T, name string, args map[string]any, wantError bool) json.RawMessage {
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
				IsError bool                    `json:"isError"`
				Content []struct{ Text string } `json:"content"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &reply) != nil || len(reply.Error) != 0 || reply.Result.IsError != wantError {
			t.Fatalf("tool %s status=%d wantError=%v %s", name, response.Code, wantError, response.Body.String())
		}
		if !wantError && len(reply.Result.Content) != 1 {
			t.Fatalf("tool %s returned no single actual result: %s", name, response.Body.String())
		}
		if wantError {
			return nil
		}
		return json.RawMessage(reply.Result.Content[0].Text)
	}
	tree := json.RawMessage(`{"version":1,"blocks":[{"id":"p","type":"paragraph","text":"original"}]}`)
	var doc generated.Document
	if err := json.Unmarshal(call(t, "create_document", map[string]any{"name": "MCP", "source_kind": "blocks", "blocks_json": tree, "variables_json": map[string]string{}}, false), &doc); err != nil || doc.ID == uuid.Nil {
		t.Fatal("actual native revision document creation", err)
	}
	targetVersion, err := q.GetLatestDocumentVersionNo(ctx, doc.ID)
	if err != nil || targetVersion != 1 {
		t.Fatal("actual native creation snapshot missing", err)
	}
	target, err := q.GetDocumentVersionByNo(ctx, generated.GetDocumentVersionByNoParams{DocumentID: doc.ID, VersionNo: targetVersion})
	if err != nil {
		t.Fatal(err)
	}
	var uncompressed bool
	if err := pool.QueryRow(ctx, "SELECT pg_column_compression(block_tree_json) IS NULL AND pg_column_compression(variables_json) IS NULL FROM document_versions WHERE id=$1", target.ID).Scan(&uncompressed); err != nil || !uncompressed {
		t.Fatal("positive restore target must be an actual uncompressed native version", err)
	}
	old := doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)
	call(t, "set_variables", map[string]any{"document_id": doc.ID.String(), "expected_updated_at": old, "variables": map[string]string{"state": "new"}}, false)
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
		"restore_document_version": {"target_version": targetVersion},
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
			previousVersion, err := q.GetLatestDocumentVersionIdentityV1(ctx, doc.ID)
			if err != nil {
				t.Fatal(err)
			}
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
			if name == "restore_document_version" {
				latest, err := q.GetLatestDocumentVersion(ctx, doc.ID)
				after, readErr := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
				if err != nil || readErr != nil || av != v+1 || ae != e+1 || latest.CreatedVia != "restore" || latest.Summary != fmt.Sprintf("restored from v%d", targetVersion) || latest.Name != target.Name || !latest.ParentID.Valid || uuid.UUID(latest.ParentID.Bytes) != previousVersion || string(after.BlocksJson) != string(target.BlockTreeJson) || string(after.VariablesJson) != string(target.VariablesJson) || after.Name != current.Name {
					t.Fatal("restore changed historical content/provenance or emitted duplicate evidence", err, readErr)
				}
				var payload json.RawMessage
				if err := pool.QueryRow(ctx, "SELECT payload_json FROM events WHERE document_id=$1 ORDER BY created_at DESC,id DESC LIMIT 1", doc.ID).Scan(&payload); err != nil {
					t.Fatal(err)
				}
				var fields map[string]json.RawMessage
				if json.Unmarshal(payload, &fields) != nil || len(fields) != 3 || string(fields["via"]) != `"mcp"` || string(fields["tool"]) != `"restore_document_version"` || string(fields["restored_from_v"]) != fmt.Sprint(targetVersion) {
					t.Fatal("restore audit payload lost its exact original schema")
				}
			}
		})
	}

	// The following stimuli use the same genuine current document and admitted
	// API credential. A legacy compressed history row is intentionally synthetic;
	// it cannot become an owned source or repair the current measured document.
	state := func(t *testing.T) string {
		t.Helper()
		var state string
		if err := pool.QueryRow(ctx, `SELECT jsonb_build_object(
 'document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),
 'versions',(SELECT jsonb_agg(to_jsonb(v) ORDER BY version_no) FROM document_versions v WHERE document_id=$1),
 'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY created_at,id) FROM events e WHERE document_id=$1),
 'policy',(SELECT to_jsonb(p) FROM document_signing_policy_sizes_v1 p WHERE document_id=$1),
 'response',(SELECT to_jsonb(p) FROM html_creation_response_sizes_v1 p WHERE document_id=$1),
 'report',(SELECT to_jsonb(p) FROM document_read_report_sizes_v1 p WHERE document_id=$1))::text`, doc.ID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	t.Run("restore_audit_failure_rolls_back_source_history_and_measurements", func(t *testing.T) {
		_, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION mcp_restore_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic restore audit failure'; END $$;
 CREATE TRIGGER mcp_restore_fail_audit BEFORE INSERT ON events FOR EACH ROW
 WHEN (NEW.document_id='%s'::uuid AND NEW.kind='document.updated') EXECUTE FUNCTION mcp_restore_fail_audit()`, doc.ID))
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, err := pool.Exec(cleanup, "DROP TRIGGER mcp_restore_fail_audit ON events; DROP FUNCTION mcp_restore_fail_audit()"); err != nil {
				t.Error(err)
			}
		}()
		current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
		if err != nil {
			t.Fatal(err)
		}
		before := state(t)
		call(t, "restore_document_version", map[string]any{"document_id": doc.ID.String(), "target_version": targetVersion, "expected_updated_at": current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}, true)
		if before != state(t) {
			t.Fatal("failed restore audit committed source, history, event or measurement state")
		}
	})
	t.Run("restore_compressed_history_refuses_without_side_effects", func(t *testing.T) {
		body, err := json.Marshal(map[string]any{"version": 1, "blocks": []any{map[string]string{"id": "legacy", "type": "paragraph", "text": strings.Repeat("legacy compressed text ", 2048)}}})
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := versions.New(q).Snapshot(ctx, versions.SnapshotInput{DocumentID: doc.ID, OrgID: org.ID, Name: "Synthetic legacy compressed target", SourceKind: "blocks", BlocksJSON: body, VariablesJS: json.RawMessage(`{}`), CreatedBy: &user.ID, Via: versions.ViaHuman, Summary: "Explicit unsupported historical storage stimulus"})
		if err != nil {
			t.Fatal(err)
		}
		var compressed bool
		if err := pool.QueryRow(ctx, "SELECT pg_column_compression(block_tree_json) IS NOT NULL FROM document_versions WHERE id=$1", legacy.ID).Scan(&compressed); err != nil || !compressed {
			t.Fatal("legacy refusal stimulus did not use actual compressed PostgreSQL storage", err)
		}
		current, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: org.ID})
		if err != nil {
			t.Fatal(err)
		}
		before := state(t)
		call(t, "restore_document_version", map[string]any{"document_id": doc.ID.String(), "target_version": legacy.VersionNo, "expected_updated_at": current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)}, true)
		if before != state(t) {
			t.Fatal("unsupported historical restore changed source, versions, audit or original measurements")
		}
	})
}
