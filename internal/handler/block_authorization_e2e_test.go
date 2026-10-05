//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type blockAuthorizationFixture struct{ lifecycleAuthorizationFixture }

var blockRESTOperationsE2E = []string{"append", "update", "delete", "reorder", "import-html", "import-md"}

func setupBlockAuthorizationE2E(t *testing.T, role string) blockAuthorizationFixture {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, role, false, false)
	f.s.Versions = versions.New(f.q)
	if _, err := f.q.CreateDraftField(f.ctx, generated.CreateDraftFieldParams{
		DocumentID: f.doc.ID, OrgID: f.org, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, Type: "text", Page: 1,
		XPct: pctToNumeric(0), YPct: pctToNumeric(0), WPct: pctToNumeric(15), HPct: pctToNumeric(4), OptionsJson: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	return blockAuthorizationFixture{f}
}

func (f blockAuthorizationFixture) enableMCP() {
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: f.s.Versions, PublicURL: f.s.PublicURL})
}

func blockRESTInputE2E(docID uuid.UUID, operation, stamp string) (string, string, map[string]any) {
	method, path := http.MethodPost, "/api/v1/documents/"+docID.String()
	input := map[string]any{"expected_updated_at": stamp}
	switch operation {
	case "append":
		path += "/blocks"
		input["block"] = map[string]any{"id": "new-block", "type": "paragraph", "text": "New reviewed terms"}
	case "update":
		method, path = http.MethodPatch, path+"/blocks/agreement"
		input["block"] = map[string]any{"id": "ignored-body-identity", "type": "paragraph", "text": "Reviewed replacement terms"}
	case "delete":
		method, path = http.MethodDelete, path+"/blocks/agreement"
	case "reorder":
		path += "/blocks/reorder"
		input["block_ids"] = []string{"signature", "agreement"}
	case "import-html":
		path += "/import-html"
		input["html"] = "<p>Reviewed imported terms</p>"
	case "import-md":
		path += "/import-md"
		input["markdown"] = "Reviewed imported terms"
	default:
		panic("unknown block fixture operation")
	}
	return method, path, input
}

func (f blockAuthorizationFixture) submit(operation, cookie, stamp string) *httptest.ResponseRecorder {
	method, path, input := blockRESTInputE2E(f.doc.ID, operation, stamp)
	body, _ := json.Marshal(input)
	return submitSessionOperationE2E(f.s, method, path, string(body), cookie)
}

// Capture through either the pool or a held parent transaction. In particular,
// expected soft-delete state is captured before the blocked request can run.
func (f blockAuthorizationFixture) snapshotDB(t *testing.T, db generated.DBTX) string {
	t.Helper()
	var state string
	err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
		'branding',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id),'[]'::jsonb) FROM document_branding_override b WHERE document_id IN (SELECT id FROM owned)),
		'fields',(SELECT coalesce(jsonb_agg(to_jsonb(f) ORDER BY id),'[]'::jsonb) FROM document_fields f WHERE document_id IN (SELECT id FROM owned)),
		'signatures',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY id),'[]'::jsonb) FROM signatures s WHERE document_id IN (SELECT id FROM owned)),
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE document_id IN (SELECT id FROM owned)),
		'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id IN (SELECT id FROM owned)),
		'privacy_requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE org_id=$1),
		'reminders',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY document_id),'[]'::jsonb) FROM reminders r WHERE document_id IN (SELECT id FROM owned)),
		'collab',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY document_id),'[]'::jsonb) FROM collab_doc_states s WHERE document_id IN (SELECT id FROM owned)),
		'generations',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY document_id),'[]'::jsonb) FROM collab_document_generations g WHERE document_id IN (SELECT id FROM owned)),
		'history_generations',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY document_id),'[]'::jsonb) FROM collab_state_generations g WHERE document_id IN (SELECT id FROM owned)),
		'archives',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM collab_recovery_archives a WHERE document_id IN (SELECT id FROM owned)),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE document_id IN (SELECT id FROM owned)),
		'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
		)::text`, f.org).Scan(&state) //nolint:rawsql -- exact synthetic authoring state, excluding intentional credential/member changes
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func (f blockAuthorizationFixture) snapshot(t *testing.T) string { return f.snapshotDB(t, f.pool) }

func (f blockAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t) != before {
		t.Fatal("refused block write changed content, variables, versions, recipient credentials, fields, privacy linkage, collaboration history, audit, intent, or outbox")
	}
}

// Attribute the wait to this fixture's actual lock holder and reject an early
// response explicitly. An unrelated blocked query cannot satisfy the proof.
func blockAwaitLockE2E(t *testing.T, f blockAuthorizationFixture, held pgx.Tx, result <-chan *httptest.ResponseRecorder, query, event string) {
	t.Helper()
	var holderPID int32
	if err := held.QueryRow(f.ctx, `SELECT pg_backend_pid()`).Scan(&holderPID); err != nil { //nolint:rawsql -- fixture connection identity
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case response := <-result:
			t.Fatalf("block mutation returned before its own %s wait: status=%d response=%s", query, response.Code, response.Body.String())
		default:
		}
		var waiting bool
		if err := f.pool.QueryRow(f.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity a
			WHERE datname=current_database() AND state='active' AND position($1 in query)>0
			AND wait_event=$2 AND $3=ANY(pg_blocking_pids(a.pid)))`, query, event, holderPID).Scan(&waiting); err != nil { //nolint:rawsql -- actual synthetic request/holder wait
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("block mutation did not reach its own %s %s wait", query, event)
}

func (f blockAuthorizationFixture) assertCommit(t *testing.T, tool, via string) *generated.Document {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	var versionCount, exactVersions, eventCount, exactEvents, outboxCount int
	if err := f.pool.QueryRow(f.ctx, `SELECT
		(SELECT count(*) FROM document_versions WHERE document_id=$1),
		(SELECT count(*) FROM document_versions v JOIN documents d ON d.id=v.document_id
		 WHERE v.document_id=$1 AND v.created_by=$2 AND v.created_via=$3 AND v.summary=$4
		 AND v.block_tree_json=d.blocks_json AND v.variables_json=d.variables_json AND v.name=d.name),
		(SELECT count(*) FROM events WHERE document_id=$1),
		(SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id=$2 AND kind='document.updated' AND payload_json->>'tool'=$4),
		(SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1))`,
		f.doc.ID, f.user.ID, via, tool).Scan(&versionCount, &exactVersions, &eventCount, &exactEvents, &outboxCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if versionCount != 1 || exactVersions != 1 || eventCount != 1 || exactEvents != 1 || outboxCount != 0 {
		t.Fatalf("block commit versions/exact/events/exact/outbox=%d/%d/%d/%d/%d want1/1/1/1/0", versionCount, exactVersions, eventCount, exactEvents, outboxCount)
	}
	rows, err := f.q.ListChainedEventsPageForOrg(f.ctx, generated.ListChainedEventsPageForOrgParams{OrgID: f.org, PageLimit: 100})
	if err != nil {
		t.Fatal(err)
	}
	verifier := audit.NewChainVerifier()
	verifier.VerifyPage(rows)
	if result := verifier.Result(); !result.OK || !result.Complete || result.TotalChecked != 1 {
		t.Fatalf("block authoring audit chain invalid: %+v", result)
	}
	return doc
}

// Fixed, fixture-scoped SQL faults exercise rollback after content, generation
// and version writes. RETURN NULL is an unexpected persistence failure, never a
// missing document or validation error.
func blockAuthoringFaultE2E(t *testing.T, f blockAuthorizationFixture, fault string) func() {
	t.Helper()
	name := "hash_block_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	table, event := "events", "INSERT"
	predicate := fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='document.updated'", f.doc.ID)
	failure := "RAISE EXCEPTION 'fixture private block database failure: validation not editable block not found';"
	if strings.HasSuffix(fault, "no-row") {
		failure = "RETURN NULL;"
	}
	switch {
	case strings.HasPrefix(fault, "mutation"):
		table, event, predicate = "documents", "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid", f.doc.ID)
	case strings.HasPrefix(fault, "version"):
		table, predicate = "document_versions", fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
	}
	if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN IF %s THEN %s END IF; RETURN NEW; END $$;
		CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, name, event, table, name)); err != nil { //nolint:rawsql,gosec -- fixed constants and generated UUID
		t.Fatal(err)
	}
	drop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil { //nolint:rawsql,gosec
			t.Error(err)
		}
	}
	t.Cleanup(drop)
	return drop
}

func TestBlockAuthoringRechecksSessionAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "sender")
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				before := f.snapshot(t)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(operation, cookie, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)) }()
				blockAwaitLockE2E(t, f, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if response.Code != http.StatusOK {
						t.Fatalf("actual demotion=%d %s", response.Code, response.Body.String())
					}
				case "logout":
					if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
						t.Fatalf("actual logout=%d", response.Code)
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				if response.Code != want {
					t.Fatalf("stale block %s=%d want%d %s", operation, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestBlockAuthoringAuditWaitExpiryRollsBackVersionsE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		t.Run(operation, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "sender")
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			stamp := f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)
			go func() { result <- f.submit(operation, cookie, stamp) }()
			blockAwaitLockE2E(t, f, blocked, result, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			f.assertUnchanged(t, before)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusUnauthorized {
				t.Fatalf("audit-expired block=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			if response := f.submit(operation, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour), stamp); response.Code != http.StatusOK {
				t.Fatalf("fresh block retry=%d %s", response.Code, response.Body.String())
			}
			via := string(versions.ViaHuman)
			if strings.HasPrefix(operation, "import") {
				via = string(versions.ViaImport)
			}
			f.assertCommit(t, blockRESTToolE2E(operation), via)
		})
	}
}

func blockRESTToolE2E(operation string) string {
	switch operation {
	case "append":
		return "rest:append_block"
	case "update":
		return "rest:update_block"
	case "delete":
		return "rest:delete_block"
	case "reorder":
		return "rest:reorder_blocks"
	case "import-html":
		return "rest:import_html"
	case "import-md":
		return "rest:import_markdown"
	default:
		panic("unknown REST fixture operation")
	}
}

func TestBlockAuthoringInternalFailuresRollBackAndRetryE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		for _, fault := range []string{"audit-exception", "audit-no-row", "version-exception", "version-no-row", "mutation-no-row"} {
			t.Run(operation+"/"+fault, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				before := f.snapshot(t)
				drop := blockAuthoringFaultE2E(t, f, fault)
				cookie, stamp := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour), f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)
				response := f.submit(operation, cookie, stamp)
				if response.Code != http.StatusInternalServerError {
					t.Fatalf("block %s/%s=%d %s", operation, fault, response.Code, response.Body.String())
				}
				for _, leak := range []string{"fixture private", "hash_block_failure_", "SQLSTATE", "PL/pgSQL", "no rows", "document_versions"} {
					if strings.Contains(response.Body.String(), leak) {
						t.Fatalf("block error exposed %q", leak)
					}
				}
				f.assertUnchanged(t, before)
				drop()
				if response := f.submit(operation, cookie, stamp); response.Code != http.StatusOK {
					t.Fatalf("block retry=%d %s", response.Code, response.Body.String())
				}
				via := string(versions.ViaHuman)
				if strings.HasPrefix(operation, "import") {
					via = string(versions.ViaImport)
				}
				f.assertCommit(t, blockRESTToolE2E(operation), via)
			})
		}
	}
}

func TestBlockAuthoringObservationsCanonicalVersionsAndPathIdentityE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		t.Run(operation, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "sender")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			before := f.snapshot(t)
			for _, observation := range []struct {
				stamp  string
				status int
			}{{"", http.StatusPreconditionRequired}, {"invalid", http.StatusBadRequest}, {f.doc.UpdatedAt.Time.Add(-time.Second).Format(time.RFC3339Nano), http.StatusPreconditionFailed}} {
				if response := f.submit(operation, cookie, observation.stamp); response.Code != observation.status {
					t.Fatalf("block observation=%d want%d %s", response.Code, observation.status, response.Body.String())
				}
				f.assertUnchanged(t, before)
			}
			if response := f.submit(operation, cookie, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)); response.Code != http.StatusOK {
				t.Fatalf("fresh canonical block=%d %s", response.Code, response.Body.String())
			}
			via := string(versions.ViaHuman)
			if strings.HasPrefix(operation, "import") {
				via = string(versions.ViaImport)
			}
			doc := f.assertCommit(t, blockRESTToolE2E(operation), via)
			tree, err := blocks.ParseTree(doc.BlocksJson)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "update" && (tree.Blocks[0].ID != "agreement" || tree.Blocks[0].Text != "Reviewed replacement terms") {
				t.Fatal("REST block replacement lost path identity or requested text")
			}
			if string(doc.VariablesJson) != "{}" {
				t.Fatal("block mutation replaced canonical variables")
			}
		})
	}
}

func TestBlockAuthoringBodyBoundsAndValidationPreserveStateE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		t.Run(operation, func(t *testing.T) {
			f := setupBlockAuthorizationE2E(t, "owner")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			before := f.snapshot(t)
			method, path, input := blockRESTInputE2E(f.doc.ID, operation, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano))
			input["unexpected_property"] = true
			unknown, _ := json.Marshal(input)
			delete(input, "unexpected_property")
			input["expected_updated_at"] = strings.Repeat("x", (1<<20)+1)
			oversized, _ := json.Marshal(input)
			for _, body := range []string{`{"expected_updated_at":`, string(unknown), string(oversized)} {
				if response := submitSessionOperationE2E(f.s, method, path, body, cookie); response.Code != http.StatusBadRequest {
					t.Fatalf("invalid block body=%d %s", response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			}
			if operation == "append" || operation == "update" {
				_, _, input = blockRESTInputE2E(f.doc.ID, operation, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano))
				input["block"] = map[string]any{"id": "invalid", "type": "unrecognized"}
				invalid, _ := json.Marshal(input)
				if response := submitSessionOperationE2E(f.s, method, path, string(invalid), cookie); response.Code != http.StatusBadRequest {
					t.Fatalf("canonical block validation=%d %s", response.Code, response.Body.String())
				}
				f.assertUnchanged(t, before)
			}
		})
	}
}

func (f blockAuthorizationFixture) seedRefusal(t *testing.T, state string, db generated.DBTX) (int, string) {
	t.Helper()
	switch state {
	case "deleted":
		if _, err := db.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID); err != nil {
			t.Fatal(err)
		}
		return http.StatusNotFound, authoring.ErrDocumentNotFound.Error()
	case "active":
		// Synthetic terminal state has no send epoch and exercises draft admission
		// without pretending to have performed a sealing/storage ceremony.
		seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, db, f.doc.ID)
		if _, err := db.Exec(f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, f.doc.ID); err != nil {
			t.Fatal(err)
		}
		return http.StatusConflict, authoring.ErrDocumentNotDraft.Error()
	case "pdf":
		if _, err := db.Exec(f.ctx, `UPDATE documents SET source_kind='pdf',pdf_storage_key=$2,pdf_sha256=$3,pdf_storage_version_id='block-fixture-version' WHERE id=$1`, f.doc.ID, "org/"+f.org.String()+"/documents/"+f.doc.ID.String()+".pdf", make([]byte, 32)); err != nil {
			t.Fatal(err)
		}
		return http.StatusConflict, authoring.ErrDocumentNotDraft.Error()
	case "evidence":
		if _, err := db.Exec(f.ctx, `UPDATE document_fields SET value='Captured retained value',completed_at=clock_timestamp() WHERE document_id=$1`, f.doc.ID); err != nil {
			t.Fatal(err)
		}
		return http.StatusConflict, authoring.ErrDocumentHasEvidence.Error()
	case "linked-privacy", "global-privacy":
		docID := pgtype.UUID{}
		if state == "linked-privacy" {
			docID = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
		}
		if _, err := generated.New(db).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, DocumentID: docID, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true}, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
			t.Fatal(err)
		}
		return http.StatusConflict, authoring.ErrPendingPrivacyReview.Error()
	default:
		t.Fatalf("unknown block refusal %s", state)
		return 0, ""
	}
}

func TestBlockAuthoringFreshStateAfterDocumentWaitE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		for _, state := range []string{"deleted", "active", "pdf", "evidence", "linked-privacy"} {
			t.Run(operation+"/"+state, func(t *testing.T) {
				f := setupBlockAuthorizationE2E(t, "owner")
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- f.submit(operation, cookie, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)) }()
				blockAwaitLockE2E(t, f, blocked, result, "-- name: GetDocumentForUpdate", "transactionid")
				want, message := f.seedRefusal(t, state, blocked)
				before := f.snapshotDB(t, blocked)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				response := receiveSessionOperationE2E(t, result)
				if response.Code != want || !strings.Contains(response.Body.String(), message) {
					t.Fatalf("fresh block state %s=%d want%d %s", state, response.Code, want, response.Body.String())
				}
				f.assertUnchanged(t, before)
			})
		}
	}
}

func TestBlockAuthoringTenantAndPrivacyFenceE2E(t *testing.T) {
	for _, operation := range blockRESTOperationsE2E {
		t.Run(operation, func(t *testing.T) {
			f, foreign := setupBlockAuthorizationE2E(t, "owner"), setupBlockAuthorizationE2E(t, "owner")
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			before, foreignBefore := f.snapshot(t), foreign.snapshot(t)
			method, path, input := blockRESTInputE2E(foreign.doc.ID, operation, foreign.doc.UpdatedAt.Time.Format(time.RFC3339Nano))
			body, _ := json.Marshal(input)
			if response := submitSessionOperationE2E(f.s, method, path, string(body), cookie); response.Code != http.StatusNotFound {
				t.Fatalf("cross-tenant block=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			foreign.assertUnchanged(t, foreignBefore)
			changing, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer changing.Rollback(context.Background())
			if _, err := f.q.WithTx(changing).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}); err != nil {
				t.Fatal(err)
			}
			if response := f.submit(operation, cookie, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), authoring.ErrPrivacyReviewChanging.Error()) {
				t.Fatalf("changing block privacy=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
			if err := changing.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			f.seedRefusal(t, "global-privacy", f.pool)
			before = f.snapshot(t)
			if response := f.submit(operation, cookie, f.doc.UpdatedAt.Time.Format(time.RFC3339Nano)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), authoring.ErrPendingPrivacyReview.Error()) {
				t.Fatalf("global block privacy=%d %s", response.Code, response.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

// Database messages can resemble user validation text. Type provenance wins
// over substrings; genuine scoped absence is already a domain sentinel.
func TestBlockMutationStatusPreservesInternalErrorTypesE2E(t *testing.T) {
	for _, message := range []string{"validation failed", "not editable", "block not found", "unknown or duplicate", "block_ids length"} {
		for _, internal := range []error{&pgconn.PgError{Message: message, Code: "P0001"}, pgx.ErrNoRows} {
			if got := mapMutationStatus(fmt.Errorf("validation: %w", internal)); got != http.StatusInternalServerError {
				t.Fatalf("internal %v mapped to %d", internal, got)
			}
		}
	}
	if got := mapMutationStatus(fmt.Errorf("lock parent: %w", authoring.ErrDocumentNotFound)); got != http.StatusNotFound {
		t.Fatalf("scoped absence mapped to %d", got)
	}
	for _, item := range []struct {
		err    error
		status int
	}{
		{auth.ErrMutationCredentialExpired, http.StatusUnauthorized},
		{auth.ErrMutationPermissionRevoked, http.StatusForbidden},
		{authoring.ErrDocumentNotDraft, http.StatusConflict},
		{authoring.ErrDocumentHasEvidence, http.StatusConflict},
		{authoring.ErrPrivacyReviewChanging, http.StatusConflict},
		{authoring.ErrPendingPrivacyReview, http.StatusConflict},
		{errBlockObservationMissing, http.StatusPreconditionRequired},
		{errBlockObservationMalformed, http.StatusBadRequest},
		{errBlockObservationStale, http.StatusPreconditionFailed},
	} {
		if got := mapMutationStatus(fmt.Errorf("mutation refused: %w", item.err)); got != item.status {
			t.Fatalf("typed %v mapped to %d want%d", item.err, got, item.status)
		}
	}
}
