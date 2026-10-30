//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type documentAuthorizationFixture struct{ fieldAuthorizationFixture }

func setupDocumentAuthorizationE2E(t *testing.T, role string) documentAuthorizationFixture {
	t.Helper()
	f := setupFieldAuthorizationE2E(t, role)
	f.s.Versions = versions.New(f.q)
	return documentAuthorizationFixture{f}
}

func (f documentAuthorizationFixture) input() updateDocumentInput {
	requiresSignature := false
	return updateDocumentInput{
		ExpectedUpdatedAt: toDocumentResponse(f.doc).UpdatedAt,
		Name:              "Updated authorized document", DefaultLocale: "sv-SE", RequiresSignature: &requiresSignature,
		ExpiresAt:     time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339),
		BlocksJSON:    json.RawMessage(`{"version":1,"blocks":[{"id":"agreement","type":"paragraph","text":"Changed agreement for {{customer}}"}]}`),
		VariablesJSON: json.RawMessage(`{"customer":"Updated fixture customer"}`),
	}
}

func (f documentAuthorizationFixture) submit(ctx context.Context, id uuid.UUID, input updateDocumentInput, cookie string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(input)
	r := httptest.NewRequest(http.MethodPatch, f.s.PublicURL+"/api/v1/documents/"+id.String(), strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.s.PublicURL)
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func (f documentAuthorizationFixture) snapshot(t *testing.T, db generated.DBTX) string {
	t.Helper()
	base := f.fieldAuthorizationFixture.snapshotDB(t, db)
	var authoring string
	err := db.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
		SELECT jsonb_build_object(
		'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY document_id,variable_name),'[]'::jsonb) FROM document_variable_bindings b WHERE document_id IN (SELECT id FROM owned)),
		'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id IN (SELECT id FROM owned)),
		'collab',(SELECT coalesce(jsonb_agg(to_jsonb(c) ORDER BY document_id),'[]'::jsonb) FROM collab_doc_states c WHERE document_id IN (SELECT id FROM owned)),
		'generations',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY document_id),'[]'::jsonb) FROM collab_document_generations g WHERE document_id IN (SELECT id FROM owned)),
		'history_generations',(SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY document_id),'[]'::jsonb) FROM collab_state_generations g WHERE document_id IN (SELECT id FROM owned)),
		'archives',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]'::jsonb) FROM collab_recovery_archives a WHERE document_id IN (SELECT id FROM owned))
		)::text`, f.org).Scan(&authoring) //nolint:rawsql -- exact synthetic authoring rows, no customer data
	if err != nil {
		t.Fatal(err)
	}
	return base + authoring
}

func (f documentAuthorizationFixture) assertUnchanged(t *testing.T, before string) {
	t.Helper()
	if f.snapshot(t, f.pool) != before {
		t.Fatal("refused document edit changed draft, variables, bindings, version/history, recipients, evidence, privacy linkage, audit or outbox")
	}
}

func TestDocumentPatchRechecksOriginalSessionAfterParentWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "logout", "expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupDocumentAuthorizationE2E(t, "sender")
			owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			before := f.snapshot(t, f.pool)
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			input := f.input()
			result := make(chan *httptest.ResponseRecorder, 1)
			startAuthoringParentRequest624E2E(t, tx, result, func() *httptest.ResponseRecorder { return f.submit(f.ctx, f.doc.ID, input, cookie) })
			awaitAuthoringParentWait624E2E(t, f.lifecycleAuthorizationFixture, tx, "-- name: GetHTMLRevisionDocumentReadHeaderV1", true)
			want := http.StatusForbidden
			switch change {
			case "demotion":
				if w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour)); w.Code != http.StatusOK {
					t.Fatalf("actual demotion=%d %s", w.Code, w.Body.String())
				}
			case "logout":
				if w := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); w.Code != http.StatusOK {
					t.Fatalf("actual logout=%d %s", w.Code, w.Body.String())
				}
			case "expiry":
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
				want = http.StatusUnauthorized
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != want {
				t.Fatalf("stale PATCH=%d want%d %s", w.Code, want, w.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDocumentPatchAuditWaitRollbackE2E(t *testing.T) {
	for _, failure := range []string{"expiry", "cancellation"} {
		t.Run(failure, func(t *testing.T) {
			f := setupDocumentAuthorizationE2E(t, "sender")
			before := f.snapshot(t, f.pool)
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if err := f.q.WithTx(tx).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if failure == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			input := f.input()
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit(ctx, f.doc.ID, input, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			want := http.StatusUnauthorized
			if failure == "expiry" {
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
			} else {
				cancel()
				want = http.StatusInternalServerError
			}
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != want {
				t.Fatalf("audit-wait PATCH=%d want%d %s", w.Code, want, w.Body.String())
			}
			f.assertUnchanged(t, before)
			if w := f.submit(f.ctx, f.doc.ID, input, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)); w.Code != http.StatusOK {
				t.Fatalf("retry PATCH=%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDocumentPatchRechecksParentAfterWaitE2E(t *testing.T) {
	for _, change := range []string{"deleted", "status", "source", "evidence", "privacy"} {
		t.Run(change, func(t *testing.T) {
			f := setupDocumentAuthorizationE2E(t, "sender")
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			input := f.input()
			result := make(chan *httptest.ResponseRecorder, 1)
			startAuthoringParentRequest624E2E(t, tx, result, func() *httptest.ResponseRecorder { return f.submit(f.ctx, f.doc.ID, input, cookie) })
			awaitAuthoringParentWait624E2E(t, f.lifecycleAuthorizationFixture, tx, "-- name: GetHTMLRevisionDocumentReadHeaderV1", true)
			want := http.StatusConflict
			switch change {
			case "deleted":
				_, err = tx.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID) //nolint:rawsql -- synthetic concurrent soft deletion
				want = http.StatusNotFound
			case "status":
				seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, tx, f.doc.ID)
				_, err = tx.Exec(f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, f.doc.ID) //nolint:rawsql -- synthetic non-draft transition
			case "source":
				f.setSourceKind(t, tx, "pdf")
				want = http.StatusPreconditionFailed
			case "evidence":
				_, err = tx.Exec(f.ctx, `UPDATE document_fields SET value='',completed_at=now() WHERE id=$1`, f.field.ID) //nolint:rawsql -- retained captured answer
			case "privacy":
				_, err = f.q.WithTx(tx).CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{OrgID: f.org, SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
			}
			if err != nil {
				t.Fatal(err)
			}
			expected := f.snapshot(t, tx)
			if err := tx.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != want {
				t.Fatalf("fresh parent PATCH=%d want%d %s", w.Code, want, w.Body.String())
			}
			f.assertUnchanged(t, expected)
		})
	}
}

func TestDocumentPatchScopedPreconditionsAndValidMetadataE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		for _, source := range []string{"blocks", "pdf"} {
			t.Run(role+"/"+source, func(t *testing.T) {
				f := setupDocumentAuthorizationE2E(t, role)
				if source == "pdf" {
					f.setSourceKind(t, f.pool, source)
					var err error
					f.doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
					if err != nil {
						t.Fatal(err)
					}
				}
				before := f.snapshot(t, f.pool)
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				input := f.input()
				if source == "pdf" {
					if w := f.submit(f.ctx, f.doc.ID, input, cookie); w.Code != http.StatusBadRequest {
						t.Fatalf("PDF content PATCH=%d %s", w.Code, w.Body.String())
					}
					f.assertUnchanged(t, before)
					input.BlocksJSON, input.VariablesJSON = nil, nil
				}
				for _, stamp := range []struct {
					value  string
					status int
				}{{"", http.StatusPreconditionRequired}, {"malformed", http.StatusBadRequest}, {time.Now().Add(-24 * time.Hour).Format(time.RFC3339Nano), http.StatusPreconditionFailed}} {
					invalid := input
					invalid.ExpectedUpdatedAt = stamp.value
					if w := f.submit(f.ctx, f.doc.ID, invalid, cookie); w.Code != stamp.status {
						t.Fatalf("observation PATCH=%d want%d %s", w.Code, stamp.status, w.Body.String())
					}
					f.assertUnchanged(t, before)
				}
				if w := f.submit(f.ctx, uuid.New(), input, cookie); w.Code != http.StatusNotFound {
					t.Fatalf("missing PATCH=%d %s", w.Code, w.Body.String())
				}
				foreign := setupDocumentAuthorizationE2E(t, "owner")
				foreignBefore := foreign.snapshot(t, foreign.pool)
				if w := f.submit(f.ctx, foreign.doc.ID, input, cookie); w.Code != http.StatusNotFound {
					t.Fatalf("foreign PATCH=%d %s", w.Code, w.Body.String())
				}
				f.assertUnchanged(t, before)
				foreign.assertUnchanged(t, foreignBefore)
				if w := f.submit(f.ctx, f.doc.ID, input, cookie); w.Code != http.StatusOK {
					t.Fatalf("valid PATCH=%d %s", w.Code, w.Body.String())
				}
				fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				if fresh.Name != input.Name || fresh.DefaultLocale != "sv" || fresh.RequiresSignature || !fresh.ExpiresAt.Valid || fresh.ExpiresAt.Time.UTC().Format(time.RFC3339) != input.ExpiresAt {
					t.Fatal("metadata PATCH lost authorized name, expiration, locale or signature mode")
				}
				if source == "blocks" && (!strings.Contains(string(fresh.BlocksJson), "Changed agreement") || !strings.Contains(string(fresh.VariablesJson), "Updated fixture customer")) {
					t.Fatal("block PATCH did not persist content and variables")
				}
				var count, wrongActor int
				if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER(WHERE actor_user_id IS DISTINCT FROM $2) FROM events WHERE document_id=$1 AND kind=$3`, f.doc.ID, f.user.ID, audit.KindDocumentUpdated).Scan(&count, &wrongActor); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- canonical audit assertion
				if count != 1 || wrongActor != 0 {
					t.Fatalf("PATCH audits=%d wrong actors=%d", count, wrongActor)
				}
				version, err := f.q.GetLatestDocumentVersion(f.ctx, f.doc.ID)
				if err != nil {
					t.Fatal(err)
				}
				if version.VersionNo != 1 || !version.CreatedBy.Valid || version.CreatedBy.Bytes != f.user.ID || version.CreatedVia != string(versions.ViaHuman) || version.Summary != "update_document" || version.Name != fresh.Name || version.SourceKind != fresh.SourceKind || string(version.BlockTreeJson) != string(fresh.BlocksJson) || string(version.VariablesJson) != string(fresh.VariablesJson) {
					t.Fatal("PATCH history is not the committed content/variables with the canonical live actor")
				}
			})
		}
	}
}

func TestDocumentPatchInternalFailureRollsBackAndRetriesE2E(t *testing.T) {
	for _, fault := range []string{"audit", "audit-no-row", "version", "version-no-row", "mutation-no-row"} {
		t.Run(fault, func(t *testing.T) {
			f := setupDocumentAuthorizationE2E(t, "owner")
			before := f.snapshot(t, f.pool)
			name := "hash_document_failure_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			table, operation, predicate, failure := "events", "INSERT", fmt.Sprintf("NEW.document_id='%s'::uuid AND NEW.kind='%s'", f.doc.ID, audit.KindDocumentUpdated), "RAISE EXCEPTION 'fixture document failure';"
			if fault == "audit-no-row" {
				failure = "RETURN NULL;"
			}
			if fault == "version" || fault == "version-no-row" {
				table, predicate = "document_versions", fmt.Sprintf("NEW.document_id='%s'::uuid", f.doc.ID)
				if fault == "version-no-row" {
					failure = "RETURN NULL;"
				}
			}
			if fault == "mutation-no-row" {
				table, operation, predicate, failure = "documents", "UPDATE", fmt.Sprintf("NEW.id='%s'::uuid AND NEW.default_locale='sv'", f.doc.ID), "RETURN NULL;"
			}
			if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF %s THEN %s END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION %s()`, name, predicate, failure, name, operation, table, name)); err != nil {
				t.Fatal(err)
			} //nolint:rawsql,gosec -- fixed constants plus fixture UUIDs
			drop := func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON %s; DROP FUNCTION IF EXISTS %s()`, name, table, name)); err != nil {
					t.Error(err)
				}
			} //nolint:rawsql,gosec
			t.Cleanup(drop)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			input := f.input()
			w := f.submit(f.ctx, f.doc.ID, input, cookie)
			if w.Code != http.StatusInternalServerError {
				t.Fatalf("internal PATCH=%d %s", w.Code, w.Body.String())
			}
			for _, leak := range []string{name, "fixture document failure", "SQLSTATE", "PL/pgSQL", "no rows"} {
				if strings.Contains(w.Body.String(), leak) {
					t.Fatalf("PATCH exposed %q", leak)
				}
			}
			f.assertUnchanged(t, before)
			drop()
			if w := f.submit(f.ctx, f.doc.ID, input, cookie); w.Code != http.StatusOK {
				t.Fatalf("retry PATCH=%d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestDraftSQLMutatorsPreserveDeletedAndNonDraftRowsE2E(t *testing.T) {
	for _, state := range []string{"deleted", "voided"} {
		t.Run(state, func(t *testing.T) {
			f := setupDocumentAuthorizationE2E(t, "owner")
			var err error
			if state == "deleted" {
				_, err = f.pool.Exec(f.ctx, `UPDATE documents SET deleted_at=clock_timestamp() WHERE id=$1`, f.doc.ID) //nolint:rawsql -- exact fixture's soft-deleted row
			} else {
				seedCompleteFrozenBrandingHandlerE2E(t, f.ctx, f.pool, f.doc.ID)
				_, err = f.pool.Exec(f.ctx, `UPDATE documents SET status='voided' WHERE id=$1`, f.doc.ID) //nolint:rawsql -- exact fixture's non-draft row
			}
			if err != nil {
				t.Fatal(err)
			}
			before := f.snapshot(t, f.pool)
			for name, mutation := range map[string]func() error{
				"blocks": func() error {
					_, err := f.q.UpdateDocumentBlocks(f.ctx, generated.UpdateDocumentBlocksParams{ID: f.doc.ID, OrgID: f.org, BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
					return err
				},
				"metadata": func() error {
					_, err := f.q.UpdateDocumentMetadata(f.ctx, generated.UpdateDocumentMetadataParams{ID: f.doc.ID, OrgID: f.org, Name: "Forbidden metadata", Metadata: json.RawMessage(`{}`)})
					return err
				},
				"locale": func() error {
					_, err := f.q.SetDocumentDefaultLocale(f.ctx, generated.SetDocumentDefaultLocaleParams{ID: f.doc.ID, OrgID: f.org, DefaultLocale: "sv"})
					return err
				},
				"mode": func() error {
					_, err := f.q.SetDocumentRequiresSignature(f.ctx, generated.SetDocumentRequiresSignatureParams{ID: f.doc.ID, OrgID: f.org, RequiresSignature: false})
					return err
				},
				"binding": func() error {
					_, err := f.q.UpsertVariableBinding(f.ctx, generated.UpsertVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer", SourceKind: "static", SourceRef: "Forbidden binding"})
					return err
				},
			} {
				if err := mutation(); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatalf("%s SQL mutation=%v want no-row refusal", name, err)
				}
				f.assertUnchanged(t, before)
			}
			if err := f.q.DeleteVariableBinding(f.ctx, generated.DeleteVariableBindingParams{DocumentID: f.doc.ID, VariableName: "customer"}); err != nil {
				t.Fatal(err)
			}
			f.assertUnchanged(t, before)
		})
	}
}

func TestDocumentPatchRejectsAmbiguousOrUnstorableJSONE2E(t *testing.T) {
	f := setupDocumentAuthorizationE2E(t, "owner")
	before := f.snapshot(t, f.pool)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	stamp, err := json.Marshal(toDocumentResponse(f.doc).UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	prefix := `{"expected_updated_at":` + string(stamp)
	for name, suffix := range map[string]string{
		"duplicate":            `,"name":"First","name":"Second"}`,
		"case":                 `,"NAME":"Wrong case"}`,
		"trailing":             `,"name":"First"} {"name":"Second"}`,
		"name NUL":             `,"name":"Bad\u0000name"}`,
		"name surrogate":       `,"name":"Bad\ud800"}`,
		"literal invalid UTF8": ",\"name\":\"" + string([]byte{0xff}) + "\"}",
		"variables NUL":        `,"variables_json":{"customer":"Bad\u0000value"}}`,
		"variables surrogate":  `,"variables_json":{"customer":"Bad\udc00"}}`,
		"block NUL":            `,"blocks_json":{"version":1,"blocks":[{"id":"terms","type":"paragraph","text":"Bad\u0000text"}]}}`,
		"attrs NUL key":        `,"blocks_json":{"version":1,"blocks":[{"id":"terms","type":"paragraph","text":"Terms","attrs":{"bad\u0000key":"value"}}]}}`,
		"oversized body":       `,"name":"` + strings.Repeat("x", 1<<20) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+f.doc.ID.String(), prefix+suffix, cookie)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("invalid PATCH=%d %s", w.Code, w.Body.String())
			}
			f.assertUnchanged(t, before)
		})
	}
}
