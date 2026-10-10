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

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// These tests enter the actual session middleware and template routes, wait on
// real PostgreSQL row/audit locks, and compare all tenant template/audit state.
// The fixture never starts an email dispatcher or touches production storage.
func templateMutationSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'templates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM templates t WHERE org_id=$1),
		'audit',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1 AND kind LIKE 'template.%')
		)::text`, f.org).Scan(&state); err != nil { //nolint:rawsql -- exact synthetic tenant snapshot
		t.Fatal(err)
	}
	return state + "\n" + f.snapshot(t)
}

func seedAuthorizationTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture, source string) *generated.Template {
	t.Helper()
	var template *generated.Template
	var err error
	if source == "pdf" {
		template, err = f.q.CreatePDFTemplate(f.ctx, generated.CreatePDFTemplateParams{
			OrgID: f.org, Name: "Synthetic PDF template", CreatedBy: f.user.ID,
			PdfStorageKey: pgtype.Text{String: "synthetic-template-source.pdf", Valid: true},
			PageCount:     pgtype.Int4{Int32: 1, Valid: true}, FieldsJson: json.RawMessage(`[]`),
		})
	} else {
		template, err = f.q.CreateBlocksTemplate(f.ctx, generated.CreateBlocksTemplateParams{
			OrgID: f.org, Name: "Synthetic blocks template", CreatedBy: f.user.ID,
			BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Original terms"}]}`),
			VariablesJson: json.RawMessage(`{"customer":"Original customer"}`),
		})
	}
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func submitTemplateMutationE2E(f lifecycleAuthorizationFixture, operation string, id uuid.UUID, cookie string) *httptest.ResponseRecorder {
	switch operation {
	case "create":
		return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/templates", `{"name":"New blocks template"}`, cookie)
	case "starter":
		return submitSessionOperationE2E(f.s, http.MethodPost, "/api/v1/templates/starter", `{"key":"services-agreement-sv"}`, cookie)
	case "blocks":
		return submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+id.String(), `{"name":"Updated blocks template","variables_json":{"customer":"Updated customer"}}`, cookie)
	case "pdf":
		return submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+id.String(), `{"fields_json":{"version":1,"parties":[{"role":"signer","label":"Signer"}],"fields":[{"party_role":"signer","type":"signature","page":1,"x_pct":10,"y_pct":70,"w_pct":25,"h_pct":8,"required":true}]}}`, cookie)
	default:
		return submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/templates/"+id.String(), "", cookie)
	}
}

func TestTemplateCreationRechecksMemberAndOriginalSessionE2E(t *testing.T) {
	for _, operation := range []string{"create", "starter"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
				before := templateMutationSnapshotE2E(t, f)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "sender"}); err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitTemplateMutationE2E(f, operation, uuid.Nil, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetUserForShare", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					_, err = f.q.WithTx(blocked).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
				case "logout":
					_, err = f.q.WithTx(blocked).RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w := receiveSessionOperationE2E(t, result); w.Code != want {
					t.Fatalf("late %s %s=%d want%d %s", operation, change, w.Code, want, w.Body.String())
				}
				if templateMutationSnapshotE2E(t, f) != before {
					t.Fatal("refused creation changed tenant templates, audit, documents or outbox")
				}
			})
		}
	}
}

func TestTemplateMutationRechecksSessionAfterTemplateWaitE2E(t *testing.T) {
	for _, operation := range []string{"blocks", "pdf", "archive"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				template := seedAuthorizationTemplateE2E(t, f, operation)
				before := templateMutationSnapshotE2E(t, f)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if _, err := f.q.WithTx(blocked).GetTemplateForUpdate(f.ctx, generated.GetTemplateForUpdateParams{ID: template.ID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitTemplateMutationE2E(f, operation, template.ID, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetTemplateForUpdate", "transactionid")
				want := http.StatusForbidden
				switch change {
				case "demotion":
					w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if w.Code != http.StatusOK {
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
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w := receiveSessionOperationE2E(t, result); w.Code != want {
					t.Fatalf("late %s %s=%d want%d %s", operation, change, w.Code, want, w.Body.String())
				}
				if templateMutationSnapshotE2E(t, f) != before {
					t.Fatal("refused mutation changed tenant templates, audit, documents or outbox")
				}
			})
		}
	}
}

func TestTemplateMutationExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"create", "starter", "blocks", "pdf", "archive"} {
		t.Run(operation, func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
			template := seedAuthorizationTemplateE2E(t, f, operation)
			before := templateMutationSnapshotE2E(t, f)
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
			go func() { result <- submitTemplateMutationE2E(f, operation, template.ID, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
				t.Fatalf("audit-wait expired %s=%d %s", operation, w.Code, w.Body.String())
			}
			if templateMutationSnapshotE2E(t, f) != before {
				t.Fatal("expiry after data/audit mutation left committed template or event")
			}
		})
	}
}

func TestTemplateUpdateRetainsFreshOmittedContentE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
	template := seedAuthorizationTemplateE2E(t, f, "blocks")
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	q := f.q.WithTx(blocked)
	if _, err := q.GetTemplateForUpdate(f.ctx, generated.GetTemplateForUpdateParams{ID: template.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		result <- submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), `{"name":"Later name"}`, cookie)
	}()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetTemplateForUpdate", "transactionid")
	current, err := q.UpdateBlocksTemplate(f.ctx, generated.UpdateBlocksTemplateParams{
		ID: template.ID, OrgID: f.org, Name: "Earlier name",
		BlocksJson:    json.RawMessage(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Fresh negotiated terms"}]}`),
		VariablesJson: json.RawMessage(`{"customer":"Fresh customer"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusOK {
		t.Fatalf("fresh update=%d %s", w.Code, w.Body.String())
	}
	fresh, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Name != "Later name" || fresh.Version != current.Version+1 || string(fresh.BlocksJson) != string(current.BlocksJson) || string(fresh.VariablesJson) != string(current.VariablesJson) {
		t.Fatal("waiting partial update replaced fresh omitted blocks/variables/version")
	}
}

func TestTemplateMutationScopedAbsenceAndConcurrentArchiveE2E(t *testing.T) {
	for _, operation := range []string{"blocks", "archive"} {
		for _, change := range []string{"missing", "foreign", "archived", "concurrent-archive"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
				template := seedAuthorizationTemplateE2E(t, f, "blocks")
				id := template.ID
				if change == "missing" {
					id = uuid.New()
				} else if change == "foreign" {
					foreign := setupLifecycleAuthorizationE2E(t, "owner", false, false)
					id = seedAuthorizationTemplateE2E(t, foreign, "blocks").ID
				} else if change == "archived" {
					if err := f.q.ArchiveTemplate(f.ctx, generated.ArchiveTemplateParams{ID: id, OrgID: f.org}); err != nil {
						t.Fatal(err)
					}
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
				var w *httptest.ResponseRecorder
				if change == "concurrent-archive" {
					blocked, err := f.pool.Begin(f.ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer blocked.Rollback(context.Background())
					q := f.q.WithTx(blocked)
					if _, err := q.GetTemplateForUpdate(f.ctx, generated.GetTemplateForUpdateParams{ID: id, OrgID: f.org}); err != nil {
						t.Fatal(err)
					}
					result := make(chan *httptest.ResponseRecorder, 1)
					go func() { result <- submitTemplateMutationE2E(f, operation, id, cookie) }()
					awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetTemplateForUpdate", "transactionid")
					if err := q.ArchiveTemplate(f.ctx, generated.ArchiveTemplateParams{ID: id, OrgID: f.org}); err != nil {
						t.Fatal(err)
					}
					if err := blocked.Commit(f.ctx); err != nil {
						t.Fatal(err)
					}
					before := templateMutationSnapshotE2E(t, f)
					w = receiveSessionOperationE2E(t, result)
					if templateMutationSnapshotE2E(t, f) != before {
						t.Fatal("concurrent archive refusal added mutation or audit")
					}
				} else {
					before := templateMutationSnapshotE2E(t, f)
					w = submitTemplateMutationE2E(f, operation, id, cookie)
					if templateMutationSnapshotE2E(t, f) != before {
						t.Fatal("scoped absence refusal added mutation or audit")
					}
				}
				if w.Code != http.StatusNotFound {
					t.Fatalf("%s/%s=%d %s", operation, change, w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestTemplateAuthorizedCreationUpdateArchiveE2E(t *testing.T) {
	for _, role := range []string{"sender", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, role, false, false)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			for _, operation := range []string{"create", "starter"} {
				if w := submitTemplateMutationE2E(f, operation, uuid.Nil, cookie); w.Code != http.StatusCreated {
					t.Fatalf("authorized %s=%d %s", operation, w.Code, w.Body.String())
				}
			}
			for _, operation := range []string{"blocks", "pdf"} {
				template := seedAuthorizationTemplateE2E(t, f, operation)
				if w := submitTemplateMutationE2E(f, operation, template.ID, cookie); w.Code != http.StatusOK {
					t.Fatalf("authorized %s=%d %s", operation, w.Code, w.Body.String())
				}
				if w := submitTemplateMutationE2E(f, "archive", template.ID, cookie); w.Code != http.StatusNoContent {
					t.Fatalf("authorized archive=%d %s", w.Code, w.Body.String())
				}
			}
			var events, wrongActors int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE actor_user_id IS DISTINCT FROM $2) FROM events WHERE org_id=$1 AND kind LIKE 'template.%'`, f.org, f.user.ID).Scan(&events, &wrongActors); err != nil { //nolint:rawsql -- fixture audit accounting
				t.Fatal(err)
			}
			if events != 6 || wrongActors != 0 {
				t.Fatalf("authorized audit count/wrong actors=%d/%d want6/0", events, wrongActors)
			}
		})
	}
}

func TestTemplateMutationInternalAuditFailureRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"create", "starter", "blocks", "pdf", "archive"} {
		for _, failure := range []string{"exception", "no-row"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
				template := seedAuthorizationTemplateE2E(t, f, operation)
				before := templateMutationSnapshotE2E(t, f)
				name := "hash_template_failure_" + strings.ReplaceAll(f.org.String(), "-", "")
				const marker = "fixture template internal audit failure"
				action := "RAISE EXCEPTION '" + marker + "'"
				if failure == "no-row" {
					action = "RETURN NULL"
				}
				if _, err := f.pool.Exec(f.ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.org_id='%s'::uuid AND NEW.kind LIKE 'template.%%' THEN %s; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, name, f.org, action, name, name)); err != nil { //nolint:rawsql,gosec -- fixture generated UUID identifiers and fixed predicates/messages only
					t.Fatal(err)
				}
				t.Cleanup(func() {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					if _, err := f.pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON events; DROP FUNCTION IF EXISTS %s()`, name, name)); err != nil { //nolint:rawsql,gosec
						t.Error(err)
					}
				})
				w := submitTemplateMutationE2E(f, operation, template.ID, dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if w.Code != http.StatusInternalServerError {
					t.Fatalf("internal audit %s=%d %s", failure, w.Code, w.Body.String())
				}
				for _, detail := range []string{marker, name, "SQLSTATE", "PL/pgSQL"} {
					if strings.Contains(w.Body.String(), detail) {
						t.Fatalf("internal error exposed %q: %s", detail, w.Body.String())
					}
				}
				if templateMutationSnapshotE2E(t, f) != before {
					t.Fatal("internal audit failure left template, event, document or outbox mutation")
				}
			})
		}
	}
}
