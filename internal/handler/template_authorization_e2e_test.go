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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Keep the original single-document baseline, roles and billing configuration.
// Only these authorization families select the genuine direct authoring factory;
// legacy lifecycle/component fixtures elsewhere retain their deliberate setup.
func setupNativeTemplateAuthorizationE2E(t *testing.T, role string) lifecycleAuthorizationFixture {
	t.Helper()
	return setupHTMLTemplateAuthorizationE2E(t, isolateHTMLTemplateDatabaseE2E(t), role)
}

func startNativeTemplateRequestE2E(t *testing.T, f lifecycleAuthorizationFixture, run func(context.Context) *httptest.ResponseRecorder, held ...pgx.Tx) (<-chan *httptest.ResponseRecorder, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	result := make(chan *httptest.ResponseRecorder, 1)
	joined := make(chan struct{})
	go func() { defer close(joined); result <- run(ctx) }()
	return result, func() { joinHTMLAuthoringRequestE2E(t, cancel, joined, held...) }
}

func awaitTemplateMutationTargetLockE2E(t *testing.T, f lifecycleAuthorizationFixture, held pgx.Tx, operation string) {
	t.Helper()
	if operation == "archive" {
		awaitNativeTemplateLockE2E(t, f, held, "GetNonHTMLTemplateSourceHeaderForUpdateV1", true)
		return
	}
	// The existing PATCH dispatch reads its bounded kind header using the
	// original pool before its native source/update owner can begin.
	awaitNativeTemplateLockE2E(t, f, held, "GetNonHTMLTemplateSourceHeaderForShareV1", false)
}

// Observe the named statement on this exact factory/pool and its actual held
// blocker. A lock elsewhere in this owned DB is not evidence for this request.
func awaitNativeTemplateLockE2E(t *testing.T, f lifecycleAuthorizationFixture, held pgx.Tx, query string, native bool) {
	t.Helper()
	var holder int32
	if err := held.QueryRow(f.ctx, "SELECT pg_backend_pid()").Scan(&holder); err != nil {
		t.Fatal(err)
	}
	awaitNativeTemplatePIDLockE2E(t, f, holder, query, native)
}

func awaitNativeTemplatePIDLockE2E(t *testing.T, f lifecycleAuthorizationFixture, holder int32, query string, native bool) {
	t.Helper()
	application := f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	if native {
		application = htmlAuthoringNativeApplicationNameE2E(t, f.s)
	}
	if application == "" || holder <= 0 {
		t.Fatal("authorization waiter requires an exact backend and blocker identity")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM pg_stat_activity a
		 WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active'
		 AND a.wait_event_type='Lock' AND a.query LIKE $2
		 AND ($3=ANY(pg_blocking_pids(a.pid)) OR EXISTS(SELECT 1 FROM unnest(pg_blocking_pids(a.pid)) AS b(pid) WHERE $3=ANY(pg_blocking_pids(b.pid))))`, application, "%-- name: "+query+"%", holder).Scan(&count) //nolint:rawsql -- exact fixture identity and real one-hop lock queue
		if err != nil {
			t.Fatal(err)
		}
		if count == 1 {
			return
		}
		if count > 1 {
			t.Fatalf("unexpected authorization waiters for %s: %d", query, count)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("actual authorization request did not wait on %s behind held backend", query)
}

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
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	var response *httptest.ResponseRecorder
	if source == "pdf" {
		worker := os.Getenv("HASH_E2E_PDF_WORKER_PATH")
		if worker == "" {
			t.Fatal("native PDF template authorization requires the source-built PDF worker")
		}
		if err := sanitize.ConfigurePDFWorker(f.ctx, worker, "production"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := sanitize.ConfigurePDFWorker(context.Background(), "", "development"); err != nil {
				t.Error(err)
			}
		})
		peer := templateAuthorizationStoragePeerE2E(t, f)
		response = submitPDFIntakeE2E(f, f.ctx, cookie, "/api/v1/templates")
		assertImportStorageE2E(t, peer, 1, 0, 1)
	} else {
		response = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPost, "/api/v1/templates", map[string]any{
			"name":           "Native authorization blocks template",
			"blocks_json":    json.RawMessage(`{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Original terms"}]}`),
			"variables_json": map[string]string{"customer": "Original customer"},
		})
	}
	if response.Code != http.StatusCreated {
		t.Fatalf("native authorization template seed=%d %s", response.Code, response.Body.String())
	}
	var created templateResponse
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.ID == uuid.Nil {
		t.Fatal("native template seed identity unavailable", err)
	}
	template, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	return template
}

func templateAuthorizationStoragePeerE2E(t *testing.T, f lifecycleAuthorizationFixture) *importStoragePeer {
	t.Helper()
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	f.s.Storage, err = storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-template-access", SecretKey: "synthetic-template-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	return peer
}

func submitTemplateMutationE2E(f lifecycleAuthorizationFixture, operation string, id uuid.UUID, cookie string) *httptest.ResponseRecorder {
	return submitTemplateMutationContextE2E(f, f.ctx, operation, id, cookie)
}

func submitTemplateMutationContextE2E(f lifecycleAuthorizationFixture, ctx context.Context, operation string, id uuid.UUID, cookie string) *httptest.ResponseRecorder {
	switch operation {
	case "create":
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/templates", `{"name":"New blocks template"}`, cookie)
	case "starter":
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/templates/starter", `{"key":"services-agreement-sv"}`, cookie)
	case "blocks":
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+id.String(), `{"name":"Updated blocks template","variables_json":{"customer":"Updated customer"}}`, cookie)
	case "pdf":
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+id.String(), `{"fields_json":{"version":1,"parties":[{"role":"signer","label":"Signer"}],"fields":[{"party_role":"signer","type":"signature","page":1,"x_pct":10,"y_pct":70,"w_pct":25,"h_pct":8,"required":true}]}}`, cookie)
	default:
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodDelete, "/api/v1/templates/"+id.String(), "", cookie)
	}
}

func TestTemplateCreationRechecksMemberAndOriginalSessionE2E(t *testing.T) {
	for _, operation := range []string{"create", "starter"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupNativeTemplateAuthorizationE2E(t, "sender")
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
				result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
					return submitTemplateMutationContextE2E(f, ctx, operation, uuid.Nil, cookie)
				}, blocked)
				defer join()
				awaitNativeTemplateLockE2E(t, f, blocked, "GetHTMLAuthoringActorHeaderV1", true)
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
				f := setupNativeTemplateAuthorizationE2E(t, "sender")
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
				result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
					return submitTemplateMutationContextE2E(f, ctx, operation, template.ID, cookie)
				}, blocked)
				defer join()
				awaitTemplateMutationTargetLockE2E(t, f, blocked, operation)
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
			f := setupNativeTemplateAuthorizationE2E(t, "sender")
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
			result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
				return submitTemplateMutationContextE2E(f, ctx, operation, template.ID, cookie)
			}, blocked)
			defer join()
			awaitNativeTemplateLockE2E(t, f, blocked, "AcquireOrgChainLock", true)
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
	f := setupNativeTemplateAuthorizationE2E(t, "sender")
	template := seedAuthorizationTemplateE2E(t, f, "blocks")
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	first, joinFirst := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), `{"name":"Earlier name","blocks_json":{"version":1,"blocks":[{"id":"body","type":"paragraph","text":"Fresh negotiated terms"}]},"variables_json":{"customer":"Fresh customer"}}`, cookie)
	}, blocked)
	defer joinFirst()
	awaitNativeTemplateLockE2E(t, f, blocked, "AcquireOrgChainLock", true)
	var firstPID int32
	if err := f.pool.QueryRow(f.ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND query LIKE '%-- name: AcquireOrgChainLock%' AND wait_event='advisory' AND state='active'`, htmlAuthoringNativeApplicationNameE2E(t, f.s)).Scan(&firstPID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual first native writer, never an unrelated waiter
	result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), `{"name":"Later name"}`, cookie)
	}, blocked)
	defer join()
	// The original PATCH kind-header lookup waits before native full-body work.
	awaitNativeTemplatePIDLockE2E(t, f, firstPID, "GetNonHTMLTemplateSourceHeaderForShareV1", false)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	w := receiveSessionOperationE2E(t, first)
	if w.Code != http.StatusOK {
		t.Fatalf("first genuine PATCH=%d %s", w.Code, w.Body.String())
	}
	var current templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &current); err != nil {
		t.Fatal(err)
	}
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusOK {
		t.Fatalf("fresh update=%d %s", w.Code, w.Body.String())
	}
	fresh, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Name != "Later name" || fresh.Version != current.Version+1 || string(fresh.BlocksJson) != string(current.BlocksJSON) || string(fresh.VariablesJson) != string(current.VariablesJSON) {
		t.Fatal("waiting partial update replaced fresh omitted blocks/variables/version")
	}
	ownedBlocksTemplateExactSourceV1(t, f, template.ID)
}

func TestTemplateMutationScopedAbsenceAndConcurrentArchiveE2E(t *testing.T) {
	for _, operation := range []string{"blocks", "archive"} {
		for _, change := range []string{"missing", "foreign", "archived", "concurrent-archive"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupNativeTemplateAuthorizationE2E(t, "sender")
				template := seedAuthorizationTemplateE2E(t, f, "blocks")
				id := template.ID
				if change == "missing" {
					id = uuid.New()
				} else if change == "foreign" {
					foreign := setupHTMLTemplateAuthorizationE2E(t, f.pool.Config().ConnConfig.Database, "owner")
					id = seedAuthorizationTemplateE2E(t, foreign, "blocks").ID
					var exists bool
					if err := f.pool.QueryRow(f.ctx, "SELECT EXISTS(SELECT 1 FROM templates WHERE id=$1 AND org_id=$2)", id, foreign.org).Scan(&exists); err != nil || !exists {
						t.Fatal("foreign template target must exist in the same actual database", exists, err)
					}
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
					result, join := startNativeTemplateRequestE2E(t, f, func(ctx context.Context) *httptest.ResponseRecorder {
						return submitTemplateMutationContextE2E(f, ctx, operation, id, cookie)
					}, blocked)
					defer join()
					awaitTemplateMutationTargetLockE2E(t, f, blocked, operation)
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
			f := setupNativeTemplateAuthorizationE2E(t, role)
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
			var events, created, updated, archived, wrongActors int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE kind='template.created'),count(*) FILTER (WHERE kind='template.updated'),count(*) FILTER (WHERE kind='template.archived'),count(*) FILTER (WHERE actor_user_id IS DISTINCT FROM $2) FROM events WHERE org_id=$1 AND kind LIKE 'template.%'`, f.org, f.user.ID).Scan(&events, &created, &updated, &archived, &wrongActors); err != nil { //nolint:rawsql -- includes the two genuine positive seed producers
				t.Fatal(err)
			}
			if events != 8 || created != 4 || updated != 2 || archived != 2 || wrongActors != 0 {
				t.Fatalf("authorized audit total/create/update/archive/wrong actors=%d/%d/%d/%d/%d want8/4/2/2/0", events, created, updated, archived, wrongActors)
			}
		})
	}
}

func TestTemplateMutationInternalAuditFailureRollsBackE2E(t *testing.T) {
	for _, operation := range []string{"create", "starter", "blocks", "pdf", "archive"} {
		for _, failure := range []string{"exception", "no-row"} {
			t.Run(operation+"/"+failure, func(t *testing.T) {
				f := setupNativeTemplateAuthorizationE2E(t, "sender")
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
