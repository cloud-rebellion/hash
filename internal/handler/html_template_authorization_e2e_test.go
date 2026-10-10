//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/versions"
)

// Each top-level test owns a unique disposable database. Full migration Down
// checks and explicit fixture teardown never affect the supplied parent DB.
// The ordinary lifecycle fixture is retained, including its real middleware,
// audit chain, row-lock observations, and original signed session credentials.
func isolateHTMLTemplateDatabaseE2E(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HASH_E2E_DB_URL")
	if dsn == "" {
		t.Skip("set HASH_E2E_DB_URL to run")
	}
	u, err := url.Parse(dsn)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		t.Fatal("HTML fixture requires a PostgreSQL URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("connect disposable PostgreSQL fixture:", err)
	}
	name := "hash_html_e2e_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); err != nil { //nolint:rawsql -- unique synthetic DB, never the source DB
		_ = admin.Close(context.Background())
		t.Fatal("create isolated HTML fixture database:", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		// Registered before fixture pools, so their cleanup/Close runs first.
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); err != nil { //nolint:rawsql -- exact DB created above
			t.Error("drop isolated HTML fixture database:", err)
		}
		_ = admin.Close(cleanupCtx)
	})
	u.Path = "/" + name
	u.RawPath = ""
	t.Setenv("HASH_E2E_DB_URL", u.String())
	return name
}

func setupHTMLTemplateAuthorizationE2E(t *testing.T, database, role string) lifecycleAuthorizationFixture {
	t.Helper()
	f := setupLifecycleAuthorizationE2E(t, role, false, false)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var actual string
		if err := f.pool.QueryRow(ctx, "SELECT current_database()").Scan(&actual); err != nil { //nolint:rawsql -- teardown identity fence
			t.Error(err)
			return
		}
		if actual != database || !strings.HasPrefix(actual, "hash_html_e2e_") {
			t.Error("refusing HTML fixture teardown outside its exact disposable database")
			return
		}
		// DELETE is intentionally forbidden for immutable authoring history.
		// This explicit whole synthetic-estate teardown runs only after checks;
		// it neither disables the triggers nor supplies a product disposal API.
		if _, err := f.pool.Exec(ctx, "TRUNCATE orgs CASCADE"); err != nil { //nolint:rawsql -- all rows belong to this unique test DB
			t.Error(err)
		}
	})
	return f
}

func htmlTemplateInputE2E(t *testing.T, expected int32, label string) htmlTemplateInput {
	t.Helper()
	master, err := json.Marshal(htmlmaster.Master{SchemaVersion: 1,
		HTML:   `<p>` + label + `: <span data-hash-value="customer"></span></p>`,
		Values: []htmlmaster.Value{{Name: "customer", Required: true, MaxChars: 200}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return htmlTemplateInput{Name: "HTML template " + label, HTMLMasterJSON: master,
		VariablesJSON: json.RawMessage(`{"customer":"Approved default AB"}`), ExpectedVersion: expected}
}

func submitHTMLTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture, operation string, id uuid.UUID, input any, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	method, path := http.MethodPost, "/api/v1/templates/html"
	if operation == "update" {
		method, path = http.MethodPatch, "/api/v1/templates/"+id.String()+"/html"
	} else if operation == "approve" {
		path = "/api/v1/templates/" + id.String() + "/html/approve"
	}
	return submitSessionOperationE2E(f.s, method, path, string(body), cookie)
}

func createHTMLTemplateE2E(t *testing.T, f lifecycleAuthorizationFixture) *generated.Template {
	t.Helper()
	w := submitHTMLTemplateE2E(t, f, "create", uuid.Nil, htmlTemplateInputE2E(t, 0, "Original"),
		dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	if w.Code != http.StatusCreated {
		t.Fatalf("create HTML template=%d %s", w.Code, w.Body.String())
	}
	var response templateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.ID == uuid.Nil || response.SourceKind != "html" || len(response.HTMLMasterJSON) == 0 {
		t.Fatalf("HTML creation detail missing id/source/master: err=%v body=%s", err, w.Body.String())
	}
	template, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: response.ID, OrgID: f.org})
	if err != nil || response.ContentSHA256 != hex.EncodeToString(template.HtmlContentSha256) {
		t.Fatalf("created template commitment: err=%v", err)
	}
	return template
}

func htmlTemplateSnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'templates',(SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY id),'[]'::jsonb) FROM templates t WHERE org_id=$1),
		'revisions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY template_id,version),'[]'::jsonb) FROM html_template_revisions r WHERE org_id=$1),
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE org_id=$1),
		'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
		'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1)
		)::text`, f.org).Scan(&state); err != nil { //nolint:rawsql -- exact synthetic tenant snapshot
		t.Fatal(err)
	}
	return state
}

func assertHTMLTemplateUnchangedE2E(t *testing.T, f lifecycleAuthorizationFixture, before string) {
	t.Helper()
	if after := htmlTemplateSnapshotE2E(t, f); after != before {
		t.Fatal("refused HTML mutation committed template, immutable revision, approval, or audit changes")
	}
}

func htmlApprovalInputE2E(template *generated.Template) htmlTemplateApprovalInput {
	return htmlTemplateApprovalInput{ExpectedVersion: template.Version, ExpectedContentSHA256: hex.EncodeToString(template.HtmlContentSha256)}
}

func TestHTMLTemplateLifecycleApprovalAndRevisionE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	first, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: 1})
	if err != nil || first.ApprovedBy.Valid || first.ApprovedAt.Valid || !bytes.Equal(first.ContentSha256, template.HtmlContentSha256) {
		t.Fatalf("first revision must be unapproved with exact commitment: %+v err=%v", first, err)
	}
	listed, err := f.q.ListTemplates(f.ctx, generated.ListTemplatesParams{OrgID: f.org, Limit: 500})
	if err != nil || len(listed) != 1 || len(listed[0].HtmlMasterJson) != 0 || !bytes.Equal(listed[0].HtmlContentSha256, template.HtmlContentSha256) {
		t.Fatalf("metadata list must omit asset master and preserve cached digest: len=%d err=%v", len(listed), err)
	}
	firstApproval := previewApprovalInputE2E(t, f, template, cookie)
	if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, firstApproval, cookie); w.Code != http.StatusOK {
		t.Fatalf("owner approval=%d %s", w.Code, w.Body.String())
	}
	approved, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: 1})
	if err != nil || !approved.ApprovedBy.Valid || uuid.UUID(approved.ApprovedBy.Bytes) != f.user.ID || !approved.ApprovedAt.Valid {
		t.Fatalf("server-derived owner approval missing: %+v err=%v", approved, err)
	}
	if w := submitHTMLTemplateE2E(t, f, "update", template.ID, htmlTemplateInputE2E(t, 1, "Updated"), cookie); w.Code != http.StatusOK {
		t.Fatalf("update HTML template=%d %s", w.Code, w.Body.String())
	}
	current, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil || current.Version != 2 || bytes.Equal(current.HtmlContentSha256, template.HtmlContentSha256) {
		t.Fatalf("updated master must create new committed version: %+v err=%v", current, err)
	}
	second, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: 2})
	if err != nil || second.ApprovedBy.Valid || second.ApprovedAt.Valid {
		t.Fatalf("new prose inherited prior approval: %+v err=%v", second, err)
	}
	old, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: 1})
	if err != nil || !bytes.Equal(old.HtmlMasterJson, approved.HtmlMasterJson) || !bytes.Equal(old.ContentSha256, approved.ContentSha256) || old.ApprovedBy != approved.ApprovedBy || !old.ApprovedAt.Time.Equal(approved.ApprovedAt.Time) {
		t.Fatal("updating current template rewrote approved historical revision")
	}
	currentApproval := previewApprovalInputE2E(t, f, current, cookie)
	wrongDigest := currentApproval
	wrongDigest.ExpectedContentSHA256 = strings.Repeat("0", 64)
	for _, tc := range []struct {
		name, operation string
		input           any
	}{
		{"stale edit", "update", htmlTemplateInputE2E(t, 1, "Lost edit")},
		{"stale approval", "approve", firstApproval},
		{"wrong digest", "approve", wrongDigest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := htmlTemplateSnapshotE2E(t, f)
			if w := submitHTMLTemplateE2E(t, f, tc.operation, template.ID, tc.input, cookie); w.Code != http.StatusConflict {
				t.Fatalf("%s=%d %s", tc.name, w.Code, w.Body.String())
			}
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
	if w := submitHTMLTemplateE2E(t, f, "approve", current.ID, currentApproval, cookie); w.Code != http.StatusOK {
		t.Fatalf("approve current revision=%d %s", w.Code, w.Body.String())
	}
	history, err := f.q.ListApprovedHTMLTemplateRevisions(f.ctx, generated.ListApprovedHTMLTemplateRevisionsParams{TemplateID: template.ID, OrgID: f.org, ResultLimit: 10})
	if err != nil || len(history) != 2 || history[0].Version != 2 || history[1].Version != 1 {
		t.Fatalf("approved history=%+v err=%v", history, err)
	}
}

func TestHTMLTemplateTenantAndOwnerRefusalsE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	foreign := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	sender, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Name: "Synthetic sender", Email: uuid.NewString() + "@html.test", Role: "sender"})
	if err != nil {
		t.Fatal(err)
	}
	viewer, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Name: "Synthetic viewer", Email: uuid.NewString() + "@html.test", Role: "viewer"})
	if err != nil {
		t.Fatal(err)
	}
	ownerCookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	approval := previewApprovalInputE2E(t, f, template, ownerCookie)
	for _, tc := range []struct {
		name, operation string
		actor           lifecycleAuthorizationFixture
		user            *generated.User
		want            int
	}{
		{"sender cannot approve", "approve", f, sender, http.StatusForbidden},
		{"viewer cannot create", "create", f, viewer, http.StatusForbidden},
		{"viewer cannot edit", "update", f, viewer, http.StatusForbidden},
		{"foreign owner cannot edit", "update", foreign, foreign.user, http.StatusNotFound},
		{"foreign owner cannot approve", "approve", foreign, foreign.user, http.StatusConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before, foreignBefore := htmlTemplateSnapshotE2E(t, f), htmlTemplateSnapshotE2E(t, foreign)
			var input any = htmlTemplateInputE2E(t, template.Version, "Refused")
			if tc.operation == "approve" {
				input = approval
			} else if tc.operation == "create" {
				input = htmlTemplateInputE2E(t, 0, "Refused")
			}
			cookie := dsrSessionCookieE2E(t, tc.actor.s, tc.user.ID, tc.user.SessionGeneration, time.Hour)
			if w := submitHTMLTemplateE2E(t, tc.actor, tc.operation, template.ID, input, cookie); w.Code != tc.want {
				t.Fatalf("%s=%d want%d %s", tc.name, w.Code, tc.want, w.Body.String())
			}
			assertHTMLTemplateUnchangedE2E(t, f, before)
			assertHTMLTemplateUnchangedE2E(t, foreign, foreignBefore)
		})
	}
	if _, err := f.q.ApproveHTMLTemplateRevision(f.ctx, generated.ApproveHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, ExpectedVersion: 1, ExpectedContentSha256: template.HtmlContentSha256, ApprovedBy: sender.ID}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("query nonowner approval=%v", err)
	}
	if _, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: foreign.org, Version: 1}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross-tenant revision lookup=%v", err)
	}
}

func TestHTMLTemplateConcurrentUpdateCASHasOneWinnerE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	start := make(chan struct{})
	result := make(chan *httptest.ResponseRecorder, 2)
	for _, label := range []string{"Concurrent A", "Concurrent B"} {
		input := htmlTemplateInputE2E(t, template.Version, label)
		go func() {
			<-start
			result <- submitHTMLTemplateE2E(t, f, "update", template.ID, input, cookie)
		}()
	}
	close(start)
	counts := map[int]int{}
	for range 2 {
		w := receiveSessionOperationE2E(t, result)
		counts[w.Code]++
		if w.Code != http.StatusOK && w.Code != http.StatusConflict {
			t.Fatalf("concurrent HTML update=%d %s", w.Code, w.Body.String())
		}
	}
	if counts[http.StatusOK] != 1 || counts[http.StatusConflict] != 1 {
		t.Fatalf("concurrent version CAS=%v, want one commit and one conflict", counts)
	}
	current, err := f.q.GetHTMLTemplate(f.ctx, generated.GetHTMLTemplateParams{ID: template.ID, OrgID: f.org})
	if err != nil || current.Version != 2 {
		t.Fatalf("concurrent current version=%+v err=%v", current, err)
	}
	var revisions, updateEvents int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_template_revisions WHERE template_id=$1),
		(SELECT count(*) FROM events WHERE org_id=$2 AND kind='template.updated')`, template.ID, f.org).Scan(&revisions, &updateEvents); err != nil { //nolint:rawsql -- exact winning data/audit count
		t.Fatal(err)
	}
	if revisions != 2 || updateEvents != 1 {
		t.Fatalf("CAS left revisions=%d updates=%d, want2/1", revisions, updateEvents)
	}
}

func TestHTMLTemplateOriginalAuthorityAfterLocksE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, operation := range []string{"create", "update", "approve"} {
		for _, change := range []string{"demotion", "logout", "expiry"} {
			t.Run(operation+"/"+change, func(t *testing.T) {
				f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
				_ = seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				template := createHTMLTemplateE2E(t, f)
				ttl := time.Hour
				if change == "expiry" {
					ttl = 2 * time.Second
				}
				cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
				var input any = htmlTemplateInputE2E(t, 1, "Late mutation")
				if operation == "create" {
					input = htmlTemplateInputE2E(t, 0, "Late creation")
				} else if operation == "approve" {
					input = previewApprovalInputE2E(t, f, template, cookie)
				}
				hold, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer hold.Rollback(context.Background())
				query := "-- name: GetTemplateForUpdate"
				switch operation {
				case "create":
					_, err = f.q.WithTx(hold).UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "owner"})
					query = "-- name: GetUserForShare"
				case "approve":
					_, err = f.q.WithTx(hold).GetOrgForOwnerMutation(f.ctx, f.org)
					query = "-- name: GetOrgForOwnerMutation"
				default:
					_, err = f.q.WithTx(hold).GetTemplateForUpdate(f.ctx, generated.GetTemplateForUpdateParams{ID: template.ID, OrgID: f.org})
				}
				if err != nil {
					t.Fatal(err)
				}
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitHTMLTemplateE2E(t, f, operation, template.ID, input, cookie) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "transactionid")
				q := f.q
				if operation == "create" {
					q = q.WithTx(hold)
				}
				want := http.StatusForbidden
				switch change {
				case "demotion":
					role := "viewer"
					if operation == "approve" {
						role = "sender"
					}
					_, err = q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: role})
				case "logout":
					_, err = q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
				case "expiry":
					awaitSessionCookieExpiryE2E(t, f.s, cookie)
					want = http.StatusUnauthorized
				}
				if err != nil {
					t.Fatal(err)
				}
				before := htmlTemplateSnapshotE2E(t, f)
				if err := hold.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if w := receiveSessionOperationE2E(t, result); w.Code != want {
					t.Fatalf("late %s %s=%d want%d %s", operation, change, w.Code, want, w.Body.String())
				}
				assertHTMLTemplateUnchangedE2E(t, f, before)
			})
		}
	}
}

func TestHTMLTemplateAuditWaitExpiryRollsBackE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, operation := range []string{"create", "update", "approve"} {
		t.Run(operation, func(t *testing.T) {
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			template := createHTMLTemplateE2E(t, f)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, 2*time.Second)
			var input any = htmlTemplateInputE2E(t, 1, "Audit delayed")
			if operation == "create" {
				input = htmlTemplateInputE2E(t, 0, "Audit delayed")
			} else if operation == "approve" {
				input = previewApprovalInputE2E(t, f, template, cookie)
			}
			before := htmlTemplateSnapshotE2E(t, f)
			hold, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback(context.Background())
			if err := f.q.WithTx(hold).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitHTMLTemplateE2E(t, f, operation, template.ID, input, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, f.s, cookie)
			if err := hold.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
				t.Fatalf("expired audit %s=%d %s", operation, w.Code, w.Body.String())
			}
			assertHTMLTemplateUnchangedE2E(t, f, before)
		})
	}
}

func assertHTMLSchemaRefusalE2E(t *testing.T, f lifecycleAuthorizationFixture, statement string, args ...any) {
	t.Helper()
	before := htmlTemplateSnapshotE2E(t, f)
	_, err := f.pool.Exec(f.ctx, statement, args...) //nolint:rawsql -- exact synthetic row, deliberately exercising database refusal
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
		t.Fatalf("schema guard=%v, want check-violation 23514", err)
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
}

func TestHTMLTemplateSchemaImmutabilityAndDocumentReviewE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	for _, statement := range []string{
		`UPDATE html_template_revisions SET html_master_json='{"changed":true}' WHERE template_id=$1`,
		`UPDATE html_template_revisions SET variables_json='{"customer":"Rewritten"}' WHERE template_id=$1`,
		`UPDATE html_template_revisions SET created_at=created_at+interval '1 second' WHERE template_id=$1`,
		`DELETE FROM html_template_revisions WHERE template_id=$1`,
		`UPDATE templates SET html_content_sha256='\x01'::bytea WHERE id=$1`,
		`UPDATE templates SET html_master_json=NULL WHERE id=$1`,
	} {
		assertHTMLSchemaRefusalE2E(t, f, statement, template.ID)
	}
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE html_template_revisions SET approved_by=$2 WHERE template_id=$1`, template.ID, f.user.ID)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	approval := previewApprovalInputE2E(t, f, template, cookie)
	if w := submitHTMLTemplateE2E(t, f, "approve", template.ID, approval, cookie); w.Code != http.StatusOK {
		t.Fatalf("schema fixture approve=%d %s", w.Code, w.Body.String())
	}
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE html_template_revisions SET approved_at=approved_at+interval '1 second' WHERE template_id=$1`, template.ID)
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE documents SET html_source_json='{}'::jsonb WHERE id=$1`, f.doc.ID)
	// No renderer/storage call: this digest is deliberately synthetic. These
	// assertions prove schema/query identity guards, not rendered PDF acceptance.
	digest := sha256.Sum256([]byte("synthetic already-rendered PDF fixture"))
	doc, err := f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID,
		TemplateID: pgtype.UUID{Bytes: template.ID, Valid: true}, Name: "Synthetic HTML source schema witness",
		PdfStorageKey: pgtype.Text{String: "synthetic/source.pdf", Valid: true}, PdfSha256: digest[:],
		PdfStorageVersionID: pgtype.Text{String: "synthetic-version-1", Valid: true}, EvidenceVersionPinsRequired: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx, `UPDATE documents SET variables_json=$2::jsonb WHERE id=$1`, doc.ID, template.VariablesJson); err != nil { //nolint:rawsql -- synthetic rendered values, no provider acceptance
		t.Fatal(err)
	}
	doc, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.q.GetHTMLTemplateRevision(f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	source, err := htmlsource.New(htmlsource.Input{TemplateID: template.ID, TemplateVersion: 1,
		TemplateContentSHA256: hex.EncodeToString(template.HtmlContentSha256), MasterJSON: template.HtmlMasterJson,
		DefaultVarsJSON: template.VariablesJson, Values: map[string]string{"customer": "Approved default AB"},
		TemplateApprovedBy: f.user.ID, TemplateApprovedAt: revision.ApprovedAt.Time}, doc)
	if err != nil {
		t.Fatal(err)
	}
	stale := doc.UpdatedAt
	stale.Time = stale.Time.Add(-time.Second)
	if _, err := f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, HtmlSourceJson: source, ExpectedUpdatedAt: stale}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("stale first-set source=%v", err)
	}
	doc, err = f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, HtmlSourceJson: source, ExpectedUpdatedAt: doc.UpdatedAt})
	if err != nil || len(doc.HtmlSourceJson) == 0 || doc.HtmlReviewedBy.Valid || doc.HtmlReviewedAt.Valid || len(doc.HtmlReviewedPdfSha256) != 0 {
		t.Fatalf("first-set provenance/review reset: %+v err=%v", doc, err)
	}
	for _, statement := range []string{
		`UPDATE documents SET html_source_json=NULL WHERE id=$1`,
		`UPDATE documents SET html_source_json='{"changed":true}' WHERE id=$1`,
		`UPDATE documents SET html_reviewed_by=sender_id WHERE id=$1`,
		`UPDATE documents SET html_reviewed_by=sender_id,html_reviewed_at=now(),html_reviewed_pdf_sha256='\x01'::bytea WHERE id=$1`,
	} {
		assertHTMLSchemaRefusalE2E(t, f, statement, doc.ID)
	}
	if _, err := f.q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, HtmlSourceJson: source, ExpectedUpdatedAt: doc.UpdatedAt}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("second source set=%v", err)
	}
	for _, change := range []string{"digest", "timestamp", "tenant", "viewer"} {
		t.Run("review/"+change, func(t *testing.T) {
			arg := generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, ExpectedPdfSha256: digest[:], ReviewedBy: f.user.ID}
			switch change {
			case "digest":
				arg.ExpectedPdfSha256 = bytes.Repeat([]byte{1}, 32)
			case "timestamp":
				arg.ExpectedUpdatedAt = stale
			case "tenant":
				arg.OrgID = uuid.New()
			case "viewer":
				viewer, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: f.org, Name: "Synthetic viewer", Email: uuid.NewString() + "@html.test", Role: "viewer"})
				if err != nil {
					t.Fatal(err)
				}
				arg.ReviewedBy = viewer.ID
			}
			if _, err := f.q.MarkDocumentHTMLReviewed(f.ctx, arg); !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("wrong review %s=%v", change, err)
			}
		})
	}
	doc, err = f.q.MarkDocumentHTMLReviewed(f.ctx, generated.MarkDocumentHTMLReviewedParams{ID: doc.ID, OrgID: f.org,
		ExpectedUpdatedAt: doc.UpdatedAt, ExpectedPdfSha256: digest[:], ReviewedBy: f.user.ID})
	if err != nil || !doc.HtmlReviewedBy.Valid || uuid.UUID(doc.HtmlReviewedBy.Bytes) != f.user.ID || !bytes.Equal(doc.HtmlReviewedPdfSha256, digest[:]) || !doc.HtmlReviewedAt.Valid {
		t.Fatalf("exact review query=%+v err=%v", doc, err)
	}
	if err := htmlsource.Validate(doc, true); err != nil {
		t.Fatalf("JSONB round-trip broke synthetic provenance/review commitment: %v", err)
	}
	version, err := f.q.InsertDocumentVersion(f.ctx, generated.InsertDocumentVersionParams{DocumentID: doc.ID, OrgID: f.org, VersionNo: 1,
		BlockTreeJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: doc.VariablesJson, Name: doc.Name,
		SourceKind: "pdf", Summary: "Synthetic HTML source snapshot", CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true},
		CreatedVia: "human", SchemaVersion: 1, HtmlSourceJson: doc.HtmlSourceJson})
	if err != nil || !bytes.Equal(version.HtmlSourceJson, doc.HtmlSourceJson) {
		t.Fatalf("version failed to preserve immutable authoring source: %+v err=%v", version, err)
	}
	history, err := versions.New(f.q).History(f.ctx, doc.ID, 200)
	if err != nil || len(history) != 1 || len(history[0].HtmlSourceJson) != 0 {
		t.Fatalf("version history must omit full inline master: len=%d err=%v", len(history), err)
	}
	detail, err := versions.New(f.q).Get(f.ctx, version.ID)
	if err != nil || !bytes.Equal(detail.HtmlSourceJson, doc.HtmlSourceJson) {
		t.Fatalf("explicit version detail lost immutable source: err=%v", err)
	}
	assertHTMLSchemaRefusalE2E(t, f, `UPDATE document_versions SET source_kind='blocks' WHERE id=$1`, version.ID)
}

func TestHTMLTemplateDSRRequiresReviewWithoutAffectingOtherTenantE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	template := createHTMLTemplateE2E(t, f)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	if w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/templates/"+template.ID.String(), "", cookie); w.Code != http.StatusNoContent {
		t.Fatalf("archive preserves retained privacy inventory=%d %s", w.Code, w.Body.String())
	}
	request, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
		OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true},
		SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"in_progress"}`, cookie); w.Code != http.StatusOK {
		t.Fatalf("HTML privacy request may remain in progress=%d %s", w.Code, w.Body.String())
	}
	before := htmlTemplateSnapshotE2E(t, f)
	if w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"fulfilled"}`, cookie); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "privacy and retention review") {
		t.Fatalf("retained HTML erasure refusal=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	if w := submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/data-subject/export?email="+url.QueryEscape(f.recipient.Email), "", cookie); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "privacy export review") {
		t.Fatalf("partial HTML export refusal=%d %s", w.Code, w.Body.String())
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
	var terminal int
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('data_subject.fulfilled','data_subject.anonymized')`, f.org).Scan(&terminal); err != nil || terminal != 0 { //nolint:rawsql -- refusal must not claim a complete export/erasure
		t.Fatalf("refused privacy workflow emitted terminal events=%d err=%v", terminal, err)
	}
	plain := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	plainRequest, err := plain.q.CreateDataSubjectRequest(plain.ctx, generated.CreateDataSubjectRequestParams{
		OrgID: plain.org, DocumentID: pgtype.UUID{Bytes: plain.doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: plain.recipient.ID, Valid: true},
		SubjectEmail: plain.recipient.Email, SubjectName: plain.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	plainCookie := dsrSessionCookieE2E(t, plain.s, plain.user.ID, plain.user.SessionGeneration, time.Hour)
	if w := submitSessionOperationE2E(plain.s, http.MethodPatch, "/api/v1/dsr/"+plainRequest.ID.String(), `{"status":"fulfilled"}`, plainCookie); w.Code != http.StatusOK {
		t.Fatalf("foreign HTML inventory incorrectly blocked plain tenant=%d %s", w.Code, w.Body.String())
	}
	fresh, err := plain.q.GetRecipient(plain.ctx, generated.GetRecipientParams{ID: plain.recipient.ID, OrgID: plain.org})
	if err != nil || fresh.Email != AnonymizedEmail(plainRequest.ID) || fresh.Name != AnonymizationMarker {
		t.Fatalf("plain tenant targeted erasure did not commit: %+v err=%v", fresh, err)
	}
	assertHTMLTemplateUnchangedE2E(t, f, before)
}

func htmlPrivacySnapshotE2E(t *testing.T, f lifecycleAuthorizationFixture) string {
	t.Helper()
	var state string
	if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
		'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
		'requests',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM data_subject_requests r WHERE org_id=$1),
		'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id),'[]'::jsonb) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id=$1),
		'privacy_events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1 AND kind LIKE 'data_subject.%')
		)::text`, f.org).Scan(&state); err != nil { //nolint:rawsql -- creation audit is independent; all privacy state must roll back
		t.Fatal(err)
	}
	return state
}

func awaitTwoHTMLAuditWaitersE2E(t *testing.T, f lifecycleAuthorizationFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	application := f.pool.Config().ConnConfig.RuntimeParams["application_name"]
	for time.Now().Before(deadline) {
		var count int
		if err := f.pool.QueryRow(f.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database()
			AND application_name=$1 AND query LIKE '%-- name: AcquireOrgChainLock%' AND wait_event='advisory' AND state='active'`, application).Scan(&count); err != nil { //nolint:rawsql -- observe both independently queued real requests
			t.Fatal(err)
		}
		if count == 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("HTML create and privacy request did not both reach the real audit lock")
}

func TestHTMLTemplateDSRRechecksNewAuthoringAfterAuditWaitE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	for _, operation := range []string{"erasure", "export"} {
		t.Run(operation, func(t *testing.T) {
			f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
			request, err := f.q.CreateDataSubjectRequest(f.ctx, generated.CreateDataSubjectRequestParams{
				OrgID: f.org, DocumentID: pgtype.UUID{Bytes: f.doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: f.recipient.ID, Valid: true},
				SubjectEmail: f.recipient.Email, SubjectName: f.recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
			if err != nil {
				t.Fatal(err)
			}
			before := htmlPrivacySnapshotE2E(t, f)
			hold, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer hold.Rollback(context.Background())
			if err := f.q.WithTx(hold).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			creation := make(chan *httptest.ResponseRecorder, 1)
			input := htmlTemplateInputE2E(t, 0, "Concurrent privacy inventory")
			go func() { creation <- submitHTMLTemplateE2E(t, f, "create", uuid.Nil, input, cookie) }()
			// Queue creation first. Its rows remain uncommitted and invisible to
			// the privacy request's first inventory check until its audit commits.
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
			privacy := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				if operation == "erasure" {
					privacy <- submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"fulfilled"}`, cookie)
				} else {
					privacy <- submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/data-subject/export?email="+url.QueryEscape(f.recipient.Email), "", cookie)
				}
			}()
			// Reaching this second audit wait proves the initial inventory check
			// accepted absence. Both requests use this fixture's unique app name.
			awaitTwoHTMLAuditWaitersE2E(t, f)
			if err := hold.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			if w := receiveSessionOperationE2E(t, creation); w.Code != http.StatusCreated {
				t.Fatalf("queued HTML create=%d %s", w.Code, w.Body.String())
			}
			if w := receiveSessionOperationE2E(t, privacy); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "privacy") {
				t.Fatalf("late HTML %s inventory=%d %s", operation, w.Code, w.Body.String())
			}
			if after := htmlPrivacySnapshotE2E(t, f); after != before {
				t.Fatal("late HTML inventory refusal committed recipient/status changes or terminal privacy audit")
			}
			var masters, revisions, created int
			if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM templates WHERE org_id=$1 AND source_kind='html'),
				(SELECT count(*) FROM html_template_revisions WHERE org_id=$1),
				(SELECT count(*) FROM events WHERE org_id=$1 AND kind='template.created')`, f.org).Scan(&masters, &revisions, &created); err != nil { //nolint:rawsql -- the independent authorized creation must survive privacy rollback
				t.Fatal(err)
			}
			if masters != 1 || revisions != 1 || created != 1 {
				t.Fatalf("late inventory witness lost independent HTML commit: masters/revisions/audit=%d/%d/%d", masters, revisions, created)
			}
		})
	}
}

func htmlMigrationPartsE2E(t *testing.T) (string, string) {
	t.Helper()
	raw, err := os.ReadFile("../db/migrations/00073_html_template_masters.sql")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.SplitN(string(raw), "-- +goose Down", 2)
	if len(parts) != 2 {
		t.Fatal("HTML migration must contain explicit Up and Down")
	}
	// Migration74 depends on73's columns and has its own independent history
	// refusal fence. Remove that empty dependent state first; never bypass its
	// retention guards or alter73's production migration bytes.
	dependent, err := os.ReadFile("../db/migrations/00074_html_document_materializations.sql")
	if err != nil {
		t.Fatal(err)
	}
	dependentParts := strings.SplitN(string(dependent), "-- +goose Down", 2)
	if len(dependentParts) != 2 {
		t.Fatal("HTML materialization migration requires Up/Down")
	}
	provenance, err := os.ReadFile("../db/migrations/00075_pdf_sanitization_provenance.sql")
	if err != nil {
		t.Fatal(err)
	}
	provenanceParts := strings.SplitN(string(provenance), "-- +goose Down", 2)
	if len(provenanceParts) != 2 {
		t.Fatal("PDF provenance migration requires Up/Down")
	}
	return parts[0] + "\n" + dependentParts[0] + "\n" + provenanceParts[0], provenanceParts[1] + "\n" + dependentParts[1] + "\n" + parts[1]
}

func TestHTMLTemplateMigrationDownRefusesRetainedSourcesE2E(t *testing.T) {
	database := isolateHTMLTemplateDatabaseE2E(t)
	f := setupHTMLTemplateAuthorizationE2E(t, database, "owner")
	up, down := htmlMigrationPartsE2E(t)
	t.Run("empty Down and Up", func(t *testing.T) {
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(f.ctx, down); err != nil { //nolint:rawsql -- exact migration, transaction always rolled back
			t.Fatal("empty HTML migration Down:", err)
		}
		var absent bool
		if err := tx.QueryRow(f.ctx, `SELECT to_regclass('html_template_revisions') IS NULL`).Scan(&absent); err != nil || !absent { //nolint:rawsql
			t.Fatalf("Down left HTML revision schema: absent=%t err=%v", absent, err)
		}
		if _, err := tx.Exec(f.ctx, up); err != nil { //nolint:rawsql -- exact migration reapplied inside rolled-back transaction
			t.Fatal("HTML migration Up after empty Down:", err)
		}
	})
	for _, kind := range []string{"master", "revision", "document source", "historical source"} {
		t.Run(kind, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(context.Background())
			q := f.q.WithTx(tx)
			if kind == "master" || kind == "revision" {
				input := htmlTemplateInputE2E(t, 0, "Rollback witness")
				content, err := htmlmaster.CanonicalTemplate(input.HTMLMasterJSON, input.VariablesJSON)
				if err != nil {
					t.Fatal(err)
				}
				digest, _ := hex.DecodeString(content.SHA256)
				template, err := q.CreateHTMLTemplate(f.ctx, generated.CreateHTMLTemplateParams{OrgID: f.org, Name: input.Name, HtmlMasterJson: content.MasterJSON,
					VariablesJson: content.DefaultsJSON, CreatedBy: f.user.ID, HtmlContentSha256: digest})
				if err != nil {
					t.Fatal(err)
				}
				if kind == "revision" {
					if _, err := q.InsertHTMLTemplateRevision(f.ctx, generated.InsertHTMLTemplateRevisionParams{TemplateID: template.ID, OrgID: f.org,
						ExpectedVersion: 1, HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON, ContentSha256: digest, CreatedBy: f.user.ID}); err != nil {
						t.Fatal(err)
					}
					// Retain immutable history while no current HTML master remains;
					// this independently exercises the revision-table rollback fence.
					if _, err := tx.Exec(f.ctx, `UPDATE templates SET source_kind='blocks',blocks_json='{"version":1,"blocks":[]}',html_master_json=NULL,html_content_sha256=NULL WHERE id=$1`, template.ID); err != nil { //nolint:rawsql -- synthetic migration inventory shape, no guard disabled
						t.Fatal(err)
					}
				}
			} else {
				digest := sha256.Sum256([]byte("synthetic migration PDF source"))
				doc, err := q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: f.org, SenderID: f.user.ID, Name: "Rollback source witness",
					PdfStorageKey: pgtype.Text{String: "synthetic/migration.pdf", Valid: true}, PdfSha256: digest[:]})
				if err != nil {
					t.Fatal(err)
				}
				if kind == "document source" {
					_, err = q.SetDocumentHTMLSource(f.ctx, generated.SetDocumentHTMLSourceParams{ID: doc.ID, OrgID: f.org, ExpectedUpdatedAt: doc.UpdatedAt, HtmlSourceJson: json.RawMessage(`{"synthetic_schema_witness":true}`)})
				} else {
					_, err = q.InsertDocumentVersion(f.ctx, generated.InsertDocumentVersionParams{DocumentID: doc.ID, OrgID: f.org, VersionNo: 1,
						BlockTreeJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`), Name: doc.Name, SourceKind: "pdf",
						CreatedVia: "human", SchemaVersion: 1, HtmlSourceJson: json.RawMessage(`{"synthetic_schema_witness":true}`)})
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			// Flush deferred FK/ceremony guard events created by this same
			// transaction's synthetic witness. Otherwise ALTER TABLE can stop
			// with 55006 before reaching the migration's retained-state refusal.
			if _, err := tx.Exec(f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil { //nolint:rawsql -- exercise the real rollback fence, not pending-trigger setup
				t.Fatal(err)
			}
			_, err = tx.Exec(f.ctx, down) //nolint:rawsql -- exact destructive migration must refuse retained state
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" || !strings.Contains(pgerr.Message, "prevent safe migration rollback") {
				t.Fatalf("retained %s Down=%v", kind, err)
			}
			if err := tx.Rollback(f.ctx); err != nil {
				t.Fatal(err)
			}
			var exists bool
			if err := f.pool.QueryRow(f.ctx, `SELECT to_regclass('html_template_revisions') IS NOT NULL`).Scan(&exists); err != nil || !exists { //nolint:rawsql -- failed Down must preserve schema
				t.Fatalf("failed Down damaged HTML schema: exists=%t err=%v", exists, err)
			}
		})
	}
}
