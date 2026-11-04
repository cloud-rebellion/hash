//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/workspacesmtp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/stdlib"
)

// Every root has an actual native owned clone. There is no shared-estate Down,
// disabled trigger, fabricated version history, external SMTP or mock PG claim.
func smtp730Fixture(t *testing.T) folderFixture695 {
	t.Helper()
	isolateMigratedHTMLTemplateDatabaseE2E(t)
	ctx, pool, q, s, org, userID := setupDSRE2E(t)
	user, e := q.GetUser(ctx, userID)
	if e != nil {
		t.Fatal(e)
	}
	box, e := dispatch.NewStaffAuthMailBox(strings.Repeat("73", 32), "")
	if e != nil {
		t.Fatal(e)
	}
	s.StaffAuthMailBox = box
	return folderFixture695{lifecycleAuthorizationFixture: lifecycleAuthorizationFixture{ctx: ctx, pool: pool, q: q, s: s, org: org, user: user}, cookie: dsrSessionCookieE2E(t, s, userID, user.SessionGeneration, time.Hour)}
}
func smtp730Save(t *testing.T, f folderFixture695, revision int64) workspacesmtp.SafeSettings {
	t.Helper()
	raw := strings.Replace(smtp730Input, `"expected_revision":0`, `"expected_revision":`+jsonNumber730(revision), 1)
	w := f.request(http.MethodPut, "/api/v1/workspace-smtp", raw)
	if w.Code != 200 {
		t.Fatalf("owner SMTP save=%d", w.Code)
	}
	var out workspacesmtp.SafeSettings
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Revision != revision+1 || !out.Configured {
		t.Fatal("safe SMTP response missing")
	}
	return out
}
func jsonNumber730(v int64) string { raw, _ := json.Marshal(v); return string(raw) }
func TestWorkspaceSMTP730OwnerCASSecretsAndTenantE2E(t *testing.T) {
	f := smtp730Fixture(t)
	initial := f.request(http.MethodGet, "/api/v1/workspace-smtp", "")
	if initial.Code != 200 || initial.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("initial owner read failed")
	}
	var first workspacesmtp.SafeSettings
	if json.Unmarshal(initial.Body.Bytes(), &first) != nil || first.Configured || first.Mode != "unconfigured" || first.Revision != 0 {
		t.Fatal("new organization inherited installation SMTP")
	}
	smtp730Save(t, f, 0)
	var ciphertext []byte
	if e := f.pool.QueryRow(f.ctx, `SELECT config_ciphertext FROM org_smtp_settings_v1 WHERE org_id=$1`, f.org).Scan(&ciphertext); e != nil || len(ciphertext) < 30 || strings.Contains(string(ciphertext), "synthetic") {
		t.Fatal("configuration not sealed at rest")
	}
	if w := f.request(http.MethodPut, "/api/v1/workspace-smtp", smtp730Input); w.Code != 409 {
		t.Fatal("stale SMTP overwrite accepted", w.Code)
	}
	keep := strings.Replace(smtp730Input, `,"username":"synthetic","password":"synthetic"`, "", 1)
	keep = strings.Replace(keep, `"replace"`, `"keep"`, 1)
	keep = strings.Replace(keep, `"expected_revision":0`, `"expected_revision":1`, 1)
	if w := f.request(http.MethodPut, "/api/v1/workspace-smtp", strings.Replace(keep, "smtp.example.invalid", "other.example.invalid", 1)); w.Code != 400 {
		t.Fatal("stored secret redirected to changed endpoint", w.Code)
	}
	if w := f.request(http.MethodPut, "/api/v1/workspace-smtp", keep); w.Code != 200 || strings.Contains(w.Body.String(), "synthetic") {
		t.Fatal("credential keep failed or disclosed value", w.Code)
	}
	if w := f.request(http.MethodDelete, "/api/v1/workspace-smtp", `{"expected_revision":1}`); w.Code != 409 {
		t.Fatal("stale disable accepted")
	}
	if w := f.request(http.MethodDelete, "/api/v1/workspace-smtp", `{"expected_revision":2}`); w.Code != 200 {
		t.Fatal("disable failed", w.Code)
	}
	var mode string
	var sealed []byte
	var revision int64
	if e := f.pool.QueryRow(f.ctx, `SELECT mode,revision,config_ciphertext FROM org_smtp_settings_v1 WHERE org_id=$1`, f.org).Scan(&mode, &revision, &sealed); e != nil || mode != "disabled" || revision != 3 || sealed != nil {
		t.Fatal("disable retained credential or restored fallback")
	}
	foreign, e := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Other synthetic SMTP workspace", Plan: "pro"})
	if e != nil {
		t.Fatal(e)
	}
	var count int
	if e = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM org_smtp_settings_v1 WHERE org_id=$1`, foreign.ID).Scan(&count); e != nil || count != 0 {
		t.Fatal("new foreign workspace inherited settings")
	}
	if _, e = f.pool.Exec(f.ctx, `UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2`, f.user.ID, f.org); e != nil {
		t.Fatal(e)
	}
	if w := f.request(http.MethodGet, "/api/v1/workspace-smtp", ""); w.Code != 403 {
		t.Fatal("revoked owner retained SMTP read", w.Code)
	}
}
func TestWorkspaceSMTP730SyntheticOwnerTestUsesRealOutboxE2E(t *testing.T) {
	f := smtp730Fixture(t)
	smtp730Save(t, f, 0)
	if w := f.request(http.MethodPost, "/api/v1/workspace-smtp/test", `{"expected_revision":1,"to":"other@example.invalid"}`); w.Code != 400 {
		t.Fatal("caller recipient accepted")
	}
	w := f.request(http.MethodPost, "/api/v1/workspace-smtp/test", `{"expected_revision":1}`)
	if w.Code != 202 {
		t.Fatal("native test enqueue failed", w.Code)
	}
	var out workspacesmtp.TestStatus
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.DeliveryID == uuid.Nil || out.Status != "pending" || out.SMTPAccepted || out.InboxDeliveryConfirmed {
		t.Fatal("queue admission claimed delivery")
	}
	var to, purpose, body string
	var org uuid.UUID
	if e := f.pool.QueryRow(f.ctx, `SELECT to_email,smtp_purpose,smtp_org_id,text_body FROM email_deliveries WHERE id=$1`, out.DeliveryID).Scan(&to, &purpose, &org, &body); e != nil || to != f.user.Email || purpose != "workspace_test" || org != f.org || !strings.Contains(body, "synthetic") || !strings.Contains(body, "does not confirm inbox") {
		t.Fatal("test recipient/scope/body not native-bound")
	}
	if w := f.request(http.MethodPost, "/api/v1/workspace-smtp/test", `{"expected_revision":1}`); w.Code != 429 {
		t.Fatal("unbounded duplicate synthetic test")
	}
	status := f.request(http.MethodGet, "/api/v1/workspace-smtp/test/"+out.DeliveryID.String(), "")
	if status.Code != 200 || strings.Contains(status.Body.String(), `"smtp_accepted":true`) {
		t.Fatal("pending receipt claimed SMTP or inbox acceptance")
	}
	// Only the actual worker can record SMTP acceptance in the release journey.
	// This root deliberately does not send or fabricate that acknowledgement.
	if e := f.q.EnqueueStaffAuthEmail(f.ctx, generated.EnqueueStaffAuthEmailParams{ID: uuid.New(), ToEmail: f.user.Email, Subject: "Synthetic auth", StaffAuthCiphertext: []byte{1}}); e == nil {
		t.Fatal("invalid sealed auth fixture accepted")
	}
}

const oldSMTPClaim730 = `-- name: ClaimDueEmailDeliveries :many
WITH due AS (
  SELECT id
  FROM email_deliveries
  WHERE status IN ('pending', 'retrying')
    AND next_attempt_at <= now()
  ORDER BY next_attempt_at
  FOR UPDATE SKIP LOCKED
  LIMIT $1
)
UPDATE email_deliveries d
SET status = 'retrying',
    next_attempt_at = now() + interval '5 minutes'
FROM due
WHERE d.id = due.id
RETURNING d.id, d.to_email, d.subject, d.html_body, d.text_body, d.reply_to, d.from_name, d.headers_json, d.status, d.attempts, d.last_error, d.next_attempt_at, d.created_at, d.sent_at, d.staff_auth_ciphertext
`
const oldSMTPRetry730 = `-- name: MarkEmailDeliveryRetrying :exec
UPDATE email_deliveries
SET status = 'retrying',
    attempts = attempts + 1,
    last_error = $2,
    next_attempt_at = $3
WHERE id = $1
`

func smtp730CheckViolation(t *testing.T, e error) {
	t.Helper()
	var pg *pgconn.PgError
	if !errors.As(e, &pg) || pg.Code != "23514" {
		t.Fatal("expected real native route constraint refusal")
	}
}
func TestWorkspaceSMTP730OldWorkerClaimFenceAndDownE2E(t *testing.T) {
	f := smtp730Fixture(t)
	migration := stdlib.OpenDB(*f.pool.Config().ConnConfig.Copy())
	migration.SetMaxOpenConns(1)
	defer migration.Close()
	if e := db.RunMigrationsDownToContext(f.ctx, migration, 119); e != nil {
		t.Fatal("empty120 Down", e)
	}
	var legacy uuid.UUID
	if e := f.pool.QueryRow(f.ctx, `INSERT INTO email_deliveries(to_email,subject,html_body,text_body,reply_to,from_name,headers_json) VALUES('legacy@example.invalid','Retained synthetic','<p>Retained</p>','Retained','','','{}') RETURNING id`).Scan(&legacy); e != nil {
		t.Fatal(e)
	}
	if e := db.RunMigrationsContext(f.ctx, migration); e != nil {
		t.Fatal("genuine120 Up", e)
	}
	var legacyMode string
	if e := f.pool.QueryRow(f.ctx, `SELECT smtp_purpose FROM email_deliveries WHERE id=$1`, legacy).Scan(&legacyMode); e != nil || legacyMode != "installation_legacy" {
		t.Fatal("original retained mail not explicitly classified")
	}
	if _, e := f.pool.Exec(f.ctx, `INSERT INTO email_deliveries(to_email,subject,smtp_purpose) VALUES('forged@example.invalid','Synthetic','installation_legacy')`); e == nil {
		t.Fatal("new mail forged migration compatibility")
	}
	current, e := f.q.EnqueueEmailDelivery(f.ctx, generated.EnqueueEmailDeliveryParams{OrgID: f.org, ToEmail: "owner@example.invalid", Subject: "Native workspace synthetic", HtmlBody: "<p>Synthetic</p>", TextBody: "Synthetic", HeadersJson: json.RawMessage(`{}`)})
	if e != nil {
		t.Fatal(e)
	}
	var before string
	if e = f.pool.QueryRow(f.ctx, `SELECT row_to_json(d)::text FROM email_deliveries d WHERE id=$1`, legacy).Scan(&before); e != nil {
		t.Fatal(e)
	}
	rows, e := f.pool.Query(f.ctx, oldSMTPClaim730, int32(50))
	if e == nil {
		for rows.Next() {
		}
		e = rows.Err()
		rows.Close()
	}
	smtp730CheckViolation(t, e)
	var after string
	if e = f.pool.QueryRow(f.ctx, `SELECT row_to_json(d)::text FROM email_deliveries d WHERE id=$1`, legacy).Scan(&after); e != nil || before != after {
		t.Fatal("failed mixed old claim partially leased legacy mail")
	}
	claimed, e := f.q.ClaimDueEmailDeliveries(f.ctx, 50)
	if e != nil || len(claimed) != 2 {
		t.Fatal("native new claim failed", e)
	}
	var workspace *generated.EmailDelivery
	for _, d := range claimed {
		if d.ID == current.ID {
			workspace = d
		}
	}
	if workspace == nil || !workspace.SmtpClaimNonce.Valid {
		t.Fatal("new worker lacked genuine database nonce")
	}
	oldNonce := workspace.SmtpClaimNonce
	_, e = f.pool.Exec(f.ctx, oldSMTPRetry730, current.ID, "synthetic", time.Now().Add(time.Minute))
	smtp730CheckViolation(t, e)
	if e = f.q.MarkEmailDeliveryRetrying(f.ctx, generated.MarkEmailDeliveryRetryingParams{ID: current.ID, LastError: "email_delivery_transport_unavailable", NextAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(time.Minute), Valid: true}}); e != nil {
		t.Fatal("native retry failed", e)
	}
	var nonce pgtype.UUID
	if e = f.pool.QueryRow(f.ctx, `SELECT smtp_claim_nonce FROM email_deliveries WHERE id=$1`, current.ID).Scan(&nonce); e != nil || !nonce.Valid || nonce == oldNonce {
		t.Fatal("native retry reused claim nonce")
	}
	if e = db.RunMigrationsDownToContext(f.ctx, migration, 119); e == nil {
		t.Fatal("occupied workspace route lost on Down")
	}
	// This exact disposable estate owns its synthetic route. Remove only that row
	// to prove the legacy-only Down, preserving the original retained message.
	if _, e = f.pool.Exec(f.ctx, `DELETE FROM email_deliveries WHERE id=$1 AND smtp_org_id=$2`, current.ID, f.org); e != nil {
		t.Fatal(e)
	}
	if e = db.RunMigrationsDownToContext(f.ctx, migration, 119); e != nil {
		t.Fatal("legacy-only Down refused", e)
	}
	var original string
	if e = f.pool.QueryRow(f.ctx, `SELECT text_body FROM email_deliveries WHERE id=$1`, legacy).Scan(&original); e != nil || original != "Retained" {
		t.Fatal("Down changed original mail")
	}
}
