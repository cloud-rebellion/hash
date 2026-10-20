//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

type automationAuthorizationFixture struct {
	ctx                    context.Context
	pool                   *pgxpool.Pool
	q                      *generated.Queries
	s                      *Server
	org, user, keyID       uuid.UUID
	key, body, idempotency string
}

func setupAutomationAuthorizationE2E(t *testing.T, expires time.Time) automationAuthorizationFixture {
	t.Helper()
	// Preserve the caller's short credential lease from actual key creation;
	// genuine template/runtime preparation must not consume the test lease.
	var lease time.Duration
	if !expires.IsZero() {
		lease = time.Until(expires)
	}
	owned := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, owned)
	ownedAutomationAuthorizationPrepareFreePlanV1(t, owned)
	base := owned.f
	ctx, pool, q, s, org, user := base.ctx, base.pool, base.q, base.s, base.org, base.user.ID
	created := ownedBlocksTemplateCallV1(t, base, owned.cookie, http.MethodPost, "/api/v1/templates", map[string]any{
		"name":           "Authorization template",
		"blocks_json":    json.RawMessage(`{"version":1,"blocks":[{"id":"agreement","type":"paragraph","text":"Agreement for {{customer}}"},{"id":"signature","type":"signature_field","attrs":{"recipient_role":"signer"}}]}`),
		"variables_json": map[string]string{"customer": "Fixture customer"},
	})
	if created.Code != http.StatusCreated {
		t.Fatalf("actual authorization template=%d %s", created.Code, created.Body.String())
	}
	var published templateResponse
	if err := json.Unmarshal(created.Body.Bytes(), &published); err != nil || published.ID == uuid.Nil {
		t.Fatal("actual authorization template response", err)
	}
	template, err := q.GetTemplate(ctx, generated.GetTemplateParams{ID: published.ID, OrgID: org})
	if err != nil {
		t.Fatal(err)
	}
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if !expires.IsZero() {
		expires = time.Now().Add(lease)
	}
	row, err := q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{
		OrgID: org, UserID: user, KeyPrefix: key.Prefix, KeyHash: key.Hash, Name: "Synthetic automation authorization",
		Scopes: []string{"write:authoring", "write:workflow"}, ExpiresAt: pgtype.Timestamptz{Time: expires, Valid: !expires.IsZero()},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.APIKeys = &auth.PgVerifier{Queries: q}
	s.Billing = billing.New(q, billing.MockProvider{}, "", "")
	// Keep the same genuinely configured native Send/runtime/storage/render peers.
	content, err := templatepin.Canonicalize(template.BlocksJson, template.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(automationSignatureRequestInput{
		TemplateID: template.ID.String(), TemplateVersion: template.Version, TemplateContentSHA256: content.SHA256Hex(),
		Name: "Authorized machine agreement", LawfulBasis: "contract", Variables: map[string]string{},
		Recipients: []automationSignatureRecipientInput{{Name: "Synthetic signer", Email: uuid.NewString() + "@automation-authorization.test", Locale: "en"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The owned fixture independently joins and removes its entire disposable
	// database; per-org DELETE would collide with genuine immutable audit history.
	return automationAuthorizationFixture{ctx, pool, q, s, org, user, row.ID, key.Plaintext, string(body), uuid.NewString()}
}

// The original non-subscription billing fixture selects the free catalog row.
// Measure that exact real source explicitly before exercising the route; no
// route reads or repairs its cache, and its original free quota is unchanged.
func ownedAutomationAuthorizationPrepareFreePlanV1(t *testing.T, owned *ownedPublicReadFixtureV1) {
	t.Helper()
	var plan uuid.UUID
	if err := owned.f.pool.QueryRow(owned.f.ctx, "SELECT id FROM billing_plans WHERE slug='free'").Scan(&plan); err != nil || plan == uuid.Nil {
		t.Fatal("actual free plan identity unavailable", err)
	} //nolint:rawsql -- exact fixture catalog identity only
	owner, err := owned.runtime.SessionsV1().ControlledMeasurePlanSourceV1(owned.f.ctx, plan)
	if owner != nil {
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := owner.CloseV1(ctx); err != nil {
				t.Error("free catalog source cleanup", err)
			}
		})
	}
	if err != nil || owner == nil {
		t.Fatal("actual free catalog source preparation", err)
	}
	receipt, err := owner.ReceiptV1()
	if err != nil || receipt.Kind != "plan" || receipt.SourceID != plan || receipt.OrgID != uuid.Nil || receipt.WireBytes <= 0 || receipt.ServerVersionNum != 160015 || !receipt.CreatedAt.Valid || !receipt.MeasuredAt.Valid {
		t.Fatal("actual free catalog source receipt", err)
	}
	owner.CloseConsumerV1()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err = owner.CloseV1(ctx); err != nil {
		t.Fatal("actual free catalog source did not join", err)
	}
	ownedCreationAssertDrainedV1(t, owned, 2)
}

func (f automationAuthorizationFixture) submit() *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/automation/v1/signature-requests", strings.NewReader(f.body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.key)
	r.Header.Set(automationIdempotencyHeader, f.idempotency)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func (f automationAuthorizationFixture) snapshot(t *testing.T) string {
	t.Helper()
	var state string
	err := f.pool.QueryRow(f.ctx, `WITH owned AS (SELECT id FROM documents WHERE org_id=$1)
	SELECT jsonb_build_object(
	'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
	'requests',(SELECT coalesce(jsonb_agg(to_jsonb(a)-'updated_at' ORDER BY id),'[]'::jsonb) FROM automation_signature_requests a WHERE org_id=$1),
	'recipients',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY id),'[]'::jsonb) FROM recipients r WHERE document_id IN (SELECT id FROM owned)),
	'versions',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM document_versions v WHERE document_id IN (SELECT id FROM owned)),
	'events',(SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY id),'[]'::jsonb) FROM events e WHERE org_id=$1),
	'intents',(SELECT coalesce(jsonb_agg(to_jsonb(i) ORDER BY document_id),'[]'::jsonb) FROM send_sealing_intents i WHERE org_id=$1),
	'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(ed) ORDER BY id),'[]'::jsonb) FROM email_deliveries ed WHERE to_email IN (SELECT email FROM recipients WHERE document_id IN (SELECT id FROM owned)))
	)::text`, f.org).Scan(&state)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestAutomationAuthorizationRecheckedAfterQuotaWaitE2E(t *testing.T) {
	for _, change := range []string{"demotion", "delete-key", "reduce-scopes", "expire-key"} {
		t.Run(change, func(t *testing.T) {
			f := setupAutomationAuthorizationE2E(t, time.Time{})
			before := f.snapshot(t)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err = f.q.WithTx(blocked).LockAutomationSignatureRequestQuota(f.ctx, f.org.String()); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- f.submit() }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: LockAutomationSignatureRequestQuota", "advisory")
			want := http.StatusForbidden
			switch change {
			case "demotion":
				_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user, OrgID: f.org, Role: "viewer"})
			case "delete-key":
				_, err = f.pool.Exec(f.ctx, `DELETE FROM api_keys WHERE id=$1`, f.keyID)
			case "reduce-scopes":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['write:authoring'] WHERE id=$1`, f.keyID)
			case "expire-key":
				_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.keyID)
				want = http.StatusUnauthorized
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != want {
				t.Fatalf("automation admission=%d want=%d %s", response.Code, want, response.Body.String())
			}
			if f.snapshot(t) != before {
				t.Fatal("refused automation materialization retained PII, idempotency, version, audit or outbox")
			}
		})
	}
}

func TestAutomationAuthorizationExpiryDuringCreationAuditRollsBackE2E(t *testing.T) {
	f := setupAutomationAuthorizationE2E(t, time.Now().Add(2*time.Second))
	before := f.snapshot(t)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err = f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- f.submit() }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var expired bool
		if err = f.pool.QueryRow(f.ctx, `SELECT expires_at <= clock_timestamp() FROM api_keys WHERE id=$1`, f.keyID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture API credential did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	response := receiveSessionOperationE2E(t, result)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired automation=%d %s", response.Code, response.Body.String())
	}
	if f.snapshot(t) != before {
		t.Fatal("expired automation transaction retained creation, recipient, request, version, audit, notice or outbox")
	}
}

func TestAutomationAuthorizationSuccessAndReplayE2E(t *testing.T) {
	f := setupAutomationAuthorizationE2E(t, time.Time{})
	first := f.submit()
	if first.Code != http.StatusCreated {
		t.Fatalf("automation create=%d %s", first.Code, first.Body.String())
	}
	var created automationSignatureRequestResponse
	if err := json.Unmarshal(first.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if created.Status != "sent" || created.Replayed {
		t.Fatal("initial machine request did not send")
	}
	before := f.snapshot(t)
	replayed := f.submit()
	if replayed.Code != http.StatusOK {
		t.Fatalf("automation replay=%d %s", replayed.Code, replayed.Body.String())
	}
	var replay automationSignatureRequestResponse
	if err := json.Unmarshal(replayed.Body.Bytes(), &replay); err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.DocumentID != created.DocumentID || replay.AutomationRequestID != created.AutomationRequestID {
		t.Fatal("replay lost durable command identity")
	}
	// MarkAutomationSignatureRequestSent refreshes only its own bookkeeping
	// timestamp on replay; ceremony evidence and notifications remain unique.
	var documents, recipients, invites, deliveries int
	if err := f.pool.QueryRow(f.ctx, `SELECT
	(SELECT count(*) FROM documents WHERE org_id=$1),
	(SELECT count(*) FROM recipients WHERE document_id=$2),
	(SELECT count(*) FROM events WHERE document_id=$2 AND kind='recipient.invited'),
	(SELECT count(*) FROM email_deliveries WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$2))`, f.org, created.DocumentID).Scan(&documents, &recipients, &invites, &deliveries); err != nil {
		t.Fatal(err)
	}
	if documents != 1 || recipients != 1 || invites != 1 || deliveries != 1 {
		t.Fatalf("machine replay duplicated artifacts: %d/%d/%d/%d", documents, recipients, invites, deliveries)
	}
	if f.snapshot(t) != before {
		t.Fatal("machine replay changed ceremony, idempotent identity, audit or outbox")
	}
}

func TestAutomationCredentialExpiryIsSampledAfterCredentialLockE2E(t *testing.T) {
	f := setupAutomationAuthorizationE2E(t, time.Now().Add(2*time.Second))
	var admitted context.Context
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/api/automation/v1/signature-requests", nil).WithContext(f.ctx)
	r.Header.Set("Authorization", "Bearer "+f.key)
	w := httptest.NewRecorder()
	auth.RequireAPIKey(f.s.APIKeys)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		admitted = r.Context()
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || admitted == nil {
		t.Fatalf("actual credential admission failed: %d", w.Code)
	}
	authorize, err := auth.APIKeyTransactionAuthorization(admitted, uuid.Nil, "write:authoring", "write:workflow")
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	var keyID uuid.UUID
	if err = blocked.QueryRow(f.ctx, `SELECT id FROM api_keys WHERE id=$1 FOR UPDATE`, f.keyID).Scan(&keyID); err != nil {
		t.Fatal(err)
	}
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	user, err := f.q.WithTx(tx).GetUserForShare(f.ctx, generated.GetUserForShareParams{ID: f.user, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { result <- authorize(admitted, tx, user) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "FROM api_keys WHERE id=$1", "transactionid")
	deadline := time.Now().Add(3 * time.Second)
	for {
		var expired bool
		if err = f.pool.QueryRow(f.ctx, `SELECT expires_at <= clock_timestamp() FROM api_keys WHERE id=$1`, f.keyID).Scan(&expired); err != nil {
			t.Fatal(err)
		}
		if expired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fixture credential did not expire")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err = blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, auth.ErrMutationCredentialExpired) {
			t.Fatalf("first authorization after credential lock wait=%v, want expired", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("credential authorization did not finish after row lock release")
	}
}
