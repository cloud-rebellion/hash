//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Rebind only the test handle to a document and recipient produced by actual
// approved-HTML creation and normal native Send. No lifecycle rows or native
// runtime owners are fabricated to modernize the older authorization tests.
func nativeReminderAuthorizationFixture255(t *testing.T, sender bool) (*ownedPublicReadFixtureV1, lifecycleAuthorizationFixture, []signerBrowserPartyE2E) {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	doc, parties := q.createSentV1(t)
	// The process and tenant signer observers are created by the actual
	// current invitation bootstrap, then its genuine reader is retired.
	// Merely sending a document does not create the second observer.
	rc := q.lookupV1(t, parties[0].Token)
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal("actual invitation bootstrap retirement", err)
	}
	f := q.f
	f.doc = doc
	var err error
	f.recipient, err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: parties[0].RecipientID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	if sender {
		owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
		response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"sender"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
		if response.Code != http.StatusOK {
			t.Fatal("actual sender membership configuration", response.Code)
		}
		f.user, err = f.q.GetUser(f.ctx, f.user.ID)
		if err != nil || f.user.Role != "sender" {
			t.Fatal("actual sender membership readback", err)
		}
	}
	q.f = f
	return q, f, parties
}

func nativeReminderAsyncHTTP255(parent context.Context, request func(context.Context) *httptest.ResponseRecorder) (<-chan *httptest.ResponseRecorder, context.CancelFunc, <-chan struct{}) {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		result <- request(ctx)
	}()
	return result, cancel, joined
}

func nativeReminderCleanupHTTP255(t *testing.T, blocked pgx.Tx, cancel context.CancelFunc, joined <-chan struct{}) {
	t.Helper()
	cancel()
	ctx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	if err := blocked.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Error("original test blocker rollback did not join", err)
	}
	select {
	case <-joined:
	case <-ctx.Done():
		t.Error("original reminder request did not join within independent cleanup budget", ctx.Err())
	}
}

func nativeReminderRollback255(t *testing.T, blocked pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := blocked.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		t.Error("original test blocker rollback unavailable", err)
	}
}

func nativeReminderMCPRequest255(ctx context.Context, f lifecycleAuthorizationFixture, key string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "remind_recipient", "arguments": map[string]any{"document_id": f.doc.ID}}})
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+key)
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}

func TestNativeReminderSessionRechecksAuthorizationAfterDocumentWaitV1E2E(t *testing.T) {
	for _, change := range []string{"demotion", "revocation", "expiry"} {
		t.Run(change, func(t *testing.T) {
			q, f, _ := nativeReminderAuthorizationFixture255(t, true)
			defer q.assertObserversOnlyV1(t)
			owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
			before := nativeReminderSnapshot254(t, q, f.doc.ID)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nativeReminderRollback255(t, blocked)
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			ttl := time.Hour
			if change == "expiry" {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
				return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/remind", "", cookie)
			})
			defer nativeReminderCleanupHTTP255(t, blocked, cancel, joined)
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetHTMLSendDocumentStateHeaderV1", "transactionid")
			want := http.StatusForbidden
			switch change {
			case "demotion":
				response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
				if response.Code != http.StatusOK {
					t.Fatal("actual member demotion", response.Code)
				}
			case "revocation":
				if response := submitSessionOperationE2E(f.s, http.MethodPost, "/auth/logout", "", cookie); response.Code != http.StatusOK {
					t.Fatal("actual session logout", response.Code)
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
				t.Fatalf("stale reminder=%d want=%d", response.Code, want)
			}
			if nativeReminderSnapshot254(t, q, f.doc.ID) != before {
				t.Fatal("stale session changed reminder ceremony, schedule, token, outbox, audit or measurement")
			}
		})
	}
}

func TestNativeReminderMCPRechecksCredentialAfterDocumentWaitV1E2E(t *testing.T) {
	for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "document-token-revocation"} {
		t.Run(change, func(t *testing.T) {
			q, f, _ := nativeReminderAuthorizationFixture255(t, false)
			defer q.assertObserversOnlyV1(t)
			f.enableMCP()
			before := nativeReminderSnapshot254(t, q, f.doc.ID)
			mint, err := auth.MintAPIKey()
			if change == "document-token-revocation" {
				mint, err = auth.MintDocumentAgentKey()
			}
			if err != nil {
				t.Fatal(err)
			}
			var keyID uuid.UUID
			if change == "document-token-revocation" {
				key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: f.doc.ID, OrgID: f.org, Name: "Native reminder credential wait", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1})
				if err != nil {
					t.Fatal(err)
				}
				keyID = key.ID
			} else {
				key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{OrgID: f.org, UserID: f.user.ID, Name: "Native reminder credential wait", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"}})
				if err != nil {
					t.Fatal(err)
				}
				keyID = key.ID
			}
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer nativeReminderRollback255(t, blocked)
			if _, err := f.q.WithTx(blocked).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
				t.Fatal(err)
			}
			result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
				return nativeReminderMCPRequest255(ctx, f, mint.Plaintext)
			})
			defer nativeReminderCleanupHTTP255(t, blocked, cancel, joined)
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetHTMLSendDocumentStateHeaderV1", "transactionid")
			switch change {
			case "key-delete":
				response := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
				if response.Code != http.StatusNoContent {
					t.Fatal("actual key delete", response.Code)
				}
			case "scope-reduction":
				if _, err := f.pool.Exec(f.ctx, "UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1", keyID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- change the actual external credential after middleware admission
			case "key-expiry":
				if _, err := f.pool.Exec(f.ctx, "UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1", keyID); err != nil {
					t.Fatal(err)
				} //nolint:rawsql -- actual credential policy expiry while the original request is waiting
			case "document-token-revocation":
				if _, err := f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org}); err != nil {
					t.Fatal(err)
				}
			}
			if err := blocked.Commit(f.ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			assertLifecycleMCPResultE2E(t, response, true)
			want := auth.ErrMutationPermissionRevoked.Error()
			if change == "key-expiry" {
				want = auth.ErrMutationCredentialExpired.Error()
			}
			if !strings.Contains(response.Body.String(), want) {
				t.Fatal("MCP lost the original precise credential refusal")
			}
			if nativeReminderSnapshot254(t, q, f.doc.ID) != before {
				t.Fatal("stale external credential changed original reminder legal effects")
			}
		})
	}
}

func TestNativeReminderSessionExpiryDuringAuditWaitRollsBackV1E2E(t *testing.T) {
	q, f, _ := nativeReminderAuthorizationFixture255(t, true)
	defer q.assertObserversOnlyV1(t)
	before := nativeReminderSnapshot254(t, q, f.doc.ID)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer nativeReminderRollback255(t, blocked)
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Second)
	result, cancel, joined := nativeReminderAsyncHTTP255(f.ctx, func(ctx context.Context) *httptest.ResponseRecorder {
		return submitSessionOperationContextE2E(ctx, f.s, http.MethodPost, "/api/v1/documents/"+f.doc.ID.String()+"/remind", "", cookie)
	})
	defer nativeReminderCleanupHTTP255(t, blocked, cancel, joined)
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	awaitSessionCookieExpiryE2E(t, f.s, cookie)
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusUnauthorized {
		t.Fatal("reminder did not reject actual session expiry after provisional effects", response.Code)
	}
	if nativeReminderSnapshot254(t, q, f.doc.ID) != before {
		t.Fatal("audit-wait expiry committed token, schedule, outbox, event or measurement")
	}
	response := f.submit("remind", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
	var body struct {
		Reminded int `json:"reminded"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Reminded != 2 {
		t.Fatal("fresh actual sender retry failed after expired request", response.Code)
	}
}

func TestNativeReminderMCPConsumesExactlyOneDocumentTokenUseV1E2E(t *testing.T) {
	q, f, parties := nativeReminderAuthorizationFixture255(t, false)
	defer q.assertObserversOnlyV1(t)
	f.enableMCP()
	mint, err := auth.MintDocumentAgentKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{DocumentID: f.doc.ID, OrgID: f.org, Name: "One native reminder use", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: []string{"write:workflow"}, CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1})
	if err != nil {
		t.Fatal(err)
	}
	before := make([]*generated.Recipient, len(parties))
	for i, party := range parties {
		before[i], err = f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: party.RecipientID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
	}
	oldMail := completedCompanionOutboxIDsV1(t, q)
	scheduleBefore, err := f.q.GetReminderForUpdate(f.ctx, f.doc.ID)
	if err != nil {
		t.Fatal(err)
	}
	assertLifecycleMCPResultE2E(t, nativeReminderMCPRequest255(f.ctx, f, mint.Plaintext), false)
	current, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
	if err != nil || current.ID != key.ID || current.UsedCount != 1 || !current.LastUsedAt.Valid {
		t.Fatal("actual reminder reauthorization consumed more than the single admitted use", err)
	}
	for i, party := range parties {
		recipient, err := f.q.GetRecipient(f.ctx, generated.GetRecipientParams{ID: party.RecipientID, OrgID: f.org})
		if err != nil || bytes.Equal(recipient.MagicTokenHash, before[i].MagicTokenHash) || !recipient.MagicTokenExpiresAt.Valid || !recipient.MagicTokenExpiresAt.Time.After(time.Now()) {
			t.Fatal("one-use native reminder did not rotate each actual live recipient", err)
		}
	}
	schedule, err := f.q.GetReminderForUpdate(f.ctx, f.doc.ID)
	if err != nil || !schedule.LastFiredAt.Valid || !schedule.NextFireAt.Valid || !schedule.NextFireAt.Time.After(scheduleBefore.NextFireAt.Time) || schedule.FiresRemaining != scheduleBefore.FiresRemaining {
		t.Fatal("one-use native reminder did not reset the actual manual schedule", err)
	}
	if len(completedCompanionOutboxIDsV1(t, q))-len(oldMail) != len(parties) {
		t.Fatal("one-use native reminder queued a missing or duplicate delivery")
	}
	var events, measurements, wrongActors int
	if err := f.pool.QueryRow(f.ctx, `SELECT
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent'),
 (SELECT count(*)::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id AND m.document_id=e.document_id AND m.org_id=e.org_id WHERE e.document_id=$1 AND e.kind='reminder.sent'),
 (SELECT count(*)::integer FROM events WHERE document_id=$1 AND kind='reminder.sent' AND (actor_user_id IS DISTINCT FROM $2 OR payload_json->>'manual' IS DISTINCT FROM 'true'))`, f.doc.ID, f.user.ID).Scan(&events, &measurements, &wrongActors); err != nil || events != 2 || measurements != 2 || wrongActors != 0 {
		t.Fatal("one-use native reminder audit/measurement association", err, events, measurements, wrongActors)
	} //nolint:rawsql -- actual original credential and producer effects
	after := nativeReminderSnapshot254(t, q, f.doc.ID)
	if response := nativeReminderMCPRequest255(f.ctx, f, mint.Plaintext); response.Code != http.StatusUnauthorized {
		t.Fatal("exhausted native reminder token replay was not refused", response.Code)
	}
	if nativeReminderSnapshot254(t, q, f.doc.ID) != after {
		t.Fatal("exhausted replay changed actual reminder legal effects")
	}
}
