//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/webhooksecret"
)

// These tests use an isolated migrated PostgreSQL database, the actual key
// manager, generated claim/mark queries and worker attempt implementation.
// Only the local HTTP receiver and explicitly injected event-read outage are
// synthetic. They do not establish production provider or consumer acceptance.
func TestWebhookClaimNextDueAndSkipLockedE2E(t *testing.T) {
	f := setupWebhookDeliveryE2E(t)
	ep := f.endpoint(t, f.orgID)
	rows := make([]*generated.WebhookDelivery, 3)
	for i := range rows {
		rows[i] = f.enqueue(t, ep.id, f.event(t, f.orgID))
		f.execOne(t, `UPDATE webhook_deliveries SET next_attempt_at=clock_timestamp()-($2::integer*interval '1 second') WHERE id=$1`, rows[i].ID, int32(3-i))
	}
	tx, err := f.pool.Begin(f.ctx)
	webhookE2ECheck(t, err, "begin claim blocker")
	defer func() {
		cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelCleanup()
		_ = tx.Rollback(cleanupCtx)
	}()
	var held uuid.UUID
	webhookE2ECheck(t, tx.QueryRow(f.ctx, `SELECT id FROM webhook_deliveries WHERE id=$1 FOR UPDATE`, rows[0].ID).Scan(&held), "hold due delivery")
	if held != rows[0].ID {
		t.Fatal("held delivery identity differs")
	}
	before := f.clock(t)
	type claimResult struct {
		row *generated.WebhookDelivery
		err error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	claimCtx, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			row, err := f.w.queries.ClaimNextDueWebhookDelivery(claimCtx)
			results <- claimResult{row: row, err: err}
		}()
	}
	close(start)
	seen := make(map[uuid.UUID]bool)
	for i := 0; i < 2; i++ {
		result := <-results
		webhookE2ECheck(t, result.err, "concurrent just-in-time claim")
		if result.row == nil || result.row.ID == held || seen[result.row.ID] {
			t.Fatal("SKIP LOCKED returned held, missing or duplicate delivery")
		}
		if result.row.ID != rows[1].ID && result.row.ID != rows[2].ID {
			t.Fatal("concurrent claim escaped fixture inventory")
		}
		seen[result.row.ID] = true
		if result.row.Attempts != 0 {
			t.Fatal("initial claim incremented delivery attempts")
		}
		f.assertLease(t, result.row, before, f.clock(t))
	}
	_, err = f.w.queries.ClaimNextDueWebhookDelivery(claimCtx)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("held and leased deliveries were not excluded from peer claim")
	}
	webhookE2ECheck(t, tx.Rollback(f.ctx), "release claim blocker")
	claim, err := f.w.queries.ClaimNextDueWebhookDelivery(f.ctx)
	webhookE2ECheck(t, err, "claim released delivery")
	if claim.ID != held {
		t.Fatal("released due delivery was not claimed")
	}
	f.assertLease(t, claim, before, f.clock(t))
	_, err = f.w.queries.ClaimNextDueWebhookDelivery(f.ctx)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("fresh five-minute leases allowed duplicate claim")
	}
}

func TestWebhookClaimMarkFencesE2E(t *testing.T) {
	f := setupWebhookDeliveryE2E(t)
	ep := f.endpoint(t, f.orgID)
	for _, status := range []string{"delivered", "retrying", "failed"} {
		t.Run(status, func(t *testing.T) {
			row := f.enqueue(t, ep.id, f.event(t, f.orgID))
			claim := f.claim(t, row.ID)
			original := f.snapshot(t, claim.ID)
			wrongAttempts := *claim
			wrongAttempts.Attempts++
			f.assertAllMarksRefused(t, &wrongAttempts, original)
			wrongLease := *claim
			wrongLease.NextAttemptAt.Time = wrongLease.NextAttemptAt.Time.Add(time.Microsecond)
			f.assertAllMarksRefused(t, &wrongLease, original)
			wrongID := *claim
			wrongID.ID = uuid.New()
			f.assertAllMarksRefused(t, &wrongID, nil)
			if !bytes.Equal(f.snapshot(t, claim.ID), original) {
				t.Fatal("wrong-identity mark changed original delivery")
			}
			f.execOne(t, `UPDATE webhook_deliveries SET status='pending' WHERE id=$1`, claim.ID)
			f.assertAllMarksRefused(t, claim, f.snapshot(t, claim.ID))
			f.execOne(t, `UPDATE webhook_deliveries SET status='retrying',next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1`, claim.ID)
			expired := f.delivery(t, ep.id, claim.ID)
			if expired.NextAttemptAt.Time.After(f.clock(t)) {
				t.Fatal("expiry fixture remained live")
			}
			// This uses the exact persisted expired timestamp: refusing it proves
			// the deadline predicate independently from equality of the lease.
			f.assertAllMarksRefused(t, expired, f.snapshot(t, claim.ID))
			fresh := f.claim(t, claim.ID)
			if fresh.NextAttemptAt.Time.Equal(claim.NextAttemptAt.Time) || fresh.Attempts != claim.Attempts {
				t.Fatal("reclaim did not replace only the lease")
			}
			f.assertAllMarksRefused(t, claim, f.snapshot(t, fresh.ID))
			rows, err := f.w.webhookDeliveryDependencies().mark(f.ctx, fresh, webhookE2EOutcome(status))
			webhookE2ECheck(t, err, "persist fresh fenced outcome")
			if rows != 1 {
				t.Fatalf("fresh mark affected %d rows, want one", rows)
			}
			marked := f.delivery(t, ep.id, fresh.ID)
			if marked.Status != status || marked.Attempts != fresh.Attempts+1 || !marked.LastStatusCode.Valid || marked.LastStatusCode.Int32 != 202 {
				t.Fatal("fresh mark did not persist exact status, attempts and HTTP code")
			}
			if status == "delivered" && marked.LastError.String != "" || status != "delivered" && marked.LastError.String != webhookHTTPRefused {
				t.Fatal("fresh mark did not persist fixed diagnostic")
			}
			final := f.snapshot(t, marked.ID)
			f.assertAllMarksRefused(t, claim, final)
			f.assertAllMarksRefused(t, fresh, final)
		})
	}
}

func TestWebhookDependencyRecoveryAndRedactionE2E(t *testing.T) {
	f := setupWebhookDeliveryE2E(t)
	for _, failure := range []string{"authenticated_secret", "event_read"} {
		t.Run(failure, func(t *testing.T) {
			ep := f.endpoint(t, f.orgID)
			eventID := f.event(t, f.orgID)
			eventBefore := f.eventSnapshot(t, eventID)
			canonical := f.eventBytes(t, eventID)
			row := f.enqueue(t, ep.id, eventID)
			claim := f.claim(t, row.ID)
			deps := f.w.webhookDeliveryDependencies()
			requestsBefore := len(f.requests())
			code := webhookEndpointUnavailable
			if failure == "authenticated_secret" {
				// Actual manager authentication fails under the original AAD; no
				// fallback signing key may turn this into an HTTP request.
				bad := append([]byte(nil), ep.ciphertext...)
				bad[len(bad)-1] ^= 1
				f.execOne(t, `UPDATE webhook_endpoints SET secret_ciphertext=$2 WHERE id=$1`, ep.id, bad)
			} else {
				code = webhookEventUnavailable
				load := deps.event
				reads := 0
				deps.event = func(ctx context.Context, id uuid.UUID) (dispatch.WebhookEvent, error) {
					reads++
					if reads == 1 {
						return dispatch.WebhookEvent{}, errors.New(webhookE2EPrivateMarker)
					}
					return load(ctx, id)
				}
			}
			before := time.Now()
			applied, err := processClaimedWebhookDelivery(f.ctx, claim, deps)
			webhookE2ECheck(t, err, "persist dependency failure retry")
			if !applied || len(f.requests()) != requestsBefore {
				t.Fatal("dependency failure dispatched or failed to persist retry")
			}
			retry := f.delivery(t, ep.id, row.ID)
			f.assertRetry(t, retry, 1, code, before, time.Now())
			f.assertRedacted(t, retry.ID)
			if failure == "authenticated_secret" {
				f.execOne(t, `UPDATE webhook_endpoints SET secret_ciphertext=$2 WHERE id=$1`, ep.id, ep.ciphertext)
			}
			f.makeDue(t, row.ID)
			fresh := f.claim(t, row.ID)
			applied, err = processClaimedWebhookDelivery(f.ctx, fresh, deps)
			webhookE2ECheck(t, err, "recover actual dependency and deliver")
			if !applied {
				t.Fatal("recovered dependency did not apply delivery")
			}
			delivered := f.delivery(t, ep.id, row.ID)
			if delivered.Status != "delivered" || delivered.Attempts != 2 || delivered.LastError.String != "" || delivered.LastStatusCode.Int32 != http.StatusNoContent {
				t.Fatal("recovery did not produce exact delivered state")
			}
			got := f.requests()
			if len(got) != requestsBefore+1 {
				t.Fatal("dependency recovery dispatched an unexpected number of requests")
			}
			f.assertWire(t, got[len(got)-1], canonical, ep.secret)
			if !bytes.Equal(eventBefore, f.eventSnapshot(t, eventID)) {
				t.Fatal("retry or recovery changed original audit bytes and hashes")
			}
			state := f.snapshot(t, delivered.ID)
			duplicate := f.enqueue(t, ep.id, eventID)
			if duplicate.ID != delivered.ID || !bytes.Equal(state, f.snapshot(t, delivered.ID)) {
				t.Fatal("idempotent enqueue replaced or revived delivered identity")
			}
		})
	}
	t.Run("provider_refusal_exhaustion_and_legacy_read_redaction", func(t *testing.T) {
		ep := f.endpoint(t, f.orgID)
		eventID := f.event(t, f.orgID)
		eventBefore := f.eventSnapshot(t, eventID)
		canonical := f.eventBytes(t, eventID)
		row := f.enqueue(t, ep.id, eventID)
		f.setResponse(http.StatusServiceUnavailable, webhookE2EPrivateMarker)
		defer f.setResponse(http.StatusNoContent, "")
		requestsBefore := len(f.requests())
		for prior := int32(0); prior < 7; prior++ {
			if prior > 0 {
				// Advance only this isolated delivery's due time, without real
				// sleeps or changing production backoff policy.
				f.makeDue(t, row.ID)
			}
			claim := f.claim(t, row.ID)
			before := time.Now()
			applied, err := processClaimedWebhookDelivery(f.ctx, claim, f.w.webhookDeliveryDependencies())
			webhookE2ECheck(t, err, "persist bounded provider failure")
			if !applied {
				t.Fatal("provider refusal did not apply fenced outcome")
			}
			current := f.delivery(t, ep.id, row.ID)
			if prior < 6 {
				f.assertRetry(t, current, prior+1, webhookHTTPRefused, before, time.Now())
			} else if current.Status != "failed" || current.Attempts != 7 || current.LastError.String != webhookHTTPRefused {
				t.Fatal("bounded retry exhaustion did not terminate at seven failures")
			}
			if !current.LastStatusCode.Valid || current.LastStatusCode.Int32 != http.StatusServiceUnavailable {
				t.Fatal("provider failure lost safe numeric HTTP status")
			}
			f.assertRedacted(t, row.ID)
		}
		requests := f.requests()
		if len(requests)-requestsBefore != 7 {
			t.Fatal("bounded refusal path did not send exactly seven attempts")
		}
		for _, request := range requests[requestsBefore:] {
			f.assertWire(t, request, canonical, ep.secret)
		}
		if !bytes.Equal(eventBefore, f.eventSnapshot(t, eventID)) {
			t.Fatal("HTTP retries changed original canonical event bytes or hashes")
		}
		_, err := f.w.queries.ClaimNextDueWebhookDelivery(f.ctx)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("exhausted delivery remained claimable")
		}
		// Historical rows remain intact. Assert the same read-time mapper
		// used by the delivery API hides old provider text; this is not a
		// browser/UI acceptance test and does not rewrite historical rows.
		f.execOne(t, `UPDATE webhook_deliveries SET last_error=$2 WHERE id=$1`, row.ID, webhookE2EPrivateMarker)
		historical := f.delivery(t, ep.id, row.ID)
		if historical.LastError.String != webhookE2EPrivateMarker || dispatch.SafeWebhookDiagnostic(historical.LastError.String) != "legacy_delivery_error" {
			t.Fatal("historical diagnostic was rewritten or not redacted on read")
		}
	})
}

func TestWebhookForeignEndpointEventRefusedE2E(t *testing.T) {
	f := setupWebhookDeliveryE2E(t)
	foreign, err := f.w.queries.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "foreign webhook isolation fixture", Plan: "pro"})
	webhookE2ECheck(t, err, "create foreign fixture organization")
	for _, mismatch := range []string{"authenticated_foreign_endpoint", "copied_foreign_ciphertext"} {
		t.Run(mismatch, func(t *testing.T) {
			foreignEndpoint := f.endpoint(t, foreign.ID)
			originalEvent := f.event(t, f.orgID)
			eventBefore := f.eventSnapshot(t, originalEvent)
			if mismatch == "copied_foreign_ciphertext" {
				originalEndpoint := f.endpoint(t, f.orgID)
				f.execOne(t, `UPDATE webhook_endpoints SET secret_ciphertext=$2 WHERE id=$1`, foreignEndpoint.id, originalEndpoint.ciphertext)
			}
			// Deliberately seed the cross-org outbox reference to test the
			// dispatch boundary even when an enqueue caller/DB is corrupt.
			row := f.enqueue(t, foreignEndpoint.id, originalEvent)
			claim := f.claim(t, row.ID)
			requestsBefore := len(f.requests())
			applied, err := processClaimedWebhookDelivery(f.ctx, claim, f.w.webhookDeliveryDependencies())
			webhookE2ECheck(t, err, "refuse foreign delivery at dispatch boundary")
			if !applied || len(f.requests()) != requestsBefore {
				t.Fatal("foreign endpoint/event or ciphertext dispatched a request")
			}
			current := f.delivery(t, foreignEndpoint.id, row.ID)
			if current.Attempts != 1 || current.LastStatusCode.Int32 != 0 {
				t.Fatal("foreign refusal persisted an unexpected attempt or HTTP status")
			}
			if mismatch == "authenticated_foreign_endpoint" {
				if current.Status != "failed" || current.LastError.String != webhookEventInvalid {
					t.Fatal("authenticated foreign org mismatch was not permanently refused")
				}
			} else if current.Status != "retrying" || current.LastError.String != webhookEndpointUnavailable {
				t.Fatal("copied ciphertext bypassed original endpoint AAD authentication")
			}
			f.assertRedacted(t, current.ID)
			if !bytes.Equal(eventBefore, f.eventSnapshot(t, originalEvent)) {
				t.Fatal("foreign refusal changed the original organization's event")
			}
		})
	}
}

const webhookE2EPrivateMarker = "synthetic-provider-private-response-and-error-DO-NOT-PERSIST"

type webhookE2ERequest struct {
	body      []byte
	signature string
	kind      string
}

type webhookE2EEndpoint struct {
	id         uuid.UUID
	secret     string
	ciphertext []byte
}

type webhookDeliveryE2EFixture struct {
	ctx    context.Context
	pool   *pgxpool.Pool
	w      *worker
	orgID  uuid.UUID
	keys   *webhooksecret.Keyring
	peer   *httptest.Server
	mu     sync.Mutex
	seen   []webhookE2ERequest
	status int
	body   string
}

func setupWebhookDeliveryE2E(t *testing.T) *webhookDeliveryE2EFixture {
	t.Helper()
	ctx, pool, w, orgID, _, _ := setupSoftDeletePurgeE2E(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 17)
	}
	keys, err := webhooksecret.NewKeyringHex(hex.EncodeToString(key), "")
	webhookE2ECheck(t, err, "create synthetic webhook encryption keyring")
	manager, err := webhooksecret.NewManager(pool, keys, "")
	webhookE2ECheck(t, err, "create actual webhook key manager")
	f := &webhookDeliveryE2EFixture{ctx: ctx, pool: pool, w: w, orgID: orgID, keys: keys, status: http.StatusNoContent}
	f.peer = httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		body, err := io.ReadAll(io.LimitReader(request.Body, 64*1024+1))
		if err != nil || len(body) > 64*1024 || request.Method != http.MethodPost {
			response.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.seen = append(f.seen, webhookE2ERequest{body: body, signature: request.Header.Get("X-Hash-Signature"), kind: request.Header.Get("X-Hash-Event")})
		status, responseBody := f.status, f.body
		f.mu.Unlock()
		response.WriteHeader(status)
		_, _ = io.WriteString(response, responseBody)
	}))
	t.Cleanup(f.peer.Close)
	w.webhookSecrets = manager
	w.dispatcher = dispatch.NewDispatcher(dispatch.SignaturePair{})
	w.dispatcher.AllowPrivate = true // Only the synthetic loopback test receiver.
	t.Cleanup(w.dispatcher.HTTP.CloseIdleConnections)
	return f
}

func (f *webhookDeliveryE2EFixture) endpoint(t *testing.T, orgID uuid.UUID) webhookE2EEndpoint {
	t.Helper()
	ep := webhookE2EEndpoint{id: uuid.New()}
	var err error
	ep.secret, err = webhooksecret.Mint()
	webhookE2ECheck(t, err, "mint synthetic endpoint signing secret")
	ep.ciphertext, err = f.keys.SealNew(orgID, ep.id, ep.secret)
	webhookE2ECheck(t, err, "seal synthetic endpoint under exact org and ID")
	_, err = f.w.queries.CreateWebhookEndpoint(f.ctx, generated.CreateWebhookEndpointParams{
		ID: ep.id, OrgID: orgID, Url: f.peer.URL, SecretRef: "synthetic-e2e", SecretCiphertext: ep.ciphertext,
		EventsSubscribed: []string{audit.KindDocumentCreated},
	})
	webhookE2ECheck(t, err, "persist encrypted synthetic endpoint")
	return ep
}

func (f *webhookDeliveryE2EFixture) event(t *testing.T, orgID uuid.UUID) uuid.UUID {
	t.Helper()
	id, err := audit.New(f.w.queries, f.pool).Log(f.ctx, audit.Entry{
		OrgID: orgID, Kind: audit.KindDocumentCreated,
		Payload: map[string]any{"source": "webhook-e2e", "correlation": uuid.NewString(), "number": 7, "nested": map[string]any{"b": false, "a": "synthetic"}},
	})
	webhookE2ECheck(t, err, "append actual canonical audit event")
	return id
}

func (f *webhookDeliveryE2EFixture) enqueue(t *testing.T, endpointID, eventID uuid.UUID) *generated.WebhookDelivery {
	t.Helper()
	row, err := f.w.queries.EnqueueWebhookDelivery(f.ctx, generated.EnqueueWebhookDeliveryParams{EndpointID: endpointID, EventID: eventID})
	webhookE2ECheck(t, err, "enqueue exact endpoint/event identity")
	return row
}

func (f *webhookDeliveryE2EFixture) claim(t *testing.T, want uuid.UUID) *generated.WebhookDelivery {
	t.Helper()
	var attempts int32
	webhookE2ECheck(t, f.pool.QueryRow(f.ctx, `SELECT attempts FROM webhook_deliveries WHERE id=$1`, want).Scan(&attempts), "read attempts before exact claim")
	before := f.clock(t)
	row, err := f.w.queries.ClaimNextDueWebhookDelivery(f.ctx)
	webhookE2ECheck(t, err, "claim next due delivery")
	if row.ID != want || row.Attempts != attempts {
		t.Fatal("next claim differed from exact due fixture identity or attempts")
	}
	f.assertLease(t, row, before, f.clock(t))
	return row
}

func (f *webhookDeliveryE2EFixture) assertLease(t *testing.T, row *generated.WebhookDelivery, before, after time.Time) {
	t.Helper()
	if row.Status != "retrying" || !row.NextAttemptAt.Valid || row.NextAttemptAt.InfinityModifier != pgtype.Finite || row.NextAttemptAt.Time.Before(before.Add(5*time.Minute)) || row.NextAttemptAt.Time.After(after.Add(5*time.Minute)) {
		t.Fatal("claim did not atomically return exact finite five-minute retry lease")
	}
}

func (f *webhookDeliveryE2EFixture) clock(t *testing.T) time.Time {
	t.Helper()
	var now time.Time
	webhookE2ECheck(t, f.pool.QueryRow(f.ctx, `SELECT clock_timestamp()`).Scan(&now), "read PostgreSQL clock")
	return now
}

func (f *webhookDeliveryE2EFixture) delivery(t *testing.T, endpointID, id uuid.UUID) *generated.WebhookDelivery {
	t.Helper()
	rows, err := f.w.queries.ListDeliveriesByEndpoint(f.ctx, generated.ListDeliveriesByEndpointParams{EndpointID: endpointID, Limit: 100})
	webhookE2ECheck(t, err, "read endpoint delivery history")
	for _, row := range rows {
		if row.ID == id {
			return row
		}
	}
	t.Fatal("delivery absent from exact endpoint history")
	return nil
}

func (f *webhookDeliveryE2EFixture) snapshot(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	var raw []byte
	webhookE2ECheck(t, f.pool.QueryRow(f.ctx, `SELECT to_jsonb(d) FROM webhook_deliveries d WHERE id=$1`, id).Scan(&raw), "snapshot whole durable delivery")
	return raw
}

func (f *webhookDeliveryE2EFixture) eventSnapshot(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	row, err := f.w.queries.GetEventByID(f.ctx, id)
	webhookE2ECheck(t, err, "read original event bytes and ledger hashes")
	raw, err := json.Marshal(row)
	webhookE2ECheck(t, err, "snapshot original event bytes and ledger hashes")
	return raw
}

func (f *webhookDeliveryE2EFixture) eventBytes(t *testing.T, id uuid.UUID) []byte {
	t.Helper()
	event, err := dispatch.LoadEvent(f.ctx, f.w.queries, id)
	webhookE2ECheck(t, err, "load actual outbound event")
	raw, err := json.Marshal(event)
	webhookE2ECheck(t, err, "encode exact outbound wire event")
	return raw
}

func (f *webhookDeliveryE2EFixture) assertWire(t *testing.T, got webhookE2ERequest, canonical []byte, secret string) {
	t.Helper()
	if !bytes.Equal(got.body, canonical) || got.kind != audit.KindDocumentCreated || !dispatch.Verify(dispatch.SignaturePair{Primary: secret}, got.body, got.signature) {
		t.Fatal("delivery changed canonical event bytes, event correlation or signature protocol")
	}
}

func (f *webhookDeliveryE2EFixture) assertAllMarksRefused(t *testing.T, claim *generated.WebhookDelivery, snapshot []byte) {
	t.Helper()
	for _, status := range []string{"delivered", "retrying", "failed"} {
		rows, err := f.w.webhookDeliveryDependencies().mark(f.ctx, claim, webhookE2EOutcome(status))
		webhookE2ECheck(t, err, "attempt stale fenced mark")
		if rows != 0 {
			t.Fatalf("stale %s mark affected %d rows", status, rows)
		}
		if snapshot != nil && !bytes.Equal(snapshot, f.snapshot(t, claim.ID)) {
			t.Fatal("refused claim mark changed durable delivery fields")
		}
	}
}

func webhookE2EOutcome(status string) webhookDeliveryOutcome {
	return webhookDeliveryOutcome{status: status, statusCode: 202, diagnostic: webhookHTTPRefused, nextAttemptAt: time.Now().Add(time.Hour)}
}

func (f *webhookDeliveryE2EFixture) assertRetry(t *testing.T, row *generated.WebhookDelivery, attempts int32, code string, before, after time.Time) {
	t.Helper()
	delay, ok := dispatch.Backoff(int(attempts - 1))
	if !ok || row.Status != "retrying" || row.Attempts != attempts || row.LastError.String != code || !row.NextAttemptAt.Valid || row.NextAttemptAt.Time.Before(before.Add(delay)) || row.NextAttemptAt.Time.After(after.Add(delay)) {
		t.Fatal("dependency/provider retry lost exact bounded backoff, attempt or diagnostic")
	}
}

func (f *webhookDeliveryE2EFixture) assertRedacted(t *testing.T, id uuid.UUID) {
	t.Helper()
	if bytes.Contains(f.snapshot(t, id), []byte(webhookE2EPrivateMarker)) {
		t.Fatal("provider/dependency private response was persisted in delivery")
	}
}

func (f *webhookDeliveryE2EFixture) makeDue(t *testing.T, id uuid.UUID) {
	t.Helper()
	f.execOne(t, `UPDATE webhook_deliveries SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE id=$1 AND status='retrying'`, id)
}

func (f *webhookDeliveryE2EFixture) execOne(t *testing.T, query string, args ...any) {
	t.Helper()
	tag, err := f.pool.Exec(f.ctx, query, args...)
	webhookE2ECheck(t, err, "apply scoped synthetic fixture mutation")
	if tag.RowsAffected() != 1 {
		t.Fatal("scoped synthetic fixture mutation did not affect exactly one row")
	}
}

func (f *webhookDeliveryE2EFixture) requests() []webhookE2ERequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]webhookE2ERequest(nil), f.seen...)
}

func (f *webhookDeliveryE2EFixture) setResponse(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func webhookE2ECheck(t *testing.T, err error, action string) {
	t.Helper()
	if err != nil {
		// Error values can contain connection URLs or encrypted key material.
		// Static stage + concrete error type suffices for fixture diagnosis.
		t.Fatalf("%s: error_type=%T", action, err)
	}
}
