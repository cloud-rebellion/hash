//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// These cases use actual PostgreSQL, signed-session middleware and the normal
// protected CRM, creation and closure paths. The renderer/S3/CRM peers are
// synthetic; owner approval requires the source-built isolated PDF worker.
// Dropping a successful response models delivery loss, not an ambiguous DB
// COMMIT. No fixture manufactures a successful authorization or terminal GET.
func htmlClosurePathE2E(template, request uuid.UUID) string {
	return "/api/v1/templates/" + template.String() + "/html/document-requests/" + request.String()
}

func htmlClosureBodyE2E(org, user uuid.UUID) string {
	return fmt.Sprintf(`{"expected_org_id":%q,"expected_user_id":%q,"confirmed":true}`, org.String(), user.String())
}

func htmlClosureSubmitE2E(f crmTemplateCreationFixtureE2E, template, request uuid.UUID, cookie string) *httptest.ResponseRecorder {
	return submitSessionOperationE2E(f.s, http.MethodPost, htmlClosurePathE2E(template, request)+"/close", htmlClosureBodyE2E(f.org, f.user.ID), cookie)
}

func htmlClosureInventoryE2E(t *testing.T, f crmTemplateCreationFixtureE2E) string {
	t.Helper()
	var outcomes string
	if err := f.pool.QueryRow(f.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY actor_user_id,request_id),'[]'::jsonb)::text FROM html_document_creation_resolutions r WHERE org_id=$1`, f.org).Scan(&outcomes); err != nil {
		t.Fatal("read exact fixture terminal outcome inventory")
	} //nolint:rawsql -- disposable tenant only, raw inventory never emitted
	return f.inventory(t) + outcomes
}

func htmlClosureUnchangedE2E(t *testing.T, f crmTemplateCreationFixtureE2E, before string) {
	t.Helper()
	if htmlClosureInventoryE2E(t, f) != before {
		t.Fatal("refused/read-only closure changed terminal outcome, receipt, document, source, fields, review, audit or outbox")
	}
}

func htmlClosureStatusE2E(t *testing.T, w *httptest.ResponseRecorder, status int) {
	t.Helper()
	if w.Code != status || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("closure/readback status=%d want=%d or missing no-store", w.Code, status)
	}
	for _, secret := range []string{crmConnectionTokenE2E, crmConnectionKeyE2E, "credential_ciphertext", "fixture private", "Bearer "} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("closure/readback disclosed private diagnostics or credentials")
		}
	}
}

type htmlClosedOutcomeE2E struct {
	State      string    `json:"state"`
	OrgID      uuid.UUID `json:"org_id"`
	UserID     uuid.UUID `json:"user_id"`
	TemplateID uuid.UUID `json:"template_id"`
	RequestID  uuid.UUID `json:"request_id"`
	ClosedAt   string    `json:"closed_at"`
}

func htmlClosureDecodeE2E(t *testing.T, f crmTemplateCreationFixtureE2E, request uuid.UUID, w *httptest.ResponseRecorder) htmlClosedOutcomeE2E {
	t.Helper()
	htmlClosureStatusE2E(t, w, http.StatusOK)
	var out htmlClosedOutcomeE2E
	var keys map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || json.Unmarshal(w.Body.Bytes(), &keys) != nil || len(keys) != 6 ||
		out.State != "closed" || out.OrgID != f.org || out.UserID != f.user.ID || out.TemplateID != f.template.ID || out.RequestID != request {
		t.Fatal("closed response lost exact original actor/template/request witness")
	}
	for _, key := range []string{"state", "org_id", "user_id", "template_id", "request_id", "closed_at"} {
		if _, ok := keys[key]; !ok {
			t.Fatal("closed response key set changed")
		}
	}
	stamp, err := time.Parse(time.RFC3339Nano, out.ClosedAt)
	row, rowErr := f.q.GetHTMLDocumentCreationResolutionForShare(f.ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: request})
	if err != nil || stamp.IsZero() || stamp.After(time.Now()) || rowErr != nil || row.State != "closed" || row.TemplateID != f.template.ID || !row.ResolvedAt.Time.Equal(stamp) {
		t.Fatal("closed response is not the exact durable database outcome")
	}
	var receipts, events int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3), (SELECT count(*) FROM events WHERE org_id=$1 AND actor_user_id=$2 AND kind='html.document.creation.closed' AND payload_json->>'request_id'=$3::text)`, f.org, f.user.ID, request).Scan(&receipts, &events); err != nil || receipts != 0 || events != 1 {
		t.Fatal("closed outcome has a creation receipt or missing/duplicate original-actor closure audit")
	} //nolint:rawsql -- exact durable nonce/cardinality
	return out
}

func htmlClosureAssertNoIOE2E(t *testing.T, f crmTemplateCreationFixtureE2E, accounts, records, storageCalls int64, renders int) {
	t.Helper()
	if f.source.accounts.Load() != accounts || f.source.deals.Load() != records || f.storage.requests.Load() != storageCalls || len(f.renderer.sources()) != renders {
		t.Fatal("closure, terminal readback or retired retry invoked provider, renderer or storage")
	}
}

func TestHTMLCreationClosureRetiresNonceAndAllowsExplicitFreshRequestE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	in, _ := f.command(t)
	accounts, records, calls, renders := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load(), len(f.renderer.sources())
	// Closure survives unavailable account keys/client and does not need the
	// short-lived semantic command lost on reload.
	client, keys := f.s.CRMClient, f.s.CRMKeys
	f.s.CRMClient, f.s.CRMKeys = nil, nil
	closed := htmlClosureDecodeE2E(t, f, in.RequestID, htmlClosureSubmitE2E(f, f.template.ID, in.RequestID, f.cookie))
	before := htmlClosureInventoryE2E(t, f)
	if repeat := htmlClosureDecodeE2E(t, f, in.RequestID, htmlClosureSubmitE2E(f, f.template.ID, in.RequestID, f.cookie)); repeat != closed {
		t.Fatal("idempotent closure rewrote its terminal timestamp")
	}
	if inspected := htmlClosureDecodeE2E(t, f, in.RequestID, f.recovery(t, in.RequestID, f.cookie)); inspected != closed {
		t.Fatal("reloaded inspection did not retain exact closed outcome")
	}
	htmlClosureUnchangedE2E(t, f, before)
	htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
	f.s.CRMClient, f.s.CRMKeys = client, keys
	// An actually expired purpose token cannot make a retired nonce reusable.
	raw, err := f.s.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, in.CRMPopulation.ReviewReceipt)
	var receipt crmTemplateReceipt
	if err != nil || json.Unmarshal(raw, &receipt) != nil {
		t.Fatal("read original synthetic confirmation receipt")
	}
	receipt.IssuedAt, receipt.ObservedAt = time.Now().Add(-2*resolver.CRMObservationMaxAge), time.Now().Add(-2*resolver.CRMObservationMaxAge)
	receipt.ExpiresAt = receipt.ObservedAt.Add(resolver.CRMObservationMaxAge)
	raw, _ = json.Marshal(receipt)
	in.CRMPopulation.ReviewReceipt, err = f.s.Cookies.MintPurpose(crmTemplateReceiptPurpose, raw, time.Nanosecond)
	_, expired := f.s.Cookies.VerifyPurpose(crmTemplateReceiptPurpose, in.CRMPopulation.ReviewReceipt)
	if err != nil || expired == nil || receipt.validate(time.Now()) == nil {
		t.Fatal("original confirmation fixture is not expired")
	}
	if w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie); w.Code != http.StatusConflict {
		t.Fatalf("retired nonce retry status=%d want409", w.Code)
	}
	htmlClosureUnchangedE2E(t, f, before)
	htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
	fresh, _ := f.command(t)
	if fresh.RequestID == in.RequestID {
		t.Fatal("explicit fresh command reused a retired nonce")
	}
	out := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, fresh, f.cookie), http.StatusCreated)
	if out.Replayed || out.Document == nil || out.RequestID != fresh.RequestID || out.OrgID != f.org || out.UserID != f.user.ID {
		t.Fatal("fresh confirmation/new nonce did not create one actor-bound draft")
	}
	if row, err := f.q.GetHTMLDocumentCreationResolutionForShare(f.ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: fresh.RequestID}); err != nil || row.State != "committed" {
		t.Fatal("fresh creation did not atomically claim committed outcome")
	}
	htmlClosureDecodeE2E(t, f, in.RequestID, f.recovery(t, in.RequestID, f.cookie))
	assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 0, 1)
}

func TestHTMLCreationClosureWinsBeforeOriginalFinalCommitE2E(t *testing.T) {
	for _, stage := range []string{"renderer_nil_billing", "stored_source"} {
		t.Run(stage, func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			in, _ := f.command(t)
			release := make(chan struct{})
			entered := make(chan struct{}, 1)
			var once sync.Once
			finish := func() { once.Do(func() { close(release) }) }
			defer finish()
			t.Cleanup(finish)
			if stage == "renderer_nil_billing" {
				f.renderer.entered, f.renderer.release = entered, release
			} else {
				// Hold the actual PUT response after storing its exact version.
				// No author/document/quota lock may be held during this wait.
				peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					buffer := httptest.NewRecorder()
					f.storage.ServeHTTP(buffer, r)
					if r.Method == http.MethodPut {
						entered <- struct{}{}
						select {
						case <-release:
						case <-r.Context().Done():
							return
						}
					}
					for key, values := range buffer.Header() {
						w.Header()[key] = append([]string(nil), values...)
					}
					w.WriteHeader(buffer.Code)
					_, _ = w.Write(buffer.Body.Bytes())
				}))
				t.Cleanup(peer.Close)
				var err error
				f.s.Storage, err = storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(peer.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-closure-access", SecretKey: "synthetic-closure-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
				if err != nil {
					t.Fatal("configure versioned source wait peer")
				}
			}
			done := make(chan error, 1)
			if stage == "renderer_nil_billing" {
				actor, admission := f.admission(t, in)
				inputDigest, err := crmTemplateCreateInputDigest(actor, f.template.ID, in)
				if err != nil {
					t.Fatal("digest original admitted command")
				}
				digest, _ := hex.DecodeString(in.ExpectedTemplateContentSHA256)
				f.s.Billing = nil
				go func() {
					_, err := f.s.instantiateHTMLDocument(f.ctx, actor, f.template.ID, in, digest, generated.Document{}.ExpiresAt, admission, inputDigest)
					done <- err
				}()
			} else {
				go func() {
					w := submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie)
					if w.Code != http.StatusConflict {
						done <- errors.New("held original creation was not refused with409")
						return
					}
					done <- errHTMLCreationRequestClosed
				}()
			}
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("original creation did not reach external source wait")
			}
			accounts, records, calls, renders := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load(), len(f.renderer.sources())
			htmlClosureDecodeE2E(t, f, in.RequestID, htmlClosureSubmitE2E(f, f.template.ID, in.RequestID, f.cookie))
			htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
			before := htmlClosureInventoryE2E(t, f)
			finish()
			select {
			case err := <-done:
				if !errors.Is(err, errHTMLCreationRequestClosed) {
					t.Fatal("original admitted creation crossed committed closure")
				}
			case <-time.After(4 * time.Second):
				t.Fatal("retired original creation did not finish")
			}
			htmlClosureUnchangedE2E(t, f, before)
			assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 1, 0)
		})
	}
}

func TestHTMLCreationCommitWinsAndCloserReturnsOriginalPinsE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	in, _ := f.command(t)
	blocked := ownerOrgLockE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, true)
	created := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		created <- submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie)
	}()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	closed := make(chan *httptest.ResponseRecorder, 1)
	go func() { closed <- htmlClosureSubmitE2E(f, f.template.ID, in.RequestID, f.cookie) }()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: LockBillingUsageForOrg", "advisory")
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal("release creation audit lock")
	}
	out := decodeCRMTemplateCreationE2E(t, receiveSessionOperationE2E(t, created), http.StatusCreated)
	w := receiveSessionOperationE2E(t, closed)
	htmlClosureStatusE2E(t, w, http.StatusOK)
	var readback struct {
		State       string            `json:"state"`
		OrgID       uuid.UUID         `json:"org_id"`
		UserID      uuid.UUID         `json:"user_id"`
		RequestID   uuid.UUID         `json:"request_id"`
		TemplateID  uuid.UUID         `json:"template_id"`
		InputDigest string            `json:"input_digest"`
		Document    *documentResponse `json:"document"`
		Creation    htmlCreationPins  `json:"creation"`
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &readback) != nil || json.Unmarshal(w.Body.Bytes(), &keys) != nil || len(keys) != 8 || readback.State != "committed" || readback.OrgID != f.org || readback.UserID != f.user.ID || readback.TemplateID != f.template.ID || readback.RequestID != in.RequestID || readback.InputDigest != out.InputDigest || readback.Creation != out.Creation || readback.Document == nil || out.Document == nil || readback.Document.ID != out.Document.ID {
		t.Fatal("closer did not return the already committed original creation evidence")
	}
	before := htmlClosureInventoryE2E(t, f)
	accounts, records, calls, renders := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load(), len(f.renderer.sources())
	if repeated := htmlClosureSubmitE2E(f, f.template.ID, in.RequestID, f.cookie); repeated.Code != http.StatusOK || repeated.Body.String() != w.Body.String() {
		t.Fatal("repeat close changed committed result")
	}
	htmlClosureUnchangedE2E(t, f, before)
	htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
	var receipts, outcomes, createdEvents, populationEvents, closureEvents int
	if err := f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3),(SELECT count(*) FROM html_document_creation_resolutions WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3 AND state='committed'),(SELECT count(*) FROM events WHERE document_id=$4 AND kind='document.created'),(SELECT count(*) FROM events WHERE document_id=$4 AND kind='crm.template.population.created'),(SELECT count(*) FROM events WHERE org_id=$1 AND kind='html.document.creation.closed')`, f.org, f.user.ID, in.RequestID, out.Document.ID).Scan(&receipts, &outcomes, &createdEvents, &populationEvents, &closureEvents); err != nil || receipts != 1 || outcomes != 1 || createdEvents != 1 || populationEvents != 1 || closureEvents != 0 {
		t.Fatal("creation winner acquired duplicate/missing terminal, document or audit evidence")
	} //nolint:rawsql -- exact nonce/cardinality
	assertImportStorageE2E(t, f.storage.importStoragePeer, 1, 0, 1)
}

func TestHTMLCreationClosureRechecksOriginalCredentialAfterWaitE2E(t *testing.T) {
	for _, change := range []string{"quota_demotion", "quota_session_rotation", "quota_expiry", "audit_expiry"} {
		t.Run(change, func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			request := uuid.New()
			ttl := time.Hour
			if strings.HasSuffix(change, "expiry") {
				ttl = time.Second
			}
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, ttl)
			blocked, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal("begin original credential wait")
			}
			defer func() { _ = blocked.Rollback(context.Background()) }()
			query := "-- name: LockBillingUsageForOrg"
			if change == "audit_expiry" {
				err = f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String())
				query = "-- name: AcquireOrgChainLock"
			} else {
				err = f.q.WithTx(blocked).LockBillingUsageForOrg(f.ctx, f.org.String())
			}
			if err != nil {
				t.Fatal("hold actual transaction lock")
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- htmlClosureSubmitE2E(f, f.template.ID, request, cookie) }()
			awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, "advisory")
			switch change {
			case "quota_demotion":
				_, err = f.q.UpdateUserRole(f.ctx, generated.UpdateUserRoleParams{ID: f.user.ID, OrgID: f.org, Role: "viewer"})
			case "quota_session_rotation":
				_, err = f.q.RevokeUserSessions(f.ctx, generated.RevokeUserSessionsParams{ID: f.user.ID, OrgID: f.org, SessionGeneration: f.user.SessionGeneration})
			default:
				awaitSessionCookieExpiryE2E(t, f.s, cookie)
			}
			if err != nil {
				t.Fatal("change original admission during actual wait")
			}
			before := htmlClosureInventoryE2E(t, f)
			if err = blocked.Commit(f.ctx); err != nil {
				t.Fatal("release original credential wait")
			}
			want := http.StatusForbidden
			if strings.HasSuffix(change, "expiry") {
				want = http.StatusUnauthorized
			}
			htmlClosureStatusE2E(t, receiveSessionOperationE2E(t, done), want)
			htmlClosureUnchangedE2E(t, f, before)
			assertImportStorageE2E(t, f.storage.importStoragePeer, 0, 0, 0)
		})
	}
}

func TestHTMLCreationClosureScopeStrictInputAndAuditRollbackE2E(t *testing.T) {
	t.Run("actor_template_and_strict_body", func(t *testing.T) {
		f := setupCRMTemplateCreationE2E(t)
		request := uuid.New()
		htmlClosureDecodeE2E(t, f, request, htmlClosureSubmitE2E(f, f.template.ID, request, f.cookie))
		before := htmlClosureInventoryE2E(t, f)
		accounts, records, calls, renders := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load(), len(f.renderer.sources())
		otherID := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
		other, err := f.q.GetUser(f.ctx, otherID)
		if err != nil {
			t.Fatal("read separate same-org owner")
		}
		otherCookie := dsrSessionCookieE2E(t, f.s, other.ID, other.SessionGeneration, time.Hour)
		// Establish the intentional extra member before the no-effects inventory.
		before = htmlClosureInventoryE2E(t, f)
		if w := htmlClosureSubmitE2E(f, f.template.ID, request, otherCookie); w.Code != http.StatusConflict {
			t.Fatal("another actor could adopt the original pending pair")
		}
		if w := f.recovery(t, request, otherCookie); w.Code != http.StatusNotFound {
			t.Fatal("another owner could inspect original actor closure")
		}
		foreignOrg, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Foreign closure fixture", Plan: "pro"})
		if err != nil {
			t.Fatal("create separate synthetic tenant")
		}
		foreignUser, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@closure.test", Name: "Foreign closure owner", Role: "owner"})
		if err != nil {
			t.Fatal("create separate authenticated foreign owner")
		}
		foreignCookie := dsrSessionCookieE2E(t, f.s, foreignUser.ID, foreignUser.SessionGeneration, time.Hour)
		if w := htmlClosureSubmitE2E(f, f.template.ID, request, foreignCookie); w.Code != http.StatusConflict {
			t.Fatal("foreign session could adopt original actor closure")
		}
		if w := f.recovery(t, request, foreignCookie); w.Code != http.StatusNotFound {
			t.Fatal("foreign actor could inspect original closure")
		}
		htmlClosureStatusE2E(t, htmlClosureSubmitE2E(f, uuid.New(), request, f.cookie), http.StatusNotFound)
		for _, body := range []string{
			`{"expected_org_id":"` + f.org.String() + `","expected_user_id":"` + f.user.ID.String() + `","confirmed":false}`,
			`{"expected_org_id":"` + f.org.String() + `","expected_user_id":"` + f.user.ID.String() + `","confirmed":null}`,
			`{"expected_org_id":"` + f.org.String() + `","expected_user_id":"` + f.user.ID.String() + `","confirmed":true,"Confirmed":true}`,
			`{"expected_org_id":"` + f.org.String() + `","expected_user_id":"` + f.user.ID.String() + `","confirmed":true,"confirmed":true}`,
		} {
			w := submitSessionOperationE2E(f.s, http.MethodPost, htmlClosurePathE2E(f.template.ID, uuid.New())+"/close", body, f.cookie)
			htmlClosureStatusE2E(t, w, http.StatusBadRequest)
		}
		htmlClosureUnchangedE2E(t, f, before)
		htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
	})
	for _, noRow := range []bool{false, true} {
		t.Run(fmt.Sprintf("audit_no_row_%t", noRow), func(t *testing.T) {
			f := setupCRMTemplateCreationE2E(t)
			request := uuid.New()
			before := htmlClosureInventoryE2E(t, f)
			accounts, records, calls, renders := f.source.accounts.Load(), f.source.deals.Load(), f.storage.requests.Load(), len(f.renderer.sources())
			drop := ownerOrgAuditFaultE2E(t, ownerOrgMutationFixture{lifecycleAuthorizationFixture: f.lifecycleAuthorizationFixture}, noRow)
			htmlClosureStatusE2E(t, htmlClosureSubmitE2E(f, f.template.ID, request, f.cookie), http.StatusInternalServerError)
			htmlClosureUnchangedE2E(t, f, before)
			htmlClosureStatusE2E(t, f.recovery(t, request, f.cookie), http.StatusNotFound)
			drop()
			// Discard the successful response body entirely; an actual GET must
			// discover its committed closure, without another mutation or UUID.
			w := htmlClosureSubmitE2E(f, f.template.ID, request, f.cookie)
			if w.Code != http.StatusOK {
				t.Fatal("corrected closure did not commit")
			}
			before = htmlClosureInventoryE2E(t, f)
			htmlClosureDecodeE2E(t, f, request, f.recovery(t, request, f.cookie))
			htmlClosureUnchangedE2E(t, f, before)
			htmlClosureAssertNoIOE2E(t, f, accounts, records, calls, renders)
		})
	}
}

func TestHTMLCreationClosureDatabaseTerminalGuardsE2E(t *testing.T) {
	f := setupCRMTemplateCreationE2E(t)
	in, _ := f.command(t)
	out := decodeCRMTemplateCreationE2E(t, submitHTMLDocumentCreationE2E(t, f.lifecycleAuthorizationFixture, f.template.ID, in, f.cookie), http.StatusCreated)
	closed := uuid.New()
	htmlClosureDecodeE2E(t, f, closed, htmlClosureSubmitE2E(f, f.template.ID, closed, f.cookie))
	before := htmlClosureInventoryE2E(t, f)
	for _, mutation := range []struct{ name, sql string }{
		{"terminal_state_rewrite", `UPDATE html_document_creation_resolutions SET state='committed' WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"terminal_timestamp_rewrite", `UPDATE html_document_creation_resolutions SET resolved_at=resolved_at+interval '1 second' WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"terminal_identity_rewrite", `UPDATE html_document_creation_resolutions SET request_id=gen_random_uuid() WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"terminal_delete", `DELETE FROM html_document_creation_resolutions WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`},
		{"orphan_committed", `INSERT INTO html_document_creation_resolutions(org_id,actor_user_id,request_id,template_id,state) VALUES($1,$2,gen_random_uuid(),$3,'committed')`},
		{"closed_receipt_resurrection", `INSERT INTO html_document_creation_requests(org_id,actor_user_id,request_id,input_digest,template_id,original_document_id,current_document_id,html_materialization_id,html_source_commitment,pdf_sha256,page_count,created_at) SELECT org_id,actor_user_id,$3,input_digest,template_id,original_document_id,current_document_id,html_materialization_id,html_source_commitment,pdf_sha256,page_count,created_at FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$4`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			tx, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal("begin exact database corruption attempt")
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			// Parameter arity is exact; PostgreSQL must reach the intended guard.
			args := []any{f.org, f.user.ID, closed}
			if mutation.name == "orphan_committed" {
				args = []any{f.org, f.user.ID, f.template.ID}
			}
			if mutation.name == "closed_receipt_resurrection" {
				args = append(args, in.RequestID)
			}
			_, err = tx.Exec(f.ctx, mutation.sql, args...) //nolint:rawsql -- exact disposable-row adversarial SQL
			if err == nil {
				err = tx.Commit(f.ctx)
			}
			var pgerr *pgconn.PgError
			if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
				t.Fatal("terminal mutation did not reach explicit23514 invariant")
			}
			_ = tx.Rollback(f.ctx)
			htmlClosureUnchangedE2E(t, f, before)
		})
	}
	for _, iso := range []pgx.TxIsoLevel{pgx.ReadCommitted, pgx.RepeatableRead} {
		t.Run("old_snapshot_"+string(iso), func(t *testing.T) {
			request := uuid.New()
			stale, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: iso})
			if err != nil {
				t.Fatal("begin stale claimant")
			}
			defer func() { _ = stale.Rollback(context.Background()) }()
			var absent int
			if err = stale.QueryRow(f.ctx, `SELECT count(*) FROM html_document_creation_resolutions WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3`, f.org, f.user.ID, request).Scan(&absent); err != nil || absent != 0 {
				t.Fatal("stale claimant did not establish actual absent snapshot")
			} //nolint:rawsql
			winner, err := f.pool.Begin(f.ctx)
			if err != nil {
				t.Fatal("begin separate winning connection")
			}
			defer func() { _ = winner.Rollback(context.Background()) }()
			if _, err = generated.New(winner).InsertHTMLDocumentCreationClosure(f.ctx, generated.InsertHTMLDocumentCreationClosureParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: request, TemplateID: f.template.ID}); err != nil {
				t.Fatal("insert exact winning closure")
			}
			if err = winner.Commit(f.ctx); err != nil {
				t.Fatal("commit winning closure")
			}
			stable := htmlClosureInventoryE2E(t, f)
			_, err = generated.New(stale).InsertHTMLDocumentCreationClosure(f.ctx, generated.InsertHTMLDocumentCreationClosureParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: request, TemplateID: f.template.ID})
			if iso == pgx.ReadCommitted {
				if !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("RC loser did not retain winning unique outcome")
				}
				row, err := generated.New(stale).GetHTMLDocumentCreationResolutionForShare(f.ctx, generated.GetHTMLDocumentCreationResolutionForShareParams{OrgID: f.org, ActorUserID: f.user.ID, RequestID: request})
				if err != nil || row.State != "closed" {
					t.Fatal("RC loser cannot read exact winner")
				}
			} else {
				var pgerr *pgconn.PgError
				if !errors.As(err, &pgerr) || pgerr.Code != "40001" {
					t.Fatal("RR invisible unique winner did not fail with serialization refusal")
				}
			}
			_ = stale.Rollback(f.ctx)
			htmlClosureUnchangedE2E(t, f, stable)
		})
	}
	t.Run("retained_closed_down_refusal", func(t *testing.T) {
		raw, err := os.ReadFile("../db/migrations/00080_html_document_creation_resolutions.sql")
		if err != nil {
			t.Fatal("read exact migration80")
		}
		parts := strings.SplitN(string(raw), "-- +goose Down", 2)
		if len(parts) != 2 {
			t.Fatal("migration80 Down missing")
		}
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin isolated Down refusal")
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = tx.Exec(f.ctx, parts[1]) //nolint:rawsql -- exact own migration, never committed
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "P0001" {
			t.Fatal("retained closure did not reach explicit Down refusal")
		}
		_ = tx.Rollback(f.ctx)
	})
	t.Run("retained_history_refuses_delete_and_closed_metadata_cascades", func(t *testing.T) {
		// Approved HTML revisions/materializations deliberately require reviewed
		// retention disposal. Their existing protections must remain intact.
		retained := htmlClosureInventoryE2E(t, f)
		tx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin retained HTML history deletion refusal")
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		_, err = tx.Exec(f.ctx, `DELETE FROM orgs WHERE id=$1`, f.org) //nolint:rawsql -- reversible disposal refusal
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || (pgerr.Code != "23503" && pgerr.Code != "23514") {
			t.Fatal("retained HTML history did not reject unreviewed tenant disposal")
		}
		if err = tx.Rollback(f.ctx); err != nil {
			t.Fatal("restore retained HTML tenant after refused disposal")
		}
		htmlClosureUnchangedE2E(t, f, retained)

		// Test only closed metadata's organization cascade in a separate tenant
		// without approved template/materialization history. A committed79
		// receipt cannot be manufactured for an ordinary PDF: its insertion
		// guard requires exact registered HTML history. No guard is bypassed.
		org, err := f.q.CreateOrg(f.ctx, generated.CreateOrgParams{Name: "Closed metadata cascade control", Plan: "pro"})
		if err != nil {
			t.Fatal("create separate closed metadata tenant")
		}
		user, err := f.q.CreateUser(f.ctx, generated.CreateUserParams{OrgID: org.ID, Email: uuid.NewString() + "@closure-cascade.test", Name: "Closed metadata owner", Role: "owner"})
		if err != nil {
			t.Fatal("create separate closed metadata actor")
		}
		if _, err = f.q.CreatePDFDocument(f.ctx, generated.CreatePDFDocumentParams{OrgID: org.ID, SenderID: user.ID, Name: "Ordinary PDF database cascade control", PdfStorageKey: pgtype.Text{String: "synthetic-closed-cascade.pdf", Valid: true}, PdfSha256: make([]byte, 32)}); err != nil {
			t.Fatal("create ordinary PDF without retained HTML history")
		}
		if _, err = f.q.InsertHTMLDocumentCreationClosure(f.ctx, generated.InsertHTMLDocumentCreationClosureParams{OrgID: org.ID, ActorUserID: user.ID, RequestID: uuid.New(), TemplateID: uuid.New()}); err != nil {
			t.Fatal("insert genuine closed terminal metadata")
		}
		controlSnapshot := func() string {
			var raw string
			if err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_object(
				'org',(SELECT to_jsonb(o) FROM orgs o WHERE id=$1),
				'users',(SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY id),'[]'::jsonb) FROM users u WHERE org_id=$1),
				'documents',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY id),'[]'::jsonb) FROM documents d WHERE org_id=$1),
				'resolutions',(SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY actor_user_id,request_id),'[]'::jsonb) FROM html_document_creation_resolutions r WHERE org_id=$1))::text`, org.ID).Scan(&raw); err != nil {
				t.Fatal("read exact closed metadata control inventory")
			} //nolint:rawsql -- private disposable inventory, never emitted
			return raw
		}
		controlBefore := controlSnapshot()
		controlTx, err := f.pool.Begin(f.ctx)
		if err != nil {
			t.Fatal("begin reversible closed metadata cascade")
		}
		defer func() { _ = controlTx.Rollback(context.Background()) }()
		if _, err = controlTx.Exec(f.ctx, `DELETE FROM orgs WHERE id=$1`, org.ID); err != nil {
			t.Fatal("closed metadata obstructed ordinary tenant cascade")
		} //nolint:rawsql -- separate disposable tenant only
		if _, err = controlTx.Exec(f.ctx, `SET CONSTRAINTS ALL IMMEDIATE`); err != nil {
			t.Fatal("closed metadata cascade left deferred violations")
		} //nolint:rawsql
		var requests, resolutions, docs, users, orgs int
		if err = controlTx.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM html_document_creation_requests WHERE org_id=$1),(SELECT count(*) FROM html_document_creation_resolutions WHERE org_id=$1),(SELECT count(*) FROM documents WHERE org_id=$1),(SELECT count(*) FROM users WHERE org_id=$1),(SELECT count(*) FROM orgs WHERE id=$1)`, org.ID).Scan(&requests, &resolutions, &docs, &users, &orgs); err != nil || requests != 0 || resolutions != 0 || docs != 0 || users != 0 || orgs != 0 {
			t.Fatal("ordinary tenant cascade retained closed metadata or child rows")
		} //nolint:rawsql
		if err = controlTx.Rollback(f.ctx); err != nil {
			t.Fatal("restore disposable tenant after closed metadata cascade proof")
		}
		if controlSnapshot() != controlBefore {
			t.Fatal("reversible closed metadata cascade changed its exact original rows")
		}
		htmlClosureUnchangedE2E(t, f, retained)
		if _, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: out.Document.ID, OrgID: f.org}); err != nil {
			t.Fatal("closed metadata control changed original retained HTML document")
		}
	})
}
