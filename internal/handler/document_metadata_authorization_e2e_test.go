//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func documentMetadataArgumentsE2E(f lifecycleAuthorizationFixture, tool string) map[string]any {
	args := map[string]any{"document_id": f.doc.ID}
	if tool == "set_expiry" {
		args["expires_at"] = time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	} else {
		args["key"], args["value"] = "crm_deal", "metadata-fixture-deal"
	}
	return args
}

func submitDocumentMetadataE2E(f lifecycleAuthorizationFixture, ctx context.Context, tool, key string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{
		"name": tool, "arguments": documentMetadataArgumentsE2E(f, tool),
	}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func mintDocumentMetadataKeyE2E(t *testing.T, f lifecycleAuthorizationFixture, documentToken bool) (*auth.MintedKey, uuid.UUID) {
	t.Helper()
	mint, err := auth.MintAPIKey()
	if documentToken {
		mint, err = auth.MintDocumentAgentKey()
	}
	if err != nil {
		t.Fatal(err)
	}
	scopes := []string{"write:authoring", "write:workflow"}
	if documentToken {
		key, err := f.q.InsertDocAgentToken(f.ctx, generated.InsertDocAgentTokenParams{
			DocumentID: f.doc.ID, OrgID: f.org, Name: "Metadata fixture document key", Prefix: mint.Prefix, KeyHash: mint.Hash, Scopes: scopes,
			CreatedBy: pgtype.UUID{Bytes: f.user.ID, Valid: true}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true}, MaxUses: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return mint, key.ID
	}
	key, err := f.q.CreateAPIKey(f.ctx, generated.CreateAPIKeyParams{
		OrgID: f.org, UserID: f.user.ID, Name: "Metadata fixture organization key", KeyPrefix: mint.Prefix, KeyHash: mint.Hash, Scopes: scopes,
	})
	if err != nil {
		t.Fatal(err)
	}
	return mint, key.ID
}

func holdDocumentMetadataParentE2E(t *testing.T, f lifecycleAuthorizationFixture) pgx.Tx {
	t.Helper()
	tx, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err := f.q.WithTx(tx).GetDocumentForUpdate(f.ctx, generated.GetDocumentForUpdateParams{ID: f.doc.ID, OrgID: f.org}); err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestDocumentMetadataMCPOriginalCredentialAfterParentWaitE2E(t *testing.T) {
	for _, tool := range []string{"set_expiry", "attach_metadata"} {
		for _, change := range []string{"key-delete", "scope-reduction", "key-expiry", "token-revocation", "member-demotion"} {
			t.Run(tool+"/"+change, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "owner", false, false)
				f.enableMCP()
				owner := seedSessionOwnerE2E(t, f.ctx, f.q, f.org)
				mint, keyID := mintDocumentMetadataKeyE2E(t, f, change == "token-revocation")
				blocked := holdDocumentMetadataParentE2E(t, f)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitDocumentMetadataE2E(f, f.ctx, tool, mint.Plaintext) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: GetDocumentForUpdate", "transactionid")
				var err error
				switch change {
				case "key-delete":
					w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/api-keys/"+keyID.String(), "", dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour))
					if w.Code != http.StatusNoContent {
						t.Fatalf("actual metadata key deletion=%d %s", w.Code, w.Body.String())
					}
				case "scope-reduction":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET scopes=ARRAY['read']::text[] WHERE id=$1`, keyID) //nolint:rawsql -- synthetic post-admission revocation
				case "key-expiry":
					_, err = f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, keyID) //nolint:rawsql
				case "token-revocation":
					_, err = f.q.RevokeDocAgentToken(f.ctx, generated.RevokeDocAgentTokenParams{ID: keyID, OrgID: f.org})
				case "member-demotion":
					w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/members/"+f.user.ID.String()+"/role", `{"role":"viewer"}`, dsrSessionCookieE2E(t, f.s, owner, 0, time.Hour))
					if w.Code != http.StatusOK {
						t.Fatalf("actual metadata author demotion=%d %s", w.Code, w.Body.String())
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				before := recipientMCPSnapshotE2E(t, f)
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				want := auth.ErrMutationPermissionRevoked.Error()
				if change == "key-expiry" {
					want = auth.ErrMutationCredentialExpired.Error()
				}
				if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != want {
					t.Fatalf("metadata authorization refusal=%q want%q", got, want)
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
			})
		}
	}
}

func TestDocumentMetadataMCPAuditWaitRollsBackE2E(t *testing.T) {
	for _, tool := range []string{"set_expiry", "attach_metadata"} {
		for _, failure := range []string{"expiry", "cancellation"} {
			t.Run(tool+"/"+failure, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
				f.enableMCP()
				mint, keyID := mintDocumentMetadataKeyE2E(t, f, false)
				before := recipientMCPSnapshotE2E(t, f)
				blocked, err := f.pool.Begin(f.ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
					t.Fatal(err)
				}
				if failure == "expiry" {
					if _, err := f.pool.Exec(f.ctx, `UPDATE api_keys SET expires_at=clock_timestamp()+interval '1 second' WHERE id=$1`, keyID); err != nil { //nolint:rawsql -- natural expiry after final mutation, before commit
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithCancel(f.ctx)
				defer cancel()
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() { result <- submitDocumentMetadataE2E(f, ctx, tool, mint.Plaintext) }()
				awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
				if failure == "expiry" {
					deadline := time.Now().Add(3 * time.Second)
					expired := false
					for time.Now().Before(deadline) && !expired {
						if err := f.pool.QueryRow(f.ctx, `SELECT expires_at<=clock_timestamp() FROM api_keys WHERE id=$1`, keyID).Scan(&expired); err != nil { //nolint:rawsql
							t.Fatal(err)
						}
						if !expired {
							time.Sleep(10 * time.Millisecond)
						}
					}
					if !expired {
						t.Fatal("metadata fixture API credential did not expire")
					}
				} else {
					cancel()
					fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true)
				}
				if err := blocked.Commit(f.ctx); err != nil {
					t.Fatal(err)
				}
				if failure == "expiry" {
					if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationCredentialExpired.Error() {
						t.Fatalf("final metadata credential recheck=%q", got)
					}
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
				fresh, _ := mintDocumentMetadataKeyE2E(t, f, false)
				fieldMCPTextE2E(t, submitDocumentMetadataE2E(f, f.ctx, tool, fresh.Plaintext), false)
			})
		}
	}
}

func TestDocumentMetadataMCPPreservesEvidenceAndPrivacyE2E(t *testing.T) {
	for _, tool := range []string{"set_expiry", "attach_metadata"} {
		for _, protected := range []string{"filled-field", "signature", "final-artifact", "linked-privacy", "global-privacy", "sent"} {
			t.Run(tool+"/"+protected, func(t *testing.T) {
				f := setupLifecycleAuthorizationE2E(t, "sender", protected == "sent", false)
				f.enableMCP()
				mint, _ := mintDocumentMetadataKeyE2E(t, f, false)
				want := authoring.ErrDocumentHasEvidence.Error()
				var err error
				switch protected {
				case "filled-field":
					seedRecipientMCPFieldE2E(t, f)
					_, err = f.pool.Exec(f.ctx, `UPDATE document_fields SET value='retained fixture value' WHERE document_id=$1`, f.doc.ID) //nolint:rawsql -- intentional legacy draft evidence
				case "signature":
					_, err = f.pool.Exec(f.ctx, `UPDATE recipients SET signed_at=clock_timestamp() WHERE id=$1`, f.recipient.ID) //nolint:rawsql
				case "final-artifact":
					_, err = f.pool.Exec(f.ctx, `UPDATE documents SET final_pdf_key='fixture/final.pdf',final_pdf_version_id='fixture-final-v1',final_pdf_sha=decode(repeat('01',32),'hex') WHERE id=$1`, f.doc.ID) //nolint:rawsql -- pinned synthetic anomalous draft
				case "linked-privacy", "global-privacy":
					input := generated.CreateDataSubjectRequestParams{OrgID: f.org, SubjectEmail: f.recipient.Email, Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)}
					if protected == "linked-privacy" {
						input.DocumentID = pgtype.UUID{Bytes: f.doc.ID, Valid: true}
					}
					_, err = f.q.CreateDataSubjectRequest(f.ctx, input)
					want = authoring.ErrPendingPrivacyReview.Error()
				case "sent":
					want = authoring.ErrDocumentNotDraft.Error()
				}
				if err != nil {
					t.Fatal(err)
				}
				before := recipientMCPSnapshotE2E(t, f)
				if got := fieldMCPTextE2E(t, submitDocumentMetadataE2E(f, f.ctx, tool, mint.Plaintext), true); got != want {
					t.Fatalf("protected metadata refusal=%q want%q", got, want)
				}
				assertRecipientMCPUnchangedE2E(t, f, before)
			})
		}
	}
}

func TestDocumentSoftDeleteCancellationDuringAuditWaitRollsBackE2E(t *testing.T) {
	f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
	before := recipientMCPSnapshotE2E(t, f)
	blocked, err := f.pool.Begin(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback(context.Background())
	if err := f.q.WithTx(blocked).AcquireOrgChainLock(f.ctx, f.org.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(f.ctx)
	defer cancel()
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := httptest.NewRequest(http.MethodDelete, f.s.PublicURL+"/api/v1/documents/"+f.doc.ID.String(), nil).WithContext(ctx)
		r.Header.Set("Origin", f.s.PublicURL)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
		w := httptest.NewRecorder()
		f.s.Routes().ServeHTTP(w, r)
		result <- w
	}()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, "-- name: AcquireOrgChainLock", "advisory")
	cancel()
	if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusInternalServerError {
		t.Fatalf("canceled document deletion=%d %s", w.Code, w.Body.String())
	}
	if err := blocked.Commit(f.ctx); err != nil {
		t.Fatal(err)
	}
	assertRecipientMCPUnchangedE2E(t, f, before)
	if w := submitDocumentDelete(t, f.s, f.doc.ID, cookie); w.Code != http.StatusNoContent {
		t.Fatalf("healthy retry after canceled deletion=%d %s", w.Code, w.Body.String())
	}
}

func TestDocumentMetadataMCPOneUseCommitE2E(t *testing.T) {
	for _, tool := range []string{"set_expiry", "attach_metadata"} {
		t.Run(tool, func(t *testing.T) {
			f := setupLifecycleAuthorizationE2E(t, "sender", false, false)
			f.enableMCP()
			mint, _ := mintDocumentMetadataKeyE2E(t, f, true)
			fieldMCPTextE2E(t, submitDocumentMetadataE2E(f, f.ctx, tool, mint.Plaintext), false)
			fresh, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			if tool == "set_expiry" {
				if !fresh.ExpiresAt.Valid || !fresh.ExpiresAt.Time.After(time.Now()) {
					t.Fatal("authorized expiry mutation did not commit")
				}
			} else {
				var metadata map[string]any
				if json.Unmarshal(fresh.Metadata, &metadata) != nil || metadata["crm_deal"] != "metadata-fixture-deal" {
					t.Fatal("authorized metadata mutation did not commit")
				}
			}
			var total, matching int
			if err := f.pool.QueryRow(f.ctx, `SELECT count(*),count(*) FILTER (WHERE kind=$2 AND actor_user_id=$3 AND payload_json->>'via'='mcp' AND payload_json->>'tool'=$4) FROM events WHERE document_id=$1`, f.doc.ID, audit.KindDocumentUpdated, f.user.ID, tool).Scan(&total, &matching); err != nil { //nolint:rawsql -- exact authorized audit provenance
				t.Fatal(err)
			}
			if total != 1 || matching != 1 {
				t.Fatalf("metadata audit total/matching=%d/%d", total, matching)
			}
			key, err := f.q.GetDocAgentTokenByPrefix(f.ctx, mint.Prefix)
			if err != nil || key.UsedCount != 1 || !key.LastUsedAt.Valid {
				t.Fatal("metadata authorization consumed its admitted token more than once")
			}
			before := recipientMCPSnapshotE2E(t, f)
			if w := submitDocumentMetadataE2E(f, f.ctx, tool, mint.Plaintext); w.Code != http.StatusUnauthorized {
				t.Fatalf("exhausted metadata token=%d %s", w.Code, w.Body.String())
			}
			assertRecipientMCPUnchangedE2E(t, f, before)
		})
	}
}
