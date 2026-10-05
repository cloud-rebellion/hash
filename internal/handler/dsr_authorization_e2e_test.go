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
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func dsrSessionCookieE2E(t *testing.T, s *Server, user uuid.UUID, generation int64, ttl time.Duration) string {
	t.Helper()
	payload, err := json.Marshal(auth.SessionPayload{UserID: user, Generation: generation})
	if err != nil {
		t.Fatal(err)
	}
	return s.Cookies.Mint(payload, ttl)
}

func submitSessionOperationE2E(s *Server, method, path, body, cookie string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, s.PublicURL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", s.PublicURL)
	req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	response := httptest.NewRecorder()
	s.Routes().ServeHTTP(response, req)
	return response
}

func awaitSessionOperationLockE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, query, event string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND query LIKE $1 AND wait_event=$2 AND state='active'`, "%"+query+"%", event).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("session operation did not reach %s %s lock", query, event)
}

func awaitSessionCookieExpiryE2E(t *testing.T, s *Server, cookie string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.Cookies.Verify(cookie); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("fixture session did not expire")
}

func receiveSessionOperationE2E(t *testing.T, result <-chan *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case response := <-result:
		return response
	case <-time.After(4 * time.Second):
		t.Fatal("session operation did not complete after lock release")
		return nil
	}
}

func seedSessionOwnerE2E(t *testing.T, ctx context.Context, q *generated.Queries, org uuid.UUID) uuid.UUID {
	t.Helper()
	user, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: org, Email: uuid.NewString() + "@session.test", Name: "Other owner", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	return user.ID
}

func assertDSRNotRedactedE2E(t *testing.T, ctx context.Context, pool *pgxpool.Pool, q *generated.Queries, request *generated.DataSubjectRequest, recipient *generated.Recipient) {
	t.Helper()
	fresh, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: request.ID, OrgID: request.OrgID})
	if err != nil || fresh.Status != request.Status || fresh.SubjectEmail != request.SubjectEmail || fresh.SubjectName != request.SubjectName || fresh.ResolutionNote != request.ResolutionNote || fresh.FulfilledBy.Valid {
		t.Fatalf("DSR escaped authorization refusal: request=%+v err=%v", fresh, err)
	}
	person, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: request.OrgID})
	if err != nil || person.Email != recipient.Email || person.Name != recipient.Name {
		t.Fatalf("recipient escaped authorization refusal: recipient=%+v err=%v", person, err)
	}
	var signatures, terminalEvents int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM signatures WHERE recipient_id=$1 AND typed_name=$2`, recipient.ID, AnonymizationMarker).Scan(&signatures); err != nil || signatures != 0 {
		t.Fatalf("signature redaction=%d err=%v", signatures, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND payload_json->>'request_id'=$2 AND kind IN ('data_subject.fulfilled','data_subject.anonymized')`, request.OrgID, request.ID.String()).Scan(&terminalEvents); err != nil || terminalEvents != 0 {
		t.Fatalf("unauthorized terminal events=%d err=%v", terminalEvents, err)
	}
}

func TestDSRTransitionRechecksAuthorizationAfterParentAndRequestWaitE2E(t *testing.T) {
	for _, lock := range []string{"document", "request"} {
		for _, change := range []string{"demotion", "revocation", "expiry"} {
			t.Run(lock+"/"+change, func(t *testing.T) {
				ctx, pool, q, s, org, user := setupDSRE2E(t)
				otherOwner := seedSessionOwnerE2E(t, ctx, q, org)
				if _, err := q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"}); err != nil {
					t.Fatal(err)
				}
				doc, recipient := seedDSRRecipientE2E(t, ctx, pool, q, org, user, true)
				request, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
				if err != nil {
					t.Fatal(err)
				}
				blocked, err := pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer blocked.Rollback(context.Background())
				queryName := "GetDocumentForPrivacyUpdate"
				if lock == "document" {
					_, err = q.WithTx(blocked).GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: doc.ID, OrgID: org})
				} else {
					queryName = "GetDataSubjectRequestForUpdate"
					_, err = q.WithTx(blocked).GetDataSubjectRequestForUpdate(ctx, generated.GetDataSubjectRequestForUpdateParams{ID: request.ID, OrgID: org})
				}
				if err != nil {
					t.Fatal(err)
				}
				ttl := time.Hour
				if change == "expiry" {
					ttl = time.Second
				}
				cookie := dsrSessionCookieE2E(t, s, user, 0, ttl)
				result := make(chan *httptest.ResponseRecorder, 1)
				go func() {
					result <- submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/dsr/"+request.ID.String(), `{"status":"fulfilled","resolution_note":"authorized review"}`, cookie)
				}()
				awaitSessionOperationLockE2E(t, ctx, pool, "-- name: "+queryName, "transactionid")
				wantStatus := http.StatusForbidden
				switch change {
				case "demotion":
					ownerCookie := dsrSessionCookieE2E(t, s, otherOwner, 0, time.Hour)
					res := submitSessionOperationE2E(s, http.MethodPatch, "/api/v1/members/"+user.String()+"/role", `{"role":"viewer"}`, ownerCookie)
					if res.Code != http.StatusOK {
						t.Fatalf("live member demotion=%d %s", res.Code, res.Body.String())
					}
				case "revocation":
					res := submitSessionOperationE2E(s, http.MethodPost, "/auth/logout", "", cookie)
					if res.Code != http.StatusOK {
						t.Fatalf("live session revocation=%d %s", res.Code, res.Body.String())
					}
				case "expiry":
					awaitSessionCookieExpiryE2E(t, s, cookie)
					wantStatus = http.StatusUnauthorized
				}
				if err = blocked.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				res := receiveSessionOperationE2E(t, result)
				if res.Code != wantStatus {
					t.Fatalf("stale session response=%d want=%d %s", res.Code, wantStatus, res.Body.String())
				}
				assertDSRNotRedactedE2E(t, ctx, pool, q, request, recipient)
			})
		}
	}
}

func TestDSRTransactionsExpireDuringAuditWaitE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	doc, recipient := seedDSRRecipientE2E(t, ctx, pool, q, org, user, true)
	request, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true}, SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	operations := []struct{ name, method, path, body string }{
		{"transition", http.MethodPatch, "/api/v1/dsr/" + request.ID.String(), `{"status":"fulfilled"}`},
		{"creation", http.MethodPost, "/api/v1/dsr", fmt.Sprintf(`{"kind":"access","subject_email":"audit-wait@example.test","document_id":%q}`, doc.ID.String())},
		{"export", http.MethodGet, "/api/v1/data-subject/export?email=" + url.QueryEscape(recipient.Email), ""},
	}
	for _, operation := range operations {
		t.Run(operation.name, func(t *testing.T) {
			blocked, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer blocked.Rollback(context.Background())
			if err = q.WithTx(blocked).AcquireOrgChainLock(ctx, org.String()); err != nil {
				t.Fatal(err)
			}
			cookie := dsrSessionCookieE2E(t, s, user, 0, time.Second)
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				result <- submitSessionOperationE2E(s, operation.method, operation.path, operation.body, cookie)
			}()
			awaitSessionOperationLockE2E(t, ctx, pool, "-- name: AcquireOrgChainLock", "advisory")
			awaitSessionCookieExpiryE2E(t, s, cookie)
			if err = blocked.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			response := receiveSessionOperationE2E(t, result)
			if response.Code != http.StatusUnauthorized {
				t.Fatalf("expired %s=%d %s", operation.name, response.Code, response.Body.String())
			}
			assertDSRNotRedactedE2E(t, ctx, pool, q, request, recipient)
			var requests, events int
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM data_subject_requests WHERE org_id=$1`, org).Scan(&requests); err != nil || requests != 1 {
				t.Fatalf("expired creation requests=%d err=%v", requests, err)
			}
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind LIKE 'data_subject.%'`, org).Scan(&events); err != nil || events != 0 {
				t.Fatalf("expired operation audit=%d err=%v", events, err)
			}
		})
	}
}
