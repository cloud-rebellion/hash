//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func documentDeleteFixture(t *testing.T) (context.Context, *pgxpool.Pool, *generated.Queries, *Server, uuid.UUID, uuid.UUID, string) {
	t.Helper()
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{41}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	return ctx, pool, q, s, org, user, s.Cookies.Mint(payload, time.Hour)
}

func submitDocumentDelete(t *testing.T, s *Server, id uuid.UUID, cookie string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, s.PublicURL+"/api/v1/documents/"+id.String(), nil)
	req.Header.Set("Origin", s.PublicURL)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
	}
	res := httptest.NewRecorder()
	s.Routes().ServeHTTP(res, req)
	return res
}

func seedDocumentDeleteDraft(t *testing.T, ctx context.Context, q *generated.Queries, org, user uuid.UUID) *generated.Document {
	t.Helper()
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{
		OrgID: org, SenderID: user, Name: "delete privacy fixture", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func assertDocumentDeleteNotCommitted(t *testing.T, ctx context.Context, q *generated.Queries, id uuid.UUID) {
	t.Helper()
	doc, err := q.GetDocumentByID(ctx, id)
	if err != nil || doc.DeletedAt.Valid {
		t.Fatalf("document deletion escaped refusal/rollback: deleted=%v err=%v", doc != nil && doc.DeletedAt.Valid, err)
	}
}

func TestDocumentSoftDeleteRetainsPDFAndArchivesAndIsIdempotentE2E(t *testing.T) {
	ctx, pool, q, s, org, user, cookie := documentDeleteFixture(t)
	// Storage is deliberately unavailable. Soft deletion must retain the source
	// and succeed without attempting any object operation during the grace period.
	if s.Storage != nil {
		t.Fatal("fixture unexpectedly has storage")
	}
	source := "org/" + org.String() + "/documents/" + uuid.NewString() + ".pdf"
	doc, err := q.CreatePDFDocument(ctx, generated.CreatePDFDocumentParams{
		OrgID: org, SenderID: user, Name: "retained source", PdfStorageKey: pgtype.Text{String: source, Valid: true}, PdfSha256: bytes.Repeat([]byte{1}, 32),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO collab_recovery_archives(document_id,observed_canonical_generation,origin,ydoc_state) VALUES($1,1,'persisted',$2)`, doc.ID, []byte{1, 42}); err != nil {
		t.Fatal(err)
	}
	if res := submitDocumentDelete(t, s, doc.ID, ""); res.Code != 401 {
		t.Fatalf("anonymous status=%d %s", res.Code, res.Body.String())
	}
	if res := submitDocumentDelete(t, s, uuid.New(), cookie); res.Code != 404 {
		t.Fatalf("missing document status=%d %s", res.Code, res.Body.String())
	}
	foreignOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "foreign delete fixture " + uuid.NewString(), Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	foreignUser, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: foreignOrg.ID, Email: uuid.NewString() + "@delete.test", Name: "Foreign owner", Role: "owner", ZitadelSub: pgtype.Text{String: uuid.NewString(), Valid: true}})
	if err != nil {
		t.Fatal(err)
	}
	foreignDoc := seedDocumentDeleteDraft(t, ctx, q, foreignOrg.ID, foreignUser.ID)
	if res := submitDocumentDelete(t, s, foreignDoc.ID, cookie); res.Code != 404 {
		t.Fatalf("foreign document status=%d %s", res.Code, res.Body.String())
	}
	assertDocumentDeleteNotCommitted(t, ctx, q, foreignDoc.ID)
	if _, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "viewer"}); err != nil {
		t.Fatal(err)
	}
	if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code != 403 {
		t.Fatalf("viewer status=%d %s", res.Code, res.Body.String())
	}
	if _, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code != 204 {
		t.Fatalf("soft delete status=%d %s", res.Code, res.Body.String())
	}
	fresh, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || !fresh.DeletedAt.Valid || fresh.PdfStorageKey.String != source {
		t.Fatalf("source/grace state lost: document=%#v err=%v", fresh, err)
	}
	var archives, events int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&archives); err != nil || archives != 1 {
		t.Fatalf("retained archives=%d err=%v", archives, err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND actor_user_id=$2 AND kind=$3`, doc.ID, user, audit.KindDocumentDeleted).Scan(&events); err != nil || events != 1 {
		t.Fatalf("committed deletion audit=%d err=%v", events, err)
	}
	// An already-hidden draft is idempotent even when a later privacy request
	// protects it. Retry must neither alter its grace timestamp nor duplicate audit.
	if _, err = q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, SubjectEmail: "subject@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code != 204 {
		t.Fatalf("idempotent delete status=%d %s", res.Code, res.Body.String())
	}
	again, err := q.GetDocumentByID(ctx, doc.ID)
	if err != nil || !again.DeletedAt.Time.Equal(fresh.DeletedAt.Time) || !again.UpdatedAt.Time.Equal(fresh.UpdatedAt.Time) {
		t.Fatal("idempotent delete changed the grace/lease observation", err)
	}
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind=$2`, doc.ID, audit.KindDocumentDeleted).Scan(&events); err != nil || events != 1 {
		t.Fatalf("idempotent audit=%d err=%v", events, err)
	}
}

func TestDocumentSoftDeleteDefersEveryPendingLinkedAndGlobalPrivacyKindE2E(t *testing.T) {
	ctx, _, q, s, org, user, cookie := documentDeleteFixture(t)
	for _, kind := range []string{"access", "rectification", "erasure", "restriction", "portability", "objection"} {
		t.Run(kind, func(t *testing.T) {
			doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
			if _, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
				OrgID: org, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, SubjectEmail: "subject@example.test", Kind: kind, RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
			}); err != nil {
				t.Fatal(err)
			}
			if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code != 409 {
				t.Fatalf("pending %s status=%d %s", kind, res.Code, res.Body.String())
			}
			assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
		})
	}
	doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
	if _, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: org, SubjectEmail: "subject@example.test", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`),
	}); err != nil {
		t.Fatal(err)
	}
	if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code != 409 {
		t.Fatalf("global pending privacy status=%d %s", res.Code, res.Body.String())
	}
	assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
}

func TestDocumentSoftDeleteAuditFailureRollsBackE2E(t *testing.T) {
	ctx, pool, q, s, org, user, cookie := documentDeleteFixture(t)
	doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
	name := "hash_delete_audit_failure_" + strings.ReplaceAll(doc.ID.String(), "-", "")
	if _, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='document.deleted' AND NEW.document_id='%s'::uuid THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, name, doc.ID, name, name)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = pool.Exec(cleanupCtx, fmt.Sprintf(`DROP TRIGGER IF EXISTS %s ON events; DROP FUNCTION IF EXISTS %s()`, name, name))
	})
	if res := submitDocumentDelete(t, s, doc.ID, cookie); res.Code < 500 {
		t.Fatalf("audit failure status=%d %s", res.Code, res.Body.String())
	}
	assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
}

func awaitDocumentDeleteLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool, queryName string, event string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var blocked int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE query LIKE $1 AND wait_event=$2 AND state='active'`, "%-- name: "+queryName+"%", event).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("delete did not reach held %s lock", queryName)
}

func TestDocumentSoftDeleteRechecksRoleAndRevocationAfterParentWaitE2E(t *testing.T) {
	for _, revoke := range []bool{false, true} {
		t.Run(fmt.Sprintf("revoke=%t", revoke), func(t *testing.T) {
			ctx, pool, q, s, org, user, cookie := documentDeleteFixture(t)
			doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = q.WithTx(tx).GetDocumentForPrivacyUpdate(ctx, generated.GetDocumentForPrivacyUpdateParams{DocumentID: doc.ID, OrgID: org}); err != nil {
				t.Fatal(err)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- submitDocumentDelete(t, s, doc.ID, cookie) }()
			awaitDocumentDeleteLock(t, ctx, pool, "GetDocumentForPrivacyUpdate", "transactionid")
			if revoke {
				_, err = pool.Exec(ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, user)
			} else {
				_, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "viewer"})
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case res := <-result:
				if res.Code != 403 {
					t.Fatalf("changed authorization status=%d %s", res.Code, res.Body.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("delete did not finish after parent unlock")
			}
			assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
		})
	}
}

func TestDocumentSoftDeleteCookieExpiryDuringAuditWaitRollsBackE2E(t *testing.T) {
	ctx, pool, q, s, org, user, _ := documentDeleteFixture(t)
	doc := seedDocumentDeleteDraft(t, ctx, q, org, user)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = q.WithTx(tx).AcquireOrgChainLock(ctx, org.String()); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Second)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- submitDocumentDelete(t, s, doc.ID, cookie) }()
	awaitDocumentDeleteLock(t, ctx, pool, "AcquireOrgChainLock", "advisory")
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := s.Cookies.Verify(cookie); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err = s.Cookies.Verify(cookie); err == nil {
		t.Fatal("fixture cookie did not expire")
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-result:
		if res.Code != 401 {
			t.Fatalf("expired authorization status=%d %s", res.Code, res.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("delete did not finish after audit unlock")
	}
	assertDocumentDeleteNotCommitted(t, ctx, q, doc.ID)
	var events int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind=$2`, doc.ID, audit.KindDocumentDeleted).Scan(&events); err != nil || events != 0 {
		t.Fatalf("expired deletion audit=%d err=%v", events, err)
	}
}
