//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/collab"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"nhooyr.io/websocket"
)

func TestCollabRecoveryArchivesActiveSocketBeforeRetirementE2E(t *testing.T) {
	base, pool, q, s, org, user := setupDSRE2E(t)
	ctx, cancel := context.WithTimeout(base, 30*time.Second)
	defer cancel()
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{29}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	s.Collab = collab.NewHub(q)
	s.Collab.FlushEvery = 0
	defer s.Collab.Shutdown(context.Background())
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Hour)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "recovery", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s.Routes())
	defer server.Close()
	endpoint := server.URL + "/api/v1/documents/" + doc.ID.String()
	headers := http.Header{"Cookie": []string{SessionCookieName + "=" + cookie}, "Origin": []string{s.PublicURL}}
	conn, _, err := websocket.Dial(ctx, strings.Replace(endpoint, "http:", "ws:", 1)+"/collab?expected_updated_at="+url.QueryEscape(doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	for i := 0; i < 3; i++ {
		if _, _, err = conn.Read(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err = conn.Write(ctx, websocket.MessageBinary, []byte{0, 2, 1, 42}); err != nil {
		t.Fatal(err)
	}
	// Checkpoint response proves the authenticated frame has reached the room.
	request := append([]byte{7, 0}, bytes.Repeat([]byte{1}, 16)...)
	if err = conn.Write(ctx, websocket.MessageBinary, request); err != nil {
		t.Fatal(err)
	}
	for {
		_, frame, err := conn.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(frame) > 1 && frame[0] == 7 {
			break
		}
	}
	replacement := json.RawMessage(`{"version":1,"blocks":[{"id":"replacement","type":"paragraph","children":[]}]}`)
	var at pgtype.Timestamptz
	if err = pool.QueryRow(ctx, `UPDATE documents SET blocks_json=$2 WHERE id=$1 RETURNING updated_at`, doc.ID, replacement).Scan(&at); err != nil {
		t.Fatal(err)
	}
	submit := func(method, path string, body any, cookieValue string) (int, []byte, http.Header) {
		encoded, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, method, endpoint+path, bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.PublicURL)
		if cookieValue != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookieValue})
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode, data, res.Header
	}
	input := collabRecoveryInput{Generation: "2", ExpectedUpdatedAt: at.Time.UTC().Format(time.RFC3339Nano), Acknowledged: true}
	if status, _, _ := submit("POST", "/collab/recovery", input, ""); status != 401 {
		t.Fatalf("anonymous %d", status)
	}
	stale := input
	stale.Generation = "1"
	if status, _, _ := submit("POST", "/collab/recovery", stale, cookie); status != 412 {
		t.Fatalf("stale %d", status)
	}
	// Audit failure must roll back archives/reset and leave active bytes intact.
	suffix := strings.ReplaceAll(doc.ID.String(), "-", "")
	function := "hash_fail_recovery_" + suffix
	_, err = pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='collab.recovered' AND NEW.document_id='%s'::uuid THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER %s BEFORE INSERT ON events FOR EACH ROW EXECUTE FUNCTION %s()`, function, doc.ID, function, function))
	if err != nil {
		t.Fatal(err)
	}
	if status, _, _ := submit("POST", "/collab/recovery", input, cookie); status < 500 {
		t.Fatalf("audit failure %d", status)
	}
	_, err = pool.Exec(ctx, fmt.Sprintf(`DROP TRIGGER %s ON events; DROP FUNCTION %s()`, function, function))
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed audit retained archive", err)
	}
	status, data, _ := submit("POST", "/collab/recovery", input, cookie)
	if status != 200 {
		t.Fatalf("recovery %d %s", status, data)
	}
	var receipt struct {
		Generation string           `json:"generation"`
		Document   documentResponse `json:"document"`
	}
	if json.Unmarshal(data, &receipt) != nil || receipt.Generation != "3" {
		t.Fatal("missing recovery receipt")
	}
	readCtx, readCancel := context.WithTimeout(ctx, 2*time.Second)
	defer readCancel()
	if _, _, err := conn.Read(readCtx); err == nil {
		t.Fatal("old socket remained open")
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc.ID)
	if err != nil || state.Generation.Int64 != 3 || len(state.YdocState) != 0 {
		t.Fatal("history not reset atomically", err)
	}
	archives, err := q.ListCollabRecoveryArchives(ctx, generated.ListCollabRecoveryArchivesParams{DocumentID: doc.ID, OrgID: org})
	if err != nil || len(archives) != 1 {
		t.Fatal("active history missing", err)
	}
	a := archives[0]
	if a.Origin != "active_room" || a.HistoryGeneration.Int64 != 1 || a.ExpiresAt.Time.Sub(a.CreatedAt.Time) < 89*24*time.Hour {
		t.Fatal("wrong archive association/expiry")
	}
	archivePath := "/collab/recovery/archives/" + a.ID.String()
	status, data, responseHeaders := submit("GET", archivePath, nil, cookie)
	if status != 200 || !bytes.Equal(data, []byte{1, 42}) || !strings.Contains(responseHeaders.Get("Content-Disposition"), "attachment") || !strings.Contains(responseHeaders.Get("Cache-Control"), "no-store") {
		t.Fatalf("archive download %d %v", status, responseHeaders)
	}
	if status, _, _ := submit("GET", "/collab/recovery/archives/"+uuid.NewString(), nil, cookie); status != 404 {
		t.Fatalf("wrong archive %d", status)
	}
	if status, _, _ := submit("DELETE", archivePath, map[string]any{}, cookie); status != 400 {
		t.Fatalf("no delete acknowledgement %d", status)
	}
	if _, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "sender"}); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := submit("GET", archivePath, nil, cookie); status != 403 {
		t.Fatalf("demoted download %d", status)
	}
	if _, err = q.UpdateUserRole(ctx, generated.UpdateUserRoleParams{ID: user, OrgID: org, Role: "owner"}); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`, user); err != nil {
		t.Fatal(err)
	}
	if status, _, _ := submit("GET", archivePath, nil, cookie); status != 401 {
		t.Fatalf("revoked download %d", status)
	}
	payload, _ = json.Marshal(auth.SessionPayload{UserID: user, Generation: 1})
	cookie = s.Cookies.Mint(payload, time.Hour)
	if status, _, _ := submit("DELETE", archivePath, map[string]any{"acknowledged": true}, cookie); status != 204 {
		t.Fatalf("delete %d", status)
	}
	// A fresh room must initialize from the new empty, associated generation.
	headers.Set("Cookie", SessionCookieName+"="+cookie)
	// A stale tab must not seed the new empty generation with its old canonical tree.
	_, response, err := websocket.Dial(ctx, strings.Replace(endpoint, "http:", "ws:", 1)+"/collab?expected_updated_at="+url.QueryEscape(doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)), &websocket.DialOptions{HTTPHeader: headers})
	if err == nil || response == nil || response.StatusCode != 412 {
		t.Fatal("stale canonical bootstrap was admitted", err)
	}
	fresh, _, err := websocket.Dial(ctx, strings.Replace(endpoint, "http:", "ws:", 1)+"/collab?expected_updated_at="+url.QueryEscape(receipt.Document.UpdatedAt), &websocket.DialOptions{HTTPHeader: headers})
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.CloseNow()
	_, frame, err := fresh.Read(ctx)
	if err != nil || !bytes.Equal(frame, []byte{6, 1, '3'}) {
		t.Fatal("fresh generation", err, frame)
	}
}

func TestCollabArchiveAndRecoveryExpiryDuringAuditWaitE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{30}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	s.Collab = collab.NewHub(q)
	defer s.Collab.Shutdown(ctx)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "expiry", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	var archive uuid.UUID
	if err = pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives(document_id,observed_canonical_generation,origin,ydoc_state) VALUES($1,1,'persisted',$2) RETURNING id`, doc.ID, []byte{1, 42}).Scan(&archive); err != nil {
		t.Fatal(err)
	}
	routes := s.Routes()
	for _, method := range []string{"GET", "DELETE", "POST"} {
		t.Run(method, func(t *testing.T) {
			locked, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer locked.Rollback(ctx)
			if err = q.WithTx(locked).AcquireOrgChainLock(ctx, org.String()); err != nil {
				t.Fatal(err)
			}
			payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
			cookie := s.Cookies.Mint(payload, 2*time.Second)
			path := "/api/v1/documents/" + doc.ID.String() + "/collab/recovery/archives/" + archive.String()
			body := []byte(`{"acknowledged":true}`)
			if method == "POST" {
				path = "/api/v1/documents/" + doc.ID.String() + "/collab/recovery"
				body, _ = json.Marshal(collabRecoveryInput{Generation: "1", ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Acknowledged: true})
			}
			req := httptest.NewRequest(method, s.PublicURL+path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", s.PublicURL)
			req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: cookie})
			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { res := httptest.NewRecorder(); routes.ServeHTTP(res, req); done <- res }()
			deadline := time.Now().Add(5 * time.Second)
			waiting := false
			for time.Now().Before(deadline) {
				var blocked int
				if err = pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event='advisory'`).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked > 0 {
					waiting = true
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if !waiting {
				t.Fatal("request did not reach held audit lock")
			}
			for time.Now().Before(deadline) {
				if _, err = s.Cookies.Verify(cookie); err != nil {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if _, err = s.Cookies.Verify(cookie); err == nil {
				t.Fatal("fixture cookie did not expire")
			}
			if err = locked.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case res := <-done:
				if res.Code != 401 {
					t.Fatalf("expired commit %d %s", res.Code, res.Body.String())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("expired request did not finish")
			}
			var count int
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM collab_recovery_archives WHERE document_id=$1`, doc.ID).Scan(&count); err != nil || count != 1 {
				t.Fatal("expiry mutated archive", err)
			}
			generation, err := q.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: doc.ID, OrgID: org})
			if err != nil || generation != 1 {
				t.Fatal("expired recovery advanced generation", err)
			}
			if err = pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id=$1 AND kind LIKE 'collab.%'`, doc.ID).Scan(&count); err != nil || count != 0 {
				t.Fatal("expired access committed audit", err)
			}
		})
	}
}

func TestCollabRecoveryBudgetAndLegacyArchiveAccessE2E(t *testing.T) {
	ctx, pool, q, s, org, user := setupDSRE2E(t)
	var err error
	s.Cookies, err = auth.NewSignedCookie(hex.EncodeToString(bytes.Repeat([]byte{31}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	s.PublicURL = "https://hash.example.test"
	s.Collab = collab.NewHub(q)
	defer s.Collab.Shutdown(ctx)
	doc, err := q.CreateBlocksDocument(ctx, generated.CreateBlocksDocumentParams{OrgID: org, SenderID: user, Name: "budget", BlocksJson: json.RawMessage(`{"version":1,"blocks":[]}`), VariablesJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = q.UpsertCollabDocState(ctx, generated.UpsertCollabDocStateParams{DocumentID: doc.ID, YdocState: []byte{1, 42}, StateSize: 2, UpdateCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = pool.Exec(ctx, `INSERT INTO collab_recovery_archives(document_id,observed_canonical_generation,origin,ydoc_state) SELECT $1,1,'persisted',$2 FROM generate_series(1,16)`, doc.ID, []byte{1, 43})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(auth.SessionPayload{UserID: user})
	cookie := s.Cookies.Mint(payload, time.Hour)
	routes := s.Routes()
	call := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(body)
		req := httptest.NewRequest(method, s.PublicURL+"/api/v1/documents/"+doc.ID.String()+path, bytes.NewReader(encoded))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", s.PublicURL)
		req.AddCookie(&http.Cookie{Name: SessionCookieName, Value: token})
		res := httptest.NewRecorder()
		routes.ServeHTTP(res, req)
		return res
	}
	in := collabRecoveryInput{Generation: "1", ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), Acknowledged: true}
	res := call("POST", "/collab/recovery", in, cookie)
	if res.Code != 507 {
		t.Fatalf("capacity %d %s", res.Code, res.Body.String())
	}
	state, err := q.GetCollabDocStateWithGeneration(ctx, doc.ID)
	if err != nil || state.Generation.Valid || !bytes.Equal(state.YdocState, []byte{1, 42}) {
		t.Fatal("capacity refusal discarded legacy history", err)
	}
	generation, err := q.GetDocumentCollabGeneration(ctx, generated.GetDocumentCollabGenerationParams{ID: doc.ID, OrgID: org})
	if err != nil || generation != 1 {
		t.Fatal("capacity refusal advanced generation", err)
	}
	archives, err := q.ListCollabRecoveryArchives(ctx, generated.ListCollabRecoveryArchivesParams{DocumentID: doc.ID, OrgID: org})
	if err != nil || len(archives) != 16 {
		t.Fatal("capacity refusal changed archives", err)
	}
	archivePath := "/collab/recovery/archives/" + archives[0].ID.String()
	otherOrg, err := q.CreateOrg(ctx, generated.CreateOrgParams{Name: "foreign", Plan: "pro"})
	if err != nil {
		t.Fatal(err)
	}
	otherUser, err := q.CreateUser(ctx, generated.CreateUserParams{OrgID: otherOrg.ID, Email: uuid.NewString() + "@example.test", Name: "foreign", Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	otherPayload, _ := json.Marshal(auth.SessionPayload{UserID: otherUser.ID})
	foreignCookie := s.Cookies.Mint(otherPayload, time.Hour)
	if res := call("GET", archivePath, nil, foreignCookie); res.Code != 404 {
		t.Fatalf("foreign archive %d", res.Code)
	}
	// An org-wide access request defers explicit deletion as well as expiry.
	request, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{OrgID: org, SubjectEmail: "fixture@example.test", SubjectName: "fixture", Kind: "access", RequestedVia: "sender", PayloadJson: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	if res := call("DELETE", archivePath, map[string]any{"acknowledged": true}, cookie); res.Code != 409 {
		t.Fatalf("open global request deletion %d", res.Code)
	}
	_, err = pool.Exec(ctx, `UPDATE data_subject_requests SET status='denied' WHERE id=$1`, request.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res := call("DELETE", archivePath, map[string]any{"acknowledged": true}, cookie); res.Code != 204 {
		t.Fatalf("reviewed archive delete %d", res.Code)
	}
	res = call("POST", "/collab/recovery", in, cookie)
	if res.Code != 200 {
		t.Fatalf("recovery after review %d %s", res.Code, res.Body.String())
	}
	res = call("GET", "/collab/recovery", nil, cookie)
	if res.Code != 200 || !bytes.Contains(res.Body.Bytes(), []byte(`"history_generation":null`)) {
		t.Fatalf("legacy generation invented %d %s", res.Code, res.Body.String())
	}
}
