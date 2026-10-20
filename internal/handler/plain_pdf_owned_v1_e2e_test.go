//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Actual PG, middleware credentials, native runtime and restricted PDF worker.
// The existing bounded S3 protocol peer is synthetic; these are lifecycle and
// exact-byte assertions, never provider Object Lock, antivirus efficacy or
// production capacity evidence. Target caches originate ONLY in the actual
// upload/new-field writers; SQL below is a read oracle or an explicit negative
// deletion, never a fabricated measurement, backfill or alternate transaction.
type ownedPlainResponseGateV1 struct {
	*httptest.ResponseRecorder
	started, release  chan struct{}
	preview           []byte
	once, releaseOnce sync.Once
}

func newOwnedPlainResponseGateV1() *ownedPlainResponseGateV1 {
	return &ownedPlainResponseGateV1{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
}
func (w *ownedPlainResponseGateV1) Write(p []byte) (int, error) {
	w.once.Do(func() { w.preview = append([]byte(nil), p...); close(w.started); <-w.release })
	return w.ResponseRecorder.Write(p)
}
func (w *ownedPlainResponseGateV1) unblock() { w.releaseOnce.Do(func() { close(w.release) }) }

type ownedPlainAuditGateV1 struct {
	kind                       string
	eventID                    uuid.UUID
	entry                      audit.Entry
	started, release, returned chan struct{}
	releaseOnce                sync.Once
}

func newOwnedPlainAuditGateV1(kind string) *ownedPlainAuditGateV1 {
	return &ownedPlainAuditGateV1{kind: kind, started: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
}
func (g *ownedPlainAuditGateV1) unblock() { g.releaseOnce.Do(func() { close(g.release) }) }
func ownedPlainAwaitV1(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timed out awaiting actual " + what)
	}
}

func ownedPlainRequestV1(t *testing.T, q *ownedPublicReadFixtureV1, via, tool, key string, args map[string]any, pdf []byte) *http.Request {
	t.Helper()
	var r *http.Request
	if via == "MCP" {
		if tool == "create_pdf_document" {
			args = map[string]any{"name": "Owned PDF via MCP", "pdf_base64": base64.StdEncoding.EncodeToString(pdf)}
		}
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
		if err != nil {
			t.Fatal(err)
		}
		r = httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/mcp", bytes.NewReader(raw)).WithContext(q.f.ctx)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+key)
	} else {
		if tool == "create_pdf_document" {
			var body bytes.Buffer
			form := multipart.NewWriter(&body)
			if err := form.WriteField("name", "Owned PDF via REST"); err != nil {
				t.Fatal(err)
			}
			part, err := form.CreateFormFile("pdf", "owned.pdf")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = part.Write(pdf); err != nil {
				t.Fatal(err)
			}
			if err = form.Close(); err != nil {
				t.Fatal(err)
			}
			r = httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/v1/documents/import", &body).WithContext(q.f.ctx)
			r.Header.Set("Content-Type", form.FormDataContentType())
		} else {
			id, ok := args["document_id"].(string)
			if !ok {
				t.Fatal("field request needs exact document ID")
			}
			body := make(map[string]any, len(args))
			for k, v := range args {
				if k != "document_id" {
					body[k] = v
				}
			}
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			r = httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/v1/documents/"+id+"/fields", bytes.NewReader(raw)).WithContext(q.f.ctx)
			r.Header.Set("Content-Type", "application/json")
		}
		r.Header.Set("Origin", q.f.s.PublicURL)
		r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	}
	r.Header.Set("User-Agent", "owned-plain-pdf-actual-regression")
	return r
}

func ownedPlainAssertRetainedV1(t *testing.T, q *ownedPublicReadFixtureV1, what string) {
	t.Helper()
	s, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || s.Global.ParentBytes <= 0 || s.Global.DBStagingBytes <= 0 || s.Organisation.ParentBytes <= 0 || s.Organisation.DBStagingBytes <= 0 {
		t.Fatalf("%s lost actual retained native source debt: %+v err=%v", what, s, err)
	}
}
func ownedPlainAssertDrainedV1(t *testing.T, q *ownedPublicReadFixtureV1) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		q.reconcileV1(t)
		s, err := q.runtime.SnapshotV1(q.f.org)
		if err != nil {
			t.Fatal(err)
		}
		if s.Global.ParentBytes == 0 && s.Global.DBStagingBytes == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("actual joined result/audit debt did not retire: %+v", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}

func ownedPlainFreshDocumentV1(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID) string {
	t.Helper()
	var exact bool
	var snapshot string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 d.source_kind='pdf' AND d.status='draft' AND d.sender_id=$3
 AND d.html_source_json IS NULL AND d.html_current_source_json IS NULL AND d.blocks_json IS NULL
 AND d.evidence_version_pins_required AND length(d.pdf_sha256)=32 AND d.pdf_storage_version_id='import-version-1'
 AND length(d.metadata_redaction_report::text)>2
 AND p.org_id=d.org_id AND p.html_origin_wire_bytes=0 AND p.html_current_wire_bytes=0
 AND p.variables_wire_bytes=octet_length(d.variables_json::text)
 AND r.org_id=d.org_id AND r.blocks_wire_bytes=0 AND r.metadata_wire_bytes=octet_length(d.metadata::text)
 AND s.org_id=d.org_id AND s.report_wire_bytes=octet_length(d.metadata_redaction_report::text)
 AND p.measurement_server_version_num=current_setting('server_version_num')::integer
 AND r.measurement_server_version_num=p.measurement_server_version_num
 AND s.measurement_server_version_num=p.measurement_server_version_num,
 jsonb_build_object('policy',to_jsonb(p),'response',to_jsonb(r),'report',to_jsonb(s))::text
 FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id
 JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id
 JOIN document_read_report_sizes_v1 s ON s.document_id=d.id
 WHERE d.id=$1 AND d.org_id=$2`, id, q.f.org, q.f.user.ID).Scan(&exact, &snapshot)
	if err != nil || !exact || snapshot == "" {
		t.Fatal("actual upload did not produce exact native M91/M92/M93", err)
	} //nolint:rawsql -- bounded actual fresh source/cache oracle, never insertion
	return snapshot
}

func TestOwnedPlainPDFFreshRESTMCPAndFieldLifecycleE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	// Use the original concrete version-aware client/protocol oracle for both
	// REST and MCP; Sign's unrelated evidence peer is never used by this test.
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-plain", SecretKey: "synthetic-owned-plain-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Storage: q.f.s.Storage, Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL})
	if err = malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	var current atomic.Pointer[ownedPlainAuditGateV1]
	q.f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		g := current.Load()
		if g == nil || e.Kind != g.kind {
			return
		}
		g.eventID = id
		g.entry = e
		close(g.started)
		<-g.release
		close(g.returned)
	})
	key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	var latest uuid.UUID
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) {
			for _, tool := range []string{"create_pdf_document", "add_document_field"} {
				kind := audit.KindDocumentCreated
				args := map[string]any{}
				documentBefore := ""
				recipientID := uuid.Nil
				if tool == "add_document_field" {
					kind = "document.field_added"
					party := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+latest.String()+"/recipients", `{"email":"owned-pdf@example.test","name":"Owned PDF signer","role":"signer","locale":"en"}`, q.cookie)
					var recipient recipientResponse
					if party.Code != http.StatusCreated || json.Unmarshal(party.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil || recipient.DocumentID != latest {
						t.Fatalf("actual field party=%d %s", party.Code, party.Body.String())
					}
					recipientID = recipient.ID
					documentBefore = ownedPlainFreshDocumentV1(t, q, latest)
					args = map[string]any{"document_id": latest.String(), "type": "dropdown", "recipient_id": recipientID.String(), "page": 1, "required": true, "label": "Owned choice", "options": map[string]any{"choices": []string{"First 雪", "Quote \" choice"}}, "x_pct": 25, "y_pct": 25, "w_pct": 20, "h_pct": 7.5}
					if via == "MCP" {
						args["required"] = "true"
						args["x_pct"] = 2500
						args["y_pct"] = 2500
						args["w_pct"] = 2000
						args["h_pct"] = 750
					}
				}
				auditGate := newOwnedPlainAuditGateV1(kind)
				current.Store(auditGate)
				t.Cleanup(auditGate.unblock)
				response := newOwnedPlainResponseGateV1()
				t.Cleanup(response.unblock)
				done := make(chan struct{})
				request := ownedPlainRequestV1(t, q, via, tool, key.Plaintext, args, fieldBrowserPDF("Genuine restricted PDF intake"))
				go func() { defer close(done); q.f.s.Routes().ServeHTTP(response, request) }()
				ownedPlainAwaitV1(t, response.started, via+" response body")
				refused := via == "REST" && response.Code != http.StatusCreated
				if via == "MCP" {
					var envelope struct {
						Result struct {
							IsError bool `json:"isError"`
						} `json:"result"`
						Error json.RawMessage `json:"error"`
					}
					if json.Unmarshal(response.preview, &envelope) != nil || envelope.Result.IsError || len(envelope.Error) > 0 {
						refused = true
					}
				}
				if refused {
					snapshot, snapErr := q.runtime.SnapshotV1(q.f.org)
					pending := q.runtime.SessionsV1().PendingV1()
					response.unblock()
					ownedPlainAwaitV1(t, done, "refused actual response last use")
					t.Fatalf("actual %s %s refused before joined %s hook: status=%d body=%s pending=%+v resources=%+v snapshot_error=%v", via, tool, kind, response.Code, response.Body.String(), pending, snapshot, snapErr)
				}
				ownedPlainAwaitV1(t, auditGate.started, via+" joined "+kind+" hook")
				if auditGate.entry.OrgID != q.f.org || auditGate.entry.DocumentID == nil || auditGate.entry.ActorUserID == nil || *auditGate.entry.ActorUserID != q.f.user.ID || auditGate.eventID == uuid.Nil {
					t.Fatal("actual source audit lost original actor/scope")
				}
				id := *auditGate.entry.DocumentID
				ownedPlainAssertRetainedV1(t, q, "blocked real response and audit hook")
				if tool == "create_pdf_document" {
					latest = id
					ownedPlainFreshDocumentV1(t, q, id)
				} else {
					var exact bool
					var count int
					err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*)::integer,bool_and(c.field_id IS NOT NULL AND c.document_id=f.document_id AND c.org_id=d.org_id
      AND c.options_wire_bytes=octet_length(f.options_json::text)
      AND c.measurement_server_version_num=current_setting('server_version_num')::integer
      AND f.recipient_id=$3 AND f.type='dropdown' AND f.page=1 AND f.x_pct=25 AND f.y_pct=25 AND f.w_pct=20 AND f.h_pct=7.5)
      FROM document_fields f JOIN documents d ON d.id=f.document_id
      LEFT JOIN field_signing_policy_sizes_v1 c ON c.field_id=f.id
      WHERE d.id=$1 AND d.org_id=$2`, id, q.f.org, recipientID).Scan(&count, &exact)
					if err != nil || count != 1 || !exact {
						t.Fatal("actual new field lacks fresh exact M91 options measurement/geometry", err)
					} //nolint:rawsql -- genuine fresh field oracle only
					if got := ownedPlainFreshDocumentV1(t, q, id); got != documentBefore {
						t.Fatal("field creation rewrote unrelated source measurements")
					}
				}
				if via == "MCP" && tool == "add_document_field" {
					auditGate.unblock()
					ownedPlainAwaitV1(t, auditGate.returned, "actual audit hook before response last use")
					ownedPlainAssertRetainedV1(t, q, "hook ended while actual response still uses source")
					response.unblock()
					ownedPlainAwaitV1(t, done, "actual response last use")
				} else {
					response.unblock()
					ownedPlainAwaitV1(t, done, "actual response last use")
					ownedPlainAssertRetainedV1(t, q, "response ended while actual joined audit hook still uses source")
					auditGate.unblock()
					ownedPlainAwaitV1(t, auditGate.returned, "actual audit hook return")
				}
				if via == "MCP" {
					fieldMCPTextE2E(t, response.ResponseRecorder, false)
				} else if response.Code != http.StatusCreated {
					t.Fatalf("actual %s=%d %s", tool, response.Code, response.Body.String())
				}
				current.Store(nil)
				ownedPlainAssertDrainedV1(t, q)
			}
		})
	}
	assertImportStorageE2E(t, peer, 2, 0, 2)

	t.Run("original import capacity refuses before upload body", func(t *testing.T) {
		release, err := importguard.Shared.Acquire(q.f.org)
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		body := &unreadImportBody{}
		request := httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/api/v1/documents/import", nil).WithContext(q.f.ctx)
		request.Body = body
		request.Header.Set("Origin", q.f.s.PublicURL)
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
		w := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(w, request)
		if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" || body.reads != 0 {
			t.Fatalf("actual import admission=%d reads=%d", w.Code, body.reads)
		}
		assertImportStorageE2E(t, peer, 2, 0, 2)
		ownedPlainAssertDrainedV1(t, q)
	})
	t.Run("scanner unavailable remains fail closed before storage", func(t *testing.T) {
		before := q.f.snapshot(t)
		if err := malwarescan.Configure(q.f.ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
			t.Fatal("failed scanner setup did not remain unavailable", err)
		}
		defer func() {
			if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
				t.Error(err)
			}
		}()
		for _, via := range []string{"REST", "MCP"} {
			w := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, via, "create_pdf_document", key.Plaintext, nil, fieldBrowserPDF("Unavailable scanner fixture")))
			if via == "REST" {
				if w.Code != http.StatusServiceUnavailable {
					t.Fatalf("actual unavailable scanner=%d %s", w.Code, w.Body.String())
				}
			} else {
				if got := fieldMCPTextE2E(t, w, true); !strings.Contains(got, malwarescan.ErrUnavailable.Error()) {
					t.Fatalf("MCP scanner lost original verdict: %s", got)
				}
			}
			ownedPlainAssertDrainedV1(t, q)
		}
		if q.f.snapshot(t) != before {
			t.Fatal("scanner refusal changed committed document/audit state")
		}
		assertImportStorageE2E(t, peer, 2, 0, 2)
	})
	t.Run("actual member demotion precedes sanitize or storage", func(t *testing.T) {
		before := q.f.snapshot(t)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		if _, err = q.f.q.WithTx(blocked).UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
			t.Fatal(err)
		}
		request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Demotion before native intake"))
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() { w := httptest.NewRecorder(); q.f.s.Routes().ServeHTTP(w, request); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetHTMLAuthoringActorHeaderV1", "transactionid")
		if _, err = q.f.q.WithTx(blocked).UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusForbidden {
			t.Fatalf("actual delayed demotion=%d %s", w.Code, w.Body.String())
		}
		if q.f.snapshot(t) != before {
			t.Fatal("late demotion changed document/audit state")
		}
		assertImportStorageE2E(t, peer, 2, 0, 2)
		ownedPlainAssertDrainedV1(t, q)
		if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("original admitted MCP key is rechecked after actor wait", func(t *testing.T) {
		before := q.f.snapshot(t)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		if _, err = q.f.q.WithTx(blocked).UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
			t.Fatal(err)
		}
		admitted, keyID := mintRecipientMCPKeyE2E(t, q.f, false, 0)
		request := ownedPlainRequestV1(t, q, "MCP", "create_pdf_document", admitted.Plaintext, nil, fieldBrowserPDF("Revoked original key"))
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() { w := httptest.NewRecorder(); q.f.s.Routes().ServeHTTP(w, request); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetHTMLAuthoringActorHeaderV1", "transactionid")
		if _, err = q.f.pool.Exec(q.f.ctx, "DELETE FROM api_keys WHERE id=$1 AND org_id=$2", keyID, q.f.org); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- actual credential revocation during real actor wait
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationPermissionRevoked.Error() {
			t.Fatalf("actual original key refusal=%q", got)
		}
		if q.f.snapshot(t) != before {
			t.Fatal("revoked key changed document/audit state")
		}
		assertImportStorageE2E(t, peer, 2, 0, 2)
		ownedPlainAssertDrainedV1(t, q)
	})
	t.Run("late original session expiry compensates the exact stored version", func(t *testing.T) {
		before := q.f.snapshot(t)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		if err = q.f.q.WithTx(blocked).AcquireOrgChainLock(q.f.ctx, q.f.org.String()); err != nil {
			t.Fatal(err)
		}
		originalCookie := q.cookie
		q.cookie = dsrSessionCookieE2E(t, q.f.s, q.f.user.ID, q.f.user.SessionGeneration, time.Second)
		defer func() { q.cookie = originalCookie }()
		request := ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Late original credential expiry"))
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() { w := httptest.NewRecorder(); q.f.s.Routes().ServeHTTP(w, request); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "pg_advisory_xact_lock", "advisory")
		awaitSessionCookieExpiryE2E(t, q.f.s, q.cookie)
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		if w := receiveSessionOperationE2E(t, result); w.Code != http.StatusUnauthorized {
			t.Fatalf("actual late session expiry=%d %s", w.Code, w.Body.String())
		}
		if q.f.snapshot(t) != before {
			t.Fatal("expired original session left document/audit rows")
		}
		assertImportStorageE2E(t, peer, 3, 1, 2)
		ownedPlainAssertDrainedV1(t, q)
	})
	t.Run("field role refusal precedes missing source cache and never repairs it", func(t *testing.T) {
		if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", latest, q.f.org); err != nil || tag.RowsAffected() != 1 {
			t.Fatal("delete exact actual cache for refusal-order oracle", err)
		} //nolint:rawsql -- negative source-cache deletion only
		before := recipientMCPSnapshotE2E(t, q.f)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		var locked uuid.UUID
		if err = blocked.QueryRow(q.f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", latest, q.f.org).Scan(&locked); err != nil || locked != latest {
			t.Fatal("lock actual field parent for original actor wait", err)
		} //nolint:rawsql -- exact scalar fixture lock; no full body/cache or borrowed nativeTx
		args := map[string]any{"document_id": latest.String(), "type": "text", "page": 1, "w_pct": 15, "h_pct": 4}
		request := ownedPlainRequestV1(t, q, "REST", "add_document_field", "", args, nil)
		result := make(chan *httptest.ResponseRecorder, 1)
		go func() { w := httptest.NewRecorder(); q.f.s.Routes().ServeHTTP(w, request); result <- w }()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetHTMLRevisionDocumentReadHeaderV1", "transactionid")
		if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		w := receiveSessionOperationE2E(t, result)
		if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "permission or credential revoked") {
			t.Fatalf("actual delayed field role/missing-cache order=%d %s", w.Code, w.Body.String())
		}
		ownedPlainAssertDrainedV1(t, q)
		if _, err := q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
			t.Fatal(err)
		}
		args["w_pct"] = 1500
		args["h_pct"] = 400
		w = httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, "MCP", "add_document_field", key.Plaintext, args, nil))
		if got := fieldMCPTextE2E(t, w, true); !strings.Contains(got, "owned HTML revision read unavailable") {
			t.Fatalf("missing genuine cache did not refuse: %q", got)
		}
		ownedPlainAssertDrainedV1(t, q)
		if recipientMCPSnapshotE2E(t, q.f) != before {
			t.Fatal("refused field changed document/field/audit state")
		}
		var count int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", latest, q.f.org).Scan(&count); err != nil || count != 0 {
			t.Fatal("field request repaired missing genuine measurement", err)
		} //nolint:rawsql -- continued exact absence oracle
	})
}
