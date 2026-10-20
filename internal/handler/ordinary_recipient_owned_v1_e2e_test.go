//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Genuine routes, source writers, PostgreSQL measurements, native sessions and
// restricted PDF worker. The bounded S3 peer, identities and entitlement are
// synthetic; this is no production capacity/provider/antivirus efficacy claim.
// All cache SQL is a read oracle or an explicit negative deletion, never repair.
type ownedRecipientResponseGateV1 struct {
	*httptest.ResponseRecorder
	started, release  chan struct{}
	once, releaseOnce sync.Once
	preview           []byte
	status            int
}

func newOwnedRecipientResponseGateV1() *ownedRecipientResponseGateV1 {
	return &ownedRecipientResponseGateV1{ResponseRecorder: httptest.NewRecorder(), started: make(chan struct{}), release: make(chan struct{})}
}
func (w *ownedRecipientResponseGateV1) gate() { w.once.Do(func() { close(w.started); <-w.release }) }
func (w *ownedRecipientResponseGateV1) WriteHeader(status int) {
	w.status = status
	if status == http.StatusNoContent {
		w.gate()
	}
	w.ResponseRecorder.WriteHeader(status)
}
func (w *ownedRecipientResponseGateV1) Write(p []byte) (int, error) {
	w.preview = append([]byte(nil), p...)
	w.gate()
	return w.ResponseRecorder.Write(p)
}
func (w *ownedRecipientResponseGateV1) unblock() { w.releaseOnce.Do(func() { close(w.release) }) }

func ownedRecipientRequestV1(t *testing.T, q *ownedPublicReadFixtureV1, via, operation, key string, document, recipient uuid.UUID, input map[string]any) *http.Request {
	t.Helper()
	var request *http.Request
	if via == "MCP" {
		args := make(map[string]any, len(input)+2)
		for k, v := range input {
			args[k] = v
		}
		args["document_id"] = document.String()
		if operation != "create" {
			args["recipient_id"] = recipient.String()
		}
		tool := map[string]string{"create": "add_recipient", "update": "update_recipient", "delete": "delete_recipient"}[operation]
		raw, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
		if err != nil {
			t.Fatal(err)
		}
		request = httptest.NewRequest(http.MethodPost, q.f.s.PublicURL+"/mcp", bytes.NewReader(raw)).WithContext(q.f.ctx)
		request.Header.Set("Authorization", "Bearer "+key)
	} else {
		raw, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		method := http.MethodPost
		route := "/api/v1/documents/" + document.String() + "/recipients"
		if operation != "create" {
			route += "/" + recipient.String()
			method = http.MethodPatch
		}
		if operation == "delete" {
			method = http.MethodDelete
		}
		request = httptest.NewRequest(method, q.f.s.PublicURL+route, bytes.NewReader(raw)).WithContext(q.f.ctx)
		request.Header.Set("Origin", q.f.s.PublicURL)
		request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: q.cookie})
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "owned-recipient-actual-regression")
	return request
}
func ownedRecipientWireV1(t *testing.T, via string, response *httptest.ResponseRecorder, operation string) recipientResponse {
	t.Helper()
	var row recipientResponse
	if via == "MCP" {
		text := fieldMCPTextE2E(t, response, false)
		if operation == "delete" {
			return row
		}
		if err := json.Unmarshal([]byte(text), &row); err != nil {
			t.Fatal(err)
		}
	} else {
		if response.Code != recipientSuccessStatus(operation) {
			t.Fatalf("actual recipient %s=%d %s", operation, response.Code, response.Body.String())
		}
		if operation != "delete" {
			if err := json.Unmarshal(response.Body.Bytes(), &row); err != nil {
				t.Fatal(err)
			}
		}
	}
	return row
}
func ownedRecipientFreshEventV1(t *testing.T, q *ownedPublicReadFixtureV1, event, document, recipient uuid.UUID, kind string) {
	t.Helper()
	var exact bool
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT e.document_id=$2 AND e.org_id=$3 AND e.recipient_id=$4 AND e.kind=$5 AND e.actor_user_id=$6
 AND c.document_id=e.document_id AND c.org_id=e.org_id
 AND c.payload_wire_bytes=octet_length(e.payload_json::text)
 AND c.measurement_server_version_num=current_setting('server_version_num')::integer
 FROM events e JOIN html_snapshot_event_payload_sizes_v1 c ON c.event_id=e.id WHERE e.id=$1`, event, document, q.f.org, recipient, kind, q.f.user.ID).Scan(&exact)
	if err != nil || !exact {
		t.Fatal("actual recipient event lacks exact fresh M94/source/actor identity", err)
	} //nolint:rawsql -- actual committed fresh event oracle only
}
func ownedRecipientSourceSnapshotV1(t *testing.T, q *ownedPublicReadFixtureV1) string {
	t.Helper()
	var caches string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'policy',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY document_id),'[]'::jsonb) FROM document_signing_policy_sizes_v1 p WHERE org_id=$1),
 'fields',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY field_id),'[]'::jsonb) FROM field_signing_policy_sizes_v1 p WHERE org_id=$1),
 'events',(SELECT coalesce(jsonb_agg(to_jsonb(p) ORDER BY event_id),'[]'::jsonb) FROM html_snapshot_event_payload_sizes_v1 p WHERE org_id=$1))::text`, q.f.org).Scan(&caches)
	if err != nil {
		t.Fatal(err)
	}
	return recipientMCPSnapshotE2E(t, q.f) + "\n" + caches //nolint:rawsql -- bounded complete fixture refusal oracle only
}

func TestOwnedOrdinaryRecipientsActualRESTMCPSourceAuditAndLastUseE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-owned-recipient", SecretKey: "synthetic-owned-recipient-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Versions: versions.New(q.f.q), Storage: q.f.s.Storage, Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL})
	if err = malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	var current atomic.Pointer[ownedPlainAuditGateV1]
	q.f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, entry audit.Entry) {
		g := current.Load()
		if g == nil || entry.Kind != g.kind {
			return
		}
		g.eventID = id
		g.entry = entry
		close(g.started)
		<-g.release
		close(g.returned)
	})
	var lastDocument, foreignRecipient uuid.UUID
	for _, source := range []string{"pdf", "blocks"} {
		var document generated.Document
		if source == "pdf" {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "create_pdf_document", "", nil, fieldBrowserPDF("Actual ordinary recipient source")))
			if response.Code != http.StatusCreated {
				t.Fatalf("actual PDF intake=%d %s", response.Code, response.Body.String())
			}
			var envelope struct {
				Document generated.Document `json:"document"`
			}
			if err = json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
				t.Fatal(err)
			}
			document = envelope.Document
		} else {
			response := submitDocumentCreationE2E(q.f, q.f.ctx, "rest", q.cookie, map[string]any{"name": "Actual block recipient source", "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Original ordinary block document"}]}`)})
			if response.Code != http.StatusCreated {
				t.Fatalf("actual blocks create=%d %s", response.Code, response.Body.String())
			}
			if err = json.Unmarshal(response.Body.Bytes(), &document); err != nil {
				t.Fatal(err)
			}
		}
		if document.ID == uuid.Nil {
			t.Fatal("actual fresh document missing")
		}
		lastDocument = document.ID
		ownedPlainAssertDrainedV1(t, q)
		for _, via := range []string{"REST", "MCP"} {
			t.Run(source+"/"+via, func(t *testing.T) {
				recipient := uuid.Nil
				fieldID := uuid.Nil
				var original *generated.Recipient
				for _, operation := range []string{"create", "update", "delete"} {
					input := map[string]any{"email": " owned-" + strings.ToLower(via) + "@example.test ", "name": " Original recipient 雪 ", "role": "buyer", "locale": "en-US", "order_index": 7}
					if operation == "update" {
						input = map[string]any{"name": " Updated recipient 雪 "}
					}
					if operation == "delete" {
						input = nil
					}
					if operation == "delete" && source == "pdf" {
						response := httptest.NewRecorder()
						q.f.s.Routes().ServeHTTP(response, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{"document_id": document.ID.String(), "recipient_id": recipient.String(), "type": "dropdown", "page": 1, "x_pct": 20, "y_pct": 30, "w_pct": 20, "h_pct": 6, "options": map[string]any{"choices": []string{"First", "Second"}}}, nil))
						if response.Code != http.StatusCreated {
							t.Fatalf("actual assigned field=%d %s", response.Code, response.Body.String())
						}
						var field struct{ ID uuid.UUID }
						if err := json.Unmarshal(response.Body.Bytes(), &field); err != nil || field.ID == uuid.Nil {
							t.Fatal("actual assigned field ID missing", err)
						}
						fieldID = field.ID
						ownedPlainAssertDrainedV1(t, q)
					}
					gate := newOwnedPlainAuditGateV1(recipientAuditKind(operation))
					current.Store(gate)
					t.Cleanup(gate.unblock)
					response := newOwnedRecipientResponseGateV1()
					t.Cleanup(response.unblock)
					done := make(chan struct{})
					go func() {
						defer close(done)
						q.f.s.Routes().ServeHTTP(response, ownedRecipientRequestV1(t, q, via, operation, key.Plaintext, document.ID, recipient, input))
					}()
					ownedPlainAwaitV1(t, response.started, "actual recipient response "+operation)
					refused := via == "REST" && response.status != recipientSuccessStatus(operation)
					if via == "MCP" {
						var rpc struct {
							Result struct {
								IsError bool `json:"isError"`
							} `json:"result"`
							Error json.RawMessage `json:"error"`
						}
						if json.Unmarshal(response.preview, &rpc) != nil || rpc.Result.IsError || len(rpc.Error) > 0 {
							refused = true
						}
					}
					if refused {
						response.unblock()
						ownedPlainAwaitV1(t, done, "actual refused recipient response")
						t.Fatalf("actual %s %s recipient %s refused: status=%d body=%s", source, via, operation, response.Code, response.Body.String())
					}
					ownedPlainAwaitV1(t, gate.started, "actual joined recipient audit")
					if gate.entry.DocumentID == nil || *gate.entry.DocumentID != document.ID || gate.entry.RecipientID == nil || gate.entry.ActorUserID == nil || *gate.entry.ActorUserID != q.f.user.ID || gate.entry.OrgID != q.f.org {
						t.Fatal("original recipient audit identity lost")
					}
					if operation == "create" {
						recipient = *gate.entry.RecipientID
					}
					if *gate.entry.RecipientID != recipient {
						t.Fatal("original recipient UUID changed")
					}
					ownedRecipientFreshEventV1(t, q, gate.eventID, document.ID, recipient, recipientAuditKind(operation))
					ownedPlainAssertRetainedV1(t, q, "actual recipient response and joined audit")
					if via == "MCP" && operation == "update" {
						gate.unblock()
						ownedPlainAwaitV1(t, gate.returned, "recipient hook first")
						ownedPlainAssertRetainedV1(t, q, "recipient response after hook")
						response.unblock()
						ownedPlainAwaitV1(t, done, "recipient response last use")
					} else {
						response.unblock()
						ownedPlainAwaitV1(t, done, "recipient response first")
						ownedPlainAssertRetainedV1(t, q, "recipient hook after response")
						gate.unblock()
						ownedPlainAwaitV1(t, gate.returned, "recipient hook last use")
					}
					current.Store(nil)
					wire := ownedRecipientWireV1(t, via, response.ResponseRecorder, operation)
					if operation != "delete" {
						if wire.ID != recipient || wire.DocumentID != document.ID || wire.Email != "owned-"+strings.ToLower(via)+"@example.test" || wire.Role != "buyer" || wire.Locale != "en" || wire.OrderIndex != 7 || wire.Status != "pending" {
							t.Fatalf("original canonical recipient response changed: %+v", wire)
						}
						stored, err := q.f.q.GetRecipient(q.f.ctx, generated.GetRecipientParams{ID: recipient, OrgID: q.f.org})
						if err != nil {
							t.Fatal(err)
						}
						if operation == "create" {
							original = stored
							if len(stored.MagicTokenHash) != 32 || !stored.MagicTokenExpiresAt.Valid {
								t.Fatal("original magic token policy missing")
							}
						} else {
							if stored.Name != "Updated recipient 雪" || !bytes.Equal(stored.MagicTokenHash, original.MagicTokenHash) || stored.MagicTokenExpiresAt != original.MagicTokenExpiresAt || stored.Status != original.Status || stored.CreatedAt != original.CreatedAt {
								t.Fatal("partial update changed omitted identity/token/status/stamps")
							}
						}
					} else {
						var recipients, fields, fieldCaches int
						err := q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*) FROM recipients WHERE id=$1),(SELECT count(*) FROM document_fields WHERE recipient_id=$1),(SELECT count(*) FROM field_signing_policy_sizes_v1 WHERE field_id=$2)`, recipient, fieldID).Scan(&recipients, &fields, &fieldCaches)
						if err != nil || recipients != 0 || fields != 0 || fieldCaches != 0 {
							t.Fatal("actual deletion lost original recipient/assigned-field cascade", err)
						} //nolint:rawsql -- actual cascade/read oracle only
						ownedRecipientFreshEventV1(t, q, gate.eventID, document.ID, recipient, audit.KindRecipientDeleted)
					}
					ownedPlainAssertDrainedV1(t, q)
				}
			})
		}
		if source == "pdf" {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, ownedRecipientRequestV1(t, q, "REST", "create", "", document.ID, uuid.Nil, map[string]any{"email": "foreign-recipient@example.test", "name": "Actual other document participant"}))
			row := ownedRecipientWireV1(t, "REST", response, "create")
			foreignRecipient = row.ID
			if foreignRecipient == uuid.Nil {
				t.Fatal("actual foreign source recipient absent")
			}
			ownedPlainAssertDrainedV1(t, q)
		}
	}
	t.Run("exact recipient source cannot cross actual parent scope", func(t *testing.T) {
		before := ownedRecipientSourceSnapshotV1(t, q)
		for _, via := range []string{"REST", "MCP"} {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, ownedRecipientRequestV1(t, q, via, "update", key.Plaintext, lastDocument, foreignRecipient, map[string]any{"name": "Wrong parent"}))
			if via == "REST" {
				if response.Code != http.StatusNotFound {
					t.Fatalf("actual foreign parent=%d %s", response.Code, response.Body.String())
				}
			} else if got := fieldMCPTextE2E(t, response, true); got != "recipient not found" {
				t.Fatalf("actual foreign recipient refusal=%q", got)
			}
			ownedPlainAssertDrainedV1(t, q)
		}
		if ownedRecipientSourceSnapshotV1(t, q) != before {
			t.Fatal("foreign recipient request changed genuine parent/source/audit")
		}
	})
	assertImportStorageE2E(t, peer, 1, 0, 1)
	t.Run("original admitted key rechecked after actual parent wait", func(t *testing.T) {
		admitted, keyID := mintRecipientMCPKeyE2E(t, q.f, false, 0)
		before := ownedRecipientSourceSnapshotV1(t, q)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		var locked uuid.UUID
		if err = blocked.QueryRow(q.f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", lastDocument, q.f.org).Scan(&locked); err != nil || locked != lastDocument {
			t.Fatal(err)
		} //nolint:rawsql -- exact scalar actual parent lock only
		result := make(chan *httptest.ResponseRecorder, 1)
		request := ownedRecipientRequestV1(t, q, "MCP", "create", admitted.Plaintext, lastDocument, uuid.Nil, map[string]any{"email": "refused@example.test", "name": "Revoked actual key"})
		go func() {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, request)
			result <- response
		}()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetRecipientMutationSourceHeaderV1", "transactionid")
		if _, err = q.f.pool.Exec(q.f.ctx, "DELETE FROM api_keys WHERE id=$1 AND org_id=$2", keyID, q.f.org); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- actual admitted-key revocation during genuine parent wait
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		if got := fieldMCPTextE2E(t, receiveSessionOperationE2E(t, result), true); got != auth.ErrMutationPermissionRevoked.Error() {
			t.Fatalf("original revoked key verdict=%q", got)
		}
		if ownedRecipientSourceSnapshotV1(t, q) != before {
			t.Fatal("refused recipient changed source/cache/audit/credential state")
		}
		ownedPlainAssertDrainedV1(t, q)
	})
	t.Run("original role precedes missing measurement and never repairs", func(t *testing.T) {
		if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", lastDocument, q.f.org); err != nil || tag.RowsAffected() != 1 {
			t.Fatal(err)
		} //nolint:rawsql -- explicit negative cache deletion only
		before := ownedRecipientSourceSnapshotV1(t, q)
		blocked, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer blocked.Rollback(context.Background())
		var locked uuid.UUID
		if err = blocked.QueryRow(q.f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", lastDocument, q.f.org).Scan(&locked); err != nil || locked != lastDocument {
			t.Fatal(err)
		} //nolint:rawsql -- exact scalar actual parent lock only
		result := make(chan *httptest.ResponseRecorder, 1)
		request := ownedRecipientRequestV1(t, q, "REST", "create", "", lastDocument, uuid.Nil, map[string]any{"email": "refused@example.test", "name": "Demoted actual member"})
		go func() {
			response := httptest.NewRecorder()
			q.f.s.Routes().ServeHTTP(response, request)
			result <- response
		}()
		awaitSessionOperationLockE2E(t, q.f.ctx, q.f.pool, "-- name: GetRecipientMutationSourceHeaderV1", "transactionid")
		if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
		if err = blocked.Commit(q.f.ctx); err != nil {
			t.Fatal(err)
		}
		if response := receiveSessionOperationE2E(t, result); response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "permission or credential revoked") {
			t.Fatalf("original role/cache order=%d %s", response.Code, response.Body.String())
		}
		if _, err = q.f.q.UpdateUserRole(q.f.ctx, generated.UpdateUserRoleParams{ID: q.f.user.ID, OrgID: q.f.org, Role: "owner"}); err != nil {
			t.Fatal(err)
		}
		response := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(response, ownedRecipientRequestV1(t, q, "MCP", "create", key.Plaintext, lastDocument, uuid.Nil, map[string]any{"email": "refused@example.test", "name": "Missing genuine source"}))
		if got := fieldMCPTextE2E(t, response, true); !strings.Contains(got, "owned HTML revision read unavailable") {
			t.Fatalf("missing source did not refuse: %q", got)
		}
		if ownedRecipientSourceSnapshotV1(t, q) != before {
			t.Fatal("missing source refusal changed source/cache/audit state")
		}
		var cache int
		if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", lastDocument, q.f.org).Scan(&cache); err != nil || cache != 0 {
			t.Fatal("recipient reader repaired missing measurement", err)
		} //nolint:rawsql -- continued exact absence oracle
		ownedPlainAssertDrainedV1(t, q)
	})
}

func TestOwnedRecipientDispatchPreservesActualHTMLContractRulesE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, Billing: q.f.s.Billing, PDFCreationSessions: q.runtime.SessionsV1(), PublicURL: q.f.s.PublicURL})
	document := createHTMLContractDocumentE2E(t, q.f, q.template, q.cookie)
	var actualHTML bool
	var recipients int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT source_kind='pdf' AND html_source_json IS NOT NULL AND html_current_source_json IS NOT NULL,(SELECT count(*) FROM recipients WHERE document_id=d.id) FROM documents d WHERE id=$1 AND org_id=$2", document.ID, q.f.org).Scan(&actualHTML, &recipients); err != nil || !actualHTML || recipients != 2 {
		t.Fatal("actual reviewed HTML contract prerequisite missing", err)
	} //nolint:rawsql -- scalar actual source/required parties oracle
	if tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM document_signing_policy_sizes_v1 WHERE document_id=$1 AND org_id=$2", document.ID, q.f.org); err != nil || tag.RowsAffected() != 1 {
		t.Fatal(err)
	} //nolint:rawsql -- explicit native-cache absence, original HTML recipient engine never needs repair
	ownedPlainAssertDrainedV1(t, q)
	before := ownedRecipientSourceSnapshotV1(t, q)
	key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	for _, via := range []string{"REST", "MCP"} {
		response := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(response, ownedRecipientRequestV1(t, q, via, "create", key.Plaintext, document.ID, uuid.Nil, map[string]any{"email": "extra@example.test", "name": "Additional contract party"}))
		if via == "REST" {
			if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "reviewed contract recipients are created from the printed party information") {
				t.Fatalf("original HTML recipient rule=%d %s", response.Code, response.Body.String())
			}
		} else if got := fieldMCPTextE2E(t, response, true); !strings.Contains(got, "reviewed contract recipients are created from the printed party information") {
			t.Fatalf("original MCP HTML recipient rule=%q", got)
		}
		ownedPlainAssertDrainedV1(t, q)
	}
	if ownedRecipientSourceSnapshotV1(t, q) != before {
		t.Fatal("original HTML recipient refusal changed source/audit/cache or repaired native absence")
	}
}
