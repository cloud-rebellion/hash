//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/mcp"
)

// C1 (R2 twins): the rename, field-delete, reminder-policy and routing-tier
// writers log a document event through Audit.LogTx. audit.Logger measures that
// event itself, in the same transaction. Before that, each of these left an
// event with no html_snapshot_event_payload_sizes_v1 row and every later revise
// of the HTML draft answered 503 "retry later" forever.

func unmeasuredDocumentEventsE2E(t *testing.T, f lifecycleAuthorizationFixture, doc uuid.UUID) (total, unmeasured int) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx, `SELECT count(*), count(*) FILTER (WHERE NOT EXISTS (SELECT 1 FROM html_snapshot_event_payload_sizes_v1 s WHERE s.event_id=e.id AND s.document_id=e.document_id AND s.org_id=e.org_id)) FROM events e WHERE e.document_id=$1 AND e.org_id=$2`, doc, f.org).Scan(&total, &unmeasured); err != nil { //nolint:rawsql -- measurement coverage inspection
		t.Fatal(err)
	}
	return total, unmeasured
}

func reloadDocumentE2E(t *testing.T, f *lifecycleAuthorizationFixture) *generated.Document {
	t.Helper()
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: f.doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	f.doc = doc
	return doc
}

func logTxMCPRoutingTierE2E(t *testing.T, f lifecycleAuthorizationFixture, key string) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "set_document_routing_tier", "arguments": map[string]any{"document_id": f.doc.ID.String(), "routing_tier": "SES"}}})
	r := httptest.NewRequest(http.MethodPost, f.s.PublicURL+"/mcp", strings.NewReader(string(body))).WithContext(f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(w, r)
	return w
}

func TestHTMLDraftAuditLogTxWritersLeaveDraftRevisableE2E(t *testing.T) {
	cases := []struct {
		name  string
		apply func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string)
	}{
		{"rename", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			doc := reloadDocumentE2E(t, f)
			body, _ := json.Marshal(map[string]any{"name": "Renamed HTML draft", "expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)})
			if w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+doc.ID.String(), string(body), cookie); w.Code != http.StatusOK {
				t.Fatalf("rename=%d %s", w.Code, w.Body.String())
			}
		}},
		{"field-delete", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			doc := reloadDocumentE2E(t, f)
			path := "/api/v1/documents/" + doc.ID.String()
			commitment, _ := htmlsource.Commitment(doc)
			review, _ := json.Marshal(htmlDocumentReviewInput{ExpectedUpdatedAt: doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
			if w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/html/review", string(review), cookie); w.Code != http.StatusOK {
				t.Fatalf("review=%d %s", w.Code, w.Body.String())
			}
			doc = reloadDocumentE2E(t, f)
			proof := map[string]any{"expected_pdf_sha256": hex.EncodeToString(doc.PdfSha256), "expected_html_source_commitment": commitment}
			add, _ := json.Marshal(addFieldInput{Type: "text", Page: 1, XPct: 10, YPct: 10, WPct: 20, HPct: 5, ExpectedPDFSHA256: hex.EncodeToString(doc.PdfSha256), ExpectedHTMLSourceCommitment: commitment})
			w := submitSessionOperationE2E(f.s, http.MethodPost, path+"/fields", string(add), cookie)
			var placed struct {
				ID uuid.UUID `json:"id"`
			}
			if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &placed) != nil || placed.ID == uuid.Nil {
				t.Fatalf("field placement=%d %s", w.Code, w.Body.String())
			}
			// The placement itself is a writer too, so the draft must already be
			// revisable-clean before the delete under test.
			if _, unmeasured := unmeasuredDocumentEventsE2E(t, *f, doc.ID); unmeasured != 0 {
				t.Fatalf("field placement left %d unmeasured events", unmeasured)
			}
			del, _ := json.Marshal(proof)
			if w := submitSessionOperationE2E(f.s, http.MethodDelete, "/api/v1/fields/"+placed.ID.String(), string(del), cookie); w.Code != http.StatusNoContent {
				t.Fatalf("field delete=%d %s", w.Code, w.Body.String())
			}
		}},
		{"reminder-policy", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			doc := reloadDocumentE2E(t, f)
			body, _ := json.Marshal(map[string]any{"expected_revision": 0, "expected_updated_at": doc.UpdatedAt.Time.UTC(), "mode": "interval", "interval_days": 2, "max_fires": 3})
			if w := submitSessionOperationE2E(f.s, http.MethodPut, "/api/v1/documents/"+doc.ID.String()+"/reminder-policy", string(body), cookie); w.Code != http.StatusOK {
				t.Fatalf("reminder policy=%d %s", w.Code, w.Body.String())
			}
		}},
		{"routing-tier-rest", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			doc := reloadDocumentE2E(t, f)
			f.s.EIDAS = eidas.New(f.q)
			if w := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/documents/"+doc.ID.String()+"/routing-tier", `{"routing_tier":"SES"}`, cookie); w.Code != http.StatusOK {
				t.Fatalf("routing tier REST=%d %s", w.Code, w.Body.String())
			}
		}},
		// The non-transactional appender shares the insert, so it is measured too
		// (collaboration join and leave, evidence export and the send engine use it).
		{"audit-log-direct", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			doc := reloadDocumentE2E(t, f)
			actor := f.user.ID
			if _, err := f.s.Audit.Log(f.ctx, audit.Entry{OrgID: f.org, ActorUserID: &actor, DocumentID: &doc.ID, Kind: audit.KindCollabPeerJoined, Payload: map[string]any{"peer_id": "synthetic"}}); err != nil {
				t.Fatal(err)
			}
		}},
		{"routing-tier-mcp", func(t *testing.T, f *lifecycleAuthorizationFixture, cookie string) {
			reloadDocumentE2E(t, f)
			f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
			f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Send: f.s.Send, EIDAS: eidas.New(f.q), PublicURL: f.s.PublicURL, Environment: f.s.Environment, Billing: f.s.Billing})
			mint, _ := mintDocumentMetadataKeyE2E(t, *f, false)
			w := logTxMCPRoutingTierE2E(t, *f, mint.Plaintext)
			var reply struct {
				Result struct {
					IsError bool `json:"isError"`
				} `json:"result"`
				Error json.RawMessage `json:"error"`
			}
			if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Result.IsError || len(reply.Error) != 0 {
				t.Fatalf("routing tier MCP=%d %s", w.Code, w.Body.String())
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, _, _, _, cookie := setupHTMLRevisionE2E(t)
			before, unmeasured := unmeasuredDocumentEventsE2E(t, f, f.doc.ID)
			if unmeasured != 0 {
				t.Fatalf("a fresh draft already has %d unmeasured events", unmeasured)
			}
			tc.apply(t, &f, cookie)
			total, unmeasured := unmeasuredDocumentEventsE2E(t, f, f.doc.ID)
			if total <= before {
				t.Fatalf("the mutation wrote no document event (events %d -> %d); the test proves nothing", before, total)
			}
			if unmeasured != 0 {
				t.Errorf("%d of %d document events have no payload size row after %s", unmeasured, total, tc.name)
			}
			doc := reloadDocumentE2E(t, &f)
			if w := submitRevisionE2E(t, f, revisionInputE2E(t, doc), cookie); w.Code != http.StatusCreated {
				t.Fatalf("revise after %s=%d %s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

// Control: the same writers on a document that is not an HTML draft keep
// working, and their events are measured the same way.
func TestNonHTMLDocumentAuditLogTxWritersStillWorkE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", cookie, map[string]any{"name": "Plain control", "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Synthetic control terms"}]}`), "variables_json": map[string]string{}}), "rest")
	path := "/api/v1/documents/" + doc.ID.String()
	w := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, path, map[string]any{"name": "Plain control renamed", "expected_updated_at": doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano)})
	if w.Code != http.StatusOK {
		t.Fatalf("rename=%d %s", w.Code, w.Body.String())
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPut, path+"/reminder-policy", map[string]any{"expected_revision": 0, "expected_updated_at": current.UpdatedAt.Time.UTC(), "mode": "interval", "interval_days": 2, "max_fires": 3})
	if w.Code != http.StatusOK {
		t.Fatalf("reminder policy=%d %s", w.Code, w.Body.String())
	}
	f.s.EIDAS = eidas.New(f.q)
	w = ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, path+"/routing-tier", map[string]any{"routing_tier": "SES"})
	if w.Code != http.StatusOK {
		t.Fatalf("routing tier=%d %s", w.Code, w.Body.String())
	}
	total, unmeasured := unmeasuredDocumentEventsE2E(t, f, doc.ID)
	if total < 3 || unmeasured != 0 {
		t.Fatalf("control document events=%d unmeasured=%d", total, unmeasured)
	}
}
