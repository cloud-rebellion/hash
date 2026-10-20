//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ownedTopologyCallV1(t *testing.T, f lifecycleAuthorizationFixture, transport, credential, operation string, root, child uuid.UUID, ids []uuid.UUID) *httptest.ResponseRecorder {
	t.Helper()
	args := map[string]any{}
	tool, path := "", ""
	switch operation {
	case "create":
		tool = "create_envelope"
		args["name"] = "Actual native envelope"
		args["child_ids"] = ids
	case "promote":
		tool = "promote_to_envelope"
		args["document_id"] = root
		path = "/api/v1/documents/" + root.String() + "/promote-to-envelope"
	case "attach":
		tool = "attach_to_envelope"
		args["envelope_id"] = root
		args["child_id"] = child
		path = "/api/v1/envelopes/" + root.String() + "/attach"
	case "detach":
		tool = "detach_from_envelope"
		args["child_id"] = child
		path = "/api/v1/envelopes/" + root.String() + "/detach"
	case "reorder":
		tool = "reorder_envelope_children"
		args["envelope_id"] = root
		args["child_id_order"] = ids
		path = "/api/v1/envelopes/" + root.String() + "/reorder"
	default:
		t.Fatal("unknown test operation")
	}
	if transport == "mcp" {
		return submitRecipientMCPE2E(f, tool, credential, args)
	}
	if operation == "reorder" {
		args = map[string]any{"child_ids": ids}
	} else if operation == "attach" || operation == "detach" {
		args = map[string]any{"child_id": child}
	}
	body, _ := json.Marshal(args)
	request := httptest.NewRequest(http.MethodPost, f.s.PublicURL+path, bytes.NewReader(body)).WithContext(f.ctx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", f.s.PublicURL)
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: credential})
	response := httptest.NewRecorder()
	f.s.Routes().ServeHTTP(response, request)
	return response
}
func ownedTopologySucceededV1(t *testing.T, w *httptest.ResponseRecorder, transport string) {
	t.Helper()
	if transport == "mcp" {
		assertLifecycleMCPResultE2E(t, w, false)
	} else if w.Code != http.StatusOK {
		t.Fatalf("actual topology=%d %s", w.Code, w.Body.String())
	}
}

// Native measured block documents enter the actual public topology surfaces.
// Every existing source/cache must survive membership writes byte-for-byte;
// the actual root audit must acquire intrinsic M94 at the real append. This
// supplements the separate full family Send/sign/evidence journey.
func TestOwnedEnvelopeTopologyActualRESTAndMCPPreservesSourcesE2E(t *testing.T) {
	for _, transport := range []string{"rest", "mcp"} {
		t.Run(transport, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			ownedCreationPrepareProPlanV1(t, q)
			f := q.f
			f.s.Envelopes = envelopes.New(f.q)
			credential := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			if transport == "mcp" {
				f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
				f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, Envelopes: f.s.Envelopes, PDFCreationSessions: q.runtime.SessionsV1()})
				key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
				credential = key.Plaintext
			}
			var ids []uuid.UUID
			beforeSources := map[uuid.UUID]*generated.Document{}
			beforeCaches := map[uuid.UUID]string{}
			create := func(name string) uuid.UUID {
				doc := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, transport, credential, map[string]any{"name": name, "source_kind": "blocks"}), transport)
				source, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				beforeSources[doc.ID] = source
				beforeCaches[doc.ID] = ownedBlockCacheStateV1(t, f, doc.ID)
				return doc.ID
			}
			for i := 0; i < 3; i++ {
				ids = append(ids, create(fmt.Sprintf("Native topology member %d", i)))
			}
			root, spare := ids[0], uuid.Nil
			if transport == "mcp" {
				spare = root
				root = ownedBlockTestDocumentV1(t, ownedTopologyCallV1(t, f, transport, credential, "create", uuid.Nil, uuid.Nil, ids[1:]), transport).ID
				source, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: root, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				beforeSources[root] = source
				beforeCaches[root] = ownedBlockCacheStateV1(t, f, root)
			} else {
				ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "promote", root, uuid.Nil, nil), transport)
				for _, child := range ids[1:] {
					ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "attach", root, child, nil), transport)
				}
				spare = create("Independent envelope URI root")
			}
			ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "reorder", root, uuid.Nil, []uuid.UUID{ids[2], ids[1]}), transport)
			for index, id := range []uuid.UUID{ids[2], ids[1]} {
				row, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
				if err != nil || !row.ParentEnvelopeID.Valid || uuid.UUID(row.ParentEnvelopeID.Bytes) != root || !row.EnvelopePosition.Valid || row.EnvelopePosition.Int32 != int32(index+1) {
					t.Fatalf("actual ordering/topology changed: %v", err)
				}
			}
			if transport == "rest" {
				before := f.snapshot(t)
				wrong := ownedTopologyCallV1(t, f, transport, credential, "detach", spare, ids[1], nil)
				if wrong.Code >= 200 && wrong.Code < 300 {
					t.Fatal("unrelated URI envelope detached another instrument")
				}
				if f.snapshot(t) != before {
					t.Fatal("wrong URI detached or audited a different instrument")
				}
			}
			ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "detach", root, ids[1], nil), transport)
			detached, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: ids[1], OrgID: f.org})
			if err != nil || detached.ParentEnvelopeID.Valid || detached.EnvelopePosition.Valid {
				t.Fatalf("actual detach did not clear membership: %v", err)
			}
			ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "promote", spare, uuid.Nil, nil), transport)
			ownedTopologySucceededV1(t, ownedTopologyCallV1(t, f, transport, credential, "attach", spare, ids[1], nil), transport)
			var touched []uuid.UUID
			for id, before := range beforeSources {
				touched = append(touched, id)
				after, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: id, OrgID: f.org})
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(after.BlocksJson, before.BlocksJson) || !bytes.Equal(after.VariablesJson, before.VariablesJson) || !bytes.Equal(after.Metadata, before.Metadata) || !bytes.Equal(after.MetadataRedactionReport, before.MetadataRedactionReport) || !bytes.Equal(after.HtmlSourceJson, before.HtmlSourceJson) || !bytes.Equal(after.HtmlCurrentSourceJson, before.HtmlCurrentSourceJson) {
					t.Fatal("membership mutation changed original source/report/metadata")
				}
				if ownedBlockCacheStateV1(t, f, id) != beforeCaches[id] {
					t.Fatal("topology unnecessarily invalidated or remeasured genuine old M91/M92/M93")
				}
			}
			var unmeasured int
			err = f.pool.QueryRow(f.ctx, "SELECT count(*) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 m ON m.event_id=e.id WHERE e.document_id=ANY($1::uuid[]) AND e.kind='document.updated' AND m.event_id IS NULL", touched).Scan(&unmeasured)
			if err != nil || unmeasured != 0 {
				t.Fatalf("actual topology audit missing intrinsic measurement: %d %v", unmeasured, err)
			}
			if _, err = f.pool.Exec(f.ctx, "DELETE FROM html_creation_response_sizes_v1 WHERE document_id=$1", ids[1]); err != nil {
				t.Fatal(err)
			}
			cacheBefore := ownedBlockCacheStateV1(t, f, ids[1])
			before := f.snapshot(t)
			missing := ownedTopologyCallV1(t, f, transport, credential, "detach", spare, ids[1], nil)
			if transport == "rest" {
				if missing.Code != http.StatusServiceUnavailable {
					t.Fatalf("missing actual child cache=%d %s", missing.Code, missing.Body.String())
				}
			} else {
				assertLifecycleMCPResultE2E(t, missing, true)
			}
			if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, ids[1]) != cacheBefore {
				t.Fatal("topology repaired old source or committed an unbounded child mutation")
			}
			ownedCreationAssertDrainedV1(t, q, 2)
		})
	}
}
