//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

// Actual owned PostgreSQL, native PDF intake/worker, original MCP middleware and
// authenticated attachment reader. Only the existing versioned S3 peer is
// synthetic. No live data, renderer-provider or scanner-efficacy claim follows.
func metadataCacheFixture756(t *testing.T) *ownedPublicReadFixtureV1 {
	t.Helper()
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	peer := &importStoragePeer{objects: make(map[string][]byte)}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	var err error
	q.f.s.Storage, err = storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-metadata", SecretKey: "synthetic-metadata-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
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
	return q
}

func metadataCacheCreate756(t *testing.T, q *ownedPublicReadFixtureV1, via, key string) *generated.Document {
	t.Helper()
	w := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(w, ownedPlainRequestV1(t, q, via, "create_pdf_document", key, nil, fieldBrowserPDF("Exact synthetic metadata cache proposal")))
	if via == "MCP" {
		assertLifecycleMCPResultE2E(t, w, false)
	} else if w.Code != http.StatusCreated {
		t.Fatalf("native intake=%d %s", w.Code, w.Body.String())
	}
	name := "Owned PDF via " + via
	var id uuid.UUID
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT id FROM documents WHERE org_id=$1 AND name=$2`, q.f.org, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	doc, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: id, OrgID: q.f.org})
	if err != nil {
		t.Fatal(err)
	}
	q.f.doc = doc
	ownedPlainFreshDocumentV1(t, q, id)
	ownedPlainAssertDrainedV1(t, q)
	return doc
}

func metadataCacheInventory756(t *testing.T, q *ownedPublicReadFixtureV1, id uuid.UUID, want int) {
	t.Helper()
	w := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+id.String()+"/attachments", "", q.cookie)
	if w.Code != want {
		t.Fatalf("actual attachment inventory=%d want%d %s", w.Code, want, w.Body.String())
	}
	if want == http.StatusOK {
		var v struct {
			DocumentID uuid.UUID         `json:"document_id"`
			Generation string            `json:"generation"`
			Members    []json.RawMessage `json:"members"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil || v.DocumentID != id || v.Generation != "0" || len(v.Members) != 0 {
			t.Fatalf("wrong exact empty observation: %s %v", w.Body.String(), err)
		}
	}
}

func TestMetadataCache756ActualPDFCreationAttachAndInventoryE2E(t *testing.T) {
	for _, via := range []string{"REST", "MCP"} {
		t.Run(via, func(t *testing.T) {
			q := metadataCacheFixture756(t)
			key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
			old := metadataCacheCreate756(t, q, via, key.Plaintext)
			metadataCacheInventory756(t, q, old.ID, http.StatusOK)
			// First real merge establishes a key that the next merge must retain.
			first := submitRecipientMCPE2E(q.f, "attach_metadata", key.Plaintext, map[string]any{"document_id": old.ID.String(), "key": "retained", "value": "First exact value"})
			assertLifecycleMCPResultE2E(t, first, false)
			ownedPlainFreshDocumentV1(t, q, old.ID)
			metadataCacheInventory756(t, q, old.ID, http.StatusOK)
			ownedPlainAssertDrainedV1(t, q)

			var gate atomic.Pointer[ownedPlainAuditGateV1]
			q.f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
				g := gate.Load()
				if g == nil || e.Kind != audit.KindDocumentUpdated || e.DocumentID == nil || *e.DocumentID != old.ID {
					return
				}
				g.entry = e
				g.eventID = id
				close(g.started)
				<-g.release
				close(g.returned)
			})
			g := newOwnedPlainAuditGateV1(audit.KindDocumentUpdated)
			gate.Store(g)
			response := newOwnedPlainResponseGateV1()
			done := make(chan struct{})
			defer func() {
				response.unblock()
				g.unblock()
				ownedPlainAwaitV1(t, done, "metadata response cleanup")
				gate.Store(nil)
			}()
			args := map[string]any{"document_id": old.ID.String(), "key": "quote 雪", "value": "Exact \"quoted\" value\nSecond line <literal>"}
			request := ownedPlainRequestV1(t, q, "MCP", "attach_metadata", key.Plaintext, args, nil)
			go func() { defer close(done); q.f.s.Routes().ServeHTTP(response, request) }()
			ownedPlainAwaitV1(t, response.started, "actual metadata response")
			var envelope struct {
				Result struct{ IsError bool }
				Error  json.RawMessage
			}
			if json.Unmarshal(response.preview, &envelope) != nil || envelope.Result.IsError || len(envelope.Error) > 0 {
				t.Fatalf("actual metadata mutation refused: %s", response.preview)
			}
			ownedPlainAwaitV1(t, g.started, "metadata audit last use")
			ownedPlainAssertRetainedV1(t, q, "metadata response and original audit hook")
			current, err := q.f.q.GetDocument(q.f.ctx, generated.GetDocumentParams{ID: old.ID, OrgID: q.f.org})
			if err != nil {
				t.Fatal(err)
			}
			if current.PdfStorageKey != old.PdfStorageKey || current.PdfStorageVersionID != old.PdfStorageVersionID || !bytes.Equal(current.PdfSha256, old.PdfSha256) || current.RequiresSignature != old.RequiresSignature {
				t.Fatal("metadata edit rewrote the PDF/signing mode")
			}
			var metadata map[string]string
			if json.Unmarshal(current.Metadata, &metadata) != nil || metadata["retained"] != "First exact value" || metadata["quote 雪"] != args["value"] {
				t.Fatal("original metadata merge changed unrelated keys or exact values")
			}
			ownedPlainFreshDocumentV1(t, q, old.ID)
			var measured bool
			if err = q.f.pool.QueryRow(q.f.ctx, `SELECT s.document_id=e.document_id AND s.org_id=e.org_id AND s.payload_wire_bytes=octet_length(e.payload_json::text) AND s.measurement_server_version_num=current_setting('server_version_num')::integer FROM events e JOIN html_snapshot_event_payload_sizes_v1 s ON s.event_id=e.id WHERE e.id=$1 AND e.document_id=$2 AND e.org_id=$3`, g.eventID, old.ID, q.f.org).Scan(&measured); err != nil || !measured {
				t.Fatal("actual metadata audit lost its native payload measurement", err)
			}
			g.unblock()
			ownedPlainAwaitV1(t, g.returned, "metadata audit retirement")
			ownedPlainAssertRetainedV1(t, q, "metadata response after audit retirement")
			response.unblock()
			ownedPlainAwaitV1(t, done, "metadata response retirement")
			gate.Store(nil)
			assertLifecycleMCPResultE2E(t, response.ResponseRecorder, false)
			ownedPlainAssertDrainedV1(t, q)
			metadataCacheInventory756(t, q, old.ID, http.StatusOK)
		})
	}
}

func TestMetadataCache756MissingMeasurementIsNotLazyRecoveryE2E(t *testing.T) {
	q := metadataCacheFixture756(t)
	key, _ := mintRecipientMCPKeyE2E(t, q.f, false, 0)
	doc := metadataCacheCreate756(t, q, "MCP", key.Plaintext)
	// Explicit negative corruption in this owned synthetic database only. The
	// real producer above created every metric; this is never production repair.
	if _, err := q.f.pool.Exec(q.f.ctx, `DELETE FROM html_creation_response_sizes_v1 WHERE document_id=$1 AND org_id=$2`, doc.ID, q.f.org); err != nil {
		t.Fatal(err)
	}
	before := q.f.snapshot(t)
	metadataCacheInventory756(t, q, doc.ID, http.StatusConflict)
	w := submitRecipientMCPE2E(q.f, "attach_metadata", key.Plaintext, map[string]any{"document_id": doc.ID.String(), "key": "must-not-recover", "value": "no fresh authority"})
	assertLifecycleMCPResultE2E(t, w, true)
	if q.f.snapshot(t) != before {
		t.Fatal("missing-cache edit committed source/audit changes")
	}
	var n int
	if err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM html_creation_response_sizes_v1 WHERE document_id=$1 AND org_id=$2`, doc.ID, q.f.org).Scan(&n); err != nil || n != 0 {
		t.Fatal("old missing cache was silently remeasured", err, n)
	}
	ownedPlainAssertDrainedV1(t, q)
	metadataCacheInventory756(t, q, doc.ID, http.StatusConflict)
}
