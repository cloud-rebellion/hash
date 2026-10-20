//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Actual middleware/key, owned argument source, original parser and PG writer.
// The fixture identity/storage remain synthetic; no scanner efficacy, measured
// heap or configured capacity claim follows. SQL is read-only assertion data.
func TestOwnedMCPHTMLMarkdownImportConstructionAndActualLastUseE2E(t *testing.T) {
	q := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
	key, _ := mintRecipientMCPKeyE2E(t, f, false, 0)
	created := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", q.cookie, map[string]any{"name": "Actual canonical import source", "source_kind": "blocks", "blocks_json": json.RawMessage("{\"version\":0,\"blocks\":[{\"type\":\"paragraph\",\"text\":\"Original exact clause\"}]}"), "variables_json": map[string]string{"customer": "Exact original variable"}}), "rest")
	f.doc = created
	q.f.doc = created
	ownedPlainAssertDrainedV1(t, q)
	if err := malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	var current atomic.Pointer[ownedPlainAuditGateV1]
	f.s.Audit.Subscribe(func(_ context.Context, id uuid.UUID, e audit.Entry) {
		g := current.Load()
		if g == nil || e.Kind != audit.KindDocumentUpdated || e.DocumentID == nil || *e.DocumentID != created.ID {
			return
		}
		g.eventID = id
		g.entry = e
		close(g.started)
		<-g.release
		close(g.returned)
	})
	for i, call := range []struct{ tool, field, source, want string }{{"import_html", "html", "<h2>Imported heading</h2><p>Imported exact clause <b>bold</b></p><table><tr><th>Party</th></tr><tr><td>Exact customer</td></tr></table>", "Imported exact clause bold"}, {"import_markdown", "markdown", "# Imported heading\r\n\r\nImported negotiated clause\n\n- First\n- Second\n\n|Party|Term|\n|---|---|\n|Exact customer|Approved|", "Imported negotiated clause"}} {
		t.Run(call.tool, func(t *testing.T) {
			old, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			oldCache := ownedBlockCacheStateV1(t, f, old.ID)
			var previous uuid.UUID
			if i > 0 {
				version, err := f.q.GetLatestDocumentVersion(f.ctx, old.ID)
				if err != nil {
					t.Fatal(err)
				}
				previous = version.ID
			}
			args := map[string]any{"document_id": old.ID.String(), "expected_updated_at": old.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), call.field: call.source}
			gate := newOwnedPlainAuditGateV1(audit.KindDocumentUpdated)
			current.Store(gate)
			defer current.Store(nil)
			defer gate.unblock()
			response := newOwnedPlainResponseGateV1()
			defer response.unblock()
			done := make(chan struct{})
			request := ownedPlainRequestV1(t, q, "MCP", call.tool, key.Plaintext, args, nil)
			go func() { defer close(done); f.s.Routes().ServeHTTP(response, request) }()
			defer func() {
				response.unblock()
				gate.unblock()
				ownedPlainAwaitV1(t, done, "actual MCP import failure cleanup")
				select {
				case <-gate.started:
					ownedPlainAwaitV1(t, gate.returned, "actual import hook failure cleanup")
				default:
				}
			}()
			ownedPlainAwaitV1(t, response.started, "actual imported source response")
			var envelope struct {
				Result struct{ IsError bool }
				Error  json.RawMessage
			}
			if err = json.Unmarshal(response.preview, &envelope); err != nil || envelope.Result.IsError || len(envelope.Error) > 0 {
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual import refusal")
				t.Fatalf("actual original %s refused before source hook: %d %s", call.tool, response.Code, response.Body.String())
			}
			ownedPlainAwaitV1(t, gate.started, "actual document.updated import hook")
			if gate.entry.OrgID != f.org || gate.entry.ActorUserID == nil || *gate.entry.ActorUserID != f.user.ID || gate.eventID == uuid.Nil {
				t.Fatal("actual imported source audit lost original identity")
			}
			if q.runtime.SessionsV1().PendingV1().HTMLInputProducers != 1 {
				t.Fatal("actual parsed DOM/AST input retired before source response last use")
			}
			ownedPlainAssertRetainedV1(t, q, "actual blocked canonical import response and hook")
			stored, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: old.ID, OrgID: f.org})
			if err != nil {
				t.Fatal(err)
			}
			tree, err := blocks.ParseCanonicalTree(stored.BlocksJson)
			if err != nil || len(tree.Blocks) < 2 || !strings.Contains(string(stored.BlocksJson), call.want) || string(stored.VariablesJson) != string(old.VariablesJson) {
				t.Fatal("original parser source/variables not persisted", err)
			}
			if ownedBlockCacheStateV1(t, f, old.ID) == oldCache {
				t.Fatal("fresh mutation left old intrinsic measurements")
			}
			var exact bool
			err = f.pool.QueryRow(f.ctx, "SELECT p.html_origin_wire_bytes=0 AND p.html_current_wire_bytes=0 AND p.variables_wire_bytes=octet_length(d.variables_json::text) AND r.blocks_wire_bytes=octet_length(d.blocks_json::text) AND r.metadata_wire_bytes=coalesce(octet_length(d.metadata::text),0) AND s.report_wire_bytes=coalesce(octet_length(d.metadata_redaction_report::text),0) AND p.org_id=d.org_id AND r.org_id=d.org_id AND s.org_id=d.org_id AND p.measurement_server_version_num=current_setting('server_version_num')::integer AND r.measurement_server_version_num=p.measurement_server_version_num AND s.measurement_server_version_num=p.measurement_server_version_num FROM documents d JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id JOIN html_creation_response_sizes_v1 r ON r.document_id=d.id JOIN document_read_report_sizes_v1 s ON s.document_id=d.id WHERE d.id=$1 AND d.org_id=$2", old.ID, f.org).Scan(&exact)
			if err != nil || !exact {
				t.Fatal("actual import lacks exact fresh native M91/M92/M93", err)
			} //nolint:rawsql -- actual source/cache read oracle
			var payload, hashed []byte
			err = f.pool.QueryRow(f.ctx, "SELECT e.payload_json::text::bytea,e.payload_hashed FROM events e JOIN html_snapshot_event_payload_sizes_v1 s ON s.event_id=e.id WHERE e.id=$1 AND e.document_id=$2 AND e.org_id=$3 AND e.kind='document.updated' AND s.document_id=e.document_id AND s.org_id=e.org_id AND s.payload_wire_bytes=octet_length(e.payload_json::text) AND s.measurement_server_version_num=current_setting('server_version_num')::integer", gate.eventID, old.ID, f.org).Scan(&payload, &hashed)
			var event map[string]any
			if err != nil || json.Unmarshal(payload, &event) != nil || len(event) != 3 || event["via"] != "mcp" || event["tool"] != call.tool || event["blocks"] != float64(len(tree.Blocks)) || !json.Valid(hashed) {
				t.Fatal("original import audit/hash/M94 payload changed", err, string(payload))
			} //nolint:rawsql -- exact original event/M94 oracle
			latest, err := f.q.GetLatestDocumentVersion(f.ctx, old.ID)
			if err != nil || latest.VersionNo != int32(i+1) || latest.ParentID.Valid != (previous != uuid.Nil) || (latest.ParentID.Valid && uuid.UUID(latest.ParentID.Bytes) != previous) || string(latest.BlockTreeJson) != string(stored.BlocksJson) || string(latest.VariablesJson) != string(stored.VariablesJson) {
				t.Fatal("original import version source/linear parent changed", err)
			}
			if i == 0 {
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual response before import audit hook")
				if q.runtime.SessionsV1().PendingV1().HTMLInputProducers != 0 {
					t.Fatal("parsed import source outlived actual response last use")
				}
				ownedPlainAssertRetainedV1(t, q, "real M94 hook after original input result last use")
				gate.unblock()
				ownedPlainAwaitV1(t, gate.returned, "actual import audit last use")
			} else {
				gate.unblock()
				ownedPlainAwaitV1(t, gate.returned, "actual hook before import response")
				if q.runtime.SessionsV1().PendingV1().HTMLInputProducers != 1 {
					t.Fatal("actual parsed source refunded while serializer still blocked")
				}
				response.unblock()
				ownedPlainAwaitV1(t, done, "actual response last use after hook")
			}
			fieldMCPTextE2E(t, response.ResponseRecorder, false)
			current.Store(nil)
			ownedPlainAssertDrainedV1(t, q)
			cache := ownedBlockCacheStateV1(t, f, old.ID)
			before := f.snapshot(t)
			stale := submitRecipientMCPE2E(f, call.tool, key.Plaintext, args)
			assertLifecycleMCPResultE2E(t, stale, true)
			if !strings.Contains(stale.Body.String(), "changed since observation") || f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, old.ID) != cache {
				t.Fatal("parsed import stale CAS changed original source/version/audit/measurement", stale.Body.String())
			}
			ownedPlainAssertDrainedV1(t, q)
		})
	}
	current.Store(nil)
	stored, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	cache := ownedBlockCacheStateV1(t, f, created.ID)
	before := f.snapshot(t)
	fragmented := strings.Repeat("<hr>", blocks.MaxHTMLImportTokens+1)
	args := map[string]any{"document_id": created.ID.String(), "expected_updated_at": stored.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "html": fragmented}
	rejected := submitRecipientMCPE2E(f, "import_html", key.Plaintext, args)
	if got := fieldMCPTextE2E(t, rejected, true); !strings.Contains(got, "20000 tokens") {
		t.Fatal("original HTML token limit/error changed", got)
	}
	if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, created.ID) != cache {
		t.Fatal("token refusal changed any real mutation/cache")
	}
	ownedPlainAssertDrainedV1(t, q)
	scoped, _ := mintRecipientMCPKeyE2E(t, f, true, 0)
	args["document_id"] = uuid.NewString()
	denied := submitRecipientMCPE2E(f, "import_html", scoped.Plaintext, args)
	assertLifecycleMCPResultE2E(t, denied, true)
	if strings.Contains(denied.Body.String(), "20000 tokens") || f.snapshot(t) != before {
		t.Fatal("original document scope no longer wins before source parser")
	}
	ownedPlainAssertDrainedV1(t, q)
	if err = malwarescan.Configure(f.ctx, "", "production"); !errors.Is(err, malwarescan.ErrUnavailable) {
		t.Fatal(err)
	}
	args["document_id"] = created.ID.String()
	blocked := submitRecipientMCPE2E(f, "import_html", key.Plaintext, args)
	if got := fieldMCPTextE2E(t, blocked, true); !strings.Contains(got, malwarescan.ErrUnavailable.Error()) || strings.Contains(got, "20000 tokens") {
		t.Fatal("original fail-closed scanner order changed", got)
	}
	if f.snapshot(t) != before || ownedBlockCacheStateV1(t, f, created.ID) != cache {
		t.Fatal("scanner refusal changed real source/measurement")
	}
	if err = malwarescan.Configure(f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	ownedPlainAssertDrainedV1(t, q)
}
