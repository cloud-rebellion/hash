//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
	"testing"
	"time"
)

func ownedPlainDraftStateV1(t *testing.T, f lifecycleAuthorizationFixture, id uuid.UUID) string {
	t.Helper()
	var result string
	err := f.pool.QueryRow(f.ctx, `SELECT jsonb_build_array((SELECT row_to_json(d) FROM documents d WHERE id=$1),(SELECT jsonb_agg(v ORDER BY version_no) FROM document_versions v WHERE document_id=$1),(SELECT jsonb_agg(e ORDER BY created_at) FROM events e WHERE document_id=$1),(SELECT row_to_json(c) FROM document_signing_policy_sizes_v1 c WHERE document_id=$1),(SELECT row_to_json(c) FROM html_creation_response_sizes_v1 c WHERE document_id=$1),(SELECT row_to_json(c) FROM document_read_report_sizes_v1 c WHERE document_id=$1))::text`, id).Scan(&result)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func ownedPlainDraftRPCRefusedV1(t *testing.T, body []byte) {
	t.Helper()
	var rpc struct{ Result struct{ IsError bool } }
	if err := json.Unmarshal(body, &rpc); err != nil || !rpc.Result.IsError {
		t.Fatalf("actual variable tool did not refuse: %v %s", err, body)
	}
}

// Actual native sources and public middleware exercise all four original
// PATCH writes, canonical normalization, variable-only byte preservation,
// linear versions, unchanged-cache scalar edits and rollback/refusal paths.
func TestOwnedPlainDraftPATCHAndMCPVariablesActualE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, q)
	f := q.f
	f.s.Versions = versions.New(f.q)
	f.s.APIKeys = &auth.PgVerifier{Queries: f.q}
	f.s.MCP = mcp.New(mcp.Deps{Pool: f.pool, Queries: f.q, Audit: f.s.Audit, Versions: versions.New(f.q), Billing: f.s.Billing, Send: f.s.Send, PDFCreationSessions: q.runtime.SessionsV1()})
	key, keyID := mintRecipientMCPKeyE2E(t, f, false, 0)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	created := ownedBlockTestDocumentV1(t, submitDocumentCreationE2E(f, f.ctx, "rest", cookie, map[string]any{"name": "Original public draft", "source_kind": "blocks", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Original clause"}]}`), "variables_json": map[string]string{"customer": "Original"}}), "rest")
	load := func() *generated.Document {
		t.Helper()
		doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: created.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}
	stamp := func(doc *generated.Document) string { return doc.UpdatedAt.Time.UTC().Format(time.RFC3339Nano) }
	original := load()
	route := "/api/v1/documents/" + created.ID.String()
	expiry := "2027-02-03T12:13:14.123456+02:00"
	body := map[string]any{"expected_updated_at": stamp(original), "name": "Negotiated public draft", "blocks_json": json.RawMessage(`{"version":0,"blocks":[{"type":"paragraph","text":"Negotiated {{customer}}"},{"type":"paragraph","text":"Extra exact clause"}]}`), "variables_json": map[string]string{"customer": "First negotiated"}, "expires_at": expiry, "default_locale": "sv", "requires_signature": false}
	response := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, body)
	if response.Code != http.StatusOK {
		t.Fatalf("native generic PATCH=%d %s", response.Code, response.Body.String())
	}
	updated := load()
	tree, err := blocks.ParseCanonicalTree(updated.BlocksJson)
	expires, _ := time.Parse(time.RFC3339, expiry)
	if err != nil || len(tree.Blocks) != 2 || tree.Blocks[0].ID == "" || tree.Blocks[1].ID == "" || updated.Name != "Negotiated public draft" || updated.DefaultLocale != "sv" || updated.RequiresSignature || !updated.ExpiresAt.Valid || !updated.ExpiresAt.Time.Equal(expires) || !bytes.Equal(updated.Metadata, original.Metadata) || !bytes.Equal(updated.MetadataRedactionReport, original.MetadataRedactionReport) {
		t.Fatal("original PATCH semantics/source/scalars changed", err)
	}
	cache := ownedBlockCacheStateV1(t, f, created.ID)
	details := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, map[string]any{"expected_updated_at": stamp(updated), "name": "Only name changes"})
	if details.Code != http.StatusOK {
		t.Fatalf("native scalar PATCH=%d %s", details.Code, details.Body.String())
	}
	afterDetails := load()
	if ownedBlockCacheStateV1(t, f, created.ID) != cache {
		t.Fatal("scalar-only edit remeasured or invalidated unchanged source caches")
	}
	if !bytes.Equal(afterDetails.BlocksJson, updated.BlocksJson) || !bytes.Equal(afterDetails.VariablesJson, updated.VariablesJson) {
		t.Fatal("scalar-only edit changed source")
	}
	previous, err := f.q.GetLatestDocumentVersion(f.ctx, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	rpc := submitRecipientMCPE2E(f, "set_variables", key.Plaintext, map[string]any{"document_id": created.ID, "expected_updated_at": stamp(afterDetails), "variables": map[string]string{"customer": "Second negotiated", "extra": "Exact new variable"}})
	_ = ownedBlockTestDocumentV1(t, rpc, "mcp")
	afterVariables := load()
	if !bytes.Equal(afterVariables.BlocksJson, afterDetails.BlocksJson) || bytes.Equal(afterVariables.VariablesJson, afterDetails.VariablesJson) {
		t.Fatal("set_variables normalized block bytes or ignored new variables")
	}
	latest, err := f.q.GetLatestDocumentVersion(f.ctx, created.ID)
	if err != nil || !latest.ParentID.Valid || uuid.UUID(latest.ParentID.Bytes) != previous.ID || latest.VersionNo != previous.VersionNo+1 {
		t.Fatal("original variable snapshot parent/version changed", err)
	}
	var measured, updatedEvents int
	err = f.pool.QueryRow(f.ctx, "SELECT count(*) FILTER(WHERE s.event_id IS NOT NULL),count(*) FROM events e LEFT JOIN html_snapshot_event_payload_sizes_v1 s ON s.event_id=e.id WHERE e.document_id=$1 AND e.kind='document.updated'", created.ID).Scan(&measured, &updatedEvents)
	if err != nil || measured != 3 || updatedEvents != 3 {
		t.Fatal("actual update audit did not join native M94", err)
	}
	stable := ownedPlainDraftStateV1(t, f, created.ID)
	stale := submitRecipientMCPE2E(f, "set_variables", key.Plaintext, map[string]any{"document_id": created.ID, "expected_updated_at": stamp(afterDetails), "variables": map[string]string{"customer": "Stale overwrite"}})
	ownedPlainDraftRPCRefusedV1(t, stale.Body.Bytes())
	if ownedPlainDraftStateV1(t, f, created.ID) != stable {
		t.Fatal("stale variable edit changed source/version/event/cache")
	}
	invalid := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, map[string]any{"expected_updated_at": stamp(afterVariables), "variables_json": map[string]string{"customer": "Rolled back source"}, "expires_at": "invalid-date"})
	if invalid.Code != http.StatusBadRequest || ownedPlainDraftStateV1(t, f, created.ID) != stable {
		t.Fatalf("original post-source expiry error failed atomic rollback=%d %s", invalid.Code, invalid.Body.String())
	}
	if tag, e := f.pool.Exec(f.ctx, "DELETE FROM html_creation_response_sizes_v1 WHERE document_id=$1 AND org_id=$2", created.ID, f.org); e != nil || tag.RowsAffected() != 1 {
		t.Fatal("negative missing source cache", e)
	}
	missing := ownedPlainDraftStateV1(t, f, created.ID)
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role='viewer' WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
		t.Fatal(err)
	}
	denied := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, map[string]any{"expected_updated_at": stamp(afterVariables), "name": "Forbidden"})
	if denied.Code != http.StatusForbidden || ownedPlainDraftStateV1(t, f, created.ID) != missing {
		t.Fatalf("live role did not precede missing-cache body=%d %s", denied.Code, denied.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET role=$3 WHERE id=$1 AND org_id=$2", f.user.ID, f.org, f.user.Role); err != nil {
		t.Fatal(err)
	}
	absent := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, map[string]any{"expected_updated_at": stamp(afterVariables), "name": "No repair"})
	if absent.Code != http.StatusServiceUnavailable {
		t.Fatalf("missing M92 PATCH=%d %s", absent.Code, absent.Body.String())
	}
	absentRPC := submitRecipientMCPE2E(f, "set_variables", key.Plaintext, map[string]any{"document_id": created.ID, "expected_updated_at": stamp(afterVariables), "variables": map[string]string{"customer": "No repair"}})
	ownedPlainDraftRPCRefusedV1(t, absentRPC.Body.Bytes())
	if ownedPlainDraftStateV1(t, f, created.ID) != missing {
		t.Fatal("missing-cache edits repaired or changed state")
	}
	if _, err = f.pool.Exec(f.ctx, "UPDATE users SET session_generation=session_generation+1 WHERE id=$1 AND org_id=$2", f.user.ID, f.org); err != nil {
		t.Fatal(err)
	}
	revoked := ownedBlocksTemplateCallV1(t, f, cookie, http.MethodPatch, route, map[string]any{"expected_updated_at": stamp(afterVariables), "name": "Revoked"})
	if revoked.Code != http.StatusUnauthorized && revoked.Code != http.StatusForbidden {
		t.Fatalf("revoked original cookie=%d %s", revoked.Code, revoked.Body.String())
	}
	if _, err = f.pool.Exec(f.ctx, "DELETE FROM api_keys WHERE id=$1 AND org_id=$2", keyID, f.org); err != nil {
		t.Fatal(err)
	}
	revokedRPC := submitRecipientMCPE2E(f, "set_variables", key.Plaintext, map[string]any{"document_id": created.ID, "expected_updated_at": stamp(afterVariables), "variables": map[string]string{"customer": "Revoked"}})
	if revokedRPC.Code != http.StatusUnauthorized {
		t.Fatalf("revoked API credential=%d %s", revokedRPC.Code, revokedRPC.Body.String())
	}
	if ownedPlainDraftStateV1(t, f, created.ID) != missing {
		t.Fatal("revoked original credential changed state")
	}
	ownedCreationAssertDrainedV1(t, q, 2)
}
