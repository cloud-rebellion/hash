//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/mcp"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Genuine public MCP -> actual PgVerifier scoped key -> original transaction
// authorization -> same existing runtime/direct session -> intrinsic96 cache.
// No renderer, SMTP or object peer is used by this source-only rule journey.
func TestOwnedCatalogRuleMCPFreshScopedKeyAndDeletionE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	q.f.s.Send.WorkRuntime = q.runtime
	q.f.s.APIKeys = &auth.PgVerifier{Queries: q.f.q}
	q.f.s.MCP = mcp.New(mcp.Deps{Pool: q.f.pool, Queries: q.f.q, Audit: q.f.s.Audit, EIDAS: eidas.New(q.f.q), Send: q.f.s.Send, PublicURL: q.f.s.PublicURL})
	key, keyID := mintAuthoringMCPE2E(t, q.f)
	decode := func(wantError bool, tool string, credential string, args map[string]any) mcp.ToolResult {
		t.Helper()
		w := submitAuthoringMCPE2E(q.f, q.f.ctx, tool, credential, args)
		var response struct {
			Result mcp.ToolResult  `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil || len(response.Error) > 0 || response.Result.IsError != wantError || len(response.Result.Content) != 1 {
			t.Fatalf("actual public MCP rule response=%d %s", w.Code, w.Body.String())
		}
		return response.Result
	}
	args := map[string]any{"name": "Synthetic actual MCP rule", "priority": 11, "predicate_json": map[string]any{"field": "country", "op": "in", "value": []string{"SE", "NO"}}, "required_tier": "SES", "reason": "Reviewed MCP source"}
	result := decode(false, "create_eidas_rule", key.Plaintext, args)
	var created ruleDTO
	if json.Unmarshal([]byte(result.Content[0].Text), &created) != nil || created.Name != "Synthetic actual MCP rule" || created.RequiredTier != "SES" || !created.Active {
		t.Fatal("original full MCP rule wire shape changed", result)
	}
	id, err := uuid.Parse(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	row, err := q.f.q.GetEIDASRule(q.f.ctx, generated.GetEIDASRuleParams{ID: id, OrgID: q.f.org})
	if err != nil {
		t.Fatal("actual MCP rule missing", err)
	}
	var cached bool
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT s.org_id=r.org_id AND s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at AND s.predicate_wire_bytes=octet_length(r.predicate_json::text) AND s.measurement_server_version_num=current_setting('server_version_num')::integer FROM eidas_rule_wire_sizes_v1 s JOIN eidas_routing_rules r ON r.id=s.rule_id WHERE r.id=$1 AND r.org_id=$2`, id, q.f.org).Scan(&cached); err != nil || !cached || row.Name != created.Name || row.Priority != created.Priority || row.Reason != created.Reason {
		t.Fatal("actual MCP source/cache/model mismatch", err)
	} //nolint:rawsql -- exact selected synthetic intrinsic measurement oracle
	countState := func() (rules, events int) {
		t.Helper()
		if err := q.f.pool.QueryRow(q.f.ctx, `SELECT (SELECT count(*)::integer FROM eidas_routing_rules WHERE org_id=$1),(SELECT count(*)::integer FROM events WHERE org_id=$1)`, q.f.org).Scan(&rules, &events); err != nil {
			t.Fatal(err)
		}
		return
	} //nolint:rawsql -- fixed actual side-effect witnesses only
	beforeRules, beforeEvents := countState()
	aes := map[string]any{}
	for k, v := range args {
		aes[k] = v
	}
	aes["required_tier"] = "AES"
	aes["active"] = true
	decode(true, "create_eidas_rule", key.Plaintext, aes)
	readOnly, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, Name: "Synthetic read-only catalog key", KeyPrefix: readOnly.Prefix, KeyHash: readOnly.Hash, Scopes: []string{"read"}}); err != nil {
		t.Fatal(err)
	}
	decode(true, "create_eidas_rule", readOnly.Plaintext, args)
	afterRules, afterEvents := countState()
	if afterRules != beforeRules || afterEvents != beforeEvents {
		t.Fatal("original active-AES or scope refusal mutated policy/audit")
	}
	deleted := decode(false, "delete_eidas_rule", key.Plaintext, map[string]any{"rule_id": id.String()})
	var original map[string]string
	if json.Unmarshal([]byte(deleted.Content[0].Text), &original) != nil || len(original) != 1 || original["deleted"] != id.String() {
		t.Fatal("original exact MCP deletion wire changed", deleted)
	}
	if _, err = q.f.q.DeleteAPIKey(q.f.ctx, generated.DeleteAPIKeyParams{ID: keyID, UserID: q.f.user.ID}); err != nil {
		t.Fatal(err)
	}
	beforeRules, beforeEvents = countState()
	refused := submitAuthoringMCPE2E(q.f, q.f.ctx, "create_eidas_rule", key.Plaintext, args)
	if refused.Code != http.StatusUnauthorized {
		t.Fatalf("revoked original scoped key accepted=%d %s", refused.Code, refused.Body.String())
	}
	afterRules, afterEvents = countState()
	if afterRules != beforeRules || afterEvents != beforeEvents {
		t.Fatal("revoked original key mutated policy/audit")
	}
	pending := q.runtime.SessionsV1().PendingV1()
	snap, err := q.runtime.SnapshotV1(q.f.org)
	if err != nil || pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 || snap.Global != (workguard.VectorV1{SQLSessions: int64(pending.ObserverSessions)}) || snap.GlobalGrants != int64(pending.ObserverSessions) {
		t.Fatal("actual completed MCP source/input/native debt survived response", pending, snap, err)
	}
}
