//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Actual public owner routes, direct native sessions and PostgreSQL96. The
// reused fixture's renderer/object peers are synthetic and UNUSED by these
// rule-only cases; no SMTP, provider, physical-capacity or release claim.
func TestOwnedCatalogRuleFreshPartialAndUnmeasuredDeletionE2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	q.f.s.EIDAS = eidas.New(q.f.q)
	base := "/api/v1/eidas-rules"
	post := `{"name":"Synthetic SE policy","priority":7,"predicate_json":{"all":[{"field":"country","op":"==","value":"SE"},{"field":"amount","op":">=","value":10}]},"required_tier":"SES","reason":"Original reason"} trailing`
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, base, post, q.cookie)
	var created ruleDTO
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatalf("actual native fresh rule=%d %s", w.Code, w.Body.String())
	}
	id, err := uuid.Parse(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	read := func() *generated.EidasRoutingRule {
		t.Helper()
		row, err := q.f.q.GetEIDASRule(q.f.ctx, generated.GetEIDASRuleParams{ID: id, OrgID: q.f.org})
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	checkCache := func(row *generated.EidasRoutingRule) {
		t.Helper()
		var org uuid.UUID
		var wire int64
		var stamps, server bool
		if err := q.f.pool.QueryRow(q.f.ctx, `SELECT s.org_id,s.predicate_wire_bytes,s.rule_created_at=r.created_at AND s.rule_updated_at=r.updated_at,s.measurement_server_version_num=current_setting('server_version_num')::integer FROM eidas_rule_wire_sizes_v1 s JOIN eidas_routing_rules r ON r.id=s.rule_id WHERE s.rule_id=$1`, id).Scan(&org, &wire, &stamps, &server); err != nil || org != q.f.org || wire != int64(len(row.PredicateJson)) || !stamps || !server {
			t.Fatal("actual source measurement/stamps do not match", org, wire, stamps, server, err)
		}
	} //nolint:rawsql -- exact fresh intrinsic source/cache oracle only
	first := read()
	checkCache(first)
	originalPredicate := bytes.Clone(first.PredicateJson)
	w = submitSessionOperationE2E(q.f.s, http.MethodPatch, base+"/"+id.String(), `{"reason":"Human reviewed replacement"}`, q.cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("actual partial update=%d %s", w.Code, w.Body.String())
	}
	second := read()
	if second.Reason != "Human reviewed replacement" || second.Name != first.Name || second.Priority != first.Priority || second.RequiredTier != first.RequiredTier || second.Active != first.Active || !bytes.Equal(second.PredicateJson, originalPredicate) {
		t.Fatal("partial update changed an omitted original source field")
	}
	checkCache(second)
	var eventsBefore int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM events WHERE org_id=$1", q.f.org).Scan(&eventsBefore); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- actual audit side-effect oracle
	for _, bad := range []struct {
		body   string
		status int
	}{
		{`{"predicate_json":{"field":"country","op":"==","value":false}}`, http.StatusBadRequest},
		{`{"required_tier":"AES","active":true}`, http.StatusConflict},
		{`{"required_tier":"QES","active":true}`, http.StatusConflict},
	} {
		w = submitSessionOperationE2E(q.f.s, http.MethodPatch, base+"/"+id.String(), bad.body, q.cookie)
		if w.Code != bad.status {
			t.Fatalf("original rule refusal=%d want%d: %s", w.Code, bad.status, w.Body.String())
		}
		after := read()
		if after.UpdatedAt != second.UpdatedAt || after.Reason != second.Reason || !bytes.Equal(after.PredicateJson, second.PredicateJson) {
			t.Fatal("refused rule mutation changed actual source")
		}
		checkCache(after)
	}
	var eventsAfter int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM events WHERE org_id=$1", q.f.org).Scan(&eventsAfter); err != nil || eventsAfter != eventsBefore {
		t.Fatal("refused rules appended audit", err)
	} //nolint:rawsql -- actual audit side-effect oracle
	// Explicit negative fixture: old-body reads never repair a removed measure.
	tag, err := q.f.pool.Exec(q.f.ctx, "DELETE FROM eidas_rule_wire_sizes_v1 WHERE rule_id=$1 AND org_id=$2", id, q.f.org)
	if err != nil || tag.RowsAffected() != 1 {
		t.Fatal("did not remove exactly the selected source cache", err)
	} //nolint:rawsql -- deliberate missing-cache fixture, never product repair
	w = submitSessionOperationE2E(q.f.s, http.MethodPatch, base+"/"+id.String(), `{"reason":"Must be refused"}`, q.cookie)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unmeasured old source did not refuse=%d %s", w.Code, w.Body.String())
	}
	var cacheCount int
	if err = q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM eidas_rule_wire_sizes_v1 WHERE rule_id=$1", id).Scan(&cacheCount); err != nil || cacheCount != 0 {
		t.Fatal("reader repaired missing cache", err)
	} //nolint:rawsql -- exact missing-cache witness
	w = submitSessionOperationE2E(q.f.s, http.MethodDelete, base+"/"+id.String(), "", q.cookie)
	if w.Code != http.StatusNoContent {
		t.Fatalf("unmeasured source could not be deleted=%d %s", w.Code, w.Body.String())
	}
	if _, err = q.f.q.GetEIDASRule(q.f.ctx, generated.GetEIDASRuleParams{ID: id, OrgID: q.f.org}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("actual rule was not removed", err)
	}
	w = submitSessionOperationE2E(q.f.s, http.MethodDelete, base+"/"+id.String(), "", q.cookie)
	if w.Code != http.StatusNotFound {
		t.Fatalf("original missing-rule404 changed=%d %s", w.Code, w.Body.String())
	}
}
