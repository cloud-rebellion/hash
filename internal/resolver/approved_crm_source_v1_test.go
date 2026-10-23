// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/google/uuid"
)

func TestApprovedCRMSourceUsesActualProtectedReadAndRefusesForgedOrStaleWitnessV1(t *testing.T) {
	token := strings.Repeat("ab", 32)
	accounts, records := 0, 0
	changedAccount := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("original credential not used")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			accounts++
			if changedAccount && accounts%2 == 0 {
				_, _ = w.Write([]byte(`{"id":"other_user","team_id":"crm_team","is_active":true}`))
			} else {
				_, _ = w.Write([]byte(`{"id":"crm_user","team_id":"crm_team","is_active":true}`))
			}
		case "/api/v1/deals/deal_1":
			records++
			_, _ = w.Write([]byte(`{"id":"deal_1","team_id":"crm_team","updated_at":"2026-10-01T10:00:00Z","title":"Actual source title","value":9007199254740993.01}`))
		default:
			t.Error("unexpected provider path")
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	client, err := crmconnection.NewClient(upstream.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(strings.Repeat("1234", 16), "")
	if err != nil {
		t.Fatal(err)
	}
	id := crmconnection.Identity{ID: uuid.New(), OrgID: uuid.New(), Generation: 2, Origin: upstream.URL, CRMTeamID: "crm_team", CRMUserID: "crm_user"}
	cipher, err := keys.Seal(id, token)
	if err != nil {
		t.Fatal(err)
	}
	connection := crmconnection.Connection{Identity: id, Enabled: true, VerifiedAt: time.Now().Add(-time.Minute), Ciphertext: cipher}
	refs := []crmconnection.RecordRef{{Kind: crmconnection.Deal, ID: "deal_1"}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h, err := ReadApprovedCRMSourceV1(ctx, client, keys, connection, refs)
	if err != nil {
		t.Fatal(err)
	}
	if accounts != 2 || records != 1 || h.IdentityV1() != id {
		t.Fatal("account-before/record/account-after read not retained")
	}
	if value, err := h.ScalarV1("crm.deal", "deal_1", "value"); err != nil || value != "9007199254740993.01" {
		t.Fatal("actual exact scalar changed", err)
	}
	for _, bad := range []struct{ kind, id, path string }{{"crm.deal", "deal_2", "title"}, {"crm.deal", "deal_1", "missing"}, {"crm.company", "deal_1", "title"}} {
		if _, err := h.ScalarV1(bad.kind, bad.id, bad.path); err == nil {
			t.Fatal("unobserved source selected")
		}
	}
	copyHandle := *h
	if copyHandle.CheckDeadlineV1() == nil {
		t.Fatal("copied public handle minted private provenance")
	}
	if (&ApprovedCRMSourceV1{}).CheckDeadlineV1() == nil {
		t.Fatal("empty handle minted private provenance")
	}
	h.snapshot.CompletedAt = time.Now().Add(-CRMObservationMaxAge - time.Second)
	if _, err = h.ScalarV1("crm.deal", "deal_1", "title"); err == nil {
		t.Fatal("stale observation remained usable")
	}
	changedAccount = true
	if _, err = ReadApprovedCRMSourceV1(ctx, client, keys, connection, refs); err == nil {
		t.Fatal("changed account after record read accepted")
	}
	before := accounts
	if _, err = ReadApprovedCRMSourceV1(ctx, client, keys, connection, append(refs, refs[0])); err == nil || accounts != before {
		t.Fatal("duplicate kind reached upstream")
	}
}
