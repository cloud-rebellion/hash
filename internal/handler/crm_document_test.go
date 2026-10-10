// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCRMDocumentWitnessRefusesOriginalActorAndStaleLedger(t *testing.T) {
	org, user, connection := uuid.New(), uuid.New(), uuid.New()
	at := time.Now().UTC()
	actor := authoring.Actor{OrgID: org, UserID: user}
	in := CRMDocumentWitness{ExpectedOrgID: org, ExpectedUserID: user, ExpectedUpdatedAt: at.Format(time.RFC3339Nano), ExpectedBindingFingerprint: strings.Repeat("a", 64), ExpectedConnectionID: connection.String(), ExpectedConnectionGeneration: "2"}
	current := &crmDocumentContext{supported: true, doc: &generated.Document{UpdatedAt: pgtype.Timestamptz{Time: at, Valid: true}}, connection: &generated.CrmConnection{ID: connection, Generation: 2}, response: crmDocumentResponseWitness{BindingFingerprint: in.ExpectedBindingFingerprint}}
	if in.validate(actor) != nil || in.matches(current) != nil {
		t.Fatal("current original witness refused")
	}
	cases := []struct {
		name   string
		change func(*CRMDocumentWitness)
		want   error
	}{
		{"changed user", func(v *CRMDocumentWitness) { v.ExpectedUserID = uuid.New() }, errCRMDocumentChanged},
		{"changed org", func(v *CRMDocumentWitness) { v.ExpectedOrgID = uuid.New() }, errCRMDocumentChanged},
		{"leading zero generation", func(v *CRMDocumentWitness) { v.ExpectedConnectionGeneration = "02" }, errCRMDocumentInput},
		{"missing connection generation", func(v *CRMDocumentWitness) { v.ExpectedConnectionGeneration = "0" }, errCRMDocumentInput},
		{"no connection with positive generation", func(v *CRMDocumentWitness) { v.ExpectedConnectionID = "" }, errCRMDocumentInput},
		{"uppercase digest", func(v *CRMDocumentWitness) { v.ExpectedBindingFingerprint = strings.Repeat("A", 64) }, errCRMDocumentInput},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := in
			c.change(&v)
			if !errors.Is(v.validate(actor), c.want) {
				t.Fatal("invalid witness admitted")
			}
		})
	}
	stale := in
	stale.ExpectedBindingFingerprint = strings.Repeat("b", 64)
	if !errors.Is(stale.matches(current), errCRMDocumentChanged) {
		t.Fatal("unchanged document timestamp bypassed edited binding ledger")
	}
	stale = in
	stale.ExpectedUpdatedAt = at.Add(time.Nanosecond).Format(time.RFC3339Nano)
	if !errors.Is(stale.matches(current), errCRMDocumentChanged) {
		t.Fatal("precise document edit witness ignored")
	}
}

func TestCRMDocumentMappingsRequireDeclaredDestinationsAndOneRecordPerKind(t *testing.T) {
	current := &crmDocumentContext{variables: []crmDocumentVariable{{Name: "customer"}, {Name: "amount"}}}
	good := []crmDocumentMapping{{"customer", "crm.deal", "deal_one", "title"}, {"amount", "crm.deal", "deal_one", "value"}}
	sorted, refs, err := crmCanonicalMappings(current, good)
	if err != nil || len(refs) != 1 || len(sorted) != 2 || sorted[0].Variable != "amount" || good[0].Variable != "customer" {
		t.Fatal("valid grouped selection failed or changed caller order")
	}
	for _, c := range []struct {
		name string
		in   []crmDocumentMapping
	}{
		{"missing desired ledger", nil},
		{"undeclared destination", []crmDocumentMapping{{"hidden", "crm.deal", "deal_one", "title"}}},
		{"two deals", []crmDocumentMapping{{"customer", "crm.deal", "deal_one", "title"}, {"amount", "crm.deal", "deal_two", "value"}}},
		{"duplicate variable", append(append([]crmDocumentMapping{}, good...), good[0])},
		{"invented amount alias", []crmDocumentMapping{{"amount", "crm.deal", "deal_one", "amount"}}},
		{"non CRM binding", []crmDocumentMapping{{"customer", "org.profile", "", "name"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := crmCanonicalMappings(current, c.in); err == nil {
				t.Fatal("invalid mapping admitted")
			}
		})
	}
	if _, refs, err := crmCanonicalMappings(current, []crmDocumentMapping{}); err != nil || len(refs) != 0 {
		t.Fatal("explicit empty unlink refused")
	}
}

func TestCRMDocumentObservationPreservesExactScalarsAndRequiresFreshValueReview(t *testing.T) {
	t.Setenv("HASH_ENVIRONMENT", "development")
	title := "Fresh customer AB"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "user_one", "team_id": "team_one", "is_active": true})
		case "/api/v1/deals/deal_one":
			_ = json.NewEncoder(w).Encode(map[string]any{"id": "deal_one", "team_id": "team_one", "updated_at": time.Now().UTC().Format(time.RFC3339Nano), "title": title, "value": json.Number("1290.2500"), "currency": "", "stage": nil, "contact_id": nil, "company_id": nil, "assigned_to_id": nil})
		default:
			t.Error("unexpected CRM endpoint")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := crmconnection.NewClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	id := crmconnection.Identity{ID: uuid.New(), OrgID: uuid.New(), Generation: 2, Origin: server.URL, CRMTeamID: "team_one", CRMUserID: "user_one"}
	cipher, err := keys.Seal(id, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	row := &generated.CrmConnection{ID: id.ID, OrgID: id.OrgID, Generation: 2, Origin: id.Origin, CrmTeamID: id.CRMTeamID, CrmUserID: id.CRMUserID, Status: "active", CredentialCiphertext: cipher, VerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	current := &crmDocumentContext{doc: &generated.Document{VariablesJson: []byte(`{"customer":"Original AB","manual":"Approved clause"}`)}, connection: row, variables: []crmDocumentVariable{{Name: "customer", MaxChars: 200}, {Name: "amount", MaxChars: 200}, {Name: "currency", MaxChars: 200}, {Name: "stage", MaxChars: 200}}, response: crmDocumentResponseWitness{OrgID: id.OrgID, UserID: uuid.New(), DocumentID: uuid.New(), Connection: &crmDocumentConnectionDTO{ID: id.ID, Generation: "2", Origin: id.Origin, CRMTeamID: id.CRMTeamID, CRMUserID: id.CRMUserID, Status: "active"}}}
	s := &Server{CRMClient: client, CRMKeys: keys, CRMOrigin: server.URL}
	mappings := []crmDocumentMapping{{"customer", "crm.deal", "deal_one", "title"}, {"amount", "crm.deal", "deal_one", "value"}, {"currency", "crm.deal", "deal_one", "currency"}}
	first, err := s.observeCRMDocument(context.Background(), current, mappings)
	if err != nil {
		t.Fatal(err)
	}
	if !first.CanApply || !first.ContentChanged || first.values["amount"] != "1290.2500" || first.values["manual"] != "Approved clause" || first.Items[1].Value == nil || *first.Items[1].Value != "" {
		t.Fatal("CRM scalar normalization, empty string or manual preservation failed")
	}
	second, err := s.observeCRMDocument(context.Background(), current, mappings)
	if err != nil || first.ReviewDigest != second.ReviewDigest {
		t.Fatal("same mapped values changed confirmation solely due to fresh record timestamps", err)
	}
	if first.Items[0].CRMObservation == nil || first.Items[0].CRMObservation.ObservedAt.Equal(second.Items[0].CRMObservation.ObservedAt) {
		t.Fatal("Apply did not capture independently fresh provenance")
	}
	title = "Another AB"
	third, err := s.observeCRMDocument(context.Background(), current, mappings)
	if err != nil || first.ReviewDigest == third.ReviewDigest {
		t.Fatal("changed contractual value reused old review digest", err)
	}
	unavailable, err := s.observeCRMDocument(context.Background(), current, []crmDocumentMapping{{"stage", "crm.deal", "deal_one", "stage"}})
	if err != nil || unavailable.CanApply || unavailable.Items[0].Available || unavailable.Items[0].Value != nil || unavailable.Items[0].UnavailableReason != "field_unavailable" {
		t.Fatal("null became contractual empty string", err)
	}
	current.doc.HtmlSourceJson = []byte(`{}`) // Context admission separately validates the actual retained source.
	emptyHTML, err := s.observeCRMDocument(context.Background(), current, []crmDocumentMapping{{"currency", "crm.deal", "deal_one", "currency"}})
	if err != nil || emptyHTML.CanApply || emptyHTML.Items[0].Value != nil || emptyHTML.Items[0].UnavailableReason != "empty_value_not_materialized" {
		t.Fatal("omitted HTML value incorrectly offered an equal-content materialization", err)
	}
	current.doc.HtmlSourceJson = nil
	current.variables[2].Required = true
	required, err := s.observeCRMDocument(context.Background(), current, []crmDocumentMapping{{"currency", "crm.deal", "deal_one", "currency"}})
	if err != nil || required.CanApply || required.Items[0].UnavailableReason != "required_value_missing" {
		t.Fatal("required empty scalar admitted", err)
	}
}

func TestCRMDocumentExplicitUnlinkNeedsNoProviderAndPreservesValues(t *testing.T) {
	current := &crmDocumentContext{doc: &generated.Document{VariablesJson: []byte(`{"customer":"Agreed AB","clause":"Human reviewed"}`)}, variables: []crmDocumentVariable{{Name: "customer", MaxChars: 200}}}
	out, err := (&Server{}).observeCRMDocument(context.Background(), current, []crmDocumentMapping{})
	if err != nil || !out.CanApply || out.ContentChanged || out.snapshot != nil || out.ObservedAt != "" || out.values["clause"] != "Human reviewed" || out.values["customer"] != "Agreed AB" {
		t.Fatal("reviewed unlink depended on CRM or removed static text", err)
	}
}

func TestCRMDocumentObservationDeadlineRefusesExpiredFutureAndFabricatedAdmission(t *testing.T) {
	now := time.Now()
	for _, at := range []time.Time{{}, now.Add(time.Nanosecond), now.Add(-resolver.CRMObservationMaxAge - time.Nanosecond)} {
		if !errors.Is(crmObservationDeadline(at, now), errCRMDocumentChanged) {
			t.Fatal("untrusted or expired observation admitted")
		}
	}
	if crmObservationDeadline(now.Add(-resolver.CRMObservationMaxAge), now) != nil {
		t.Fatal("exact maximum age refused")
	}
	a := &crmMappingAdmission{source: &crmDocumentContext{}, observation: &crmDocumentObservation{Mappings: []crmDocumentMapping{{Variable: "customer"}}}, now: func() time.Time { return now }}
	if !errors.Is(a.checkDeadline(), errCRMDocumentChanged) {
		t.Fatal("mapping with fabricated empty private snapshot admitted")
	}
}

func TestCRMDocumentStrictJSONAcceptsOriginalWitnessAndRejectsAmbiguity(t *testing.T) {
	witness := CRMDocumentWitness{ExpectedOrgID: uuid.New(), ExpectedUserID: uuid.New(), ExpectedUpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpectedBindingFingerprint: strings.Repeat("a", 64), ExpectedConnectionGeneration: "0"}
	mappings := CRMMappingRequest{witness, []crmDocumentMapping{{"customer", "crm.deal", "deal_one", "title"}}}
	search := struct {
		CRMDocumentWitness
		Kind   string `json:"kind"`
		Query  string `json:"query"`
		Offset int    `json:"offset"`
	}{witness, "crm.deal", "ab", 0}
	apply := struct {
		CRMMappingRequest
		ReviewedDigest string `json:"reviewed_digest"`
		Confirmed      bool   `json:"confirmed"`
	}{mappings, strings.Repeat("b", 64), true}
	for _, c := range []struct {
		name   string
		input  any
		output any
	}{
		{"search", search, &struct {
			CRMDocumentWitness
			Kind   string `json:"kind"`
			Query  string `json:"query"`
			Offset int    `json:"offset"`
		}{}},
		{"observations", mappings, &CRMMappingRequest{}},
		{"apply", apply, &struct {
			CRMMappingRequest
			ReviewedDigest string `json:"reviewed_digest"`
			Confirmed      bool   `json:"confirmed"`
		}{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := json.Marshal(c.input)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("POST", "/", strings.NewReader(string(raw)))
			if err := decodeSignerJSON(req, c.output); err != nil {
				t.Fatal("valid exact flattened original witness refused", err)
			}
		})
	}
	raw, _ := json.Marshal(mappings)
	for _, bad := range []string{strings.TrimSuffix(string(raw), "}") + `,"expected_org_id":"` + witness.ExpectedOrgID.String() + `"}`, strings.Replace(string(raw), `"expected_org_id"`, `"Expected_Org_ID"`, 1), string(raw) + `{}`} {
		if err := decodeSignerJSON(httptest.NewRequest("POST", "/", strings.NewReader(bad)), &CRMMappingRequest{}); err == nil {
			t.Fatal("duplicate, alias or trailing JSON admitted")
		}
	}
}
