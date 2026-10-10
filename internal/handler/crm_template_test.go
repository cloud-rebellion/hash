// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func crmTemplateContextFixture(t *testing.T) *crmTemplateContext {
	t.Helper()
	master := htmlmaster.Master{SchemaVersion: 1, HTML: `<p><span data-hash-value="price"></span> <span data-hash-value="currency"></span></p><p><span data-hash-value="manual"></span><span data-hash-value="stage"></span></p><div data-hash-section="scope"></div>`,
		Values:   []htmlmaster.Value{{Name: "price", Required: true, MaxChars: 200}, {Name: "currency", MaxChars: 200}, {Name: "manual", Required: true, MaxChars: 200}, {Name: "stage", MaxChars: 200}},
		Sections: []htmlmaster.Section{{Name: "scope", DefaultText: "Approved default clause", MaxChars: 200}}}
	raw, _ := json.Marshal(master)
	content, err := htmlmaster.CanonicalTemplate(raw, []byte(`{"price":"1000","manual":"Approved static value"}`))
	if err != nil {
		t.Fatal(err)
	}
	master, err = htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	orgID, userID, templateID := uuid.New(), uuid.New(), uuid.New()
	approved := time.Now().UTC().Add(-time.Hour)
	digest, _ := hex.DecodeString(content.SHA256)
	current := &crmTemplateContext{template: &generated.Template{ID: templateID, OrgID: orgID, Version: 3},
		revision: &generated.HtmlTemplateRevision{TemplateID: templateID, OrgID: orgID, Version: 3, ApprovedBy: pgtype.UUID{Bytes: userID, Valid: true}, ApprovedAt: pgtype.Timestamptz{Time: approved, Valid: true}, HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON, ContentSha256: digest},
		content:  content, compiled: compiled, defaults: map[string]string{"price": "1000", "manual": "Approved static value"},
		response: crmTemplateResponseWitness{OrgID: orgID, UserID: userID, TemplateID: templateID, TemplateVersion: 3, TemplateContentSHA256: content.SHA256, TemplateApprovedBy: userID, TemplateApprovedAt: approved.Format(time.RFC3339Nano)}}
	for _, field := range master.Values {
		value, exists := current.defaults[field.Name]
		current.variables = append(current.variables, crmTemplateVariable{Name: field.Name, Required: field.Required, MaxChars: field.MaxChars, CurrentPresent: exists, CurrentValue: value})
	}
	return current
}

func crmTemplateProtectedClientFixture(t *testing.T, current *crmTemplateContext, body func() string) *Server {
	t.Helper()
	t.Setenv("HASH_ENVIRONMENT", "development")
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			_, _ = io.WriteString(w, `{"id":"user_one","team_id":"team_one","is_active":true}`)
		case "/api/v1/deals/deal_one":
			_, _ = io.WriteString(w, body())
		default:
			t.Error("unexpected synthetic CRM route")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(peer.Close)
	client, err := crmconnection.NewClient(peer.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(strings.Repeat("a", 64), "")
	if err != nil {
		t.Fatal(err)
	}
	identity := crmconnection.Identity{ID: uuid.New(), OrgID: current.response.OrgID, Generation: 2, Origin: peer.URL, CRMTeamID: "team_one", CRMUserID: "user_one"}
	cipher, err := keys.Seal(identity, strings.Repeat("b", 64))
	if err != nil {
		t.Fatal(err)
	}
	current.connection = &generated.CrmConnection{ID: identity.ID, OrgID: identity.OrgID, Generation: identity.Generation, Origin: identity.Origin,
		CrmTeamID: identity.CRMTeamID, CrmUserID: identity.CRMUserID, Status: "active", CredentialCiphertext: cipher, VerifiedAt: pgtype.Timestamptz{Time: time.Now(), Valid: true}}
	current.response.Connection = &crmDocumentConnectionDTO{ID: identity.ID, Generation: "2", Origin: identity.Origin, CRMTeamID: identity.CRMTeamID, CRMUserID: identity.CRMUserID, Status: "active"}
	return &Server{CRMClient: client, CRMKeys: keys, CRMOrigin: peer.URL}
}

func TestCRMTemplateWitnessBindsOriginalActorApprovalAndAccount(t *testing.T) {
	current := crmTemplateContextFixture(t)
	actor := authoring.Actor{OrgID: current.response.OrgID, UserID: current.response.UserID}
	witness := crmTemplateWitnessFor(current)
	if witness.validate(actor) != nil || witness.matches(current) != nil {
		t.Fatal("current approved original-actor witness refused")
	}
	for _, c := range []struct {
		name   string
		change func(*CRMTemplateWitness)
	}{
		{"foreign org", func(v *CRMTemplateWitness) { v.ExpectedOrgID = uuid.New() }},
		{"foreign actor", func(v *CRMTemplateWitness) { v.ExpectedUserID = uuid.New() }},
		{"changed approver", func(v *CRMTemplateWitness) { v.ExpectedTemplateApprovedBy = uuid.New() }},
		{"changed approval instant", func(v *CRMTemplateWitness) {
			v.ExpectedTemplateApprovedAt = current.revision.ApprovedAt.Time.Add(time.Nanosecond).Format(time.RFC3339Nano)
		}},
		{"changed master", func(v *CRMTemplateWitness) { v.ExpectedTemplateContentSHA256 = strings.Repeat("b", 64) }},
		{"changed revision", func(v *CRMTemplateWitness) { v.ExpectedTemplateVersion++ }},
		{"introduced account", func(v *CRMTemplateWitness) {
			v.ExpectedConnectionID, v.ExpectedConnectionGeneration = uuid.New().String(), "1"
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := witness
			c.change(&changed)
			if changed.validate(actor) == nil && changed.matches(current) == nil {
				t.Fatal("changed initial witness admitted")
			}
		})
	}
	for _, generation := range []string{"", "01", "-1", "9223372036854775808"} {
		bad := witness
		bad.ExpectedConnectionGeneration = generation
		if !errors.Is(bad.validate(actor), errCRMTemplateInput) {
			t.Fatal("noncanonical generation admitted")
		}
	}
}

func TestCRMTemplateObservationInitialOptionalEmptyAndFreshScalars(t *testing.T) {
	current := crmTemplateContextFixture(t)
	value := "1290.2500"
	server := crmTemplateProtectedClientFixture(t, current, func() string {
		return `{"id":"deal_one","team_id":"team_one","updated_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","title":"Fresh AB","value":` + value + `,"currency":"","stage":null,"contact_id":null,"company_id":null,"assigned_to_id":null}`
	})
	candidate := CRMTemplateCandidate{Name: "Human proposal", Values: htmlStringMap{"manual": "Human wording ÅÄÖ"}, Sections: htmlStringMap{"scope": "Two lines\nPreserved terms"}}
	mappings := []crmDocumentMapping{{"price", "crm.deal", "deal_one", "value"}, {"currency", "crm.deal", "deal_one", "currency"}}
	first, err := server.observeCRMTemplate(context.Background(), current, candidate, mappings)
	if err != nil || !first.CanCreate || first.snapshot == nil || first.values["price"] != value || first.values["manual"] != candidate.Values["manual"] {
		t.Fatal("fresh exact decimal or manual preservation failed", err)
	}
	if _, present := first.values["currency"]; !present || first.values["currency"] != "" || first.Items[0].CurrentPresent || !first.Items[0].Available || first.Items[0].Value == nil || *first.Items[0].Value != "" {
		t.Fatal("initial optional empty became unavailable or lost its presence")
	}
	if _, present := current.defaults["currency"]; present || candidate.Values["price"] != "" || candidate.Sections["scope"] != "Two lines\nPreserved terms" {
		t.Fatal("observation changed caller/default inputs")
	}
	second, err := server.observeCRMTemplate(context.Background(), current, candidate, mappings)
	if err != nil || second.ReviewDigest != first.ReviewDigest || second.snapshot.CompletedAt.Equal(first.snapshot.CompletedAt) {
		t.Fatal("equal scalar review depended on old provider read time", err)
	}
	value = "1590.1250"
	third, err := server.observeCRMTemplate(context.Background(), current, candidate, mappings)
	if err != nil || third.ReviewDigest == first.ReviewDigest || third.values["price"] != value {
		t.Fatal("changed exact scalar retained old confirmation", err)
	}
	candidate.Sections["scope"] = "Changed human clause"
	fourth, err := server.observeCRMTemplate(context.Background(), current, candidate, mappings)
	if err != nil || third.ReviewDigest == fourth.ReviewDigest {
		t.Fatal("manual wording escaped the complete candidate commitment", err)
	}
}

func TestCRMTemplateObservationUnavailableNeverFallsBack(t *testing.T) {
	current := crmTemplateContextFixture(t)
	server := crmTemplateProtectedClientFixture(t, current, func() string {
		return `{"id":"deal_one","team_id":"team_one","updated_at":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","value":null,"currency":"","stage":null,"contact_id":null,"company_id":null,"assigned_to_id":null}`
	})
	candidate := CRMTemplateCandidate{Name: "Proposal", Values: htmlStringMap{"price": "Manual fallback must not hide unavailable CRM"}}
	observation, err := server.observeCRMTemplate(context.Background(), current, candidate, []crmDocumentMapping{{"price", "crm.deal", "deal_one", "value"}})
	if err != nil || observation.CanCreate || observation.Items[0].Available || observation.Items[0].Value != nil || observation.Items[0].CRMObservation != nil || observation.Items[0].UnavailableReason != "field_unavailable" {
		t.Fatal("null selected scalar admitted a fallback contract", err)
	}
	if observation.values["price"] != candidate.Values["price"] {
		t.Fatal("unavailable selected scalar silently changed manual input")
	}
	for i := range current.variables {
		if current.variables[i].Name == "currency" {
			current.variables[i].Required = true
		}
	}
	observation, err = server.observeCRMTemplate(context.Background(), current, CRMTemplateCandidate{Name: "Proposal"}, []crmDocumentMapping{{"currency", "crm.deal", "deal_one", "currency"}})
	if err != nil || observation.CanCreate || observation.Items[0].UnavailableReason != "required_value_missing" {
		t.Fatal("required empty admitted", err)
	}
}

func TestCRMTemplateEmptyMappingNeedsNoProviderAndPreservesText(t *testing.T) {
	current := crmTemplateContextFixture(t)
	current.connection = &generated.CrmConnection{ID: uuid.New(), Generation: 2, Status: "revoked"}
	current.response.Connection = &crmDocumentConnectionDTO{ID: current.connection.ID, Generation: "2", Status: "revoked"}
	candidate := CRMTemplateCandidate{Name: "Manual proposal", Values: htmlStringMap{"price": "Agreed value"}, Sections: htmlStringMap{"scope": "Manually revised clause"}}
	observation, err := (&Server{}).observeCRMTemplate(context.Background(), current, candidate, []crmDocumentMapping{})
	if err != nil || !observation.CanCreate || observation.snapshot != nil || observation.values["price"] != "Agreed value" || observation.values["manual"] != current.defaults["manual"] || observation.ObservedAt == "" {
		t.Fatal("explicit empty population required provider or changed text", err)
	}
	if _, err = (&Server{}).observeCRMTemplate(context.Background(), current, candidate, nil); err == nil {
		t.Fatal("omitted complete mapping list admitted")
	}
}

func TestCRMTemplateMappingAndCandidateRefusalBeforePrivateRead(t *testing.T) {
	current := crmTemplateContextFixture(t)
	candidate := CRMTemplateCandidate{Name: "Proposal"}
	for _, mappings := range [][]crmDocumentMapping{
		{{"undeclared", "crm.deal", "deal_one", "title"}},
		{{"price", "crm.deal", "deal_one", "value"}, {"currency", "crm.deal", "deal_two", "currency"}},
		{{"price", "crm.deal", "deal_one", "value"}, {"price", "crm.deal", "deal_one", "value"}},
		{{"price", "crm.deal", "deal_one", "amount"}},
		{{"price", "org.profile", "", "name"}},
	} {
		if _, err := (&Server{}).observeCRMTemplate(context.Background(), current, candidate, mappings); !errors.Is(err, errCRMDocumentInput) {
			t.Fatal("invalid initial mapping reached protected client admission", err)
		}
	}
	for _, invalid := range []CRMTemplateCandidate{
		{Name: "Proposal", Values: htmlStringMap{"hidden": "Unknown"}},
		{Name: "Proposal", Sections: htmlStringMap{"hidden": "Unknown section"}},
		{Name: "Proposal", Values: htmlStringMap{"manual": strings.Repeat("x", 201)}},
	} {
		if _, err := (&Server{}).observeCRMTemplate(context.Background(), current, invalid, []crmDocumentMapping{{"price", "crm.deal", "deal_one", "value"}}); err == nil || errors.Is(err, crmconnection.ErrNotConfigured) {
			t.Fatal("invalid candidate reached private provider read", err)
		}
	}
}

func TestCRMTemplateReadinessCoversApprovedProfilesAndManualSections(t *testing.T) {
	for _, branded := range []bool{false, true} {
		name := "profile2"
		if branded {
			name = "profile3"
		}
		t.Run(name, func(t *testing.T) {
			input, _, _ := testfixture.HTMLContract(t)
			if branded {
				input, _, _ = testfixture.BrandedHTMLContract(t)
			}
			master, err := htmlmaster.Decode(input.MasterJSON)
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := htmlmaster.Compile(master)
			if err != nil {
				t.Fatal(err)
			}
			current := &crmTemplateContext{compiled: compiled, defaults: input.Values}
			for _, field := range master.Values {
				current.variables = append(current.variables, crmTemplateVariable{Name: field.Name, Required: field.Required, MaxChars: field.MaxChars})
			}
			out, err := (&Server{}).observeCRMTemplate(context.Background(), current, CRMTemplateCandidate{Name: "Reviewed proposal", Values: htmlStringMap{"customer_name": ""}}, []crmDocumentMapping{})
			if err != nil || out.CanCreate || len(out.ContractIssues) == 0 {
				t.Fatal("missing printed party admitted", err)
			}
			out, err = (&Server{}).observeCRMTemplate(context.Background(), current, CRMTemplateCandidate{Name: "Reviewed proposal"}, []crmDocumentMapping{})
			if err != nil || !out.CanCreate {
				t.Fatal("complete reviewed profile refused", err)
			}
		})
	}
}

func TestCRMTemplateStrictJSONKeepsEmbeddedFieldsReachable(t *testing.T) {
	current := crmTemplateContextFixture(t)
	in := CRMTemplateObservationRequest{CRMTemplateWitness: crmTemplateWitnessFor(current), Candidate: &CRMTemplateCandidate{Name: "Proposal", Values: htmlStringMap{"price": "1000"}, Sections: htmlStringMap{"scope": "Exact words"}}, Mappings: []crmDocumentMapping{}}
	raw, _ := json.Marshal(in)
	var decoded CRMTemplateObservationRequest
	if decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &decoded) != nil || decoded.Candidate == nil || decoded.ExpectedTemplateApprovedBy != in.ExpectedTemplateApprovedBy {
		t.Fatal("valid exported embedded witness refused")
	}
	bad := []string{
		strings.Replace(string(raw), `"name":"Proposal"`, `"name":"Proposal","name":"Changed"`, 1),
		strings.Replace(string(raw), `"expected_org_id"`, `"EXPECTED_ORG_ID"`, 1),
		strings.Replace(string(raw), `"scope":"Exact words"`, `"scope":null`, 1),
		strings.Replace(string(raw), `"price":"1000"`, `"price":null`, 1),
		strings.Replace(string(raw), `"expected_connection_id":""`, `"expected_connection_id":null`, 1),
		strings.Replace(string(raw), `"candidate":{`, `"candidate":null,"extra_candidate":{`, 1),
		strings.Replace(string(raw), `"name":"Proposal"`, `"name":"Proposal","unexpected":true`, 1),
		string(raw) + `{}`,
	}
	for _, body := range bad {
		if decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(body)), &decoded) == nil {
			t.Fatal("ambiguous candidate JSON admitted")
		}
	}
}
