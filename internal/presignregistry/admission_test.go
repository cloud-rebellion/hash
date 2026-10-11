// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func admissionFixture(t testing.TB) (WorkflowDefinition, presign.NamedRepresentative, htmlsource.Input, *generated.Document) {
	t.Helper()
	in, doc, _ := testfixture.BrandedHTMLContract(t)
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	m.Values = append(m.Values, htmlmaster.Value{Name: "optional_note", MaxChars: 100})
	m.Sections = []htmlmaster.Section{{Name: "manual_scope", DefaultText: "Approved original wording", MaxChars: 500}}
	m.HTML += `<p><span data-hash-value="optional_note"></span></p><p data-hash-section="manual_scope"></p>`
	raw, _ := json.Marshal(m)
	pin, err := htmlmaster.CanonicalTemplate(raw, []byte(`{"optional_note":"Approved default"}`))
	if err != nil {
		t.Fatal(err)
	}
	in.MasterJSON, in.DefaultVarsJSON, in.TemplateContentSHA256 = pin.MasterJSON, pin.DefaultsJSON, pin.SHA256
	rebuildAdmissionSource(t, &in, doc)
	d := definitionFixture(t)
	d.OrgID = doc.OrgID
	d.Executor = presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: doc.SenderID}
	d.Template = presign.TemplatePin{ID: in.TemplateID, Version: int64(in.TemplateVersion), ContentSHA256: in.TemplateContentSHA256, ApprovedBy: in.TemplateApprovedBy, ApprovedAt: in.TemplateApprovedAt}
	d.Kind = KindApprovedData
	d.RecipientRules.ProviderCompanyName = in.Values["provider_company"]
	d.RecipientRules.ProviderCompanyID = in.Values["provider_company_id"]
	d.RecipientRules.ProviderAuthorityBasis = in.Values["provider_authority"]
	provider := map[string]string{"provider_company": "company_name", "provider_company_id": "company_id", "provider_name": "name", "provider_email": "email", "provider_authority": "authority_basis"}
	d.DataRules.Values = []ValueRule{}
	for _, v := range m.Values {
		r := ValueRule{Variable: v.Name, Mode: ModeLiteral}
		if f := provider[v.Name]; f != "" {
			r.Mode, r.GrantorField = ModeGrantor, f
		} else if v.Name == "optional_note" {
			r.Mode = ModeAbsent
		} else {
			text := in.Values[v.Name]
			r.Literal = &text
		}
		d.DataRules.Values = append(d.DataRules.Values, r)
	}
	d.DataRules.Sections = []SectionRule{{Section: "manual_scope", Mode: ModeDefault}}
	g := presign.NamedRepresentative{UserID: doc.SenderID, Name: in.Values["provider_name"], Email: in.Values["provider_email"], CompanyName: in.Values["provider_company"], CompanyID: in.Values["provider_company_id"], AuthorityBasis: in.Values["provider_authority"]}
	return d, g, in, doc
}

func rebuildAdmissionSource(t testing.TB, in *htmlsource.Input, doc *generated.Document) {
	t.Helper()
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	c, err := htmlmaster.Compile(m)
	if err != nil {
		t.Fatal(err)
	}
	in.SigningArtifact, err = htmlsource.NewSigningArtifact(c, htmlmaster.Input{Values: in.Values, Sections: in.Sections}, in.PartyBindings, in.SigningArtifact.Composition)
	if err != nil {
		t.Fatal(err)
	}
	doc.VariablesJson, err = json.Marshal(in.Values)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = htmlsource.New(*in, doc)
	if err != nil {
		t.Fatal(err)
	}
}

func admissionAt() time.Time { return time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC) }

func TestExecutionDataAdmissionEnforcesApprovedRulesWithoutInventingReview(t *testing.T) {
	d, g, _, doc := admissionFixture(t)
	doc.HtmlReviewedBy = pgtype.UUID{}
	doc.HtmlReviewedAt = pgtype.Timestamptz{}
	doc.HtmlReviewedPdfSha256 = nil
	a, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot().InputMode != presign.InputApprovedData || a.Snapshot().ReviewKind != "none" || a.Snapshot().ReviewEvidenceSHA256 != NoHumanReviewSHA256() || doc.HtmlReviewedBy.Valid || doc.HtmlReviewedAt.Valid || len(doc.HtmlReviewedPdfSha256) != 0 {
		t.Fatal("approved data created or claimed a human review")
	}
	round, err := DecodeDataAdmission(a.CanonicalJSON())
	if err != nil || round.Commitment() != a.Commitment() {
		t.Fatal("committed admission did not roundtrip", err)
	}
	if a.Commitment() == sha(a.CanonicalJSON()) || a.Commitment() == domainSHA("hash:presign-workflow:v1", a.CanonicalJSON()) {
		t.Fatal("admission domain collides")
	}
	raw := a.CanonicalJSON()
	raw[0] = 'x'
	s := a.Snapshot()
	s.CRMRecords = append(s.CRMRecords, RecordRule{Kind: "crm.deal", ID: "fake"})
	if !bytes.Equal(a.CanonicalJSON(), round.CanonicalJSON()) || len(a.Snapshot().CRMRecords) != 0 {
		t.Fatal("caller mutated immutable admission")
	}
}

func TestExecutionDataAdmissionRejectsPrintedPolicyDrift(t *testing.T) {
	for _, name := range []string{"literal", "grantor", "section", "absent_to_empty", "foreign_org", "foreign_author", "template_approval", "unapproved_mapping"} {
		t.Run(name, func(t *testing.T) {
			d, g, in, doc := admissionFixture(t)
			var reports []resolver.ResolveReport
			switch name {
			case "literal":
				in.Values["price"] = "2000"
				rebuildAdmissionSource(t, &in, doc)
			case "grantor":
				g.Name = "A different representative"
			case "section":
				in.Sections["manual_scope"] = "New legal prose"
				rebuildAdmissionSource(t, &in, doc)
			case "absent_to_empty":
				in.Values["optional_note"] = ""
				rebuildAdmissionSource(t, &in, doc)
			case "foreign_org":
				d.OrgID = uuid.New()
			case "foreign_author":
				g.UserID = uuid.New()
			case "template_approval":
				d.Template.ApprovedAt = d.Template.ApprovedAt.Add(time.Microsecond)
			case "unapproved_mapping":
				reports = []resolver.ResolveReport{{Variable: "price", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "value", Value: in.Values["price"], ResolvedFrom: "source"}}
			}
			if _, err := EvaluateExecutionData(d, g, doc, reports, admissionAt()); err == nil {
				t.Fatal("changed rule or authority witness accepted")
			}
		})
	}
}

func TestExecutionDataAdmissionDefaultsLiteralsAndReviewedSections(t *testing.T) {
	d, g, in, doc := admissionFixture(t)
	for i := range d.DataRules.Values {
		if d.DataRules.Values[i].Variable == "optional_note" {
			d.DataRules.Values[i].Mode = ModeDefault
		}
	}
	if _, err := EvaluateExecutionData(d, g, doc, nil, admissionAt()); err == nil {
		t.Fatal("absent printed value silently adopted default")
	}
	in.Values["optional_note"] = "Approved default"
	rebuildAdmissionSource(t, &in, doc)
	base, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	in.Values["optional_note"] = "Edited default"
	rebuildAdmissionSource(t, &in, doc)
	if _, err := EvaluateExecutionData(d, g, doc, nil, admissionAt()); err == nil {
		t.Fatal("edited approved default accepted")
	}
	d.Kind = KindReviewedDocument
	for i := range d.DataRules.Values {
		d.DataRules.Values[i] = ValueRule{Variable: d.DataRules.Values[i].Variable, Mode: ModeReviewedValue}
	}
	d.DataRules.Sections[0].Mode = ModeReviewedValue
	in.Sections["manual_scope"] = "Human reviewed replacement text"
	rebuildAdmissionSource(t, &in, doc)
	a, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshot().ReviewEvidenceSHA256 == "" || a.Commitment() == base.Commitment() {
		t.Fatal("actual review or changed text not committed")
	}
	doc.HtmlReviewedBy = pgtype.UUID{}
	if _, err := EvaluateExecutionData(d, g, doc, nil, admissionAt()); err == nil {
		t.Fatal("reviewed workflow accepted missing real review")
	}
}

func TestDataAdmissionDecodeRejectsAmbiguousAndNoncanonicalEvidence(t *testing.T) {
	d, g, _, doc := admissionFixture(t)
	a, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	raw := string(a.CanonicalJSON())
	for _, bad := range []string{raw + "\n", strings.Replace(raw, `"version":1`, `"version":1,"Version":1`, 1), strings.Replace(raw, `"crm_values":[]`, `"crm_values":null`, 1), strings.Replace(raw, `"version":1`, `"version":1,"version":1`, 1), strings.Replace(raw, `"input_mode":"approved_data"`, `"input_mode":"approved_data","review_evidence_sha256":"`+strings.Repeat("a", 64)+`"`, 1)} {
		if _, err := DecodeDataAdmission([]byte(bad)); err == nil {
			t.Fatal("ambiguous or noncanonical evidence accepted")
		}
	}
}

func TestExecutionDataAdmissionRecoveryBindsActualSourceAndReview(t *testing.T) {
	d, g, in, doc := admissionFixture(t)
	d.Kind = KindReviewedDocument
	for i := range d.DataRules.Values {
		d.DataRules.Values[i] = ValueRule{Variable: d.DataRules.Values[i].Variable, Mode: ModeReviewedValue}
	}
	d.DataRules.Sections[0].Mode = ModeReviewedValue
	a, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	doc.Status = "in_progress"
	if err := ValidateDataAdmissionDocument(a, doc); err != nil {
		t.Fatal("committed recovery demanded a new draft admission", err)
	}
	doc.HtmlReviewedAt.Time = doc.HtmlReviewedAt.Time.Add(time.Second)
	if htmlsource.Validate(doc, true) != nil {
		t.Fatal("synthetic altered review is not structurally valid")
	}
	if ValidateDataAdmissionDocument(a, doc) == nil {
		t.Fatal("replacement actual review record adopted")
	}
	doc.HtmlReviewedAt.Time = doc.HtmlReviewedAt.Time.Add(-time.Second)
	in.Values["price"] = "2000"
	rebuildAdmissionSource(t, &in, doc)
	if ValidateDataAdmissionDocument(a, doc) == nil {
		t.Fatal("changed printed contract adopted during recovery")
	}
}

func TestExecutionDataAdmissionRejectsOuterAuthorityLineage(t *testing.T) {
	d, g, _, doc := admissionFixture(t)
	a, err := EvaluateExecutionData(d, g, doc, nil, admissionAt())
	if err != nil {
		t.Fatal(err)
	}
	_, definitionSHA, rules, err := CanonicalDefinition(d)
	if err != nil {
		t.Fatal(err)
	}
	approved := d.Template.ApprovedAt.Add(time.Minute)
	ps := presign.PolicySnapshot{SchemaVersion: 1, ID: d.PolicyID, OrgID: d.OrgID, Revision: d.Revision, Template: d.Template,
		Workflow: presign.WorkflowPin{ID: d.ID, Revision: d.Revision, ContentSHA256: definitionSHA, ApprovedBy: d.Template.ApprovedBy, ApprovedAt: approved},
		Executor: d.Executor, Operation: d.Operation, Rules: rules, MaxGrantDurationSeconds: d.MaxGrantDurationSeconds, MaxUses: d.MaxUses, ApprovedBy: d.Template.ApprovedBy, ApprovedAt: approved}
	p, err := presign.NewPolicy(ps)
	if err != nil {
		t.Fatal(err)
	}
	granted := approved.Add(time.Minute)
	gs := presign.GrantSnapshot{SchemaVersion: 1, ID: uuid.New(), OrgID: d.OrgID, Revision: 1, Policy: p.Reference(), Grantor: g,
		Signature: presign.SignatureStyle{Font: "Caveat", FontSHA256: strings.Repeat("a", 64)}, Disclosure: presign.CopyPin{Version: 1, SHA256: strings.Repeat("b", 64)},
		GrantedAt: granted, NotBefore: granted, ExpiresAt: granted.Add(time.Hour), MaxUses: 1}
	grant, err := presign.NewGrant(gs)
	if err != nil {
		t.Fatal(err)
	}
	s := a.Snapshot()
	descriptor := presign.DocumentSnapshot{ID: doc.ID, OrgID: doc.OrgID, SenderID: doc.SenderID, Template: d.Template,
		Materialization: presign.MaterializationPin{SourceCommitment: s.SourceCommitment}, ValuesSHA256: s.ValuesSHA256, SectionsSHA256: s.SectionsSHA256, ReviewEvidenceSHA256: s.ReviewEvidenceSHA256, DataEvidenceSHA256: a.Commitment()}
	if err := ValidateDataAdmissionForExecution(a, p, grant, descriptor); err != nil {
		t.Fatal("exact data lineage refused", err)
	}
	for _, name := range []string{"policy_org", "grant_org", "grant_policy", "policy_template", "grantor"} {
		t.Run(name, func(t *testing.T) {
			policySnapshot, grantSnapshot := ps, gs
			switch name {
			case "policy_org":
				policySnapshot.OrgID = uuid.New()
			case "grant_org":
				grantSnapshot.OrgID = uuid.New()
			case "grant_policy":
				grantSnapshot.Policy.SHA256 = strings.Repeat("c", 64)
			case "policy_template":
				policySnapshot.Template.Version++
			case "grantor":
				grantSnapshot.Grantor.UserID = uuid.New()
			}
			otherPolicy, err := presign.NewPolicy(policySnapshot)
			if err != nil {
				t.Fatal(err)
			}
			if name == "policy_org" || name == "policy_template" {
				grantSnapshot.Policy = otherPolicy.Reference()
			}
			otherGrant, err := presign.NewGrant(grantSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			if ValidateDataAdmissionForExecution(a, otherPolicy, otherGrant, descriptor) == nil {
				t.Fatal("foreign outer lineage accepted")
			}
		})
	}
}

type admissionCRMStore struct {
	connection *generated.CrmConnection
	bindings   []*generated.DocumentVariableBinding
}

func (s *admissionCRMStore) GetCRMConnectionByOrg(_ context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	if s.connection.OrgID != org {
		return nil, errors.New("foreign synthetic tenant")
	}
	r := *s.connection
	return &r, nil
}
func (s *admissionCRMStore) ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	return s.bindings, nil
}
func (*admissionCRMStore) StageVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error {
	return nil
}
func (*admissionCRMStore) StageVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error {
	return nil
}
func (*admissionCRMStore) StageCRMReports(context.Context, uuid.UUID, uuid.UUID, []resolver.ResolveReport) error {
	return nil
}

func TestExecutionDataAdmissionRequiresActualOriginalCRMScalarFence(t *testing.T) {
	d, g, in, doc := admissionFixture(t)
	in.Values["price"] = "9007199254740993.01"
	rebuildAdmissionSource(t, &in, doc)
	accountReads, recordReads := 0, 0
	token := strings.Repeat("ab", 32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("wrong synthetic credential")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			accountReads++
			_, _ = w.Write([]byte(`{"id":"crm_user","team_id":"crm_team","is_active":true}`))
		case "/api/v1/deals/deal_1":
			recordReads++
			_, _ = w.Write([]byte(`{"id":"deal_1","team_id":"crm_team","updated_at":"2026-10-01T10:00:00Z","value":9007199254740993.01}`))
		default:
			t.Error("unexpected synthetic CRM path")
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
	id := crmconnection.Identity{ID: uuid.New(), OrgID: doc.OrgID, Generation: 2, Origin: upstream.URL, CRMTeamID: "crm_team", CRMUserID: "crm_user"}
	cipher, err := keys.Seal(id, token)
	if err != nil {
		t.Fatal(err)
	}
	store := &admissionCRMStore{connection: &generated.CrmConnection{ID: id.ID, OrgID: id.OrgID, Generation: id.Generation, Origin: id.Origin, CrmTeamID: id.CRMTeamID, CrmUserID: id.CRMUserID, Status: "active", CredentialCiphertext: cipher, VerifiedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}},
		bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "price", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "value"}}}
	r := resolver.New(nil)
	r.Q = store
	r.CRM = &resolver.CRMRecords{Store: store, Client: client, Keys: keys, Origin: upstream.URL}
	_, reports, err := r.FreezeForSend(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if accountReads != 2 || recordReads != 1 {
		t.Fatal("original account bookends or grouped record read missing")
	}
	for i := range d.DataRules.Values {
		if d.DataRules.Values[i].Variable == "price" {
			d.DataRules.Values[i] = ValueRule{Variable: "price", Mode: ModeCRM, SourceKind: "crm.deal", SourcePath: "value"}
		}
	}
	d.DataRules.CRM = &CRMScope{ConnectionID: id.ID, Generation: id.Generation, Origin: id.Origin, TeamID: id.CRMTeamID, UserID: id.CRMUserID, Selection: "fixed_record_set", Records: []RecordRule{{Kind: "crm.deal", ID: "deal_1"}}}
	at := time.Now()
	a, err := EvaluateExecutionData(d, g, doc, reports, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Snapshot().CRMValues) != 1 || a.Snapshot().CRMRecords[0].ID != "deal_1" || a.Snapshot().ValidUntil.IsZero() {
		t.Fatal("exact selected observation or deadline absent")
	}
	if _, err := DecodeDataAdmission(a.CanonicalJSON()); err != nil {
		t.Fatal("actual CRM admission did not roundtrip", err)
	}
	var price resolver.ResolveReport
	for _, v := range reports {
		if v.Variable == "price" {
			price = v
		}
	}
	fake := resolver.ResolveReport{Variable: price.Variable, SourceKind: price.SourceKind, SourceRef: price.SourceRef, SourcePath: price.SourcePath, Value: price.Value, ResolvedFrom: price.ResolvedFrom, CRMObservation: price.CRMObservation}
	if _, err := EvaluateExecutionData(d, g, doc, []resolver.ResolveReport{fake}, at); err == nil {
		t.Fatal("public JSON fields impersonated a private CRM observation")
	}
	for _, name := range []string{"wrong_record", "generation", "scalar_path", "duplicate", "fallback", "altered_scalar", "expired", "execution_record_set"} {
		t.Run(name, func(t *testing.T) {
			definition := d
			scope := *d.DataRules.CRM
			scope.Records = append([]RecordRule{}, scope.Records...)
			definition.DataRules.CRM = &scope
			entries := []resolver.ResolveReport{price}
			now := at
			switch name {
			case "wrong_record":
				scope.Records[0].ID = "another_deal"
			case "generation":
				scope.Generation++
			case "scalar_path":
				entries[0].SourcePath = "title"
			case "duplicate":
				entries = append(entries, price)
			case "fallback":
				entries[0].ResolvedFrom = "fallback"
			case "altered_scalar":
				entries[0].Value = "9007199254740993.02"
			case "expired":
				now = at.Add(resolver.CRMObservationMaxAge + time.Second)
			case "execution_record_set":
				scope.Selection = "execution_record_set"
				scope.Records[0].ID = ""
			}
			_, err := EvaluateExecutionData(definition, g, doc, entries, now)
			if name == "execution_record_set" {
				if err != nil {
					t.Fatal("recognized fresh execution record selection refused", err)
				}
			} else if err == nil {
				t.Fatal("changed original CRM witness accepted")
			}
		})
	}
}
