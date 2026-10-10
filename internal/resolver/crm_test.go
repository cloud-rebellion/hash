// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateFreshCRMReportRequiresPrivateOriginalObservation(t *testing.T) {
	orgID, docID := uuid.New(), uuid.New()
	now := time.Now()
	binding := &generated.DocumentVariableBinding{DocumentID: docID, VariableName: "customer", SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "title"}
	id := crmconnection.Identity{ID: uuid.New(), OrgID: orgID, Generation: 2, Origin: "https://crm.example.test", CRMTeamID: "team_1", CRMUserID: "user_1"}
	bodySHA := sha256.Sum256([]byte("synthetic typed CRM record"))
	snapshot := crmconnection.Snapshot{Identity: id, CompletedAt: now.Add(-time.Second), Records: []crmconnection.RecordObservation{{Kind: crmconnection.Deal, ID: "deal_1", CRMTeamID: "team_1", ObservedAt: now.Add(-2 * time.Second), RecordUpdatedAt: now.Add(-time.Minute), BodySHA256: hex.EncodeToString(bodySHA[:]), Fields: map[string]crmconnection.Scalar{"title": {Present: true, Value: "Reviewed title"}}}}}
	value, proof, fence, err := crmValue(&snapshot, binding)
	if err != nil {
		t.Fatal(err)
	}
	entry := ResolveReport{bindingSnapshot: binding, crmFence: fence, CRMObservation: proof, Variable: binding.VariableName, SourceKind: binding.SourceKind, SourceRef: binding.SourceRef, SourcePath: binding.SourcePath, Value: value, ResolvedFrom: "source"}
	if err := ValidateFreshCRMReport(entry, orgID, docID, now); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"public_fields_only", "missing_binding", "foreign_org", "foreign_doc", "variable", "source", "record", "path", "value", "origin", "body_proof", "record_time", "transformation", "stale", "future"} {
		t.Run(fault, func(t *testing.T) {
			e := entry
			o := *entry.CRMObservation
			e.CRMObservation = &o
			org, doc, at := orgID, docID, now
			switch fault {
			case "public_fields_only":
				e.crmFence = nil
			case "missing_binding":
				e.bindingSnapshot = nil
			case "foreign_org":
				org = uuid.New()
			case "foreign_doc":
				doc = uuid.New()
			case "variable":
				e.Variable = "other"
			case "source":
				e.SourceKind = "crm.company"
			case "record":
				e.SourceRef = "deal_2"
			case "path":
				e.SourcePath = "value"
			case "value":
				e.Value = "Changed agreement"
			case "origin":
				o.Origin = "https://different.example.test"
			case "body_proof":
				o.BodySHA256 = strings.Repeat("0", 64)
			case "record_time":
				o.RecordUpdatedAt = o.RecordUpdatedAt.Add(time.Second)
			case "transformation":
				o.Transformation = "invented"
			case "stale":
				at = now.Add(CRMObservationMaxAge + time.Second)
			case "future":
				at = now.Add(-time.Minute)
			}
			if err := ValidateFreshCRMReport(e, org, doc, at); !errors.Is(err, ErrSourceFreshness) {
				t.Fatalf("altered/forged report accepted: %v", err)
			}
		})
	}
}

func TestValidateCRMSelectionPreservesExactRelationshipPolicy(t *testing.T) {
	deal := crmconnection.RecordObservation{Kind: crmconnection.Deal, ID: "deal_1", Relationships: map[string]crmconnection.Scalar{"contact_id": {Present: true, Value: "contact_1"}, "company_id": {Present: true, Value: "company_1"}}}
	contact := crmconnection.RecordObservation{Kind: crmconnection.Contact, ID: "contact_1", Relationships: map[string]crmconnection.Scalar{"company_id": {Present: true, Value: "company_1"}}}
	company := crmconnection.RecordObservation{Kind: crmconnection.Company, ID: "company_1"}
	if err := ValidateCRMSelection(crmconnection.Snapshot{Records: []crmconnection.RecordObservation{deal, contact, company}}); err != nil {
		t.Fatal(err)
	}
	for _, fault := range []string{"duplicate_kind", "absent_link", "null_link", "wrong_link"} {
		t.Run(fault, func(t *testing.T) {
			d := deal
			d.Relationships = map[string]crmconnection.Scalar{"contact_id": {Present: true, Value: "contact_1"}, "company_id": {Present: true, Value: "company_1"}}
			records := []crmconnection.RecordObservation{d, contact, company}
			switch fault {
			case "duplicate_kind":
				records = append(records, deal)
			case "absent_link":
				delete(d.Relationships, "company_id")
			case "null_link":
				d.Relationships["company_id"] = crmconnection.Scalar{Present: true, Null: true}
			case "wrong_link":
				d.Relationships["company_id"] = crmconnection.Scalar{Present: true, Value: "company_2"}
			}
			if err := ValidateCRMSelection(crmconnection.Snapshot{Records: records}); !errors.Is(err, ErrSourceFreshness) {
				t.Fatalf("guessed relationship accepted: %v", err)
			}
		})
	}
}

type crmResolverStore struct {
	row         *generated.CrmConnection
	bindings    []*generated.DocumentVariableBinding
	reports     []ResolveReport
	sharedReads int
}

func (s *crmResolverStore) GetCRMConnectionByOrg(_ context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	if s.row.OrgID != org {
		return nil, errors.New("another tenant")
	}
	row := *s.row
	return &row, nil
}
func (s *crmResolverStore) GetCRMConnectionByOrgForShare(ctx context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	s.sharedReads++
	return s.GetCRMConnectionByOrg(ctx, org)
}
func (s *crmResolverStore) ListVariableBindings(context.Context, uuid.UUID) ([]*generated.DocumentVariableBinding, error) {
	return s.bindings, nil
}
func (*crmResolverStore) StageVariableBindingResolved(context.Context, generated.UpdateVariableBindingResolvedParams) error {
	return nil
}
func (*crmResolverStore) StageVariableBindingError(context.Context, generated.UpdateVariableBindingErrorParams) error {
	return nil
}
func (s *crmResolverStore) StageCRMReports(_ context.Context, _, _ uuid.UUID, reports []ResolveReport) error {
	s.reports = reports
	return nil
}

func TestCRMResolverGroupsExactValuesAndRetainsConnectionFence(t *testing.T) {
	token := strings.Repeat("ab", 32)
	accountReads, recordReads := 0, 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("wrong original credential")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			accountReads++
			_, _ = w.Write([]byte(`{"id":"crm_user","team_id":"crm_team","is_active":true}`))
		case "/api/v1/deals/deal_1":
			recordReads++
			_, _ = w.Write([]byte(`{"id":"deal_1","team_id":"crm_team","updated_at":"2026-10-01T10:00:00Z","title":"Reviewed title","value":9007199254740993.01}`))
		default:
			t.Error("unexpected upstream path")
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
	org, docID := uuid.New(), uuid.New()
	id := crmconnection.Identity{ID: uuid.New(), OrgID: org, Generation: 2, Origin: upstream.URL, CRMTeamID: "crm_team", CRMUserID: "crm_user"}
	cipher, err := keys.Seal(id, token)
	if err != nil {
		t.Fatal(err)
	}
	store := &crmResolverStore{row: &generated.CrmConnection{OrgID: org, ID: id.ID, Generation: 2, Status: "active", Origin: id.Origin, CrmTeamID: id.CRMTeamID, CrmUserID: id.CRMUserID, CredentialCiphertext: cipher, VerifiedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}}}
	for _, b := range []struct{ name, path string }{{"amount", "value"}, {"title", "title"}} {
		store.bindings = append(store.bindings, &generated.DocumentVariableBinding{DocumentID: docID, VariableName: b.name, SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: b.path})
	}
	doc := &generated.Document{ID: docID, OrgID: org, Status: "draft", VariablesJson: json.RawMessage(`{"amount":"9007199254740993.01","title":"Reviewed title"}`)}
	engine := New(nil)
	engine.Q = store
	engine.CRM = &CRMRecords{Store: store, Client: client, Keys: keys, Origin: upstream.URL}
	engine.Cache.put(sourceCacheKey(org, "crm.deal", "deal_1", "value"), "untrusted cache")
	frozen, report, err := engine.FreezeForSend(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if accountReads != 2 || recordReads != 1 || !strings.Contains(string(frozen), "9007199254740993.01") || len(store.reports) != 2 {
		t.Fatal("grouped exact observation lost")
	}
	if len(report) != 2 || report[0].CRMObservation == nil || report[0].CRMObservation.Origin != upstream.URL || report[1].CRMObservation == nil || report[1].CRMObservation.Origin != upstream.URL {
		t.Fatal("observed provider origin lost")
	}
	if err = CheckCRMReports(context.Background(), store, org, report); err != nil || store.sharedReads != 1 {
		t.Fatal("fresh report could not retain one connection lock", err)
	}
	report[0].CRMObservation.Origin = "https://substituted-provider.example"
	if err = CheckCRMReports(context.Background(), store, org, report); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("substituted provider origin accepted")
	}
	report[0].CRMObservation.Origin = upstream.URL
	store.row.Generation++
	if err = CheckCRMReports(context.Background(), store, org, report); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("changed connection accepted", err)
	}
	store.row.Generation--
	store.row.Status = "revoked"
	if err = CheckCRMReports(context.Background(), store, org, report); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("revoked connection accepted", err)
	}
	store.row.Status = "active"
	if err = CheckCRMReports(context.Background(), store, uuid.New(), report); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("other organization accepted", err)
	}
	if err = CheckCRMReportDeadlines(report, time.Now().Add(CRMObservationMaxAge+time.Second)); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("expired observation accepted", err)
	}
	report[0].Value = "substituted value"
	if err = CheckCRMReports(context.Background(), store, org, report); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("value substitution accepted", err)
	}
	doc.VariablesJson = json.RawMessage(`{"amount":"1","title":"Reviewed title"}`)
	if _, _, err = engine.FreezeForSend(context.Background(), doc); !errors.Is(err, ErrCRMReviewRequired) {
		t.Fatal("new CRM amount silently replaced reviewed terms", err)
	}
	out, report, err := engine.Resolve(context.Background(), doc, ResolveOptions{AgentOverrides: map[string]string{"amount": "human supplied"}})
	if err != nil || out["amount"] != "human supplied" || report[0].CRMObservation != nil || report[0].ResolvedFrom != "agent_override" || report[0].Value != "human supplied" {
		t.Fatal("override inherited source verification", err)
	}
}

func TestCRMSelectedRelationshipsRefuseGuessingAndAmbiguity(t *testing.T) {
	linked := func(id string) crmconnection.Scalar { return crmconnection.Scalar{Present: true, Value: id} }
	s := crmconnection.Snapshot{Records: []crmconnection.RecordObservation{
		{Kind: crmconnection.Deal, ID: "deal", Relationships: map[string]crmconnection.Scalar{"contact_id": linked("contact"), "company_id": linked("company")}},
		{Kind: crmconnection.Contact, ID: "contact", Relationships: map[string]crmconnection.Scalar{"company_id": linked("company")}}, {Kind: crmconnection.Company, ID: "company"},
	}}
	if err := validateCRMRelationships(s); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []crmconnection.Scalar{{}, {Present: true, Null: true}, {Present: true, Value: "other"}} {
		s.Records[0].Relationships["contact_id"] = missing
		if err := validateCRMRelationships(s); !errors.Is(err, ErrSourceFreshness) {
			t.Fatal("unproved relationship accepted", err)
		}
	}
	s.Records[0].Relationships["contact_id"] = linked("contact")
	s.Records = append(s.Records, crmconnection.RecordObservation{Kind: crmconnection.Contact, ID: "second_contact"})
	if err := validateCRMRelationships(s); !errors.Is(err, ErrSourceFreshness) {
		t.Fatal("ambiguous parties accepted", err)
	}
}

func TestCRMScalarBindingsUseSourceNativeCatalog(t *testing.T) {
	for _, row := range []struct {
		kind SourceKind
		path string
	}{{SourceCRMDeal, "value"}, {SourceCRMContact, "full_name"}, {SourceCRMCompany, "orgnr"}} {
		if err := ValidateBinding("customer", row.kind, "opaque_CUID2", row.path, ""); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		kind      SourceKind
		ref, path string
	}{{SourceCRMDeal, "deal", ""}, {SourceCRMDeal, "deal", "amount"}, {SourceCRMContact, "contact", "authority"}, {SourceCRMCompany, "company", "vat_number"}, {SourceCRMCompany, "../company", "name"}, {SourceCRMDeal, "version@example.test", "title"}} {
		if err := ValidateBinding("customer", row.kind, row.ref, row.path, ""); err == nil {
			t.Fatal("unsupported CRM selector accepted", row)
		}
	}
}
