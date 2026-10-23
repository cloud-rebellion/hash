//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Real registered workflow approval/self-grant for one actual org API key.
// Approved defaults come from the exact retained template revision, and the
// printed provider is the actual grantor. There are no placeholder references,
// reconstructed source receipts or fabricated interactive CRM reviews.
func preSign488ApprovedAPIAuthorityV1(t *testing.T, f preSign488PreparationFixtureV1, doc *generated.Document, credential uuid.UUID) (presign.Reference, presign.Reference) {
	t.Helper()
	q := f.q
	revision, err := q.f.q.GetHTMLTemplateRevision(q.f.ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: f.template.ID, OrgID: q.f.org, Version: f.template.Version})
	if err != nil || !revision.ApprovedBy.Valid || !revision.ApprovedAt.Valid {
		t.Fatal("actual approved revision missing", err)
	}
	master, err := htmlmaster.Decode(revision.HtmlMasterJson)
	if err != nil {
		t.Fatal(err)
	}
	var defaults map[string]string
	if json.Unmarshal(revision.VariablesJson, &defaults) != nil {
		t.Fatal("actual template defaults invalid")
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	providerRules := map[string]string{}
	if master.ContractProfile == nil {
		t.Fatal("actual approved contract profile missing")
	}
	for _, party := range master.ContractProfile.Parties {
		if party.Slot == "provider" {
			providerRules = map[string]string{party.RepresentativeName: "name", party.RepresentativeEmail: "email", party.CompanyName: "company_name", party.CompanyID: "company_id", party.RepresentativeAuthority: "authority_basis"}
		}
	}
	var company, companyID, basis string
	for _, party := range parties {
		if party.Slot == "provider" {
			if party.Name != q.f.user.Name || party.Email != q.f.user.Email {
				t.Fatal("actual printed provider differs from grantor")
			}
			company, companyID, basis = party.CompanyName, party.CompanyID, party.Authority
		}
	}
	definition := presignregistry.WorkflowDefinition{Version: 1, ID: uuid.New(), PolicyID: uuid.New(), OrgID: q.f.org, Revision: 1, Name: "Controlled original API source488", Kind: presignregistry.KindApprovedData,
		Template: presign.TemplatePin{ID: f.template.ID, Version: int64(f.template.Version), ContentSHA256: hex.EncodeToString(revision.ContentSha256), ApprovedBy: uuid.UUID(revision.ApprovedBy.Bytes), ApprovedAt: revision.ApprovedAt.Time.UTC()},
		Executor: presign.ExecutorIdentity{Kind: presign.ExecutorAPIKey, UserID: q.f.user.ID, CredentialID: credential}, Operation: presign.OperationPreSignAndSend,
		InputRules:     presignregistry.InputRules{Version: 1, SourceSchemaVersion: 3, Standalone: true, SignatureFieldsOnly: true, AuthorMustBeGrantor: true},
		DataRules:      presignregistry.DataRules{Version: 1, Values: []presignregistry.ValueRule{}, Sections: []presignregistry.SectionRule{}},
		RecipientRules: presignregistry.RecipientRules{Version: 1, Provider: "named_grantor_exact", Customer: "printed_profile_exact", Mode: "parallel", ProviderCompanyName: company, ProviderCompanyID: companyID, ProviderAuthorityBasis: basis}, MaxGrantDurationSeconds: 3600, MaxUses: 2}
	for _, value := range master.Values {
		if field := providerRules[value.Name]; field != "" {
			definition.DataRules.Values = append(definition.DataRules.Values, presignregistry.ValueRule{Variable: value.Name, Mode: presignregistry.ModeGrantor, GrantorField: field})
			continue
		}
		mode := presignregistry.ModeAbsent
		if _, ok := defaults[value.Name]; ok {
			mode = presignregistry.ModeDefault
		}
		definition.DataRules.Values = append(definition.DataRules.Values, presignregistry.ValueRule{Variable: value.Name, Mode: mode})
	}
	for _, section := range master.Sections {
		definition.DataRules.Sections = append(definition.DataRules.Sections, presignregistry.SectionRule{Section: section.Name, Mode: presignregistry.ModeDefault})
	}
	if err = presignregistry.ValidateDefinitionAgainstTemplate(definition, revision.HtmlMasterJson, revision.VariablesJson); err != nil {
		t.Fatal("actual approved-data fixture violates retained template rules", err)
	}
	in := presignregistry.WorkflowIntent{RequestID: uuid.New(), ExpectedOrgID: q.f.org, ExpectedUserID: q.f.user.ID, Definition: definition}
	preview := presign488Decode[presignregistry.WorkflowPreview](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/workflows/preview", in, true, "", http.StatusOK).body)
	approved := presign488Decode[presignregistry.Outcome](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/workflows/approve", presignregistry.ConfirmWorkflowInput{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}, true, "", http.StatusOK).body)
	view := presign488Decode[presignregistry.WorkflowView](t, presign488Call(t, f.h, q.f.ctx, http.MethodGet, "/api/v1/presign/workflows/"+approved.Reference.ID.String(), nil, true, "", http.StatusOK).body)
	grant := presignregistry.GrantIntent{RequestID: uuid.New(), ExpectedOrgID: q.f.org, ExpectedUserID: q.f.user.ID, GrantID: uuid.New(), Policy: view.PolicyReference, CompanyName: company, CompanyID: companyID, AuthorityBasis: basis, Font: "Caveat", ExpiresAt: time.Now().UTC().Add(30 * time.Minute), MaxUses: 2}
	gp := presign488Decode[presignregistry.GrantPreview](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/self-grants/preview", grant, true, "", http.StatusOK).body)
	created := presign488Decode[presignregistry.Outcome](t, presign488Call(t, f.h, q.f.ctx, http.MethodPost, "/api/v1/presign/self-grants/create", presignregistry.ConfirmGrantInput{Intent: gp.Intent, Receipt: gp.Receipt, Confirmed: true}, true, "", http.StatusOK).body)
	return view.PolicyReference, created.Reference
}

func TestPreSign488SealedNonCRMSourceRejectsNewCRMRowWithNilResolverE2E(t *testing.T) {
	f := newPreSign488PreparationFixtureV1(t)
	q := f.q
	printed := createBrandedDocumentE2E(t, q.f, f.template, q.cookie)
	minted, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal("controlled API key mint failed")
	}
	credential, err := q.f.q.CreateAPIKey(q.f.ctx, generated.CreateAPIKeyParams{OrgID: q.f.org, UserID: q.f.user.ID, KeyPrefix: minted.Prefix, KeyHash: minted.Hash, Name: "Controlled original source488", Scopes: []string{"write:authoring", "write:workflow"}, ExpiresAt: pgtype.Timestamptz{Time: time.Now().UTC().Add(time.Hour), Valid: true}})
	if err != nil {
		t.Fatal("actual API key row missing", err)
	}
	policy, grant := preSign488ApprovedAPIAuthorityV1(t, f, printed, credential.ID)
	api := preSignAuthFixture488{owned: q, router: q.f.s.Routes()}
	birth := preSignAPISourceInputV1{RequestID: uuid.New(), ExpectedOrgID: q.f.org, ExpectedUserID: q.f.user.ID, Policy: policy, Grant: grant, DocumentName: "Controlled sealed nonCRM source"}
	response := api.call(t, http.MethodPost, "/api/automation/v1/presign/documents", "", minted.Plaintext, birth, http.StatusCreated)
	source := presign488Decode[pdfadmission.PreSignAPISourceViewV1](t, response.Body.Bytes())
	if source.State != "committed" || source.Source == nil || source.Source.DocumentID == uuid.Nil {
		t.Fatal("actual original API source did not commit")
	}
	var sealed bool
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT state='committed' AND crm_bindings_sha256 IS NULL FROM presign_source_requests_v1 WHERE org_id=$1 AND executor_credential_id=$2 AND request_id=$3 AND document_id=$4`, q.f.org, credential.ID, birth.RequestID, source.Source.DocumentID).Scan(&sealed); err != nil || !sealed {
		t.Fatal("actual source is not the original sealed noCRM lineage", err)
	}
	q.f.s.Send.Resolver = nil // explicitly exercise the supported noCRM configuration
	doc := packageLatest223(t, q, source.Source.DocumentID)
	positive := preSign488IntentForV1(t, q, doc, uuid.New(), policy, grant)
	api.call(t, http.MethodPost, "/api/automation/v1/presign/executions/preview", "", minted.Plaintext, positive, http.StatusOK)
	// This genuine draft binding mutation leaves the original immutable source
	// receipt untouched. No connection/report is fabricated; absence of a real
	// CRM lineage is exactly why a new CRM row cannot be admitted here.
	if _, err = q.f.q.UpsertVariableBinding(q.f.ctx, generated.UpsertVariableBindingParams{DocumentID: doc.ID, VariableName: "customer_name", SourceKind: "crm.contact", SourceRef: "controlled-contact-488", SourcePath: "email", Fallback: ""}); err != nil {
		t.Fatal("actual binding mutation unavailable", err)
	}
	doc = packageLatest223(t, q, doc.ID)
	current := preSign488IntentForV1(t, q, doc, uuid.New(), policy, grant)
	currentResponse := api.call(t, http.MethodPost, "/api/automation/v1/presign/executions/preview", "", minted.Plaintext, current, http.StatusOK)
	preview := presign488Decode[presignexecute.PreviewV1](t, currentResponse.Body.Bytes())
	before := api.snapshot(t)
	renders, provider := preSign488RendererCallsV1(q), q.storagePeer.requests.Load()
	var bindingsBefore string
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY variable_name),'[]'::jsonb)::text FROM document_variable_bindings b WHERE document_id=$1`, doc.ID).Scan(&bindingsBefore); err != nil {
		t.Fatal("actual binding inventory unavailable", err)
	}
	api.call(t, http.MethodPost, "/api/automation/v1/presign/executions", "", minted.Plaintext, presignexecute.ConfirmV1{Intent: preview.Intent, Receipt: preview.Receipt, Confirmed: true}, http.StatusConflict)
	api.unchanged(t, before)
	var bindingsAfter string
	if err = q.f.pool.QueryRow(q.f.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(b) ORDER BY variable_name),'[]'::jsonb)::text FROM document_variable_bindings b WHERE document_id=$1`, doc.ID).Scan(&bindingsAfter); err != nil || bindingsAfter != bindingsBefore {
		t.Fatal("refusal changed original binding evidence", err)
	}
	if preSign488RendererCallsV1(q) != renders || q.storagePeer.requests.Load() != provider {
		t.Fatal("unowned CRM membership reached renderer/storage before source admission")
	}
}
