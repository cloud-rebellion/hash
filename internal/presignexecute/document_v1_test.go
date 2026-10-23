// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignexecute

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is a pure model/commitment fixture, not rendered PDF or SQL acceptance.
// It evaluates actual stored workflow rules against a validated schema3 source;
// no DataAdmission is fabricated or decoded from an invented receipt.
func preSignDocumentOptionsFixtureV1(t testing.TB) (*generated.Document, []*generated.Recipient, []*generated.DocumentField, presignregistry.DataAdmission) {
	t.Helper()
	in, doc, rows := testfixture.BrandedHTMLContract(t)
	doc.RoutingMode = "parallel"
	doc.SigningAdmissionPolicy = "historical"
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentSourceJson = bytes.Clone(doc.HtmlSourceJson)
	fields := testfixture.BrandedSignatureFields(t, doc)
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	d := presignregistry.WorkflowDefinition{Version: 1, ID: uuid.New(), PolicyID: uuid.New(), OrgID: doc.OrgID, Revision: 1, Name: "Synthetic canonical field options",
		Kind: presignregistry.KindApprovedData, Operation: presign.OperationPreSignAndSend,
		Template:                presign.TemplatePin{ID: in.TemplateID, Version: int64(in.TemplateVersion), ContentSHA256: in.TemplateContentSHA256, ApprovedBy: in.TemplateApprovedBy, ApprovedAt: in.TemplateApprovedAt},
		Executor:                presign.ExecutorIdentity{Kind: presign.ExecutorMember, UserID: doc.SenderID},
		InputRules:              presignregistry.InputRules{Version: 1, SourceSchemaVersion: 3, Standalone: true, SignatureFieldsOnly: true, AuthorMustBeGrantor: true},
		DataRules:               presignregistry.DataRules{Version: 1, Values: []presignregistry.ValueRule{}, Sections: []presignregistry.SectionRule{}},
		RecipientRules:          presignregistry.RecipientRules{Version: 1, Provider: "named_grantor_exact", Customer: "printed_profile_exact", Mode: "parallel", ProviderCompanyName: in.Values["provider_company"], ProviderCompanyID: in.Values["provider_company_id"], ProviderAuthorityBasis: in.Values["provider_authority"]},
		MaxGrantDurationSeconds: 3600, MaxUses: 1}
	provider := map[string]string{"provider_name": "name", "provider_email": "email", "provider_company": "company_name", "provider_company_id": "company_id", "provider_authority": "authority_basis"}
	for _, v := range m.Values {
		r := presignregistry.ValueRule{Variable: v.Name, Mode: presignregistry.ModeLiteral}
		if field := provider[v.Name]; field != "" {
			r.Mode = presignregistry.ModeGrantor
			r.GrantorField = field
		} else {
			value := in.Values[v.Name]
			r.Literal = &value
		}
		d.DataRules.Values = append(d.DataRules.Values, r)
	}
	g := presign.NamedRepresentative{UserID: doc.SenderID, Name: in.Values["provider_name"], Email: in.Values["provider_email"], CompanyName: in.Values["provider_company"], CompanyID: in.Values["provider_company_id"], AuthorityBasis: in.Values["provider_authority"]}
	a, err := presignregistry.EvaluateExecutionData(d, g, doc, nil, doc.UpdatedAt.Time)
	if err != nil {
		t.Fatal(err)
	}
	return doc, rows, fields, a
}

func TestPreSignDocumentSnapshotUsesCanonicalOptionsAcrossJSONBSpellingV1(t *testing.T) {
	doc, rows, fields, a := preSignDocumentOptionsFixtureV1(t)
	want, err := DocumentSnapshotFromModelsV1(doc, rows, fields, a, 1000)
	if err != nil {
		t.Fatal(err)
	}
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		t.Fatal("missing actual source plan", err)
	}
	for i, slot := range []string{"customer", "provider"} {
		canonical, err := htmlsource.SigningFieldOptions(doc, slot)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(canonical)
		if want.Fields[i].OptionsSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("snapshot does not bind the existing typed options encoding")
		}
		for _, f := range fields {
			if f.RecipientID.Valid && uuid.UUID(f.RecipientID.Bytes) == want.Parties[i].ID {
				// PostgreSQL JSONB emits these short keys first and includes spaces;
				// constructor bytes have policy,slot,source_commitment compact order.
				f.OptionsJson = []byte(fmt.Sprintf(`{"slot": %q, "policy": %q, "source_commitment": %q}`, slot, artifact.Policy, want.Materialization.SourceCommitment))
				if bytes.Equal(f.OptionsJson, canonical) {
					t.Fatal("fixture did not cross the JSONB wire-spelling boundary")
				}
				rawSum := sha256.Sum256(f.OptionsJson)
				if hex.EncodeToString(rawSum[:]) == want.Fields[i].OptionsSHA256 {
					t.Fatal("fixture fails to distinguish the old raw JSONB hash")
				}
			}
		}
	}
	got, err := DocumentSnapshotFromModelsV1(doc, rows, fields, a, 1000)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("JSONB spelling changed the full captured snapshot", err)
	}
}

func TestPreSignDocumentSnapshotStillRejectsChangedStoredOptionsV1(t *testing.T) {
	for _, name := range []string{"policy", "slot", "source_commitment", "extra", "missing", "duplicate", "case_alias", "null", "trailing"} {
		t.Run(name, func(t *testing.T) {
			doc, rows, fields, a := preSignDocumentOptionsFixtureV1(t)
			if _, err := DocumentSnapshotFromModelsV1(doc, rows, fields, a, 1000); err != nil {
				t.Fatal("valid source control refused", err)
			}
			// Mutate the stored field only. Source and admission remain original.
			// Exact options keys and binding semantics are still owned by the
			// existing complete ValidateSigningFields call in the production path.
			_, artifact, err := htmlsource.SigningPage(doc)
			if err != nil || artifact == nil {
				t.Fatal(err)
			}
			commitment, err := htmlsource.Commitment(doc)
			if err != nil {
				t.Fatal(err)
			}
			slot := artifact.Fields[0].Slot
			raw := fmt.Sprintf(`{"slot": %q, "policy": %q, "source_commitment": %q}`, slot, artifact.Policy, commitment)
			switch name {
			case "policy":
				raw = strings.Replace(raw, fmt.Sprintf(`"policy": %q`, artifact.Policy), `"policy": "other"`, 1)
			case "slot":
				other := "provider"
				if slot == other {
					other = "customer"
				}
				raw = strings.Replace(raw, fmt.Sprintf(`"slot": %q`, slot), fmt.Sprintf(`"slot": %q`, other), 1)
			case "source_commitment":
				raw = strings.Replace(raw, commitment, strings.Repeat("f", 64), 1)
			case "extra":
				raw = strings.TrimSuffix(raw, "}") + `, "extra": true}`
			case "missing":
				raw = fmt.Sprintf(`{"slot": %q, "policy": %q}`, slot, artifact.Policy)
			case "duplicate":
				raw = strings.TrimSuffix(raw, "}") + fmt.Sprintf(`, "slot": %q}`, slot)
			case "case_alias":
				raw = strings.TrimSuffix(raw, "}") + fmt.Sprintf(`, "Slot": %q}`, slot)
			case "null":
				raw = `null`
			case "trailing":
				raw += `{}`
			}
			fields[0].OptionsJson = []byte(raw)
			if _, err := DocumentSnapshotFromModelsV1(doc, rows, fields, a, 1000); err == nil {
				t.Fatal("canonicalization bypassed stored field validation")
			}
		})
	}
}
