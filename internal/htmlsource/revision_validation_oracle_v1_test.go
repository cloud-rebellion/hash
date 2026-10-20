// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func revisionPublicErrorOracleV1(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) || (got != nil && got.Error() != want.Error()) {
		t.Fatalf("got %v; original %v", got, want)
	}
}
func revisionPublicValueOracleV1(t *testing.T, got, want any, gotErr, wantErr error) {
	t.Helper()
	revisionPublicErrorOracleV1(t, gotErr, wantErr)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("prepared value differs: got %#v; original %#v", got, want)
	}
}

func TestRevisionValidationContractAndSigningPagePublicOraclesV1(t *testing.T) {
	for _, schema := range []int{2, 3} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			_, doc, rows := testfixture.HTMLContract(t)
			if schema == 3 {
				_, doc, rows = testfixture.BrandedHTMLContract(t)
			}
			v, err := htmlsource.NewRevisionValidationV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			gotInput, gotErr := v.InputForCurrentV1()
			wantInput, wantErr := htmlsource.InputForCurrent(doc)
			revisionPublicValueOracleV1(t, gotInput, wantInput, gotErr, wantErr)
			gotProfile, gotErr := v.ContractProfileV1()
			wantProfile, wantErr := htmlsource.ContractProfile(doc)
			revisionPublicValueOracleV1(t, gotProfile, wantProfile, gotErr, wantErr)
			gotParties, gotErr := v.ContractPartiesV1()
			wantParties, wantErr := htmlsource.ContractParties(doc)
			revisionPublicValueOracleV1(t, gotParties, wantParties, gotErr, wantErr)
			gotPolicy, gotArtifact, gotErr := v.SigningPageV1()
			wantPolicy, wantArtifact, wantErr := htmlsource.SigningPage(doc)
			revisionPublicErrorOracleV1(t, gotErr, wantErr)
			if !reflect.DeepEqual(gotPolicy, wantPolicy) || !reflect.DeepEqual(gotArtifact, wantArtifact) {
				t.Fatal("prepared signing page differs")
			}
			revisionPublicErrorOracleV1(t, v.ValidateContractPartiesV1(rows), htmlsource.ValidateContractParties(doc, rows))
			for _, slot := range []string{"customer", "provider", "invalid"} {
				got, ge := v.SigningFieldOptionsV1(slot)
				want, we := htmlsource.SigningFieldOptions(doc, slot)
				revisionPublicValueOracleV1(t, got, want, ge, we)
			}
			gotChanged, ge := v.ChangedSectionsV1()
			wantChanged, we := htmlsource.ChangedSections(doc)
			revisionPublicValueOracleV1(t, gotChanged, wantChanged, ge, we)
			if gotProfile != nil {
				gotProfile.Parties[0].CompanyName = "caller-copy"
			}
			if len(gotParties) > 0 {
				gotParties[0].Name = "caller-copy"
			}
			if gotPolicy != nil {
				gotPolicy.Branding.TextHex = "#010101"
			}
			if gotArtifact != nil {
				gotArtifact.Fields[0].X = 0
			}
			if gotInput.SigningArtifact != nil {
				gotInput.SigningArtifact.Fields[0].Y = 0
			}
			after, err := v.ContractProfileV1()
			if err != nil || !reflect.DeepEqual(after, wantProfile) {
				t.Fatal("profile output alias", err)
			}
			revisionPublicErrorOracleV1(t, v.ValidateContractPartiesV1(rows), htmlsource.ValidateContractParties(doc, rows))
			if schema == 3 {
				fields := testfixture.BrandedSignatureFields(t, doc)
				revisionPublicErrorOracleV1(t, v.ValidateSigningFieldsV1(fields, 2), htmlsource.ValidateSigningFields(doc, fields, 2))
				for _, field := range fields {
					var pretty bytes.Buffer
					if err = json.Indent(&pretty, field.OptionsJson, "", " "); err != nil {
						t.Fatal(err)
					}
					field.OptionsJson = pretty.Bytes()
				}
				revisionPublicErrorOracleV1(t, v.ValidateSigningFieldsV1(fields, 2), htmlsource.ValidateSigningFields(doc, fields, 2))
				fields[0].OptionsJson = bytes.Replace(fields[0].OptionsJson, []byte("\"slot\""), []byte("\"Slot\""), 1)
				revisionPublicErrorOracleV1(t, v.ValidateSigningFieldsV1(fields, 2), htmlsource.ValidateSigningFields(doc, fields, 2))
				fields = testfixture.BrandedSignatureFields(t, doc)
				revisionPublicErrorOracleV1(t, v.ValidateSigningFieldsV1(fields, 1), htmlsource.ValidateSigningFields(doc, fields, 1))
			} else {
				revisionPublicErrorOracleV1(t, v.ValidateSigningFieldsV1(nil, 0), htmlsource.ValidateSigningFields(doc, nil, 0))
				revisionPublicErrorOracleV1(t, v.ValidateSigningBrandingV1(nil), htmlsource.ValidateSigningBranding(doc, nil))
			}
		})
	}
}

func TestRevisionValidationOptionalEmptyUsesActualPinnedDesignOracleV1(t *testing.T) {
	for _, schema := range []int{1, 2, 3} {
		for _, change := range []string{"none", "optional-empty", "optional-nonempty", "unknown", "section-present", "required-empty"} {
			t.Run(fmt.Sprintf("%d/%s", schema, change), func(t *testing.T) {
				_, doc := optionalEmptyFixture(t, schema)
				v, err := htmlsource.NewRevisionValidationV1(doc)
				if err != nil {
					t.Fatal(err)
				}
				values, sections := map[string]string{}, map[string]string{}
				switch change {
				case "optional-empty":
					values["note"] = ""
					values["memo"] = ""
				case "optional-nonempty":
					values["note"] = "new text"
				case "unknown":
					values["unknown"] = ""
				case "section-present":
					values["note"] = ""
					sections["details"] = "Approved unchanged details"
				case "required-empty":
					values["price"] = ""
				}
				gotInput, gotResult, gotChanged, gotErr := v.MaterializeRevisionV1(values, sections)
				wantInput, err := htmlsource.InputForCurrent(doc)
				if err != nil {
					t.Fatal(err)
				}
				wantInput.Values = maps.Clone(wantInput.Values)
				wantInput.Sections = maps.Clone(wantInput.Sections)
				for k, x := range values {
					wantInput.Values[k] = x
				}
				for k, x := range sections {
					wantInput.Sections[k] = x
				}
				master, err := htmlmaster.Decode(wantInput.MasterJSON)
				if err != nil {
					t.Fatal(err)
				}
				compiled, err := htmlmaster.Compile(master)
				if err != nil {
					t.Fatal(err)
				}
				wantResult, wantErr := compiled.Materialize(htmlmaster.Input{Values: wantInput.Values, Sections: wantInput.Sections})
				revisionPublicErrorOracleV1(t, gotErr, wantErr)
				if wantErr != nil {
					return
				}
				before, err := htmlsource.MaterializationDigest(doc)
				if err != nil {
					t.Fatal(err)
				}
				wantChanged := before != wantResult.ContentDigest
				if !wantChanged {
					wantChanged, err = htmlsource.IsOptionalEmptyAddition(doc, wantInput)
					if err != nil {
						t.Fatal(err)
					}
				}
				if gotChanged != wantChanged || !reflect.DeepEqual(gotInput, wantInput) || !reflect.DeepEqual(gotResult, wantResult) {
					t.Fatal("optional/content/materialized oracle differs")
				}
				if schema == 3 {
					gotHTML, ge := v.SigningPageHTMLV1(wantInput.Values, wantInput.Sections)
					wantHTML, we := compiled.SigningPageHTML(htmlmaster.Input{Values: wantInput.Values, Sections: wantInput.Sections})
					revisionPublicValueOracleV1(t, gotHTML, wantHTML, ge, we)
					gotArtifact, ge := v.NewSigningArtifactV1(wantInput.Values, wantInput.Sections, wantInput.SigningArtifact.Composition)
					wantArtifact, we := htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: wantInput.Values, Sections: wantInput.Sections}, wantInput.PartyBindings, wantInput.SigningArtifact.Composition)
					revisionPublicValueOracleV1(t, gotArtifact, wantArtifact, ge, we)
				}
			})
		}
	}
}

func TestRevisionValidationDistinctCandidateAndOriginScopesV1(t *testing.T) {
	doc, rows := contractRevision(t, false)
	v, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	current, err := v.CommitmentV1()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := v.OriginCommitmentV1()
	if err != nil || origin == current {
		t.Fatal("normalized origin conflated", err)
	}
	revisionPublicErrorOracleV1(t, v.ValidateContractPartiesV1(rows), htmlsource.ValidateContractParties(doc, rows))
	rows[1].Name, rows[1].Email = "New declared customer representative", "NewCustomer@example.test"
	revisionPublicErrorOracleV1(t, v.ValidateContractPartiesV1(rows), htmlsource.ValidateContractParties(doc, rows))
	input, _, changed, err := v.MaterializeRevisionV1(map[string]string{"customer_name": "Next Representative"}, nil)
	if err != nil || !changed {
		t.Fatal(err)
	}
	candidate := *doc
	candidate.VariablesJson, err = json.Marshal(input.Values)
	if err != nil {
		t.Fatal(err)
	}
	candidate.PdfStorageKey.String = "org/synthetic/documents/next.pdf"
	candidate.PdfStorageVersionID.String = "new-version"
	nextSource, err := htmlsource.New(input, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	candidate.HtmlCurrentSourceJson = nextSource
	candidate.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	candidate.HtmlCurrentMaterializationSequence.Int32++
	if v.MatchesDocumentV1(&candidate) {
		t.Fatal("new tuple reused old operation")
	}
	next, err := htmlsource.NewRevisionValidationV1(&candidate)
	if err != nil {
		t.Fatal(err)
	}
	nextCommitment, err := next.CommitmentV1()
	if err != nil || nextCommitment == current {
		t.Fatal("candidate did not get independent validated scope", err)
	}
	if after, _ := v.CommitmentV1(); after != current {
		t.Fatal("candidate mutated original operation")
	}
	// Current validation must fail here, while the independent origin-only API
	// still succeeds. The new full-current operation cannot replace that API.
	broken := candidate
	broken.HtmlCurrentSourceJson = []byte("{}")
	if _, err = htmlsource.NewRevisionValidationV1(&broken); err == nil {
		t.Fatal("broken current accepted")
	}
	if _, err = htmlsource.OriginCommitment(&broken); err != nil {
		t.Fatal("origin-only oracle unexpectedly invalid", err)
	}
}

type revisionQueryOracleV1 struct {
	calls      []string
	recipients []*generated.Recipient
	fields     []*generated.DocumentField
	branding   *generated.DocumentBrandingOverride
	fail       string
}

func (q *revisionQueryOracleV1) ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error) {
	q.calls = append(q.calls, "recipients")
	if q.fail == "recipients" {
		return nil, errors.New("query failed")
	}
	return q.recipients, nil
}
func (q *revisionQueryOracleV1) ListFieldsByDocument(context.Context, uuid.UUID) ([]*generated.DocumentField, error) {
	q.calls = append(q.calls, "fields")
	if q.fail == "fields" {
		return nil, errors.New("query failed")
	}
	return q.fields, nil
}
func (q *revisionQueryOracleV1) GetDocumentBrandingOverride(context.Context, uuid.UUID) (*generated.DocumentBrandingOverride, error) {
	q.calls = append(q.calls, "branding")
	if q.fail == "branding" {
		return nil, errors.New("query failed")
	}
	return q.branding, nil
}
func revisionBrandingOracleV1(t *testing.T, doc *generated.Document) *generated.DocumentBrandingOverride {
	t.Helper()
	policy, _, err := htmlsource.SigningPage(doc)
	if err != nil || policy == nil {
		t.Fatal(err)
	}
	b := policy.Branding
	text := func(s string) pgtype.Text { return pgtype.Text{String: s, Valid: true} }
	return &generated.DocumentBrandingOverride{DocumentID: doc.ID, PrimaryHex: text(b.PrimaryHex), AccentHex: text(b.AccentHex), SurfaceHex: text(b.SurfaceHex), TextHex: text(b.TextHex), MutedHex: text(b.MutedHex), LogoUrl: text(b.LogoURL), LogoAlt: text(b.LogoAlt), FontHeading: text(b.FontHeading), FontBody: text(b.FontBody), SignatureColor: text(b.SignatureColor)}
}
func TestRevisionValidationPreservesFreshQueryOrderAndRowDecisionsV1(t *testing.T) {
	for _, name := range []string{"good", "recipient-read", "recipient-drift", "field-read", "field-drift", "wrong-pages", "branding-read", "branding-drift"} {
		t.Run(name, func(t *testing.T) {
			_, doc, rows := testfixture.BrandedHTMLContract(t)
			fields := testfixture.BrandedSignatureFields(t, doc)
			brand := revisionBrandingOracleV1(t, doc)
			v, err := htmlsource.NewRevisionValidationV1(doc)
			if err != nil {
				t.Fatal(err)
			}
			q := &revisionQueryOracleV1{recipients: rows, fields: fields, branding: brand}
			pages := 2
			switch name {
			case "recipient-read":
				q.fail = "recipients"
			case "recipient-drift":
				rows[0].Name = "changed after operation construction"
			case "field-read":
				q.fail = "fields"
			case "field-drift":
				fields[0].Required = false
			case "wrong-pages":
				pages = 1
			case "branding-read":
				q.fail = "branding"
			case "branding-drift":
				brand.LogoUrl.Valid = false
			}
			original := *q
			got := v.ValidateSigningPageStateV1(context.Background(), q, pages)
			want := htmlsource.ValidateSigningPageState(context.Background(), &original, doc, pages)
			revisionPublicErrorOracleV1(t, got, want)
			if !reflect.DeepEqual(q.calls, original.calls) {
				t.Fatalf("query order differs: %v / %v", q.calls, original.calls)
			}
			revisionPublicErrorOracleV1(t, v.ValidateSigningPageStateV1(context.Background(), nil, pages), htmlsource.ValidateSigningPageState(context.Background(), nil, doc, pages))
		})
	}
	_, legacy, rows := testfixture.HTMLContract(t)
	v, err := htmlsource.NewRevisionValidationV1(legacy)
	if err != nil {
		t.Fatal(err)
	}
	q := &revisionQueryOracleV1{recipients: rows}
	if err = v.ValidateSigningPageStateV1(context.Background(), q, 0); err != nil || len(q.calls) != 0 {
		t.Fatal("schema2 acquired signing-page SQL", err)
	}
}

func TestRevisionValidationSchema3SourceDriftOracleV1(t *testing.T) {
	for _, name := range []string{"artifact-policy", "artifact-plan", "artifact-geometry", "content", "commitment", "case-alias", "requires-signature", "wrong-pdf", "wrong-version", "printed-values", "source-kind"} {
		t.Run(name, func(t *testing.T) {
			_, doc, _ := testfixture.BrandedHTMLContract(t)
			var root map[string]json.RawMessage
			if err := json.Unmarshal(doc.HtmlSourceJson, &root); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "artifact-policy", "artifact-plan", "artifact-geometry":
				var artifact map[string]json.RawMessage
				if err := json.Unmarshal(root["signing_artifact"], &artifact); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "artifact-policy":
					artifact["policy"] = json.RawMessage("\"other\"")
				case "artifact-plan":
					artifact["plan_sha256"] = json.RawMessage("\"0000000000000000000000000000000000000000000000000000000000000000\"")
				case "artifact-geometry":
					artifact["fields"] = json.RawMessage("[]")
				}
				root["signing_artifact"], _ = json.Marshal(artifact)
				doc.HtmlSourceJson, _ = json.Marshal(root)
			case "content":
				root["content_digest"] = json.RawMessage("\"forged\"")
				doc.HtmlSourceJson, _ = json.Marshal(root)
			case "commitment":
				root["commitment"] = json.RawMessage("\"forged\"")
				doc.HtmlSourceJson, _ = json.Marshal(root)
			case "case-alias":
				doc.HtmlSourceJson = bytes.Replace(doc.HtmlSourceJson, []byte("\"schema_version\""), []byte("\"SCHEMA_VERSION\""), 1)
			case "requires-signature":
				doc.RequiresSignature = false
			case "wrong-pdf":
				doc.PdfSha256 = bytes.Repeat([]byte{9}, 32)
			case "wrong-version":
				doc.PdfStorageVersionID.String = "foreign-version"
			case "printed-values":
				doc.VariablesJson = json.RawMessage("{}")
			case "source-kind":
				doc.SourceKind = "blocks"
			}
			_, got := htmlsource.NewRevisionValidationV1(doc)
			want := htmlsource.Validate(doc, false)
			if want == nil {
				t.Fatal("negative oracle fixture remained valid")
			}
			revisionPublicErrorOracleV1(t, got, want)
		})
	}
}
