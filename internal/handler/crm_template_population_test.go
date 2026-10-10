// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/testfixture"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestCRMTemplateCreateDigestBindsSemanticCommandAndPreservesRetryIdentity(t *testing.T) {
	current := crmTemplateContextFixture(t)
	actor := authoring.Actor{OrgID: current.response.OrgID, UserID: current.response.UserID}
	input := htmlDocumentInput{Name: "Proposal", ExpectedTemplateVersion: current.response.TemplateVersion, ExpectedTemplateContentSHA256: current.response.TemplateContentSHA256,
		Values: htmlStringMap{"manual": "Human value", "price": "Manual starting price"}, Sections: htmlStringMap{"scope": "Exact words"}, ExpiresAt: "2030-01-02T03:04:05+01:00", RequestID: uuid.New(),
		CRMPopulation: &CRMTemplatePopulationInput{CRMTemplateWitness: crmTemplateWitnessFor(current), Mappings: []crmDocumentMapping{{"price", "crm.deal", "deal_one", "value"}, {"currency", "crm.deal", "deal_one", "currency"}}, ReviewedDigest: strings.Repeat("c", 64), ReviewReceipt: "old token", Confirmed: true}}
	first, err := crmTemplateCreateInputDigest(actor, current.response.TemplateID, input)
	if err != nil {
		t.Fatal(err)
	}
	retry := input
	population := *input.CRMPopulation
	retry.CRMPopulation = &population
	retry.RequestID = uuid.New()
	retry.CRMPopulation.ReviewReceipt = "renewed transport authenticator"
	retry.CRMPopulation.Mappings = []crmDocumentMapping{input.CRMPopulation.Mappings[1], input.CRMPopulation.Mappings[0]}
	retry.Values = htmlStringMap{"price": "Manual starting price", "manual": "Human value"}
	retry.ExpiresAt = "2030-01-02T02:04:05Z"
	second, err := crmTemplateCreateInputDigest(actor, current.response.TemplateID, retry)
	if err != nil || second != first {
		t.Fatal("equivalent semantic retry changed identity", err)
	}
	for _, c := range []struct {
		name   string
		change func(*htmlDocumentInput)
	}{
		{"name", func(v *htmlDocumentInput) { v.Name = "Different proposal" }},
		{"expiry", func(v *htmlDocumentInput) { v.ExpiresAt = "2030-01-02T02:04:06Z" }},
		{"manual values", func(v *htmlDocumentInput) {
			v.Values = htmlStringMap{"price": "Different manual price", "manual": "Human value"}
		}},
		{"manual sections", func(v *htmlDocumentInput) { v.Sections = htmlStringMap{"scope": "Different words"} }},
		{"approval", func(v *htmlDocumentInput) { v.CRMPopulation.ExpectedTemplateApprovedBy = uuid.New() }},
		{"account", func(v *htmlDocumentInput) {
			v.CRMPopulation.ExpectedConnectionID = uuid.New().String()
			v.CRMPopulation.ExpectedConnectionGeneration = "1"
		}},
		{"record", func(v *htmlDocumentInput) {
			v.CRMPopulation.Mappings = []crmDocumentMapping{{"price", "crm.deal", "deal_other", "value"}, {"currency", "crm.deal", "deal_other", "currency"}}
		}},
		{"reviewed scalar digest", func(v *htmlDocumentInput) { v.CRMPopulation.ReviewedDigest = strings.Repeat("d", 64) }},
		{"CRM omission", func(v *htmlDocumentInput) { v.CRMPopulation = nil }},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := input
			p := *input.CRMPopulation
			changed.CRMPopulation = &p
			c.change(&changed)
			digest, err := crmTemplateCreateInputDigest(actor, current.response.TemplateID, changed)
			if err != nil || digest == first {
				t.Fatal("changed semantic command reused identity", err)
			}
		})
	}
	foreign := actor
	foreign.UserID = uuid.New()
	if _, err := crmTemplateCreateInputDigest(foreign, current.response.TemplateID, input); err == nil {
		t.Fatal("foreign actor digest admitted")
	}
	manual := input
	manual.CRMPopulation = nil
	manual.Values = nil
	absent, err := crmTemplateCreateInputDigest(actor, current.response.TemplateID, manual)
	if err != nil {
		t.Fatal(err)
	}
	manual.Values = htmlStringMap{}
	empty, err := crmTemplateCreateInputDigest(actor, current.response.TemplateID, manual)
	if err != nil || absent == empty {
		t.Fatal("omitted input collapsed into explicitly empty map", err)
	}
}

func crmTemplateProjectedAdmissionFixture(t *testing.T) (*crmTemplatePopulationAdmission, *generated.Document, authoring.Actor) {
	t.Helper()
	input, doc, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(input.MasterJSON, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	current := &crmTemplateContext{template: &generated.Template{ID: input.TemplateID, OrgID: doc.OrgID, Version: input.TemplateVersion},
		revision: &generated.HtmlTemplateRevision{ApprovedBy: pgtype.UUID{Bytes: input.TemplateApprovedBy, Valid: true}, ApprovedAt: pgtype.Timestamptz{Time: input.TemplateApprovedAt, Valid: true}}, content: canonical, compiled: compiled,
		response: crmTemplateResponseWitness{OrgID: doc.OrgID, UserID: doc.SenderID, TemplateID: input.TemplateID, TemplateVersion: input.TemplateVersion, TemplateContentSHA256: input.TemplateContentSHA256, TemplateApprovedBy: input.TemplateApprovedBy, TemplateApprovedAt: input.TemplateApprovedAt.UTC().Format(time.RFC3339Nano)}}
	candidate := CRMTemplateCandidate{Name: doc.Name, Values: htmlStringMap(maps.Clone(input.Values)), Sections: htmlStringMap(maps.Clone(input.Sections))}
	candidateSHA, err := crmTemplateCandidateDigest(candidate)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	receipt := crmTemplateReceipt{CRMTemplateWitness: crmTemplateWitnessFor(current), SchemaVersion: 1, ReceiptID: uuid.New(), TemplateID: input.TemplateID,
		CandidateSHA256: candidateSHA, ReviewDigest: strings.Repeat("c", 64), SessionSHA256: strings.Repeat("a", 64), ObservedAt: now, IssuedAt: now, ExpiresAt: now.Add(resolver.CRMObservationMaxAge)}
	admission := &crmTemplatePopulationAdmission{source: current, witness: crmTemplateWitnessFor(current), candidate: candidate, receipt: receipt,
		observation: &crmTemplateObservation{Mappings: []crmDocumentMapping{}, CanCreate: true, ReviewDigest: receipt.ReviewDigest, candidateSHA: candidateSHA, observationAt: now, values: maps.Clone(input.Values)}, now: func() time.Time { return now }}
	doc.HtmlReviewedBy, doc.HtmlReviewedAt, doc.HtmlReviewedPdfSha256 = pgtype.UUID{}, pgtype.Timestamptz{}, nil
	doc.HtmlCurrentMaterializationID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	doc.HtmlCurrentMaterializationSequence = pgtype.Int4{Int32: 1, Valid: true}
	doc.HtmlCurrentPageCount = pgtype.Int4{Int32: 2, Valid: true}
	doc.HtmlCurrentSourceJson = bytes.Clone(doc.HtmlSourceJson)
	return admission, doc, authoring.Actor{OrgID: doc.OrgID, UserID: doc.SenderID}
}

func TestCRMTemplateProjectionCanonicalJSONBSpellingAndExactSource(t *testing.T) {
	admission, doc, actor := crmTemplateProjectedAdmissionFixture(t)
	var source map[string]json.RawMessage
	if json.Unmarshal(doc.HtmlCurrentSourceJson, &source) != nil {
		t.Fatal("source fixture invalid")
	}
	var master map[string]any
	if json.Unmarshal(source["master"], &master) != nil {
		t.Fatal("master fixture invalid")
	}
	source["master"], _ = json.MarshalIndent(master, "", "  ")
	source["default_values"] = json.RawMessage("{\n  }")
	pretty, _ := json.MarshalIndent(source, "", " ")
	doc.HtmlCurrentSourceJson = pretty
	before := bytes.Clone(doc.HtmlCurrentSourceJson)
	if err := admission.validateDocument(doc, actor); err != nil {
		t.Fatal("equivalent JSONB/pretty source spelling refused", err)
	}
	if !bytes.Equal(before, doc.HtmlCurrentSourceJson) {
		t.Fatal("projection validation rewrote immutable source bytes")
	}
	for _, c := range []struct {
		name   string
		change func(*generated.Document)
	}{
		{"foreign org", func(v *generated.Document) { v.OrgID = uuid.New() }},
		{"foreign sender", func(v *generated.Document) { v.SenderID = uuid.New() }},
		{"different name", func(v *generated.Document) { v.Name = "Other name" }},
		{"later materialization", func(v *generated.Document) { v.HtmlCurrentMaterializationSequence.Int32 = 2 }},
		{"review transplanted", func(v *generated.Document) { v.HtmlReviewedBy = pgtype.UUID{Bytes: actor.UserID, Valid: true} }},
		{"different printed values", func(v *generated.Document) { v.VariablesJson = []byte(`{"price":"forged"}`) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			changed := *doc
			c.change(&changed)
			if admission.validateDocument(&changed, actor) == nil {
				t.Fatal("different initial projection admitted")
			}
		})
	}
}
