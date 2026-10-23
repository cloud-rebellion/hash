// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlsource_test

import (
	"encoding/json"
	"testing"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/testfixture"
)

func TestPresentedAmendmentPolicyUsesValidatedReviewedSnapshot483(t *testing.T) {
	in, doc, _ := testfixture.HTMLContract(t)
	m, err := htmlmaster.Decode(in.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	m.ContractProfile.AmendmentPolicy = &htmlmaster.AmendmentPolicyV1{Term: "scope", ClauseReference: "Section 12", AllowedModes: []string{"agreed_notice"}, AllowedChannels: []string{"email"}, EffectiveCondition: "after 30 days"}
	clause := "Section 12: agreed changes can be notified by email after 30 days."
	for _, term := range m.ContractProfile.Terms {
		if term.Name == "scope" {
			if term.Value != "" {
				in.Values[term.Value] = clause
			} else {
				in.Sections[term.Section] = clause
			}
		}
	}
	master, _ := json.Marshal(m)
	c, err := htmlmaster.CanonicalTemplate(master, in.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	in.MasterJSON = c.MasterJSON
	in.TemplateContentSHA256 = c.SHA256
	doc.VariablesJson, _ = json.Marshal(in.Values)
	doc.HtmlSourceJson, err = htmlsource.New(in, doc)
	if err != nil {
		t.Fatal(err)
	}
	v, err := htmlsource.NewRevisionValidationV1(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !v.HasAmendmentPolicyV1() {
		t.Fatal("declared source policy missing")
	}
	projected, err := v.PresentedAmendmentPolicyV1()
	if err != nil || projected == nil || projected.ReviewedClause != clause {
		t.Fatal("actual clause projection differs", err)
	}
	projected.AllowedModes[0] = "forged"
	projected.EffectiveCondition = "forged"
	// The pure operation pins its original reviewed tuple. Neither caller model
	// mutation nor a returned policy view can replace that retained snapshot.
	doc.PdfStorageVersionID.String = "different-version"
	doc.HtmlReviewedPdfSha256 = []byte("bad")
	again, err := v.PresentedAmendmentPolicyV1()
	if err != nil || again.AllowedModes[0] != "agreed_notice" || again.EffectiveCondition != "after 30 days" {
		t.Fatal("caller changed retained source", err)
	}
	if _, err := htmlsource.NewRevisionValidationV1(doc); err == nil {
		t.Fatal("fresh validation accepted tampered PDF tuple")
	}
}
