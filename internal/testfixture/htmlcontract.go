// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package testfixture provides synthetic inputs for lifecycle tests. Its PDF
// bytes are deliberately not a rendered document and establish no renderer,
// integration, legal, or production acceptance.
package testfixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// HTMLContract creates one approved proposal design, its committed synthetic
// PDF/source, and the two exact recipient UUIDs named by its party bindings.
func HTMLContract(t testing.TB) (htmlsource.Input, *generated.Document, []*generated.Recipient) {
	t.Helper()
	values := map[string]string{
		"provider_company": "Synthetic Provider AB", "provider_company_id": "SE-PROVIDER-TEST",
		"provider_name": "Synthetic Provider", "provider_email": "provider@example.test", "provider_authority": "Declared representative in synthetic fixture",
		"customer_company": "Synthetic Customer AB", "customer_company_id": "SE-CUSTOMER-TEST",
		"customer_name": "Synthetic Customer", "customer_email": "customer@example.test", "customer_authority": "Declared representative in synthetic fixture",
		"scope": "Approved synthetic service scope", "price": "1000", "currency": "SEK", "tax": "Synthetic tax treatment",
		"payment_terms": "Synthetic reviewed payment terms", "valid_until": "2026-12-31",
	}
	profile := &htmlmaster.ContractProfile{ID: "synthetic_proposal", Version: 1, Kind: "proposal",
		Parties: []htmlmaster.ContractParty{
			{Slot: "provider", CompanyName: "provider_company", CompanyID: "provider_company_id", RepresentativeName: "provider_name", RepresentativeEmail: "provider_email", RepresentativeAuthority: "provider_authority"},
			{Slot: "customer", CompanyName: "customer_company", CompanyID: "customer_company_id", RepresentativeName: "customer_name", RepresentativeEmail: "customer_email", RepresentativeAuthority: "customer_authority"},
		},
	}
	master := htmlmaster.Master{SchemaVersion: htmlmaster.ContractSchemaVersion, ContractProfile: profile}
	var html strings.Builder
	// Stable declaration order keeps fixture diagnostics independent of map order.
	for _, name := range []string{"provider_company", "provider_company_id", "provider_name", "provider_email", "provider_authority", "customer_company", "customer_company_id", "customer_name", "customer_email", "customer_authority", "scope", "price", "currency", "tax", "payment_terms", "valid_until"} {
		master.Values = append(master.Values, htmlmaster.Value{Name: name, Required: true, MaxChars: 500})
		html.WriteString(`<p><span data-hash-value="` + name + `"></span></p>`)
	}
	for _, name := range []string{"scope", "price", "currency", "tax", "payment_terms", "valid_until"} {
		profile.Terms = append(profile.Terms, htmlmaster.ContractTerm{Name: name, Value: name})
	}
	master.HTML = html.String()
	masterJSON, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(masterJSON, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	variables, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 10, 9, 0, 0, 0, time.UTC)
	senderID, templateID := uuid.New(), uuid.New()
	sum := sha256.Sum256([]byte("synthetic PDF bytes; no renderer acceptance"))
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), SenderID: senderID, SourceKind: "pdf", Status: "draft",
		Name: "Synthetic reviewed proposal", RequiresSignature: true, RoutingTier: "SES", DefaultLocale: "en",
		TemplateID: pgtype.UUID{Bytes: templateID, Valid: true}, VariablesJson: variables,
		PdfStorageKey: pgtype.Text{String: "org/synthetic/documents/proposal.pdf", Valid: true}, PdfSha256: sum[:],
		PdfStorageVersionID: pgtype.Text{String: "synthetic-pdf-version", Valid: true}, EvidenceVersionPinsRequired: true,
		CreatedAt: pgtype.Timestamptz{Time: now, Valid: true}, UpdatedAt: pgtype.Timestamptz{Time: now, Valid: true},
	}
	rows := []*generated.Recipient{
		{ID: uuid.New(), DocumentID: doc.ID, Role: "provider", Name: values["provider_name"], Email: values["provider_email"], Locale: "en", Status: "pending"},
		{ID: uuid.New(), DocumentID: doc.ID, Role: "customer", Name: values["customer_name"], Email: values["customer_email"], Locale: "en", Status: "pending", OrderIndex: 1},
	}
	input := htmlsource.Input{TemplateID: templateID, TemplateVersion: 1, TemplateContentSHA256: canonical.SHA256,
		MasterJSON: canonical.MasterJSON, DefaultVarsJSON: canonical.DefaultsJSON, Values: values, Sections: map[string]string{},
		TemplateApprovedBy: senderID, TemplateApprovedAt: now.Add(-time.Hour),
		PartyBindings: []htmlsource.PartyBinding{{Slot: "provider", RecipientID: rows[0].ID}, {Slot: "customer", RecipientID: rows[1].ID}},
	}
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlReviewedPdfSha256 = bytes.Clone(doc.PdfSha256)
	doc.HtmlReviewedBy = pgtype.UUID{Bytes: senderID, Valid: true}
	doc.HtmlReviewedAt = pgtype.Timestamptz{Time: now, Valid: true}
	return input, doc, rows
}

// ContractSignatureFields provides synthetic, valid first-page geometry bound
// to each supplied recipient. The caller still chooses status/signature data.
func ContractSignatureFields(doc *generated.Document, rows []*generated.Recipient) []*generated.DocumentField {
	number := func(value int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(value), Valid: true} }
	fields := make([]*generated.DocumentField, 0, len(rows))
	for i, row := range rows {
		fields = append(fields, &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: row.ID, Valid: true},
			Type: "signature", Required: true, Page: 1, XPct: number(10), YPct: number(20 + int64(i)*20), WPct: number(25), HPct: number(8)})
	}
	return fields
}

func BrandedSigningPolicy() *htmlmaster.SigningPagePolicy {
	return &htmlmaster.SigningPagePolicy{Version: 1, Policy: htmlmaster.SigningPagePolicyName, FontSHA256: htmlmaster.SigningPageFontSHA256,
		Branding: htmlmaster.SigningPageBranding{PrimaryHex: "#102038", AccentHex: "#2458A6", SurfaceHex: "#FFFFFF", TextHex: "#102038", MutedHex: "#526176",
			LogoURL: "", LogoAlt: "", FontHeading: "Inter", FontBody: "Inter", SignatureColor: "#102038"}, LogoAsset: "", LogoSHA256: "", LogoAlt: ""}
}

// BrandedHTMLContract has synthetic manifest hashes and no rendered proof. It
// is suitable for pure canonicalization and state-guard tests only.
func BrandedHTMLContract(t testing.TB) (htmlsource.Input, *generated.Document, []*generated.Recipient) {
	t.Helper()
	input, doc, rows := HTMLContract(t)
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	master.SchemaVersion = htmlmaster.SigningPageSchemaVersion
	master.SigningPage = BrandedSigningPolicy()
	raw, err := json.Marshal(master)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := htmlmaster.CanonicalTemplate(raw, input.DefaultVarsJSON)
	if err != nil {
		t.Fatal(err)
	}
	input.MasterJSON = canonical.MasterJSON
	input.DefaultVarsJSON = canonical.DefaultsJSON
	input.TemplateContentSHA256 = canonical.SHA256
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	geometry := sanitize.PDFPageGeometry{UserUnitMilli: 1000}
	for i := range geometry.BoxesMilliPoints {
		geometry.BoxesMilliPoints[i] = [4]int64{0, 0, 594960, 841920}
	}
	composition := sanitize.PDFCompositionManifest{SchemaVersion: 1, Policy: sanitize.PDFSigningPagePolicy, BodySHA256: strings.Repeat("a", 64), SigningPageSHA256: strings.Repeat("b", 64),
		MergedSHA256: strings.Repeat("c", 64), MergedBytes: 1000, OutputSHA256: hex.EncodeToString(doc.PdfSha256), BodyPages: 1, FinalPages: 2, BodyGeometrySHA256: strings.Repeat("d", 64), GeometrySHA256: strings.Repeat("e", 64), SigningPage: geometry}
	input.SigningArtifact, err = htmlsource.NewSigningArtifact(compiled, htmlmaster.Input{Values: input.Values, Sections: input.Sections}, input.PartyBindings, composition)
	if err != nil {
		t.Fatal(err)
	}
	doc.HtmlSourceJson, err = htmlsource.New(input, doc)
	if err != nil {
		t.Fatal(err)
	}
	return input, doc, rows
}

func BrandedSignatureFields(t testing.TB, doc *generated.Document) []*generated.DocumentField {
	t.Helper()
	_, artifact, err := htmlsource.SigningPage(doc)
	if err != nil || artifact == nil {
		t.Fatal("missing synthetic branded artifact", err)
	}
	parties, err := htmlsource.ContractParties(doc)
	if err != nil {
		t.Fatal(err)
	}
	bySlot := map[string]htmlsource.ContractParty{}
	for _, party := range parties {
		bySlot[party.Slot] = party
	}
	number := func(n int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(n), Exp: -4, Valid: true} }
	fields := make([]*generated.DocumentField, 0, 2)
	for _, r := range artifact.Fields {
		options, err := htmlsource.SigningFieldOptions(doc, r.Slot)
		if err != nil {
			t.Fatal(err)
		}
		fields = append(fields, &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: bySlot[r.Slot].RecipientID, Valid: true},
			Type: "signature", Page: r.Page, XPct: number(r.X), YPct: number(r.Y), WPct: number(r.W), HPct: number(r.H), Required: true,
			Label: pgtype.Text{String: strings.ToUpper(r.Slot[:1]) + r.Slot[1:] + " signature", Valid: true}, OptionsJson: options})
	}
	return fields
}
