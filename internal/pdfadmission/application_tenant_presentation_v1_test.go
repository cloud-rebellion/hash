// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"html"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func tenantPresentationFixture767() (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
	document := &generated.Document{ID: uuid.New(), OrgID: uuid.New(), LawfulBasis: "contract", Name: "Synthetic agreement"}
	confirmation := &generated.DocumentLawfulBasisConfirmation{DocumentID: document.ID, OrgID: document.OrgID, LawfulBasis: "contract", ControllerName: " Frozen tenant company ", ControllerContact: "privacy@example.invalid", ConfirmedAt: pgtype.Timestamptz{Time: time.Unix(1800000000, 0).UTC(), Valid: true}}
	return document, confirmation
}

func TestTenantPresentation767FrozenScopeIgnoresMutableOrgAndOperator(t *testing.T) {
	document, confirmation := tenantPresentationFixture767()
	currentOrg := generated.Org{ID: document.OrgID, Name: "Current renamed company"}
	name, err := applicationTenantPresentationNameV1(document, confirmation)
	if err != nil || name != "Frozen tenant company" || name == currentOrg.Name {
		t.Fatal("presentation did not select exact frozen controller", err)
	}
	currentOrg.Name = "An unrelated installation name"
	again, err := applicationTenantPresentationNameV1(document, confirmation)
	if err != nil || again != name || confirmation.ControllerName != " Frozen tenant company " {
		t.Fatal("presentation rewrote stored evidence or used a mutable company", err)
	}
}

func TestTenantPresentation767ForeignOrUnavailableConfirmationRefuses(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document, *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation)
	}{
		{"missing document", func(_ *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			return nil, c
		}},
		{"missing confirmation", func(d *generated.Document, _ *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			return d, nil
		}},
		{"foreign tenant", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.OrgID = uuid.New()
			return d, c
		}},
		{"foreign document", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.DocumentID = uuid.New()
			return d, c
		}},
		{"unconfirmed", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.ConfirmedAt.Valid = false
			return d, c
		}},
		{"different basis", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.LawfulBasis = "different"
			return d, c
		}},
		{"blank controller", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.ControllerName = " \t "
			return d, c
		}},
		{"blank contact", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			c.ControllerContact = " "
			return d, c
		}},
		{"blank scope", func(d *generated.Document, c *generated.DocumentLawfulBasisConfirmation) (*generated.Document, *generated.DocumentLawfulBasisConfirmation) {
			d.OrgID = uuid.Nil
			c.OrgID = uuid.Nil
			return d, c
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document, confirmation := tenantPresentationFixture767()
			document, confirmation = tc.mutate(document, confirmation)
			if name, err := applicationTenantPresentationNameV1(document, confirmation); err == nil || name != "" {
				t.Fatal("foreign/missing frozen identity acquired a presentation fallback")
			}
		})
	}
}

func TestTenantPresentation767NativeEmailEscapesCompanyAndKeepsFrozenOutput(t *testing.T) {
	document, confirmation := tenantPresentationFixture767()
	confirmation.ControllerName = `Åsa & <script>alert("x")</script>`
	company, err := applicationTenantPresentationNameV1(document, confirmation)
	if err != nil {
		t.Fatal(err)
	}
	ctx := dispatch.TemplateContext{DocumentName: document.Name, OrgName: company, RecipientName: "Synthetic signer", SenderName: "Synthetic sender", SignURL: "https://example.invalid/sign/test"}
	tpl := &dispatch.ServiceEmailTemplateV1{Revision: 1, SubjectTemplate: "{{org_name}}", HTMLTemplate: "<p>{{org_name}}</p>", TextTemplate: "{{org_name}}"}
	_, body, text, err := dispatch.RenderServiceEmailV1(dispatch.KindInvite, ctx, tpl)
	if err != nil || !strings.Contains(body, html.EscapeString(company)) || strings.Contains(body, "<script>") || !strings.Contains(text, company) {
		t.Fatal("native company presentation was not safely rendered", err)
	}
	beforeBody, beforeText := body, text
	confirmation.ControllerName = "Later record in a different test ceremony"
	if ctx.OrgName != company || body != beforeBody || text != beforeText {
		t.Fatal("later source mutation rewrote already rendered output")
	}
}
