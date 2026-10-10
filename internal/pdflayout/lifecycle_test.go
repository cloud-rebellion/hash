// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdflayout

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func lifecycleFixture() (*generated.Document, []*generated.Recipient, []*generated.DocumentField) {
	doc := &generated.Document{ID: uuid.New(), SourceKind: "pdf", RequiresSignature: true}
	rows := []*generated.Recipient{
		{ID: uuid.New(), DocumentID: doc.ID, Role: "provider", Status: "signed"},
		{ID: uuid.New(), DocumentID: doc.ID, Role: "customer", Status: "signed"},
	}
	num := func(n int64) pgtype.Numeric { return pgtype.Numeric{Int: big.NewInt(n), Valid: true} }
	var fields []*generated.DocumentField
	for _, row := range rows {
		fields = append(fields, &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: row.ID, Valid: true}, Type: "signature", Required: true,
			Page: 1, XPct: num(10), YPct: num(20), WPct: num(25), HPct: num(8)})
	}
	return doc, rows, fields
}

func TestRequiredRolesNamedPDFPartiesMustEachOwnAVisibleRequiredSignature(t *testing.T) {
	doc, rows, fields := lifecycleFixture()
	roles, err := RequiredRoles(doc, rows, fields, 1)
	if err != nil || !reflect.DeepEqual(roles, []string{"customer", "provider"}) {
		t.Fatalf("roles=%v error=%v", roles, err)
	}
	for _, scenario := range []string{"missing_field", "duplicate_role", "unassigned", "optional", "mutable_visible_content", "foreign_recipient", "invalid_geometry"} {
		t.Run(scenario, func(t *testing.T) {
			doc, rows, fields := lifecycleFixture()
			switch scenario {
			case "missing_field":
				fields = fields[:1]
			case "duplicate_role":
				rows[1].Role = rows[0].Role
			case "unassigned":
				fields[1].RecipientID = pgtype.UUID{}
			case "optional":
				fields[1].Required = false
			case "mutable_visible_content":
				extra := *fields[0]
				extra.Type = "text"
				fields = append(fields, &extra)
			case "foreign_recipient":
				rows[1].DocumentID = uuid.New()
			case "invalid_geometry":
				fields[1].XPct = pgtype.Numeric{Int: big.NewInt(95), Valid: true}
			}
			if _, err := RequiredRoles(doc, rows, fields, 1); err == nil {
				t.Fatal("unsafe PDF ceremony was accepted")
			}
		})
	}
}

func TestRequiredRolesPreservesLegacySingleSignerFillablePDF(t *testing.T) {
	doc, rows, fields := lifecycleFixture()
	rows, fields = rows[:1], fields[:1]
	rows[0].Role = "signer"
	extra := *fields[0]
	extra.Type = "text"
	extra.Required = false
	fields = append(fields, &extra)
	roles, err := RequiredRoles(doc, rows, fields, 1)
	if err != nil || !reflect.DeepEqual(roles, []string{"signer"}) {
		t.Fatalf("legacy roles=%v err=%v", roles, err)
	}
}

func TestValidateSignatureRowsRequiresEveryExactPartyAndField(t *testing.T) {
	doc, rows, fields := lifecycleFixture()
	sigs := []*generated.Signature{
		{ID: uuid.New(), DocumentID: doc.ID, RecipientID: rows[0].ID, FieldID: fields[0].ID},
		{ID: uuid.New(), DocumentID: doc.ID, RecipientID: rows[1].ID, FieldID: fields[1].ID},
	}
	if err := ValidateSignatureRows(doc, rows, fields, sigs, 1); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSignatureRows(doc, rows, fields, sigs[:1], 1); err == nil {
		t.Fatal("signed status without a captured signature was accepted")
	}
	sigs[1].FieldID = fields[0].ID
	if err := ValidateSignatureRows(doc, rows, fields, sigs, 1); err == nil {
		t.Fatal("a signature bound to the other party's field was accepted")
	}
}
