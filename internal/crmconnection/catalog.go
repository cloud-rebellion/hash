// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import "sort"

// FieldDefinition names a source-native scalar or an explicitly derived field.
// Company id, orgnr and tax_id have different semantics; contact role is a job
// title and never a grant of signing authority. There is no fabricated VAT or
// representative-authority field in this catalog.
type FieldDefinition struct {
	Path     string `json:"path"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Derived  bool   `json:"derived"`
}

type fieldRule struct {
	typ      string
	nullable bool
	derived  bool
}

var catalogs = map[RecordKind]map[string]fieldRule{
	Deal: {
		"title": {typ: "string"}, "value": {typ: "decimal", nullable: true},
		"currency": {typ: "string"}, "stage": {typ: "string"},
		"stage_code":          {typ: "string", nullable: true},
		"expected_close_date": {typ: "timestamp", nullable: true},
		"pipeline_id":         {typ: "reference", nullable: true},
		"company_id":          {typ: "reference", nullable: true},
		"contact_id":          {typ: "reference", nullable: true},
		"assigned_to_id":      {typ: "reference", nullable: true},
		"lead_id":             {typ: "reference", nullable: true},
	},
	Contact: {
		"first_name": {typ: "string"}, "last_name": {typ: "string"}, "email": {typ: "string"},
		"full_name": {typ: "string", nullable: true, derived: true},
		"role":      {typ: "string", nullable: true}, "phone": {typ: "string", nullable: true},
		"mobile_phone": {typ: "string", nullable: true}, "preferred_language": {typ: "string", nullable: true},
		"company_id":     {typ: "reference", nullable: true},
		"do_not_contact": {typ: "boolean"}, "is_primary": {typ: "boolean"},
	},
	Company: {
		"name": {typ: "string"}, "legal_name": {typ: "string", nullable: true},
		"orgnr": {typ: "string", nullable: true}, "tax_id": {typ: "string", nullable: true},
		"email": {typ: "string", nullable: true}, "currency": {typ: "string", nullable: true},
		"payment_terms": {typ: "string", nullable: true}, "address": {typ: "string", nullable: true},
		"street": {typ: "string", nullable: true}, "city": {typ: "string", nullable: true},
		"state": {typ: "string", nullable: true}, "zip": {typ: "string", nullable: true}, "country": {typ: "string", nullable: true},
		"billing_street": {typ: "string", nullable: true}, "billing_city": {typ: "string", nullable: true},
		"billing_state": {typ: "string", nullable: true}, "billing_zip": {typ: "string", nullable: true}, "billing_country": {typ: "string", nullable: true},
	},
}

func fieldCatalog(kind RecordKind) map[string]fieldRule { return catalogs[kind] }

// Catalog returns an independent, deterministically ordered definition list.
func Catalog(kind RecordKind) []FieldDefinition {
	rules := fieldCatalog(kind)
	out := make([]FieldDefinition, 0, len(rules))
	for path, r := range rules {
		out = append(out, FieldDefinition{Path: path, Type: r.typ, Nullable: r.nullable, Derived: r.derived})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
