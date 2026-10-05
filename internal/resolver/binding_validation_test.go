// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateBindingPreservesResolverSemantics(t *testing.T) {
	for _, kind := range []SourceKind{SourceStatic, SourceAgentComputed, SourceOrgSetting, SourceCRMDeal, SourceCRMContact, SourceScannerFind} {
		t.Run(string(kind), func(t *testing.T) {
			ref := ""
			if kind == SourceCRMDeal || kind == SourceCRMContact || kind == SourceScannerFind {
				ref = "deal_fixture:version@example.test"
			}
			if err := ValidateBinding("customer.legal_name", kind, ref, "", "Line one\nLine two\t💡"); err != nil {
				t.Fatalf("compatible empty path, reference, or multiline fallback refused: %v", err)
			}
		})
	}
	if err := ValidateBinding("_amount2", SourceCRMDeal, "deal_1", "deal.items.0.line item", ""); err != nil {
		t.Fatalf("literal dotted lookup path refused: %v", err)
	}
	if err := ValidateBinding("org_name", SourceOrgSetting, "unused but preserved", "org.name", ""); err != nil {
		t.Fatalf("unused org.setting reference semantics changed: %v", err)
	}
}

func TestValidateBindingByteBoundaries(t *testing.T) {
	cases := []struct {
		field, value string
		limit        int
	}{
		{"variable", "a", 128}, {"source_ref", "r", 256}, {"source_path", "p", 1024}, {"fallback", "💡", 16 * 1024},
	}
	for _, test := range cases {
		t.Run(test.field, func(t *testing.T) {
			for _, excess := range []int{0, 1} {
				name, ref, path, fallback := "customer", "deal_1", "name", ""
				value := strings.Repeat(test.value, test.limit/len(test.value))
				if excess > 0 {
					value += "x"
				}
				switch test.field {
				case "variable":
					name = value
				case "source_ref":
					ref = value
				case "source_path":
					path = value
				case "fallback":
					fallback = value
				}
				err := ValidateBinding(name, SourceCRMDeal, ref, path, fallback)
				var invalid *BindingValidationError
				if excess == 0 && err != nil || excess > 0 && (!errors.As(err, &invalid) || invalid.Field != test.field) {
					t.Fatalf("boundary excess=%d error=%v", excess, err)
				}
			}
		})
	}
	for _, kind := range []SourceKind{SourceStatic, SourceAgentComputed, SourceOrgSetting} {
		if err := ValidateBinding("customer", kind, strings.Repeat("r", 1024), "", ""); err != nil {
			t.Fatalf("non-HTTP reference boundary rejected for %s: %v", kind, err)
		}
		if err := ValidateBinding("customer", kind, strings.Repeat("r", 1025), "", ""); err == nil {
			t.Fatalf("non-HTTP reference boundary ignored for %s", kind)
		}
	}
}

func TestValidateBindingRejectsMalformedAndUnsafeStorageInputs(t *testing.T) {
	for _, name := range []string{"", "1customer", "customer name", "{{customer}}", "customer/name", "客户", "customer\x00", string([]byte{0xff})} {
		if err := ValidateBindingName(name); err == nil {
			t.Fatalf("invalid variable accepted: %q", name)
		}
	}
	for _, field := range []string{"source_ref", "source_path", "fallback"} {
		for _, value := range []string{"private\x00value", string([]byte{0xff})} {
			t.Run(field, func(t *testing.T) {
				ref, path, fallback := "ref", "path", "fallback"
				switch field {
				case "source_ref":
					ref = value
				case "source_path":
					path = value
				case "fallback":
					fallback = value
				}
				err := ValidateBinding("customer", SourceAgentComputed, ref, path, fallback)
				var invalid *BindingValidationError
				if !errors.As(err, &invalid) || invalid.Field != field || strings.Contains(err.Error(), "private") {
					t.Fatalf("invalid storage input error=%v", err)
				}
			})
		}
	}
	for _, kind := range []SourceKind{SourceCRMDeal, SourceCRMContact, SourceScannerFind} {
		for _, ref := range []string{"", ".", "..", "../admin", "id?include=secrets", "id%2fadmin", "id#fragment", "space id"} {
			if err := ValidateBinding("customer", kind, ref, "name", ""); err == nil {
				t.Fatalf("unsafe %s entity reference accepted: %q", kind, ref)
			}
		}
	}
	if err := ValidateBinding("customer", SourceKind("unknown"), "", "", ""); err == nil {
		t.Fatal("unknown source kind accepted")
	}
}
