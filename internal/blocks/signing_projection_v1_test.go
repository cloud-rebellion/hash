// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"errors"
	"reflect"
	"testing"
)

func TestSigningSignatureFieldAdmitsOriginalConditionalOrderV1(t *testing.T) {
	refusal := errors.New("actual signature decimal refused")
	tree := &Tree{Version: 1, Blocks: []Block{
		{ID: "off", Type: TypeConditional, Attrs: map[string]any{"expression": "var(amount) < 0"}, Content: []Block{{ID: "hidden", Type: TypeSignatureField}}},
		{ID: "active", Type: TypeConditional, Attrs: map[string]any{"expression": "var(amount) > 0"}, Content: []Block{{ID: "first", Type: TypeSignatureField}, {ID: "second", Type: TypeSignatureField}}},
		{ID: "later", Type: TypeConditional, Attrs: map[string]any{"expression": "1e1000000 > 0"}, Content: []Block{{ID: "must-not-visit", Type: TypeSignatureField}}},
	}}
	rec := &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	got, err := SignatureFieldIDForVariablesForSigningV1(tree, "signer", map[string]string{"amount": "2"}, rec)
	if err != nil || got != "first" {
		t.Fatalf("pre-order conditional field=%q err=%v", got, err)
	}
	for _, v := range rec.seen {
		if v == "1e1000000" {
			t.Fatal("projection visited later conditional after first assigned field")
		}
	}
	rec = &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	if got, err = SignatureFieldIDForVariablesForSigningV1(tree, "buyer", map[string]string{"amount": "2"}, rec); got != "" || !errors.Is(err, refusal) {
		t.Fatalf("native denial=%q err=%v", got, err)
	}
}
func TestSigningSignatureFieldPreservesRolesAndNestedFirstMatchV1(t *testing.T) {
	tree := &Tree{Version: 1, Blocks: []Block{{ID: "outer", Type: TypeCallout, Attrs: map[string]any{"tone": "info"}, Content: []Block{{ID: "buyer-first", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "buyer"}}}}, {ID: "buyer-second", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "buyer"}}, {ID: "default", Type: TypeSignatureField}}}
	for _, tc := range []struct{ role, want string }{{"buyer", "buyer-first"}, {"signer", "default"}, {"seller", ""}} {
		rec := &sendDecimalRecorderV1{}
		got, err := SignatureFieldIDForVariablesForSigningV1(tree, tc.role, nil, rec)
		if err != nil || got != tc.want || !reflect.DeepEqual(rec.seen, []string(nil)) {
			t.Fatalf("role=%q got=%q err=%v decimals=%v", tc.role, got, err, rec.seen)
		}
	}
	if got, err := SignatureFieldIDForVariablesForSigningV1(nil, "signer", nil, nil); got != "" || err != nil {
		t.Fatal("nil projection changed")
	}
}
