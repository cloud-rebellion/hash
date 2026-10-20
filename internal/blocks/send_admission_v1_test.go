// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package blocks

import (
	"encoding/json"
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

type sendDecimalRecorderV1 struct {
	seen    []string
	deny    string
	failure error
}

func (r *sendDecimalRecorderV1) BeforeDecimalV1(value string) error {
	r.seen = append(r.seen, value)
	if value == r.deny {
		return r.failure
	}
	return nil
}
func sendConditionTreeV1(expr string) []byte {
	tree := Tree{Version: 1, Blocks: []Block{{ID: "condition", Type: TypeConditional, Attrs: map[string]any{"expression": expr}, Content: []Block{{ID: "signature", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}}}}}}
	raw, err := json.Marshal(tree)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestSendDecimalAdmissionBeforeLiteralExpansionV1(t *testing.T) {
	refusal := errors.New("native decimal capacity refused")
	recorder := &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	tree, err := ParseCanonicalTreeForSendV1(sendConditionTreeV1("1e1000000 > 0"), recorder)
	if tree != nil || !errors.Is(err, refusal) {
		t.Fatalf("expected native refusal, tree=%v err=%v", tree, err)
	}
	if !reflect.DeepEqual(recorder.seen, []string{"1e1000000"}) {
		t.Fatalf("unexpected expansion sites: %v", recorder.seen)
	}
	// Original decimal grammar must reject underscores before invoking admission.
	recorder = &sendDecimalRecorderV1{}
	if _, err = ParseCanonicalTreeForSendV1(sendConditionTreeV1("1_000 > 0"), recorder); err == nil || len(recorder.seen) != 0 {
		t.Fatalf("original lexical rejection must precede admission: seen=%v err=%v", recorder.seen, err)
	}
	// The missing-ID canonical guard must still precede conditional validation.
	raw := []byte("{\"version\":1,\"blocks\":[{\"type\":\"conditional\",\"attrs\":{\"expression\":\"1e1000000 > 0\"},\"content\":[{\"id\":\"p\",\"type\":\"paragraph\"}]}]}")
	recorder = &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	if _, err = ParseCanonicalTreeForSendV1(raw, recorder); !errors.Is(err, ErrMissingID) || len(recorder.seen) != 0 {
		t.Fatalf("missing ID precedence changed: seen=%v err=%v", recorder.seen, err)
	}
}

func TestSendDecimalAdmissionBeforeFrozenValueExpansionV1(t *testing.T) {
	tree, err := ParseCanonicalTree(sendConditionTreeV1("var(amount) > 0"))
	if err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("frozen value capacity refused")
	recorder := &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	values, err := ValidateResolvedVariableValuesForSendV1(tree, []byte("{\"amount\":\" 1e1000000 \"}"), recorder)
	if values != nil || !errors.Is(err, refusal) {
		t.Fatalf("expected frozen decimal refusal: values=%v err=%v", values, err)
	}
	if len(recorder.seen) == 0 || recorder.seen[len(recorder.seen)-1] != "1e1000000" {
		t.Fatalf("trimmed actual numeric value was not admitted: %v", recorder.seen)
	}
	recorder = &sendDecimalRecorderV1{deny: "1e1000000", failure: refusal}
	roles, err := RequiredSignerRolesForVariablesForSendV1(tree, map[string]string{"amount": " 1e1000000 "}, recorder)
	if roles != nil || !errors.Is(err, refusal) {
		t.Fatalf("expected role projection refusal: roles=%v err=%v", roles, err)
	}
	if len(recorder.seen) == 0 || recorder.seen[len(recorder.seen)-1] != "1e1000000" {
		t.Fatalf("role projection missed actual numeric value: %v", recorder.seen)
	}
}

func TestSendCanonicalAdmissionPreservesDecoderSemanticsV1(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"duplicate slice reuses prior struct", "{\"version\":1,\"blocks\":[{\"id\":\"retained\",\"type\":\"paragraph\",\"text\":\"old\"}],\"blocks\":[{\"type\":\"paragraph\",\"text\":\"new\"}]}"},
		{"duplicate attrs merge", "{\"version\":1,\"blocks\":[{\"id\":\"image\",\"type\":\"image\",\"attrs\":{\"storage_key\":\"asset\"},\"attrs\":{\"alt\":\"kept\",\"width_pct\":\"50\"}}]}"},
		{"case folded struct fields", "{\"Version\":1,\"BLOCKS\":[{\"ID\":\"p\",\"TYPE\":\"paragraph\",\"TEXT\":\"body\"}]}"},
		{"null slice reset", "{\"version\":1,\"blocks\":[{\"id\":\"discarded\",\"type\":\"paragraph\"}],\"blocks\":null}"},
		{"null scalar no op", "{\"version\":1,\"version\":null,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\"kept\",\"text\":null}]}"},
		{"unknown attrs still rejected by original validator", "{\"version\":1,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"attrs\":{\"nested\":[{},null,[1]]}}]}"},
		{"explicit version required", "{\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\"}]}"},
		{"trailing content rejected", "{\"version\":1,\"blocks\":[]} {}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old, oldErr := ParseCanonicalTree([]byte(tc.raw))
			recorder := &sendDecimalRecorderV1{}
			got, err := ParseCanonicalTreeForSendV1([]byte(tc.raw), recorder)
			if !reflect.DeepEqual(got, old) || errorTextForSendV1(err) != errorTextForSendV1(oldErr) {
				t.Fatalf("decoder behavior changed: old=%#v/%v got=%#v/%v", old, oldErr, got, err)
			}
			if len(recorder.seen) != 0 {
				t.Fatalf("nonconditional tree invoked numeric admission: %v", recorder.seen)
			}
			if tc.name == "duplicate slice reuses prior struct" && (got == nil || len(got.Blocks) != 1 || got.Blocks[0].ID != "retained" || got.Blocks[0].Text != "new") {
				t.Fatal("original duplicate slice merge must remain")
			}
			if tc.name == "duplicate attrs merge" && (got == nil || got.Blocks[0].AttrString("storage_key", "") != "asset" || got.Blocks[0].AttrString("alt", "") != "kept") {
				t.Fatal("original duplicate attrs map merge must remain")
			}
		})
	}
	// encoding/json's replacement of invalid UTF8 remains accepted.
	raw := append([]byte("{\"version\":1,\"blocks\":[{\"id\":\"p\",\"type\":\"paragraph\",\"text\":\""), 0xff)
	raw = append(raw, []byte("\"}]}")...)
	got, err := ParseCanonicalTreeForSendV1(raw, &sendDecimalRecorderV1{})
	if err != nil || got.Blocks[0].Text != "\ufffd" {
		t.Fatalf("original invalid UTF8 replacement changed: tree=%v err=%v", got, err)
	}
}
func errorTextForSendV1(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestSendResolvedDefaultsAndDuplicateValuesV1(t *testing.T) {
	tree := &Tree{Version: 1, Blocks: []Block{
		{ID: "default", Type: TypeDynamicVar, Attrs: map[string]any{"name": "amount", "default": "30"}},
		{ID: "condition", Type: TypeConditional, Attrs: map[string]any{"expression": "var(amount) > 10"}, Content: []Block{{ID: "signature", Type: TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}}}},
	}}
	if err := ValidateForSendV1(tree, &sendDecimalRecorderV1{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateResolvedVariableValuesForSendV1(tree, []byte("{}"), &sendDecimalRecorderV1{}); err == nil || !strings.Contains(err.Error(), "unresolved variables: amount") {
		t.Fatalf("block default must not satisfy a hard reference: %v", err)
	}
	raw := []byte("{\"amount\":\"2\",\"amount\":\"20\"}")
	old, oldErr := ValidateResolvedVariableValues(tree, raw)
	recorder := &sendDecimalRecorderV1{}
	got, err := ValidateResolvedVariableValuesForSendV1(tree, raw, recorder)
	if err != nil || oldErr != nil || !reflect.DeepEqual(got, old) || got["amount"] != "20" {
		t.Fatalf("duplicate effective variable changed: old=%v/%v got=%v/%v", old, oldErr, got, err)
	}
	oldRoles, oldErr := RequiredSignerRolesForVariables(tree, old)
	roles, err := RequiredSignerRolesForVariablesForSendV1(tree, got, recorder)
	if err != nil || oldErr != nil || !reflect.DeepEqual(roles, oldRoles) || !reflect.DeepEqual(roles, []string{"signer"}) {
		t.Fatalf("role projection changed: old=%v/%v got=%v/%v", oldRoles, oldErr, roles, err)
	}
}

func TestSendDecimalLogicalBoundsV1(t *testing.T) {
	for _, value := range []string{"0", "-0", "+12", "01.2300E+2", ".1e-2", "1.e2", "1e1000", "1e-1000", "1e1000001", "1e-1000001", "0e9223372036854775807", "0.00e-9223372036854775808", "0e9223372036854775808", "1e9223372036854775807", "1e-9223372036854775808"} {
		t.Run(value, func(t *testing.T) {
			bound, err := DecimalLogicalBoundForSendV1(value)
			if err != nil {
				t.Fatal(err)
			}
			number, ok := new(big.Rat).SetString(value)
			if bound.ConversionPossible != ok {
				t.Fatalf("pinned conversion prediction differs: bound=%+v ok=%v", bound, ok)
			}
			if bound.SourceBytes != int64(len(value)) || bound.MantissaBits < 0 || bound.PowerFiveBits < 0 {
				t.Fatalf("invalid components: %+v", bound)
			}
			if ok && (int64(number.Num().BitLen()) > bound.NumeratorBits || int64(number.Denom().BitLen()) > bound.DenominatorBits) {
				t.Fatalf("magnitude exceeded bound: n=%d d=%d bound=%+v", number.Num().BitLen(), number.Denom().BitLen(), bound)
			}
		})
	}
	// This accepted tiny lexical spelling expands to a million decimal powers.
	// Inspect it without executing any big-number conversion.
	b, err := DecimalLogicalBoundForSendV1("1e1000000")
	if err != nil || !b.ConversionPossible || b.SourceBytes != 9 || b.MantissaDigits != 1 || b.AdjustedExponent != 1_000_000 || b.PowerFiveBits != 3_000_001 || b.NumeratorBits != 4_000_004 || b.DenominatorBits != 1 {
		t.Fatalf("high exponent bound: %+v err=%v", b, err)
	}
	b, err = DecimalLogicalBoundForSendV1("0.001e1000003")
	if err != nil || !b.ConversionPossible || b.FractionDigits != 3 || b.AdjustedExponent != 1_000_000 {
		t.Fatalf("fraction-adjusted accepted exponent changed: %+v err=%v", b, err)
	}
	for _, bad := range []string{"1_000", "1/2", "0x10", "1e", ".", "NaN", " 1", "1,5"} {
		if _, err := DecimalLogicalBoundForSendV1(bad); err == nil {
			t.Fatalf("original decimal grammar must reject %q", bad)
		}
	}
}

func TestWithdrawnBuiltInLegalDraftForSendV1ExactFragments(t *testing.T) {
	fragments := []string{
		"Atomicsite-binären levereras under sin öppna licens Apache 2.0",
		"Ett personuppgiftsbiträdesavtal (Bilaga A) gäller från driftstart",
		"DRAFT KIT v1 (auto-seeded by Hash",
	}
	if WithdrawnBuiltInLegalDraftForSendV1(nil) {
		t.Fatal("nil must remain false")
	}
	for _, fragment := range fragments {
		for _, tree := range []*Tree{
			{Blocks: []Block{{Text: "prefix " + fragment + " suffix"}}},
			{Blocks: []Block{{Rows: [][]string{{"safe", fragment}}}}},
			{Blocks: []Block{{Content: []Block{{Text: fragment}}}}},
		} {
			if !WithdrawnBuiltInLegalDraftForSendV1(tree) {
				t.Fatalf("existing fragment missed: %q", fragment)
			}
		}
		if WithdrawnBuiltInLegalDraftForSendV1(&Tree{Blocks: []Block{{Text: strings.ToLower(fragment)}}}) {
			t.Fatalf("guard must retain exact case-sensitive fragments: %q", fragment)
		}
	}
	if WithdrawnBuiltInLegalDraftForSendV1(&Tree{Blocks: []Block{{Attrs: map[string]any{"label": fragments[0]}}}}) {
		t.Fatal("existing guard must not grow to attributes")
	}
}
