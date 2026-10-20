// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/eidas"
	"strconv"
	"strings"
	"testing"
)

// This allocating test oracle walks actual RawMessages. The native component
// itself must not decode the tree merely to price the unchanged validator.
func catalogRulePredicateSpanOracleV1(t *testing.T, raw json.RawMessage, depth, rootBytes int64) (spans, paths, containers, stringsCount, scalars int64) {
	t.Helper()
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		t.Fatal("empty oracle")
	}
	digits := int64(len(strconv.FormatInt(rootBytes, 10)))
	switch trim[0] {
	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trim, &object); err != nil {
			t.Fatal(err)
		}
		depth++
		spans = int64(len(trim))
		paths = 9 + (6+digits)*depth
		containers = 1
		stringsCount = int64(len(object))
		for _, child := range object {
			a, b, c, d, e := catalogRulePredicateSpanOracleV1(t, child, depth, rootBytes)
			spans += a
			paths += b
			containers += c
			stringsCount += d
			scalars += e
		}
	case '[':
		var array []json.RawMessage
		if err := json.Unmarshal(trim, &array); err != nil {
			t.Fatal(err)
		}
		depth++
		spans = int64(len(trim))
		containers = 1
		for _, child := range array {
			a, b, c, d, e := catalogRulePredicateSpanOracleV1(t, child, depth, rootBytes)
			spans += a
			paths += b
			containers += c
			stringsCount += d
			scalars += e
		}
	case '"':
		stringsCount = 1
	default:
		scalars = 1
	}
	return
}
func TestCatalogRulePredicateActualCopiesPathsAndOriginalDecisionsV1(t *testing.T) {
	for index, raw := range []string{`{"field":"country","op":"==","value":"SE"}`, `{"all":[{"field":"country","op":"in","value":["SE","NO"]},{"field":"amount","op":">=","value":12.5}]}`, `{"a\u006cl":[{"field":"variables.\"key","op":"!=","value":"A\u0000B<&\\"}]}`, `{"any":[{"field":"country","op":"==","value":{"unknown":[1,2,3]}}]}`} {
		t.Run(strconv.Itoa(len(raw)), func(t *testing.T) {
			actual := []byte(raw)
			before := bytes.Clone(actual)
			got, err := catalogRulePredicateComponentsForV1(actual)
			if err != nil {
				t.Fatal(err)
			}
			spans, paths, containers, strs, scalars := catalogRulePredicateSpanOracleV1(t, actual, 0, int64(len(actual)))
			if got.rawBytes != int64(len(raw)) || got.rawMessageCopies != 2*spans+6*int64(len(raw)) || got.pathCopies != 4*paths || got.containers != containers || got.strings != strs || got.scalars != scalars || got.parentBytes != got.rawMessageCopies+got.pathCopies+got.typedExpressions || got.typedExpressions <= 0 {
				t.Fatal("actual validator expression masses differ from raw-span oracle", got)
			}
			if !bytes.Equal(before, actual) {
				t.Fatal("pricing mutated actual predicate")
			}
			original := eidas.ValidateRule(actual, eidas.TierSES)
			if (original == nil) != (index < 3) {
				t.Fatal("fixture did not cross its genuine original validator branch", original)
			}
		})
	}
}

func TestCatalogRulePredicateNestedCopyGrowthAndLargeScalarV1(t *testing.T) {
	leaf := `{"field":"country","op":"==","value":"SE"}`
	deep := leaf
	for i := 0; i < 128; i++ {
		deep = `{"all":[` + deep + `]}`
	}
	got, err := catalogRulePredicateComponentsForV1([]byte(deep))
	if err != nil || got.rawMessageCopies <= 64*int64(len(deep)) || got.pathCopies <= int64(len(deep)) {
		t.Fatal("real recursive RawMessage/path growth was missed", got, err)
	}
	if err = eidas.ValidateRule([]byte(deep), eidas.TierSES); err != nil {
		t.Fatal("unchanged valid deep predicate rejected", err)
	}
	large := `{"field":"country","op":"==","value":"` + strings.Repeat("x", 32<<10) + `"}`
	got, err = catalogRulePredicateComponentsForV1([]byte(large))
	if err != nil || got.rawMessageCopies != 8*int64(len(large)) || got.parentBytes > 16*int64(len(large)) {
		t.Fatal("one large scalar acquired an invented quadratic tree", got, err)
	}
	if err = eidas.ValidateRule([]byte(large), eidas.TierSES); err != nil {
		t.Fatal("component introduced a new accepted value limit", err)
	}
}

func TestCatalogRulePredicateComponentCannotSubstituteSchemaAuthorityV1(t *testing.T) {
	for _, raw := range []string{`[]`, `{"unknown":{"all":[{},{}]}}`, `{"field":"country","op":"==","value":false}`, `{"field":"country","op":"in","value":[{},[]]}`} {
		if _, err := catalogRulePredicateComponentsForV1([]byte(raw)); err != nil {
			t.Fatal("pricing attempted a schema policy", raw, err)
		}
		if err := eidas.ValidateRule([]byte(raw), eidas.TierSES); err == nil {
			t.Fatal("original validator unexpectedly accepted malformed schema", raw)
		}
	}
	for _, raw := range []string{"", "{", "[}", "\"unfinished"} {
		if _, err := catalogRulePredicateComponentsForV1([]byte(raw)); err == nil {
			t.Fatal("incomplete topology produced credit", raw)
		}
	}
	if _, err := catalogRulePredicateComponentsForV1([]byte(strings.Repeat("[", 10001) + "0" + strings.Repeat("]", 10001))); err == nil {
		t.Fatal("existing encoding/json depth bound was exceeded")
	}
}
