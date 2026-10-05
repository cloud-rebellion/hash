// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fields

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestOptionsJSONRejectsDatabaseUnsafeStringsAndNumbers(t *testing.T) {
	cases := map[string]string{
		"nested_nul_value":                `{"metadata":{"value":"\u0000"}}`,
		"nested_nul_key":                  `{"metadata":{"\u0000":"value"}}`,
		"nul_array_value":                 `{"metadata":["valid","\u0000"]}`,
		"high_surrogate_value":            `{"metadata":{"value":"\ud800"}}`,
		"low_surrogate_key":               `{"metadata":{"\udfff":true}}`,
		"bad_surrogate_pair":              `{"metadata":"\ud800\u0041"}`,
		"two_high_surrogates":             `{"metadata":"\ud800\ud801"}`,
		"separated_surrogates":            `{"metadata":"\ud800x\udc00"}`,
		"positive_numeric_overflow":       `{"metadata":1e131072}`,
		"negative_scale_overflow":         `{"metadata":1e-16384}`,
		"exponent_parse_overflow":         `{"metadata":1e999999999999999999999999999}`,
		"zero_exponent_overflow":          `{"metadata":0e2147483647}`,
		"positive_readback_amplification": `{"metadata":1e100000}`,
		"negative_readback_amplification": `{"metadata":1e-16383}`,
		"combined_expansion":              `{"a":1e10000,"b":1e10000}`,
		"depth":                           `{"metadata":` + strings.Repeat("[", 32) + `0` + strings.Repeat("]", 32) + `}`,
		"canonical_separator_expansion":   `{"values":[` + strings.Repeat("0,", 5500) + `0]}`,
		"object_shape":                    `[]`,
		"trailing_value":                  `{} {}`,
		"bad_json":                        `{"metadata":`,
		"invalid_utf8":                    "{\"metadata\":\"" + string([]byte{0xff}) + "\"}",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			var invalid *ValidationError
			if err := validateOptionsJSON([]byte(raw)); !errors.As(err, &invalid) || invalid.Field != "options" {
				t.Fatalf("unsafe options error=%v, want typed options validation", err)
			}
		})
	}
}

func TestOptionsJSONAcceptsUnicodeNestedMetadataAndPreservesRaw(t *testing.T) {
	for name, raw := range map[string]string{
		"empty":                   `{}`,
		"unicode":                 ` {"metadata":{"label":"Å\ud834\udd1e🙂","\ud83d\ude80":"ready"}} `,
		"literal_unicode_escape":  `{"metadata":{"\\u0000":"\\ud800"}}`,
		"escaped_quote_backslash": `{"metadata":"quote: \" and slash: \\"}`,
		"nested":                  `{"metadata":[true,null,{"count":1.230e-5,"negative":-123.4500}]}`,
		"depth_boundary":          `{"metadata":` + strings.Repeat("[", 31) + `0` + strings.Repeat("]", 31) + `}`,
		"dropdown":                `{"choices":["First option","Second option"],"metadata":{"number":1e3}}`,
	} {
		t.Run(name, func(t *testing.T) {
			original := []byte(raw)
			input := CreateInput{Type: "text", Page: 1, WPct: 20, HPct: 5, Options: append(json.RawMessage(nil), original...)}
			if name == "dropdown" {
				input.Type = "dropdown"
			}
			if err := validateOptionsJSON(input.Options); err != nil {
				t.Fatal(err)
			}
			values, err := normalizeCreateInput(input, &generated.Document{SourceKind: "blocks"})
			if err != nil || !bytes.Equal(values.Options, original) || !bytes.Equal(input.Options, original) {
				t.Fatalf("accepted options were changed or refused: %v", err)
			}
		})
	}
	values, err := normalizeCreateInput(CreateInput{Type: "text", WPct: 20, HPct: 5}, &generated.Document{SourceKind: "blocks"})
	if err != nil || !bytes.Equal(values.Options, []byte(`{}`)) {
		t.Fatalf("default options=%s error=%v", values.Options, err)
	}
}

func TestOptionsNumberSizeChecksDatabaseRangeWithoutDecimalAllocation(t *testing.T) {
	for number, want := range map[string]int64{
		"0": 1, "-0": 2, "123.4500": 8, "1.230e-5": 10, "0.001e3": 1, "120.00e-1": 6,
		"1e131071": 131072, "0.001e131074": 131072, "1e-16383": 16385, "1.000e-16380": 16385,
	} {
		if size, err := optionsNumberSize(number); err != nil || size != want {
			t.Errorf("number %s size=%d error=%v want%d", number, size, err, want)
		}
	}
	for _, number := range []string{"1e131072", "1e-16384", "1.000e-16381", "1e999999999999999999999", "0e2147483647"} {
		if _, err := optionsNumberSize(number); err == nil {
			t.Errorf("out-of-range number accepted: %s", number)
		}
	}
}

func TestOptionsJSONBoundsTotalExpandedReadbackAtSixteenKiB(t *testing.T) {
	for _, raw := range []string{`{"n":1e16376}`, `{"n":1e-16375}`} {
		if err := validateOptionsJSON([]byte(raw)); err != nil {
			t.Fatalf("exact readback size boundary rejected: %v", err)
		}
	}
	for _, raw := range []string{`{"n":1e16377}`, `{"n":1e-16376}`, `{"a":1e10000,"b":1e10000}`} {
		if err := validateOptionsJSON([]byte(raw)); err == nil {
			t.Fatal("decimal expansion bypassed the total readback limit")
		}
	}
	if err := validateOptionsJSON([]byte(`{"n":"` + strings.Repeat("a", maxFieldOptionsBytes) + `"}`)); err == nil {
		t.Fatal("original raw-size limit was bypassed")
	}
}
