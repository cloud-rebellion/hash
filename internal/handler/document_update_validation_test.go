// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateDocumentUpdateStoragePreservesExactUnicodeAndNumericTokens(t *testing.T) {
	for _, input := range []updateDocumentInput{
		{},
		{Name: "Agreement � 💡"},
		{BlocksJSON: json.RawMessage(`{"version":1,"blocks":[{"id":"paragraph","type":"paragraph","text":"Literal � and emoji \uD83D\uDCA1","attrs":{"number":1e400,"tiny":1e-400,"literal":"\\u0000"}}]}`)},
		{VariablesJSON: json.RawMessage(`{"customer":"Literal � and emoji \uD83D\uDCA1","lines":"First\nSecond\tline","literal":"\\uD800"}`)},
	} {
		if err := validateDocumentUpdateStorage(input); err != nil {
			t.Fatalf("storage validation rejected exact Unicode or a numeric token: %v", err)
		}
	}
}

func TestValidateDocumentUpdateStorageRejectsUnstorableTextWithoutEchoingIt(t *testing.T) {
	for _, name := range []string{"private\x00name", string([]byte{0xff})} {
		if err := validateDocumentUpdateStorage(updateDocumentInput{Name: name}); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("unsafe name validation error=%v", err)
		}
	}
	for _, raw := range []string{
		`{"private":"bad\u0000value"}`,
		`{"private\u0000key":"value"}`,
		`{"nested":{"attrs":{"label":"private\u0000label"}}}`,
		`{"nested":[{"private\u0000key":"value"}]}`,
		`{"private":"\uD800"}`,
		`{"private":"\uDFFF"}`,
		`{"private":"\uD800\u0041"}`,
		`{"\uD800":"private"}`,
		"{\"private\":\"\xff\"}",
		`{"private":"first","private":"last"}`,
		`{"nested":{"private":"first","private":"last"}}`,
		`{"private":"first"}{"other":"last"}`,
		`[]`,
		`{"private":`,
	} {
		for _, field := range []string{"blocks", "variables"} {
			t.Run(field, func(t *testing.T) {
				input := updateDocumentInput{}
				if field == "blocks" {
					input.BlocksJSON = json.RawMessage(raw)
				} else {
					input.VariablesJSON = json.RawMessage(raw)
				}
				if err := validateDocumentUpdateStorage(input); err == nil || strings.Contains(err.Error(), "private") {
					t.Fatalf("unsafe document JSON validation error=%v", err)
				}
			})
		}
	}
}
