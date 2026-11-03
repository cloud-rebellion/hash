// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package documentpurpose

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestPurposeStrictMetadataV1(t *testing.T) {
	for _, raw := range []string{"", `{}`, `{"customer_id":"external","purpose":"unrelated"}`} {
		t.Run("legacy/"+raw, func(t *testing.T) {
			p, err := Parse([]byte(raw))
			if err != nil || p != Signing {
				t.Fatalf("%q %v", p, err)
			}
		})
	}
	for _, p := range []Purpose{Document, Presentation, Signing} {
		t.Run(string(p), func(t *testing.T) {
			raw, err := With([]byte(`{"external":{"number":9007199254740993,"array":[true,"å"]}}`), p)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(raw)
			if err != nil || got != p {
				t.Fatal(got, err)
			}
			var m map[string]json.RawMessage
			_ = json.Unmarshal(raw, &m)
			equal, err := EqualMetadata(m["external"], []byte(`{"number":9007199254740993,"array":[true,"å"]}`))
			if err != nil || !equal {
				t.Fatal("external metadata changed", err)
			}
			err = RequireSigning(raw)
			if (p == Signing) != (err == nil) {
				t.Fatal("workflow mode mismatch", p, err)
			}
		})
	}
	for _, raw := range []string{`null`, `[]`, `true`, `broken`, `{"hash:document-purpose:v1":null}`, `{"hash:document-purpose:v1":"document"}`, `{"hash:document-purpose:v1":{"schema_version":2,"purpose":"document"}}`, `{"hash:document-purpose:v1":{"schema_version":1,"purpose":"signature"}}`, `{"hash:document-purpose:v1":{"schema_version":1,"purpose":"signing","extra":true}}`, `{"hash:document-purpose:v1":{"schema_version":1}}`, `{"hash:document-purpose:v1":{"schema_version":1,"purpose":"document","purpose":"signing"}}`, `{"hash:document-purpose:v1":{},"hash\u003adocument-purpose:v1":{"schema_version":1,"purpose":"signing"}}`} {
		t.Run("invalid/"+raw, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
				t.Fatal("malformed purpose accepted", err)
			}
			if Response([]byte(raw)) != "" {
				t.Fatal("malformed purpose became signing")
			}
			if _, err := With([]byte(raw), Document); err == nil {
				t.Fatal("invalid stored state silently repaired")
			}
		})
	}
	if !IsReservedKey(MetadataKey) || IsReservedKey("customer_purpose") {
		t.Fatal("reserved key scope")
	}
	if _, err := With([]byte(`{}`), Purpose("signature")); err == nil {
		t.Fatal("unknown enum accepted")
	}
}
func TestPurposeMetadataNumericEqualityDoesNotLosePrecisionV1(t *testing.T) {
	same, err := EqualMetadata([]byte(`{"n":9007199254740992}`), []byte(`{"n":9007199254740993}`))
	if err != nil || same {
		t.Fatal("lossy numeric equality", same, err)
	}
}

func TestPurposeExplicitWireAndExactReservedKeysV1(t *testing.T) {
	for _, raw := range []string{`null`, `""`, `"signature"`, `false`, `{}`, `[]`} {
		var p Purpose
		if json.Unmarshal([]byte(raw), &p) == nil {
			t.Fatal("explicit invalid value accepted", raw)
		}
	}
	for _, raw := range []string{`{"hash:document-purpose:v1":{"Schema_Version":1,"purpose":"document"}}`, `{"hash:document-purpose:v1":{"schema_version":1,"Purpose":"document"}}`} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("non-exact reserved keys accepted", raw)
		}
	}
}
