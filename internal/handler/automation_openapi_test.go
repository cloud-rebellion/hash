// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// Prevent published client contracts from quietly losing or inventing fields
// as request/response types change. Optionality in requests is explicit since
// Go zero-value fields need not carry omitempty to be accepted as omitted.
func TestAutomationOpenAPIWireFields(t *testing.T) {
	raw, err := os.ReadFile("../../docs/openapi-automation.json")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]json.RawMessage `json:"properties"`
				Required   []string                   `json:"required"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		schema   string
		value    any
		required string
	}{
		{"SignatureRequest", automationSignatureRequestInput{}, "template_id,template_version,template_content_sha256,name,recipients,lawful_basis"},
		{"Recipient", automationSignatureRecipientInput{}, "email,name"},
		{"SignatureRequestResult", automationSignatureRequestResponse{}, "automation_request_id,document_id,status,replayed"},
		{"PreparedDocumentSend", sendDocumentInput{}, "lawful_basis"},
		{"PreparedDocumentSendResult", automationDocumentSendResponse{}, "document_id,status"},
		{"PackageSendObservation", packageSendInputV1{}, "expected_updated_at,package_id,generation"},
		{"PackageSendOutcome", packageSendResponseV1{}, "attempt_id,outcome,reconciliation_required"},
	}
	for _, c := range cases {
		schema, ok := spec.Components.Schemas[c.schema]
		if !ok {
			t.Fatalf("missing schema %s", c.schema)
		}
		typ := reflect.TypeOf(c.value)
		if len(schema.Properties) != typ.NumField() {
			t.Errorf("%s property count differs from wire type", c.schema)
		}
		for i := 0; i < typ.NumField(); i++ {
			field := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
			if _, ok := schema.Properties[field]; !ok {
				t.Errorf("%s lacks %s", c.schema, field)
			}
		}
		want := strings.Split(c.required, ",")
		got := map[string]bool{}
		for _, field := range schema.Required {
			got[field] = true
		}
		if len(got) != len(want) {
			t.Errorf("%s required fields differ", c.schema)
		}
		for _, field := range want {
			if !got[field] {
				t.Errorf("%s does not require %s", c.schema, field)
			}
		}
	}
}
