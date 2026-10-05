// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// These are the registered transport handlers. Empty dependencies cannot do
// database I/O, and well-shaped inputs stop at the missing private credential
// receipt; malformed inputs must be refused before that authorization boundary.
func bindingArgumentTestServer() *Server {
	return New(Deps{Pool: &pgxpool.Pool{}, Audit: &audit.Logger{}, Resolver: resolver.New(nil)})
}

func TestBindingToolArgumentsRejectSuppliedNonStrings(t *testing.T) {
	s := bindingArgumentTestServer()
	for _, tool := range []struct{ name, ref string }{
		{"bind_variable_to_crm_deal", "deal_id"},
		{"bind_variable_to_crm_contact", "contact_id"},
		{"bind_variable_to_scanner_finding", "scan_id"},
		{"bind_variable_to_org_setting", ""},
	} {
		fields := []string{"variable", "path", "fallback"}
		if tool.ref != "" {
			fields = append(fields, tool.ref)
		}
		for _, field := range fields {
			for _, malformed := range []any{nil, true, 123, []string{"private"}, map[string]string{"private": "value"}} {
				t.Run(tool.name+"/"+field, func(t *testing.T) {
					args := map[string]any{"document_id": uuid.NewString(), "variable": "customer", "path": "name"}
					if tool.ref != "" {
						args[tool.ref] = "entity_1"
					}
					args[field] = malformed
					raw, err := json.Marshal(args)
					if err != nil {
						t.Fatal(err)
					}
					_, err = s.tools[tool.name].Handler(httptest.NewRequest(http.MethodPost, "/mcp", nil), raw)
					if err == nil || err.Error() != "binding arguments must be strings" {
						t.Fatalf("malformed binding argument reached credential validation or was silently truncated: %v", err)
					}
				})
			}
		}
	}
}

func TestBindingToolArgumentsPreserveOptionalFallbackAndOrgSettingShape(t *testing.T) {
	s := bindingArgumentTestServer()
	for _, tool := range []struct{ name, ref string }{
		{"bind_variable_to_crm_deal", "deal_id"},
		{"bind_variable_to_crm_contact", "contact_id"},
		{"bind_variable_to_scanner_finding", "scan_id"},
		{"bind_variable_to_org_setting", ""},
	} {
		for _, supplied := range []bool{false, true} {
			args := map[string]any{"document_id": uuid.NewString(), "variable": "customer", "path": "name"}
			if tool.ref != "" {
				args[tool.ref] = "entity_1"
			}
			if supplied {
				args["fallback"] = ""
			}
			raw, _ := json.Marshal(args)
			_, err := s.tools[tool.name].Handler(httptest.NewRequest(http.MethodPost, "/mcp", nil), raw)
			if !errors.Is(err, auth.ErrMutationPermissionRevoked) {
				t.Fatalf("valid %s optional fallback=%t did not reach original credential validation: %v", tool.name, supplied, err)
			}
		}
	}
	for _, field := range []string{"variable", "deal_id", "path"} {
		args := map[string]any{"document_id": uuid.NewString(), "variable": "customer", "deal_id": "entity_1", "path": "name"}
		delete(args, field)
		raw, _ := json.Marshal(args)
		_, err := s.tools["bind_variable_to_crm_deal"].Handler(httptest.NewRequest(http.MethodPost, "/mcp", nil), raw)
		if err == nil || err.Error() != field+" required" {
			t.Fatalf("missing required %s changed transport semantics: %v", field, err)
		}
	}
}
