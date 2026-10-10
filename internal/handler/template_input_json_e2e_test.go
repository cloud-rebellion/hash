//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// Exercise the authenticated route and exact persisted state: ambiguous outer
// JSON must not clear a reviewed layout or record a misleading template update.
func TestTemplatePATCHRejectsAmbiguousOuterLayoutJSONE2E(t *testing.T) {
	layout := string(layoutFixtureJSONE2E())
	for _, test := range []struct {
		name string
		body string
	}{
		{"duplicate fields", `{"fields_json":` + layout + `,"fields_json":[]}`},
		{"case alias", `{"fields_json":` + layout + `,"FIELDS_JSON":[]}`},
		{"noncanonical case", `{"FIELDS_JSON":[]}`},
		{"second JSON value", `{"fields_json":[]} {"fields_json":` + layout + `}`},
		{"trailing invalid bytes", `{"fields_json":[]} trailing`},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, template := setupNamedPDFLayoutE2E(t)
			before := templateMutationSnapshotE2E(t, f)
			cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
			response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), test.body, cookie)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("ambiguous layout PATCH=%d, want400: %s", response.Code, response.Body.String())
			}
			if templateMutationSnapshotE2E(t, f) != before {
				t.Fatal("refused outer JSON changed templates, audit, documents or outbox")
			}
		})
	}
}

func TestTemplatePATCHStrictJSONPreservesLayoutUpdatesAndDefaultsE2E(t *testing.T) {
	f, template := setupNamedPDFLayoutE2E(t)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	layout := bytes.Replace(layoutFixtureJSONE2E(), []byte(`"label":"Provider"`), []byte(`"label":"Service provider"`), 1)
	for _, body := range []string{`{"fields_json":` + string(layout) + `}`, `{}`} {
		response := submitSessionOperationE2E(f.s, http.MethodPatch, "/api/v1/templates/"+template.ID.String(), body, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("canonical layout PATCH=%d: %s", response.Code, response.Body.String())
		}
		stored, err := f.q.GetTemplate(f.ctx, generated.GetTemplateParams{ID: template.ID, OrgID: f.org})
		if err != nil {
			t.Fatal(err)
		}
		var got, want any
		if err := json.Unmarshal(stored.FieldsJson, &got); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(layout, &want); err != nil {
			t.Fatal(err)
		}
		gotJSON, _ := json.Marshal(got)
		wantJSON, _ := json.Marshal(want)
		if !bytes.Equal(gotJSON, wantJSON) || stored.Version != template.Version+1 || stored.Name != template.Name ||
			stored.PdfStorageKey != template.PdfStorageKey || stored.PdfStorageVersionID != template.PdfStorageVersionID ||
			!bytes.Equal(stored.PdfSha256, template.PdfSha256) || !bytes.Equal(stored.VariablesJson, template.VariablesJson) {
			t.Fatal("strict PATCH lost the reviewed layout, revision increment or omitted defaults/source pins")
		}
		template = stored
	}
}
