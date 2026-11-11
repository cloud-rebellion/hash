// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/google/uuid"
)

type pdfRevisionBridgeFake struct {
	replace  *PDFReplaceInputV1
	review   *PDFReviewInputV1
	history  int
	actor    DesignActorV1
	document uuid.UUID
}

func (f *pdfRevisionBridgeFake) ReplacePDFV1(_ context.Context, a DesignActorV1, id uuid.UUID, in PDFReplaceInputV1) (any, error) {
	f.replace, f.actor, f.document = &in, a, id
	return map[string]any{"revision": 1}, nil
}
func (f *pdfRevisionBridgeFake) PDFHistoryV1(_ context.Context, a DesignActorV1, id uuid.UUID) (any, error) {
	f.history, f.actor, f.document = f.history+1, a, id
	return map[string]any{"revisions": []any{}}, nil
}
func (f *pdfRevisionBridgeFake) ReviewPDFV1(_ context.Context, a DesignActorV1, id uuid.UUID, in PDFReviewInputV1) (any, error) {
	f.review, f.actor, f.document = &in, a, id
	return map[string]any{"reviewer_kind": "agent"}, nil
}

func pdfRevisionTransportV1(t *testing.T) (*Server, *serviceEmailCredentialFixture, *pdfRevisionBridgeFake) {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &serviceEmailCredentialFixture{key: key, id: uuid.New(), user: uuid.New(), org: uuid.New(), role: "owner", scopes: []string{"read", "write:authoring"}}
	f := &pdfRevisionBridgeFake{}
	s := NewServer()
	registerPDFRevisionToolsV1(s, Deps{PDFRevisions: f})
	return s, v, f
}

const pdfRevisionPinsJSONV1 = `"expected_updated_at":"2026-11-07T10:00:00.123456Z","expected_pdf_sha256":"` +
	"0000000000000000000000000000000000000000000000000000000000000000" + `"`

func TestPDFRevisionToolSchemasAndScopesV1(t *testing.T) {
	s, _, _ := pdfRevisionTransportV1(t)
	want := map[string]struct {
		scope    string
		required []string
	}{
		"replace_document_pdf":     {mcpScopeWriteAuthoring, []string{"document_id", "expected_updated_at", "expected_pdf_sha256", "pdf_base64"}},
		"review_document_pdf":      {mcpScopeWriteAuthoring, []string{"document_id", "expected_updated_at", "expected_pdf_sha256", "visually_reviewed", "reviewed_pages"}},
		"get_document_pdf_history": {mcpScopeRead, []string{"document_id"}},
	}
	for name, expect := range want {
		tool, ok := s.tools[name]
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatalf("%s accepts unknown arguments", name)
		}
		required, _ := tool.InputSchema["required"].([]string)
		if strings.Join(required, ",") != strings.Join(expect.required, ",") {
			t.Fatalf("%s required=%v", name, required)
		}
		if got := mcpToolRequiredScopes[name]; got != expect.scope {
			t.Fatalf("%s scope=%q want %q", name, got, expect.scope)
		}
		if !docScopeSafeTools[name] {
			t.Fatalf("%s must be allowed for a per-document token (it enforces the document scope)", name)
		}
		if tool.Write != (expect.scope == mcpScopeWriteAuthoring) {
			t.Fatalf("%s Write flag disagrees with its scope", name)
		}
	}
}

func TestPDFRevisionToolsDelegateOriginalPinsV1(t *testing.T) {
	s, v, f := pdfRevisionTransportV1(t)
	id := uuid.New()
	pdf := base64.StdEncoding.EncodeToString([]byte("%PDF-1.7 synthetic"))
	resp := serviceEmailCall(t, s, v, "replace_document_pdf", `{"document_id":"`+id.String()+`",`+pdfRevisionPinsJSONV1+`,"pdf_base64":"`+pdf+`","summary":"new cover"}`)
	if resp.Error != nil || decodedToolResult(t, resp).IsError {
		t.Fatalf("replace refused: %v", resp)
	}
	if f.replace == nil || f.replace.Summary != "new cover" || string(f.replace.PDF) != "%PDF-1.7 synthetic" || f.replace.ExpectedUpdatedAt != "2026-11-07T10:00:00.123456Z" ||
		f.actor.KeyID != v.id || f.actor.UserID != v.user || f.actor.OrgID != v.org || f.actor.Authorize == nil || f.document != id {
		t.Fatal("replace lost the original actor, document or pins", f)
	}
	resp = serviceEmailCall(t, s, v, "get_document_pdf_history", `{"document_id":"`+id.String()+`"}`)
	if resp.Error != nil || decodedToolResult(t, resp).IsError || f.history != 1 {
		t.Fatal("history not delegated")
	}
	resp = serviceEmailCall(t, s, v, "review_document_pdf", `{"document_id":"`+id.String()+`",`+pdfRevisionPinsJSONV1+`,"visually_reviewed":true,"reviewed_pages":[1,2]}`)
	if resp.Error != nil || decodedToolResult(t, resp).IsError || f.review == nil || len(f.review.ReviewedPages) != 2 {
		t.Fatal("review not delegated")
	}
}

func TestPDFRevisionToolsRefuseBadInputV1(t *testing.T) {
	s, v, f := pdfRevisionTransportV1(t)
	id := uuid.New().String()
	good := base64.StdEncoding.EncodeToString([]byte("%PDF-1.7"))
	cases := map[string]struct{ tool, args string }{
		"not base64":          {"replace_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"pdf_base64":"***"}`},
		"empty pdf":           {"replace_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"pdf_base64":""}`},
		"oversize":            {"replace_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"pdf_base64":"` + strings.Repeat("A", maxPDFRevisionBase64V1+1) + `"}`},
		"unknown argument":    {"replace_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"pdf_base64":"` + good + `","reviewer":"human"}`},
		"bad document":        {"replace_document_pdf", `{"document_id":"nope",` + pdfRevisionPinsJSONV1 + `,"pdf_base64":"` + good + `"}`},
		"review not attested": {"review_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"visually_reviewed":false,"reviewed_pages":[1]}`},
		"review unknown key":  {"review_document_pdf", `{"document_id":"` + id + `",` + pdfRevisionPinsJSONV1 + `,"visually_reviewed":true,"reviewed_pages":[1],"reviewer_kind":"human"}`},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			resp := serviceEmailCall(t, s, v, c.tool, c.args)
			if resp.Error == nil && !decodedToolResult(t, resp).IsError {
				t.Fatal("accepted")
			}
		})
	}
	if f.replace != nil || f.review != nil {
		t.Fatal("a refused call reached the bridge")
	}
}
