// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
)

type boundedCreatePDFTransportV1 struct{ calls int }

func (p *boundedCreatePDFTransportV1) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls++
	return nil, errors.New("oversized import must not reach renderer")
}

// Direct registered-tool defense. The MCP HTTP transport's existing1MiB cap
// is narrower; this does not claim that an oversized HTTP message is accepted.
func TestCreatePDFDocumentBoundedSanitizerBeforeDispatchV1(t *testing.T) {
	if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
		t.Fatal(err)
	}
	defer malwarescan.Configure(context.Background(), "", "development")
	source := "<img src=\"/secret\" alt=\"" + strings.Repeat("&", render.MaxDesignedHTMLBytes/4) + "\">"
	var args bytes.Buffer
	enc := json.NewEncoder(&args)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]string{"name": "bounded import", "html": source}); err != nil {
		t.Fatal(err)
	}
	transport := &boundedCreatePDFTransportV1{}
	pdf := render.NewGotenberg("http://renderer.invalid")
	pdf.HTTP = &http.Client{Transport: transport}
	server := New(Deps{PDF: pdf})
	org := uuid.New()
	ctx := context.WithValue(context.Background(), auth.OrgIDKey, org)
	ctx = context.WithValue(ctx, auth.UserIDKey, uuid.New())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil).WithContext(ctx)
	result, err := server.tools["create_pdf_document"].Handler(req, args.Bytes())
	if !errors.Is(err, render.ErrDesignedHTMLTooLarge) || result != nil || transport.calls != 0 {
		t.Fatalf("expanded tool input: calls=%d result=%T err=%v", transport.calls, result, err)
	}
	release, err := importguard.Shared.Acquire(org)
	if err != nil {
		t.Fatal("size refusal leaked import admission", err)
	}
	release()
}
