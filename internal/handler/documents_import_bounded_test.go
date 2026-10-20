// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/google/uuid"
)

type boundedImportTransportV1 struct{ calls int }

func (p *boundedImportTransportV1) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls++
	return nil, errors.New("oversized import must not reach renderer")
}
func TestDesignedImportExpandedSizeReturns413BeforeRendererV1(t *testing.T) {
	if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
		t.Fatal(err)
	}
	defer malwarescan.Configure(context.Background(), "", "development")
	source := "<img src=\"/secret\" alt=\"" + strings.Repeat("&", render.MaxDesignedHTMLBytes/4) + "\">"
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(importProposalInput{Name: "bounded import", HTML: source}); err != nil {
		t.Fatal(err)
	}
	if body.Len() >= maxProposalHTML {
		t.Fatal("fixture must pass original JSON bound")
	}
	transport := &boundedImportTransportV1{}
	pdf := render.NewGotenberg("http://renderer.invalid")
	pdf.HTTP = &http.Client{Transport: transport}
	server := &Server{Sign: &sign.Engine{PDF: pdf}}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/documents/import", &body)
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.importDocumentFromHTML(response, req, uuid.New(), uuid.New())
	if response.Code != http.StatusRequestEntityTooLarge || transport.calls != 0 || !strings.Contains(response.Body.String(), render.ErrDesignedHTMLTooLarge.Error()) {
		t.Fatalf("expanded input: status=%d calls=%d response=%q", response.Code, transport.calls, response.Body.String())
	}
}

func TestDesignedImportKnownJSONLimitBeforeBodyReadV1(t *testing.T) {
	body := &unreadImportBody{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/documents/import", nil)
	req.Body = body
	req.ContentLength = maxProposalHTML + 1
	response := httptest.NewRecorder()
	server := &Server{Sign: &sign.Engine{PDF: render.NewGotenberg("http://renderer.invalid")}}
	server.importDocumentFromHTML(response, req, uuid.New(), uuid.New())
	if response.Code != http.StatusRequestEntityTooLarge || body.reads != 0 {
		t.Fatalf("known oversizedJSON: %d reads=%d", response.Code, body.reads)
	}
}

type boundedJSONImportBodyV1 struct {
	io.Reader
	read int
}

func (b *boundedJSONImportBodyV1) Read(p []byte) (int, error) {
	n, e := b.Reader.Read(p)
	b.read += n
	return n, e
}
func (*boundedJSONImportBodyV1) Close() error { return nil }
func TestDesignedImportUnknownJSONLimitV1(t *testing.T) {
	input := "{\"name\":\"limit\",\"html\":\"" + strings.Repeat("x", maxProposalHTML) + "\"}"
	body := &boundedJSONImportBodyV1{Reader: strings.NewReader(input)}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/documents/import", nil)
	req.Body = body
	req.ContentLength = -1
	response := httptest.NewRecorder()
	server := &Server{Sign: &sign.Engine{PDF: render.NewGotenberg("http://renderer.invalid")}}
	server.importDocumentFromHTML(response, req, uuid.New(), uuid.New())
	if response.Code != http.StatusRequestEntityTooLarge || body.read != maxProposalHTML+1 {
		t.Fatalf("unknown oversizedJSON: status=%d read=%d", response.Code, body.read)
	}
}

func TestDesignedImportTrailingJSONRejectedBeforeDispatchV1(t *testing.T) {
	for _, tc := range []struct {
		name, tail string
		status     int
	}{
		{"oversized trailing whitespace", strings.Repeat(" ", maxProposalHTML), http.StatusRequestEntityTooLarge},
		{"second JSON value", "{}", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prefix := "{\"name\":\"bounded\",\"html\":\"<p>safe</p>\"}"
			body := &boundedJSONImportBodyV1{Reader: io.MultiReader(strings.NewReader(prefix), strings.NewReader(tc.tail))}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/documents/import", nil)
			req.Body = body
			req.ContentLength = -1
			response := httptest.NewRecorder()
			transport := &boundedImportTransportV1{}
			pdf := render.NewGotenberg("http://renderer.invalid")
			pdf.HTTP = &http.Client{Transport: transport}
			(&Server{Sign: &sign.Engine{PDF: pdf}}).importDocumentFromHTML(response, req, uuid.New(), uuid.New())
			if response.Code != tc.status || transport.calls != 0 || body.read > maxProposalHTML+1 {
				t.Fatalf("trailing input: status=%d calls=%d read=%d", response.Code, transport.calls, body.read)
			}
		})
	}
}
