// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

type multipartLimitRoundTripperV1 func(*http.Request) (*http.Response, error)

func (f multipartLimitRoundTripperV1) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func multipartLimitClientV1(t *testing.T, inspect func(*http.Request)) *Gotenberg {
	t.Helper()
	g := NewGotenberg("http://renderer.invalid")
	g.HTTP = &http.Client{Transport: multipartLimitRoundTripperV1(func(r *http.Request) (*http.Response, error) {
		defer r.Body.Close()
		inspect(r)
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("%PDF-1.7\nunit transport fixture"))}, nil
	})}
	return g
}

func TestHTMLMultipartExactEncodedBoundaryV1(t *testing.T) {
	var lengths []int64
	g := multipartLimitClientV1(t, func(r *http.Request) {
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil || n != r.ContentLength {
			t.Fatalf("frozen request length=%d declared=%d err=%v", n, r.ContentLength, err)
		}
		lengths = append(lengths, n)
	})
	opts := PDFOptions{Assets: []FontAsset{}}
	if _, err := g.HTMLToPDF(context.Background(), "x", opts); err != nil {
		t.Fatal(err)
	}
	overhead := int(lengths[0]) - 1
	exact := strings.Repeat("x", MaxHTMLMultipartBytes-overhead)
	if _, err := g.HTMLToPDF(context.Background(), exact, opts); err != nil {
		t.Fatal("exact body cap refused", err)
	}
	if lengths[1] != MaxHTMLMultipartBytes {
		t.Fatalf("exact body=%d", lengths[1])
	}
	before := len(lengths)
	if out, err := g.HTMLToPDF(context.Background(), exact+"x", opts); !errors.Is(err, ErrHTMLMultipartTooLarge) || len(out) != 0 || len(lengths) != before {
		t.Fatalf("cap+1 dispatched or wrong refusal: calls=%d output=%d err=%v", len(lengths), len(out), err)
	}
}
func TestHTMLMultipartClosingBoundaryIsChargedV1(t *testing.T) {
	b := &htmlMultipartBuffer{}
	mw := multipart.NewWriter(b)
	boundary := strings.Repeat("b", 60)
	if err := mw.SetBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	part, err := mw.CreateFormField("x")
	if err != nil {
		t.Fatal(err)
	}
	closing := len("\r\n--" + boundary + "--\r\n")
	payload := MaxHTMLMultipartBytes - b.Len() - closing + 1
	if _, err := part.Write(make([]byte, payload)); err != nil {
		t.Fatal(err)
	}
	before := b.Len()
	if err := mw.Close(); !errors.Is(err, ErrHTMLMultipartTooLarge) || b.Len() != before {
		t.Fatalf("closing boundary not atomic: %d/%d %v", before, b.Len(), err)
	}
	if n, err := b.Write([]byte("later")); n != 0 || !errors.Is(err, ErrHTMLMultipartTooLarge) || b.Len() != before {
		t.Fatal("overflow did not stay failed")
	}
}
func TestHTMLMultipartMetadataAndCombinedPreflightV1(t *testing.T) {
	calls := 0
	g := multipartLimitClientV1(t, func(r *http.Request) { calls++; io.Copy(io.Discard, r.Body) })
	huge := strings.Repeat("x", MaxHTMLMultipartBytes+1)
	tests := []struct {
		name, html string
		opts       PDFOptions
	}{
		{"HTML", huge, PDFOptions{}},
		{"filename", "x", PDFOptions{Assets: []FontAsset{{Filename: huge}}}},
		{"MIME", "x", PDFOptions{Assets: []FontAsset{{Mime: huge}}}},
		{"expression", "x", PDFOptions{WaitForExpression: huge}},
		{"delay", "x", PDFOptions{WaitDelay: huge}},
		{"combined", strings.Repeat("x", 20<<20), PDFOptions{Assets: []FontAsset{{Filename: "a", Bytes: make([]byte, 5<<20)}}}},
		{"empty attachment flood", "x", PDFOptions{Assets: make([]FontAsset, MaxHTMLMultipartBytes/64+1)}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := g.HTMLToPDF(context.Background(), tc.html, tc.opts); !errors.Is(err, ErrHTMLMultipartTooLarge) || out != nil || calls != 0 {
				t.Fatalf("preflight: calls=%d err=%v", calls, err)
			}
		})
	}
}
func TestHTMLMultipartApprovedMasterAndAssetsV1(t *testing.T) {
	for _, tc := range []struct {
		name      string
		assets    []FontAsset
		wantFiles int
	}{
		{"default", nil, 8}, {"explicit empty", []FontAsset{}, 1},
		{"custom", []FontAsset{{Filename: "custom.woff2", Bytes: []byte("font")}}, 2},
		{"many empty", make([]FontAsset, 128), 129},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := "<p>bound</p>"
			if tc.name == "default" {
				source = strings.Repeat("x", 16<<20)
			}
			seen := false
			g := multipartLimitClientV1(t, func(r *http.Request) {
				seen = true
				_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
				if err != nil {
					t.Fatal(err)
				}
				reader := multipart.NewReader(r.Body, params["boundary"])
				files, sourceBytes := 0, int64(0)
				for {
					part, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Fatal(err)
					}
					n, err := io.Copy(io.Discard, part)
					if err != nil {
						t.Fatal(err)
					}
					if part.FormName() == "files" {
						files++
						if part.FileName() == "index.html" {
							sourceBytes = n
						}
					}
				}
				if files != tc.wantFiles || sourceBytes != int64(len(source)) {
					t.Fatalf("files=%d source=%d", files, sourceBytes)
				}
				if r.ContentLength > MaxHTMLMultipartBytes {
					t.Fatal("oversized accepted body")
				}
			})
			if _, err := g.HTMLToPDF(context.Background(), source, PDFOptions{Assets: tc.assets}); err != nil || !seen {
				t.Fatal(err)
			}
		})
	}
}
func TestHTMLMultipartCanceledPreflightV1(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := validateHTMLMultipartSize(ctx, "x", PDFOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
