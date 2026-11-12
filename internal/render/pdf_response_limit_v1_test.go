// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package render

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type pdfLimitRoundTripV1 func(*http.Request) (*http.Response, error)

func (f pdfLimitRoundTripV1) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type pdfLimitStreamV1 struct {
	remaining, read int
	closed          bool
}

func (b *pdfLimitStreamV1) Read(p []byte) (int, error) {
	if b.remaining == 0 {
		return 0, io.EOF
	}
	n := min(len(p), b.remaining)
	clear(p[:n])
	b.remaining -= n
	b.read += n
	return n, nil
}
func (b *pdfLimitStreamV1) Close() error { b.closed = true; return nil }

func TestHTMLToPDFResponseLimitIsTypedBoundedAndKeepsLegacyTextV1(t *testing.T) {
	const limit = 32
	for _, size := range []int{limit, limit + 1, limit + 1024} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			stream := &pdfLimitStreamV1{remaining: size}
			calls := 0
			g := NewGotenberg("https://renderer.invalid")
			g.HTTP.Transport = pdfLimitRoundTripV1(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.Method != http.MethodPost || r.URL.String() != "https://renderer.invalid/forms/chromium/convert/html" {
					t.Fatal("unexpected renderer request")
				}
				return &http.Response{StatusCode: http.StatusOK, Body: stream, Header: make(http.Header)}, nil
			})
			pdf, err := g.HTMLToPDF(context.Background(), "<p>Synthetic</p>", PDFOptions{MaxResponseBytes: limit})
			if size == limit {
				if err != nil || len(pdf) != limit {
					t.Fatal("exact byte boundary was refused")
				}
			} else if !errors.Is(err, ErrPDFResponseTooLarge) || len(pdf) != 0 || err.Error() != "gotenberg render exceeded the 32-byte limit" {
				t.Fatal("typed byte limit or exact legacy error text changed")
			}
			if calls != 1 || stream.read != min(size, limit+1) || !stream.closed {
				t.Fatal("renderer cap retried, over-read or leaked its response")
			}
		})
	}
	t.Run("other-transport-error-is-not-size", func(t *testing.T) {
		g := NewGotenberg("https://renderer.invalid")
		g.HTTP.Transport = pdfLimitRoundTripV1(func(*http.Request) (*http.Response, error) {
			return nil, context.Canceled
		})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := g.HTMLToPDF(ctx, "<p>Synthetic</p>", PDFOptions{MaxResponseBytes: limit})
		if err == nil || errors.Is(err, ErrPDFResponseTooLarge) {
			t.Fatal("unrelated cancellation became a size refusal")
		}
	})
}
