// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type fakeDoer struct {
	resp *http.Response
	err  error
	last *http.Request
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) {
	f.last = req
	return f.resp, f.err
}

func mkResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

func TestHTTPSource_NotConfigured(t *testing.T) {
	src := NewCRMDealSource("", "")
	_, err := src.Fetch(context.Background(), Ref{Source: "deal_1"})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestHTTPSource_HappyPath(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(200, `{"deal":{"amount":42000,"name":"Acme MSA"}}`)}
	src := NewCRMDealSource("https://crm.test", "tok-abc")
	src.Client = doer

	val, err := src.Fetch(context.Background(), Ref{
		Source: "deal_1",
		Path:   "deal.amount",
	})
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if val != "42000" {
		t.Fatalf("want 42000, got %q", val)
	}
	if got := doer.last.URL.Path; got != "/api/v1/deals/deal_1" {
		t.Fatalf("wrong url path %q", got)
	}
	if got := doer.last.Header.Get("Authorization"); got != "Bearer tok-abc" {
		t.Fatalf("wrong auth header %q", got)
	}
}

func TestHTTPSource_RejectsPathAndQueryInjectionBeforeSendingBearerToken(t *testing.T) {
	for _, sourceRef := range []string{
		"../admin",
		"deal_1?include=secrets",
		"deal_1#fragment",
		"deal_1%2fadmin",
		"deal_1\\admin",
		strings.Repeat("a", 257),
	} {
		t.Run(sourceRef, func(t *testing.T) {
			doer := &fakeDoer{resp: mkResp(200, `{}`)}
			src := NewCRMDealSource("https://crm.test", "tok-abc")
			src.Client = doer
			if _, err := src.Fetch(context.Background(), Ref{Source: sourceRef}); err == nil {
				t.Fatalf("unsafe source_ref %q was accepted", sourceRef)
			}
			if doer.last != nil {
				t.Fatalf("request was sent for unsafe source_ref %q", sourceRef)
			}
		})
	}
}

func TestHTTPSource_404IsErrNotFound(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(404, `{}`)}
	src := NewCRMContactSource("https://crm.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "contact_x", Path: "name"})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound, got %v", err)
	}
}

func TestHTTPSource_PathMissing(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(200, `{"deal":{"name":"x"}}`)}
	src := NewCRMDealSource("https://crm.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: "deal.amount"})
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("want path-not-found error, got %v", err)
	}
}

func TestHTTPSource_ServerError(t *testing.T) {
	doer := &fakeDoer{resp: mkResp(500, "boom")}
	src := NewScannerFindingSource("https://svar.test", "tok")
	src.Client = doer

	_, err := src.Fetch(context.Background(), Ref{Source: "scan_1", Path: "summary.critical_count"})
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("want 5xx error, got %v", err)
	}
}

func TestJSONPathLookup_NestedAndArray(t *testing.T) {
	root := map[string]any{
		"deal": map[string]any{
			"amount": float64(42),
			"items": []any{
				map[string]any{"sku": "A"},
				map[string]any{"sku": "B"},
			},
		},
	}
	cases := []struct {
		path string
		want string
		ok   bool
	}{
		{"deal.amount", "42", true},
		{"deal.items.1.sku", "B", true},
		{"deal.items.5.sku", "", false},
		{"missing", "", false},
		{"", "", true}, // empty path returns root
	}
	for _, c := range cases {
		got, ok := jsonPathLookup(root, c.path)
		if ok != c.ok {
			t.Errorf("path %q: ok=%v want %v", c.path, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		if c.path == "" {
			continue // root is a map, can't compare to want
		}
		s, _ := stringify(got)
		if s != c.want {
			t.Errorf("path %q: got %q want %q", c.path, s, c.want)
		}
	}
}

func TestStringify(t *testing.T) {
	cases := []struct {
		in   any
		want string
		ok   bool
	}{
		{"hello", "hello", true},
		{float64(42), "42", true},
		{float64(3.14), "3.14", true},
		{true, "true", true},
		{false, "false", true},
		{nil, "", false},
		{map[string]any{"a": 1}, `{"a":1}`, true},
	}
	for _, c := range cases {
		got, ok := stringify(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("stringify(%v): got (%q,%v) want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestHTTPSourceRejectsOversizedValidJSONPrefix(t *testing.T) {
	prefix := `{"name":"Proposal"}`
	for _, size := range []int{maxSourceResponseBytes, maxSourceResponseBytes + 1} {
		src := NewCRMDealSource("https://crm.example.test", "test-token")
		src.Client = &fakeDoer{resp: mkResp(200, prefix+strings.Repeat(" ", size-len(prefix)))}
		got, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: "name"})
		if size == maxSourceResponseBytes {
			if err != nil || got != "Proposal" {
				t.Fatalf("boundary response rejected: %q %v", got, err)
			}
		} else if err == nil || got != "" {
			t.Fatal("truncated oversized response accepted")
		}
	}
}

func TestHTTPSourceRefusesUnsuccessfulJSONAndRedactsBody(t *testing.T) {
	for _, status := range []int{199, 301, 302, 307, 401, 500} {
		src := NewCRMDealSource("https://crm.example.test", "test-token")
		src.Client = &fakeDoer{resp: mkResp(status, `{"name":"private-upstream-diagnostic"}`)}
		value, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: "name"})
		if err == nil || value != "" {
			t.Fatalf("status%d trusted", status)
		}
		if strings.Contains(err.Error(), "private-upstream-diagnostic") {
			t.Fatal("upstream error body exposed")
		}
	}
}

func TestHTTPSourceRejectsAmbiguousContractValues(t *testing.T) {
	cases := []string{
		`{"amount":"one","amount":"two"}`,
		`{"amount":"one","\u0061mount":"two"}`,
		`{"deal":{"amount":"one","amount":"two"}}`,
		`{"amount":"ok","history":[{"name":"a","name":"b"}]}`,
		"{\"amount\":\"bad\xff\"}",
		`null`, `[]`, `{"amount":"one"} {"amount":"two"}`,
		`{"amount":"ok","nested":` + strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66) + "}",
	}
	for _, raw := range cases {
		src := NewCRMDealSource("https://crm.test", "token")
		src.Client = &fakeDoer{resp: mkResp(200, raw)}
		value, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: "amount"})
		if err == nil || value != "" {
			t.Fatalf("ambiguous response accepted: value=%q err=%v", value, err)
		}
		if strings.Contains(err.Error(), "one") || strings.Contains(err.Error(), "bad") {
			t.Fatalf("upstream text leaked: %v", err)
		}
	}
}

func TestCRMArrayPathOverflowCannotSelectAnotherRecord(t *testing.T) {
	for _, path := range []string{
		"items.18446744073709551616.name", // wraps to zero under 64-bit unchecked arithmetic
		"items.18446744073709551617.name",
		"items.4294967296.name", // overflow on 32-bit; out of bounds on 64-bit
		"items." + strings.Repeat("9", 256) + ".name",
	} {
		src := NewCRMDealSource("https://crm.test", "token")
		src.Client = &fakeDoer{resp: mkResp(200, `{"items":[{"name":"wrong-customer"},{"name":"other-customer"}]}`)}
		value, err := src.Fetch(context.Background(), Ref{Source: "deal_1", Path: path})
		if err == nil || value != "" {
			t.Fatalf("overflow path selected CRM record: value=%q err=%v", value, err)
		}
	}
}

func TestConcurrentFetchDoesNotMutateClientConfiguration(t *testing.T) {
	source := &HTTPSource{BaseURL: "://invalid", Token: "test", kind: SourceCRMDeal, pathFor: func(Ref) string { return "/deal" }}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Invalid URL stops before network I/O, after client selection.
			if _, err := source.Fetch(context.Background(), Ref{Source: "deal_1"}); err == nil {
				t.Error("invalid URL accepted")
			}
		}()
	}
	wg.Wait()
	if source.Client != nil {
		t.Fatal("Fetch mutated shared source configuration")
	}
}
