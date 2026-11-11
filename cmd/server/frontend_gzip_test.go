// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGzipAssets(t *testing.T) {
	body := strings.Repeat("export const worker = 1;\n", 400)
	g := newGzipAssets(fstest.MapFS{
		"w.mjs":   {Data: []byte(body)},
		"tiny.js": {Data: []byte("x")},
		"a.woff2": {Data: []byte(body)},
	})
	do := func(method, name, accept, rng string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/"+name, nil)
		if accept != "" {
			r.Header.Set("Accept-Encoding", accept)
		}
		if rng != "" {
			r.Header.Set("Range", rng)
		}
		w := httptest.NewRecorder()
		g.serve(w, r, name)
		return w
	}

	w := do(http.MethodGet, "w.mjs", "br, gzip;q=0.8", "")
	if w.Header().Get("Content-Encoding") != "gzip" || w.Header().Get("Vary") != "Accept-Encoding" {
		t.Fatalf("headers = %v", w.Header())
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("content type = %q", w.Header().Get("Content-Type"))
	}
	zr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(zr)
	if string(got) != body || w.Body.Len() >= len(body) {
		t.Fatalf("round trip failed: %d -> %d", len(body), w.Body.Len())
	}
	if h := do(http.MethodHead, "w.mjs", "gzip", ""); h.Body.Len() != 0 || h.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("HEAD must carry headers only: %v", h.Header())
	}
	for name, c := range map[string]*httptest.ResponseRecorder{
		"no accept":         do(http.MethodGet, "w.mjs", "", ""),
		"gzip refused":      do(http.MethodGet, "w.mjs", "gzip;q=0", ""),
		"refused, odd case": do(http.MethodGet, "w.mjs", "gzip;Q=0.", ""),
		"range":             do(http.MethodGet, "w.mjs", "gzip", "bytes=0-9"),
		"tiny":              do(http.MethodGet, "tiny.js", "gzip", ""),
	} {
		if c.Header().Get("Content-Encoding") != "" || c.Body.Len() != 0 {
			t.Fatalf("%s must fall through to the stored file", name)
		}
		if c.Header().Get("Vary") != "Accept-Encoding" {
			t.Fatalf("%s must still vary on Accept-Encoding", name)
		}
	}
	if f := do(http.MethodGet, "a.woff2", "gzip", ""); f.Header().Get("Content-Encoding") != "" || f.Header().Get("Vary") != "" {
		t.Fatalf("already-compressed assets must be untouched: %v", f.Header())
	}
}

func TestFrontendHandlerKeepsIndexRedirectAndSkipsMapEncoding(t *testing.T) {
	body := strings.Repeat("<html>shell</html>\n", 400)
	h := frontendHandlerFS(fstest.MapFS{
		"index.html":    {Data: []byte(body)},
		"_app/x.js.map": {Data: []byte(strings.Repeat("{\"mappings\":\"AAAA\"}", 400))},
	})
	for _, accept := range []string{"", "gzip"} {
		r := httptest.NewRequest(http.MethodGet, "/index.html", nil)
		if accept != "" {
			r.Header.Set("Accept-Encoding", accept)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusMovedPermanently || w.Header().Get("Content-Encoding") != "" {
			t.Fatalf("Accept-Encoding %q: /index.html = %d %v", accept, w.Code, w.Header())
		}
		m := httptest.NewRequest(http.MethodGet, "/_app/x.js.map", nil)
		if accept != "" {
			m.Header.Set("Accept-Encoding", accept)
		}
		mw := httptest.NewRecorder()
		h.ServeHTTP(mw, m)
		if mw.Code != http.StatusOK || mw.Header().Get("Content-Encoding") != "" {
			t.Fatalf("Accept-Encoding %q: .map = %d %v", accept, mw.Code, mw.Header())
		}
	}
	if compressibleAsset("x.js.map") {
		t.Fatal(".map files must be served as stored")
	}
}
