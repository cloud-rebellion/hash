// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strconv"
	"strings"
	"sync"
)

// gzipMinBytes skips files where compression buys nothing.
const gzipMinBytes = 1024

// compressibleAsset reports whether a static asset is text-like. Fonts, images
// and other already-compressed formats are served as stored.
func compressibleAsset(name string) bool {
	switch path.Ext(name) {
	case ".js", ".mjs", ".css", ".json", ".svg", ".html", ".txt", ".wasm":
		return true
	}
	return false
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		token, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(token), "gzip") {
			continue
		}
		// A q-value of zero (any spelling: Q=0, q=0.0, q=0.) refuses the coding.
		if _, value, ok := strings.Cut(strings.TrimSpace(params), "="); ok {
			if q, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil && q <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

// gzipAssets compresses embedded files once per process; the embedded bytes are
// immutable, so a cached copy can never go stale.
type gzipAssets struct {
	fsys   fs.FS
	mu     sync.Mutex
	cached map[string][]byte
}

func newGzipAssets(fsys fs.FS) *gzipAssets {
	return &gzipAssets{fsys: fsys, cached: map[string][]byte{}}
}

func (g *gzipAssets) bytes(name string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if b, ok := g.cached[name]; ok {
		return b, nil
	}
	f, err := g.fsys.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(raw) < gzipMinBytes {
		g.cached[name] = nil
		return nil, nil
	}
	var buf bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if _, err := zw.Write(raw); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	g.cached[name] = buf.Bytes()
	return buf.Bytes(), nil
}

// serve writes the gzip form and returns true. Otherwise it only adds Vary and
// returns false so the caller serves the stored file. Range requests are left
// to the stored file, whose byte offsets must not apply to the encoded body.
func (g *gzipAssets) serve(w http.ResponseWriter, r *http.Request, name string) bool {
	// index.html keeps http.FileServer's redirect to the directory URL.
	if name == "index.html" || !compressibleAsset(name) {
		return false
	}
	w.Header().Add("Vary", "Accept-Encoding")
	if !acceptsGzip(r) || r.Header.Get("Range") != "" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		return false
	}
	body, err := g.bytes(name)
	if err != nil || body == nil {
		return false
	}
	if ct := mime.TypeByExtension(path.Ext(name)); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
	return true
}
