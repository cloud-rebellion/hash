// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package api

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHashAPIUsesDirectPeerIPDespiteForwardedHeaders(t *testing.T) {
	// Exercise the actual production Start constructor, then stop at its normal
	// module-readiness boundary before opening a listener.
	stop := errors.New("test stops before listener creation")
	a := &Api{rootPath: "/", timeout: time.Second, startTimeout: time.Second,
		logger: slog.New(slog.DiscardHandler), readyFn: []func() error{func() error { return stop }}}
	if err := a.Start(); !errors.Is(err, stop) || a.srv == nil {
		t.Fatalf("production constructor did not reach readiness boundary: %v", err)
	}
	for _, tc := range []struct {
		name, forwarded, real string
	}{
		{"forwarded", "203.0.113.7, 198.51.100.8", ""},
		{"real", "", "203.0.113.9"},
		{"both", "203.0.113.10", "203.0.113.11"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/health", nil)
			req.RemoteAddr = "192.0.2.23:43123"
			req.Header.Set("X-Forwarded-For", tc.forwarded)
			req.Header.Set("X-Real-IP", tc.real)
			if got := a.srv.NewContext(req, httptest.NewRecorder()).RealIP(); got != "192.0.2.23" {
				t.Fatalf("caller-controlled IP header replaced direct peer: %q", got)
			}
		})
	}
}

func TestHashRendererDoesNotWireEchoProxyOrRateLimiter(t *testing.T) {
	// The reviewed Echo findings concern these specific middleware defaults.
	// Refuse new wiring or aliases without a new review; Hash's separate
	// Chromium pinning proxy is not Echo's reverse-proxy middleware.
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("test source location unavailable")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(here), "../.."))
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		aliases := map[string]bool{}
		for _, imp := range file.Imports {
			module, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if module == "github.com/labstack/echo/v4/middleware" {
				alias := "middleware"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				if alias == "." {
					t.Errorf("%s uses an unreviewable dot middleware import", path)
				}
				aliases[alias] = true
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := selector.X.(*ast.Ident)
			if ok && aliases[id.Name] {
				switch selector.Sel.Name {
				case "Proxy", "ProxyWithConfig", "RateLimiter", "RateLimiterWithConfig":
					t.Errorf("%s wires %s.%s outside the reviewed renderer configuration", path, id.Name, selector.Sel.Name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
