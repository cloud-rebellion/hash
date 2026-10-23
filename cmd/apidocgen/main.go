// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strconv"
	"strings"
)

type route struct {
	method, path, handler string
	gates, conditions     []string
	line                  int
	source                string
}
type extractor struct {
	fs           *token.FileSet
	methods      map[string]*ast.FuncDecl
	routes       []route
	err          error
	active       map[string]bool
	noticeAccess *noticeAccessExtractorV1
}

func (e *extractor) expression(node ast.Node) string {
	if _, ok := node.(*ast.FuncLit); ok {
		position := e.fs.Position(node.Pos())
		return fmt.Sprintf("inline middleware at %s:%d", position.Filename, position.Line)
	}
	var b bytes.Buffer
	_ = format.Node(&b, e.fs, node)
	return b.String()
}
func literal(x ast.Expr) (string, bool) {
	s, ok := x.(*ast.BasicLit)
	if !ok || s.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(s.Value)
	return v, err == nil
}
func join(prefix, suffix string) string {
	if prefix == "" {
		return suffix
	}
	if suffix == "/" {
		return strings.TrimRight(prefix, "/") + "/"
	}
	return strings.TrimRight(prefix, "/") + "/" + strings.TrimLeft(suffix, "/")
}
func clone(values []string) []string { return append([]string(nil), values...) }

func (e *extractor) walk(block *ast.BlockStmt, prefix string, gates, conditions []string) {
	if block == nil {
		return
	}
	gates = clone(gates)
	for _, stmt := range block.List {
		switch s := stmt.(type) {
		case *ast.IfStmt:
			condition := e.expression(s.Cond)
			e.walk(s.Body, prefix, gates, append(clone(conditions), condition))
			if b, ok := s.Else.(*ast.BlockStmt); ok {
				e.walk(b, prefix, gates, append(clone(conditions), "!("+condition+")"))
			}
		case *ast.BlockStmt:
			e.walk(s, prefix, gates, conditions)
		case *ast.ExprStmt:
			call, ok := s.X.(*ast.CallExpr)
			if !ok {
				continue
			}
			if e.walkNoticeAccessV1(call, prefix, gates, conditions) {
				if e.err != nil {
					return
				}
				continue
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if recv, ok := sel.X.(*ast.Ident); ok && recv.Name == "s" && len(call.Args) == 1 {
				if arg, ok := call.Args[0].(*ast.Ident); ok && arg.Name == "r" {
					if method := e.methods[sel.Sel.Name]; method != nil {
						if e.active[method.Name.Name] {
							e.err = fmt.Errorf("recursive router helper %s", method.Name.Name)
							return
						}
						e.active[method.Name.Name] = true
						e.walk(method.Body, prefix, gates, conditions)
						delete(e.active, method.Name.Name)
					}
				}
				continue
			}
			local := clone(gates)
			receiver := sel.X
			if with, ok := receiver.(*ast.CallExpr); ok {
				ws, ok := with.Fun.(*ast.SelectorExpr)
				if !ok || ws.Sel.Name != "With" {
					continue
				}
				receiver = ws.X
				for _, arg := range with.Args {
					local = append(local, e.expression(arg))
				}
			}
			id, ok := receiver.(*ast.Ident)
			if !ok || id.Name != "r" {
				continue
			}
			name := sel.Sel.Name
			if name == "Use" {
				for _, arg := range call.Args {
					gates = append(gates, e.expression(arg))
				}
				continue
			}
			if name == "Route" || name == "Group" {
				nested := prefix
				if name == "Route" {
					part, ok := literal(call.Args[0])
					if !ok {
						e.err = fmt.Errorf("nonliteral route path")
						return
					}
					nested = join(prefix, part)
				}
				fn, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
				if !ok {
					e.err = fmt.Errorf("unresolved router callback")
					return
				}
				e.walk(fn.Body, nested, local, conditions)
				continue
			}
			methods := map[string]string{"Get": "GET", "Post": "POST", "Put": "PUT", "Patch": "PATCH", "Delete": "DELETE", "Head": "HEAD", "Options": "OPTIONS", "Handle": "ANY", "HandleFunc": "ANY", "Mount": "MOUNT"}
			method, ok := methods[name]
			if !ok {
				continue
			}
			if len(call.Args) < 2 {
				e.err = fmt.Errorf("incomplete %s registration", name)
				return
			}
			part, ok := literal(call.Args[0])
			if !ok {
				e.err = fmt.Errorf("nonliteral endpoint path")
				return
			}
			position := e.fs.Position(call.Pos())
			handler := e.expression(call.Args[1])
			if _, inline := call.Args[1].(*ast.FuncLit); inline && position.Filename == noticeAccessSourceV1 {
				handler = fmt.Sprintf("inline handler at %s:%d", position.Filename, position.Line)
			}
			e.routes = append(e.routes, route{method: method, path: join(prefix, part), handler: handler, gates: local, conditions: clone(conditions), line: position.Line, source: position.Filename})
		}
	}
}

func generate(source []byte) ([]byte, error) {
	return generateWithNoticeAccessV1(source, nil)
}

func generateWithNoticeAccessV1(source, noticeSource []byte) ([]byte, error) {
	fs := token.NewFileSet()
	file, err := parser.ParseFile(fs, "server.go", source, 0)
	if err != nil {
		return nil, err
	}
	noticeAccess, err := newNoticeAccessExtractorV1(file, noticeSource)
	if err != nil {
		return nil, err
	}
	e := &extractor{fs: fs, methods: map[string]*ast.FuncDecl{}, active: map[string]bool{}, noticeAccess: noticeAccess}
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			e.methods[fn.Name.Name] = fn
		}
	}
	root := e.methods["Routes"]
	if root == nil {
		return nil, fmt.Errorf("Routes function missing")
	}
	e.active["Routes"] = true
	e.walk(root.Body, "", nil, nil)
	if e.err != nil {
		return nil, e.err
	}
	sort.SliceStable(e.routes, func(i, j int) bool {
		if e.routes[i].path == e.routes[j].path {
			return e.routes[i].method < e.routes[j].method
		}
		return e.routes[i].path < e.routes[j].path
	})
	var b strings.Builder
	b.WriteString("# HTTP route inventory\n\nGenerated from `internal/handler/server.go`; update with `go run ./cmd/apidocgen`, verify with `go run ./cmd/apidocgen -check`.\n\nThis inventories registered endpoints, their middleware and availability conditions. Authorization and validation performed inside handlers still apply. `MOUNT` delegates a subtree and `ANY` is a catch-all handler, not a promise that every HTTP method is supported. This inventory is not a complete request/response schema or a production configuration receipt.\n\nSee [Automation API](AUTOMATION-API.md) for the machine signature-request contract and [API guide](API.md) for authentication, lifecycle and documentation boundaries.\n\n")
	if noticeAccess.used {
		b.WriteString("The supported `noticeaccess.MountV1(r, s.NoticeAccess)` boundary is expanded from `internal/noticeaccess/http_v1.go`. Its routes inherit parent middleware; handler-level purpose checks still apply and missing service returns unavailable. See [later amendments and agreed notice](LATER-AMENDMENTS-API.md).\n\n")
	}
	b.WriteString("| Method | Path | Handler | Authorization / rate middleware | Availability | Source |\n| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range e.routes {
		var relevant []string
		for _, gate := range r.gates {
			if strings.Contains(gate, "auth.") || strings.Contains(gate, "require") || strings.Contains(gate, "Limit") || strings.Contains(gate, "inline middleware") {
				relevant = append(relevant, "`"+strings.ReplaceAll(gate, "|", "&#124;")+"`")
			}
		}
		availability := "Always registered"
		if len(r.conditions) > 0 {
			availability = "`" + strings.ReplaceAll(strings.Join(r.conditions, "; "), "|", "&#124;") + "`"
		}
		link, err := routeSourceLinkV1(r.source)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` | %s | %s | [%s:%d](%s#L%d) |\n", r.method, r.path, r.handler, strings.Join(relevant, "<br>"), availability, r.source, r.line, link, r.line)
	}
	fmt.Fprintf(&b, "\n%d route registrations. Conditional registrations are listed even when a deployment disables them.\n", len(e.routes))
	return []byte(b.String()), nil
}

func main() {
	input := flag.String("input", "internal/handler/server.go", "router source")
	output := flag.String("output", "docs/API-ROUTES.md", "generated inventory")
	noticeInput := flag.String("notice-input", "internal/noticeaccess/http_v1.go", "supported noticeaccess router source")
	check := flag.Bool("check", false, "fail when inventory differs")
	flag.Parse()
	source, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	result, err := generate(source)
	if err == errNoticeSourceRequiredV1 {
		noticeSource, readErr := os.ReadFile(*noticeInput)
		if readErr != nil {
			fmt.Fprintln(os.Stderr, readErr)
			os.Exit(1)
		}
		result, err = generateWithNoticeAccessV1(source, noticeSource)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *check {
		current, err := os.ReadFile(*output)
		if err != nil || !bytes.Equal(current, result) {
			fmt.Fprintln(os.Stderr, "API route inventory is stale; run go run ./cmd/apidocgen")
			os.Exit(1)
		}
		return
	}
	if err := os.WriteFile(*output, result, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
