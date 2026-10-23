// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"strconv"
	"strings"
)

const noticeAccessImportV1 = "github.com/bright-interaction/hash/internal/noticeaccess"
const noticeAccessSourceV1 = "noticeaccess/http_v1.go"

var errNoticeSourceRequiredV1 = errors.New("noticeaccess.MountV1 requires its router source; use -notice-input")

// This is one explicitly supported router boundary, not a package-wide call
// walker. Only the imported noticeaccess MountV1(r,s.NoticeAccess) is followed.
type noticeAccessExtractorV1 struct {
	alias  string
	source []byte
	mount  *ast.FuncDecl
	used   bool
}

func newNoticeAccessExtractorV1(file *ast.File, source []byte) (*noticeAccessExtractorV1, error) {
	out := &noticeAccessExtractorV1{source: source}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			return nil, err
		}
		if path != noticeAccessImportV1 {
			continue
		}
		alias := "noticeaccess"
		if imp.Name != nil {
			alias = imp.Name.Name
		}
		if alias == "_" {
			continue
		}
		if alias == "." || out.alias != "" {
			return nil, errors.New("unsupported noticeaccess router import")
		}
		out.alias = alias
	}
	return out, nil
}

func (e *extractor) walkNoticeAccessV1(call *ast.CallExpr, prefix string, gates, conditions []string) bool {
	d := e.noticeAccess
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || d == nil || d.alias == "" {
		return false
	}
	receiver, ok := sel.X.(*ast.Ident)
	if !ok || receiver.Name != d.alias {
		return false
	}
	if sel.Sel.Name != "MountV1" {
		if strings.HasPrefix(sel.Sel.Name, "Mount") {
			e.err = errors.New("unsupported noticeaccess router mount")
			return true
		}
		return false
	}
	if len(call.Args) != 2 {
		e.err = errors.New("unsupported noticeaccess.MountV1 arguments")
		return true
	}
	router, ok := call.Args[0].(*ast.Ident)
	service, serviceOK := call.Args[1].(*ast.SelectorExpr)
	if !ok || router.Name != "r" || !serviceOK {
		e.err = errors.New("unsupported noticeaccess.MountV1 boundary")
		return true
	}
	owner, ownerOK := service.X.(*ast.Ident)
	if !ownerOK || owner.Name != "s" || service.Sel.Name != "NoticeAccess" {
		e.err = errors.New("unsupported noticeaccess.MountV1 service")
		return true
	}
	if len(d.source) == 0 {
		e.err = errNoticeSourceRequiredV1
		return true
	}
	if d.mount == nil {
		file, err := parser.ParseFile(e.fs, noticeAccessSourceV1, d.source, 0)
		if err != nil {
			e.err = err
			return true
		}
		if file.Name.Name != "noticeaccess" {
			e.err = errors.New("unexpected noticeaccess router package")
			return true
		}
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "MountV1" {
				continue
			}
			if d.mount != nil || fn.Recv != nil || fn.Body == nil || fn.Type.Params == nil || len(fn.Type.Params.List) != 2 || fn.Type.Results != nil || fn.Type.TypeParams != nil {
				e.err = errors.New("unsupported noticeaccess.MountV1 declaration")
				return true
			}
			params := fn.Type.Params.List
			if len(params[0].Names) != 1 || params[0].Names[0].Name != "r" || len(params[1].Names) != 1 || params[1].Names[0].Name != "e" {
				e.err = errors.New("unsupported noticeaccess.MountV1 parameter names")
				return true
			}
			d.mount = fn
		}
		if d.mount == nil {
			e.err = errors.New("noticeaccess.MountV1 router missing")
			return true
		}
		if err := validateNoticeRouterBlockV1(d.mount.Body); err != nil {
			e.err = err
			return true
		}
	}
	d.used = true
	e.walk(d.mount.Body, prefix, gates, conditions)
	return true
}

// Keep the supported module's router structure explicit. Handler/middleware
// bodies are not traversed. A future helper, alias or statement needs reviewed
// extraction support rather than silently hiding another registration.
func validateNoticeRouterBlockV1(block *ast.BlockStmt) error {
	for _, stmt := range block.List {
		switch s := stmt.(type) {
		case *ast.BlockStmt:
			if err := validateNoticeRouterBlockV1(s); err != nil {
				return err
			}
		case *ast.IfStmt:
			if s.Init != nil {
				return errors.New("unsupported noticeaccess router initializer")
			}
			if err := validateNoticeRouterBlockV1(s.Body); err != nil {
				return err
			}
			if s.Else != nil {
				other, ok := s.Else.(*ast.BlockStmt)
				if !ok {
					return errors.New("unsupported noticeaccess router else")
				}
				if err := validateNoticeRouterBlockV1(other); err != nil {
					return err
				}
			}
		case *ast.ExprStmt:
			call, ok := s.X.(*ast.CallExpr)
			if !ok {
				return errors.New("unsupported noticeaccess router expression")
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return errors.New("unsupported noticeaccess router helper")
			}
			receiver := sel.X
			if with, ok := receiver.(*ast.CallExpr); ok {
				ws, ok := with.Fun.(*ast.SelectorExpr)
				if !ok || ws.Sel.Name != "With" {
					return errors.New("unsupported noticeaccess router receiver")
				}
				receiver = ws.X
			}
			id, ok := receiver.(*ast.Ident)
			if !ok || id.Name != "r" {
				return errors.New("unsupported noticeaccess router delegate")
			}
			switch sel.Sel.Name {
			case "Use", "Get", "Post", "Put", "Patch", "Delete", "Head", "Options", "Handle", "HandleFunc", "Mount":
			case "Route", "Group":
				if len(call.Args) == 0 {
					return errors.New("incomplete noticeaccess router group")
				}
				fn, ok := call.Args[len(call.Args)-1].(*ast.FuncLit)
				if !ok {
					return errors.New("unsupported noticeaccess router callback")
				}
				if err := validateNoticeRouterBlockV1(fn.Body); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported noticeaccess router operation %s", sel.Sel.Name)
			}
		default:
			return errors.New("unsupported noticeaccess router statement")
		}
	}
	return nil
}

func routeSourceLinkV1(file string) (string, error) {
	switch file {
	case "server.go":
		return "../internal/handler/server.go", nil
	case noticeAccessSourceV1:
		return "../internal/noticeaccess/http_v1.go", nil
	default:
		return "", fmt.Errorf("unsupported inventory source %q", file)
	}
}
