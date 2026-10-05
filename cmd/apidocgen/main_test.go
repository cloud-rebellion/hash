// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"strings"
	"testing"
)

func TestInventoryIncludesNestedConditionalAndMountedHelperRoutes(t *testing.T) {
	source := []byte(`package handler
func (s *Server) Routes() any {
 r.Use(s.requireProxy)
 r.Route("/api",func(r Router){
  r.Use(auth.RequireSession(s.Cookies))
  r.With(auth.RequireRole(auth.Owner)).Post("/documents",s.create)
  r.Group(func(r Router){r.Use(limit(10));r.Get("/documents/{id}",s.read)})
 })
 if s.Sign != nil {s.mountSignerRoutes(r)}
 if s.MCP != nil {r.Mount("/mcp",s.MCP.Handler())} else {r.Get("/disabled",s.disabled)}
 return r
}
func (s *Server) mountSignerRoutes(r Router){r.Route("/sign/{token}",func(r Router){r.Get("/",s.signer)})}
`)
	raw, err := generate(source)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, fragment := range []string{"POST | `/api/documents`", "GET | `/api/documents/{id}`", "GET | `/sign/{token}/`", "MOUNT | `/mcp`", "GET | `/disabled`", "auth.RequireRole(auth.Owner)", "s.Sign != nil", "!(s.MCP != nil)", "5 route registrations"} {
		if !strings.Contains(doc, fragment) {
			t.Fatalf("missing %q in inventory", fragment)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "GET | `/sign/{token}/`") && strings.Contains(line, "RequireSession") {
			t.Fatal("sibling session middleware leaked into signer routes")
		}
	}
}

func TestDynamicPathCannotSilentlyDisappear(t *testing.T) {
	_, err := generate([]byte(`package handler; func (s *Server) Routes() any {r.Get(s.path,s.get);return r}`))
	if err == nil {
		t.Fatal("dynamic route needs explicit generator support")
	}
}

func TestRecursiveRouterHelperFails(t *testing.T) {
	_, err := generate([]byte(`package handler; func (s *Server) Routes() any {s.loop(r);return r};func(s *Server)loop(r Router){s.loop(r)}`))
	if err == nil {
		t.Fatal("recursive helper was not rejected")
	}
}
