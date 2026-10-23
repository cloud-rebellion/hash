// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"os"
	"strings"
	"testing"
)

const noticeCaller487 = `package handler
import na "github.com/bright-interaction/hash/internal/noticeaccess"
func(s *Server) Routes() any {
 r.Use(s.requireProxy)
 if s.NoticeEnabled {
  r.Route("/preview",func(r Router){na.MountV1(r,s.NoticeAccess)})
 }
 r.Route("/api/v1",func(r Router){r.Use(auth.RequireSession(s.Cookies));r.Get("/staff",s.staff)})
 return r
}`
const noticeRouter487 = `package noticeaccess
func MountV1(r chi.Router,e *EngineV1) {
 r.Group(func(r chi.Router){
  r.Use(httprate.LimitByIP(240,time.Minute))
  r.Post("/api/v1/notices/{notice_id}/access",func(w Writer,r Request){e.exchangeV1(w,r)})
  r.With(noticeCredentialLimitV1(e,240)).Get("/api/v1/notices/{notice_id}",func(w Writer,r Request){e.presentationV1(w,r)})
  r.With(httprate.LimitByIP(60,time.Minute),noticeCredentialLimitV1(e,30)).Get("/api/v1/notices/{notice_id}/files/{position}",func(w Writer,r Request){e.fileV1(w,r)})
 })
}`

func TestNoticeAccessV1ExpandsExactAliasPrefixMethodsAndMiddleware(t *testing.T) {
	raw, err := generateWithNoticeAccessV1([]byte(noticeCaller487), []byte(noticeRouter487))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	for _, fragment := range []string{
		"POST | `/preview/api/v1/notices/{notice_id}/access`",
		"GET | `/preview/api/v1/notices/{notice_id}`",
		"GET | `/preview/api/v1/notices/{notice_id}/files/{position}`",
		"GET | `/api/v1/staff`", "4 route registrations",
		"../internal/noticeaccess/http_v1.go#L", "noticeaccess.MountV1(r, s.NoticeAccess)",
	} {
		if !strings.Contains(doc, fragment) {
			t.Fatalf("missing %q", fragment)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "| `/preview/api/v1/notices/") {
			for _, gate := range []string{"s.requireProxy", "s.NoticeEnabled", "httprate.LimitByIP(240, time.Minute)"} {
				if !strings.Contains(line, gate) {
					t.Fatalf("missing parent/module gate %q: %s", gate, line)
				}
			}
			if strings.Contains(line, "RequireSession") || strings.Contains(line, "../internal/handler/server.go#L") {
				t.Fatalf("wrong public boundary/source: %s", line)
			}
		}
		if strings.Contains(line, "| `/api/v1/staff` |") {
			if !strings.Contains(line, "RequireSession") || strings.Contains(line, "LimitByIP(240") || strings.Contains(line, "NoticeEnabled") {
				t.Fatalf("module gates leaked to sibling: %s", line)
			}
		}
	}
	if strings.Contains(doc, "GET | `/preview/api/v1/notices/{notice_id}/access`") || strings.Contains(doc, "POST | `/preview/api/v1/notices/{notice_id}/files/{position}`") {
		t.Fatal("method changed")
	}
}

func TestNoticeAccessV1RefusesMissingChangedOrUnresolvedMount(t *testing.T) {
	cases := []struct{ name, caller, module string }{
		{"missing-source", noticeCaller487, ""},
		{"missing-mount", noticeCaller487, `package noticeaccess;func Other(r chi.Router,e *EngineV1){}`},
		{"wrong-package", noticeCaller487, strings.Replace(noticeRouter487, "package noticeaccess", "package other", 1)},
		{"duplicate-mount", noticeCaller487, noticeRouter487 + `;func MountV1(r chi.Router,e *EngineV1){}`},
		{"wrong-parameter", noticeCaller487, strings.Replace(noticeRouter487, "MountV1(r chi.Router,e *EngineV1)", "MountV1(router chi.Router,e *EngineV1)", 1)},
		{"unknown-helper", noticeCaller487, `package noticeaccess;func MountV1(r chi.Router,e *EngineV1){e.mountMore(r)}`},
		{"router-alias", noticeCaller487, `package noticeaccess;func MountV1(r chi.Router,e *EngineV1){other:=r;other.Get("/hidden",e.handler)}`},
		{"dynamic-path", noticeCaller487, strings.Replace(noticeRouter487, `"/api/v1/notices/{notice_id}/access"`, `e.dynamicPath`, 1)},
		{"empty-group", noticeCaller487, `package noticeaccess;func MountV1(r chi.Router,e *EngineV1){r.Group()}`},
		{"renamed-mount", strings.Replace(noticeCaller487, "na.MountV1", "na.MountV2", 1), noticeRouter487},
		{"wrong-router", strings.Replace(noticeCaller487, "na.MountV1(r,", "na.MountV1(other,", 1), noticeRouter487},
		{"wrong-service", strings.Replace(noticeCaller487, "s.NoticeAccess", "s.Other", 1), noticeRouter487},
		{"wrong-arity", strings.Replace(noticeCaller487, "na.MountV1(r,s.NoticeAccess)", "na.MountV1(r)", 1), noticeRouter487},
		{"dot-import", strings.Replace(noticeCaller487, "import na ", "import . ", 1), noticeRouter487},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generateWithNoticeAccessV1([]byte(tc.caller), []byte(tc.module))
			if err == nil {
				t.Fatal("changed or unresolved module silently disappeared")
			}
		})
	}
	_, err := generate([]byte(noticeCaller487))
	if err != errNoticeSourceRequiredV1 {
		t.Fatalf("missing delegate must request exact source: %v", err)
	}
}

func TestNoticeAccessV1DoesNotWalkOtherPackagesOrUnusedFiles(t *testing.T) {
	caller := strings.Replace(noticeCaller487, noticeAccessImportV1, "example.test/unrelated", 1)
	expected, err := generate([]byte(caller))
	if err != nil {
		t.Fatal(err)
	}
	actual, err := generateWithNoticeAccessV1([]byte(caller), []byte("malformed unused source"))
	if err != nil {
		t.Fatal(err)
	}
	if string(expected) != string(actual) {
		t.Fatal("unrelated module/source changed existing inventory")
	}
	if strings.Contains(string(actual), "/notices/") || !strings.Contains(string(actual), "1 route registrations") {
		t.Fatal("untrusted package acquired supported delegate behavior")
	}
}

func TestNoticeAccessV1CurrentSourceIncludesFiveStaffAndThreePurposeRoutes(t *testing.T) {
	caller, err := os.ReadFile("../../internal/handler/server.go")
	if err != nil {
		t.Fatal(err)
	}
	module, err := os.ReadFile("../../internal/noticeaccess/http_v1.go")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := generateWithNoticeAccessV1(caller, module)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	expected := []string{
		"GET | `/api/v1/documents/{id}/amendments`", "POST | `/api/v1/documents/{id}/amendments`",
		"GET | `/api/v1/documents/{id}/amendment`",
		"POST | `/api/v1/documents/{id}/amendments/{amendmentId}/notice`",
		"POST | `/api/v1/documents/{id}/amendments/{amendmentId}/notice/access/{accessId}/revoke`",
		"POST | `/api/v1/notices/{notice_id}/access`", "GET | `/api/v1/notices/{notice_id}`",
		"GET | `/api/v1/notices/{notice_id}/files/{position}`",
	}
	for _, fragment := range expected {
		if strings.Count(doc, fragment) != 1 {
			t.Fatalf("expected exactly one %q", fragment)
		}
	}
	for _, line := range strings.Split(doc, "\n") {
		if strings.Contains(line, "| `/api/v1/notices/") {
			if strings.Contains(line, "RequireSession") || !strings.Contains(line, "s.requireProductionProxyAuth") || !strings.Contains(line, "../internal/noticeaccess/http_v1.go#L") {
				t.Fatalf("wrong real public boundary: %s", line)
			}
		}
		for _, fragment := range expected[:5] {
			if strings.Contains(line, fragment) && !strings.Contains(line, "RequireSession") {
				t.Fatalf("staff session omitted: %s", line)
			}
		}
	}
}
