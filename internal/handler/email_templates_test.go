// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/go-chi/chi/v5"
)

func TestEmailTemplate720ExactRequestContract(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"expected_revision":0,"subject_template":"","html_template":"","text_template":""}`, true},
		{`{"subject_template":"","html_template":"","text_template":""}`, false},
		{`{"expected_revision":null,"subject_template":"","html_template":"","text_template":""}`, false},
		{`{"expected_revision":0,"subject_template":"","html_template":""}`, false},
		{`{"expected_revision":0,"subject_template":"","html_template":"","text_template":null}`, false},
		{`{"expected_revision":0,"expected_revision":1,"subject_template":"","html_template":"","text_template":""}`, false},
		{`{"EXPECTED_REVISION":0,"subject_template":"","html_template":"","text_template":""}`, false},
		{`{"expected_revision":0,"subject_template":"","html_template":"","text_template":"","transport":"shared"}`, false},
		{`{"expected_revision":0,"subject_template":"","html_template":"","text_template":""}{}`, false},
		{strings.Repeat(" ", 160*1024) + `{}`, false},
	} {
		r := httptest.NewRequest(http.MethodPut, "/api/v1/email-templates/email.invite", strings.NewReader(tc.body))
		c := chi.NewRouteContext()
		c.URLParams.Add("kind", dispatch.KindInvite)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, c))
		w := httptest.NewRecorder()
		kind, _, ok := (&Server{}).decodeEmailTemplate(w, r)
		if ok != tc.valid || ok && kind != dispatch.KindInvite || !ok && w.Code != 400 {
			t.Fatal("ambiguous input accepted or valid reset refused", w.Code)
		}
	}
}
