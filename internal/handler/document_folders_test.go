// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFolderNameBodyRefusesAmbiguousOrOversizedJSON(t *testing.T) {
	for _, body := range []string{`{}`, `{"name":null}`, `{"name":"a","name":"b"}`, `{"NAME":"a"}`, `{"name":"a","extra":true}`, `{"name":"a"} {}`, `{"name":"` + strings.Repeat("x", 4096) + `"}`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		w := httptest.NewRecorder()
		if _, ok := decodeFolderName(w, r); ok || w.Code != 400 {
			t.Error("ambiguous folder body admitted")
		}
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"name":"  Kunder  "}`))
	w := httptest.NewRecorder()
	if got, ok := decodeFolderName(w, r); !ok || got != "Kunder" {
		t.Error("valid folder body refused")
	}
}
