// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/send"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAutomation121ReminderInputUsesRealStrictDecoder(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		doc, ok    bool
	}{
		{"template", `{"expected_revision":0,"mode":"legacy","interval_days":0,"max_fires":2}`, false, true},
		{"document", `{"expected_revision":2,"expected_updated_at":"2030-01-01T12:00:00Z","mode":"inherit","interval_days":0,"max_fires":0}`, true, true},
		{"missing-day", `{"expected_revision":0,"mode":"legacy","max_fires":2}`, false, false},
		{"null-day", `{"expected_revision":0,"mode":"legacy","interval_days":null,"max_fires":2}`, false, false},
		{"duplicate", `{"expected_revision":0,"expected_revision":1,"mode":"legacy","interval_days":0,"max_fires":2}`, false, false},
		{"unknown", `{"expected_revision":0,"mode":"legacy","interval_days":0,"max_fires":2,"other":true}`, false, false},
		{"template-null-observation", `{"expected_revision":0,"expected_updated_at":null,"mode":"legacy","interval_days":0,"max_fires":2}`, false, false},
		{"doc-null-observation", `{"expected_revision":0,"expected_updated_at":null,"mode":"inherit","interval_days":0,"max_fires":0}`, true, false},
		{"trailing", `{"expected_revision":0,"mode":"legacy","interval_days":0,"max_fires":2} {}`, false, false},
		{"oversized", strings.Repeat(" ", 2049) + `{}`, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPut, "/", strings.NewReader(tc.body))
			_, err := decodeReminderPolicyV1(httptest.NewRecorder(), r, tc.doc)
			if (err == nil) != tc.ok {
				t.Fatal("strict input result", err)
			}
		})
	}
}
func TestAutomation121CleanupUncertaintyDoesNotBecomeNotFoundOrStale(t *testing.T) {
	s := &Server{}
	for _, known := range []error{send.ErrAutomationNotFoundV1, send.ErrAutomationStaleV1, send.ErrAutomationObservationV1} {
		w := httptest.NewRecorder()
		s.writeAutomationErrorV1(w, errors.Join(known, send.ErrAutomationUnavailableV1))
		if w.Code != 503 {
			t.Fatal("cleanup uncertainty masked by known refusal", w.Code)
		}
	}
}
