// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSignerFieldsFailureResponsesPreservePriorityAndPrivacyV1(t *testing.T) {
	databaseError := &pgconn.PgError{Code: "P0001", Message: "synthetic private SQL diagnostic", Detail: "synthetic private SQL detail"}
	assertResponse := func(t *testing.T, err error, status int, message string) {
		t.Helper()
		w := httptest.NewRecorder()
		writeSignerFieldsFailureV1(w, err)
		var body map[string]string
		if decodeErr := json.Unmarshal(w.Body.Bytes(), &body); decodeErr != nil || w.Code != status || body["error"] != message {
			t.Fatalf("unexpected field error response: status=%d body=%q", w.Code, w.Body.String())
		}
		for _, secret := range []string{databaseError.Message, databaseError.Detail, databaseError.Code} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("field response exposed a private database diagnostic")
			}
		}
		if w.Header().Get("X-Hash-PDF-SHA256") != "" {
			t.Fatal("field failure emitted a success PDF witness")
		}
	}
	for _, status := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusConflict, http.StatusPreconditionRequired} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			business := signerFieldsResponseV1(status, "controlled field refusal")
			assertResponse(t, business, status, "controlled field refusal")
			for _, err := range []error{errors.Join(business, sign.ErrSigningAdmissionUnavailableV1), errors.Join(sign.ErrSigningAdmissionUnavailableV1, business)} {
				assertResponse(t, err, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
			}
			assertResponse(t, errors.Join(databaseError, business), http.StatusInternalServerError, "internal error")
			assertResponse(t, errors.Join(business, databaseError), http.StatusInternalServerError, "internal error")
		})
	}
	for _, err := range []error{
		errors.Join(sign.ErrSigningAdmissionUnavailableV1, databaseError, errSignerReadChanged),
		fmt.Errorf("synthetic wrapper: %w", errors.Join(errSignerReadChanged, databaseError, sign.ErrSigningAdmissionUnavailableV1)),
	} {
		assertResponse(t, err, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
	}
	assertResponse(t, errors.Join(pdfadmission.ErrApplicationSessionV1, databaseError, errSignerReadChanged), http.StatusInternalServerError, "internal error")
	assertResponse(t, errSignerReadChanged, http.StatusConflict, "the document or signing link changed; reload before continuing")
	assertResponse(t, errors.New("synthetic unknown error"), http.StatusInternalServerError, "internal error")
}
