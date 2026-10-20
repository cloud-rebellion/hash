// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/send"
)

// A bounded authenticated history read, not Send replay or background authority.
func (s *Server) handlePackageSendAttemptInspectionV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	document, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	attempt, ok := parseUUIDParam(w, r, "attempt_id")
	if !ok {
		return
	}
	if s.Send == nil {
		writeError(w, http.StatusServiceUnavailable, "Send inspection is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return
	}
	result, err := s.Send.InspectPackageSendAttemptV1(ctx, send.Actor{OrgID: u.OrgID, UserID: &u.UserID, Authorize: authorize, Via: "rest"}, document, attempt)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		if errors.Is(err, pdfadmission.ErrHTMLSendPackageInspectionV1) || errors.Is(err, pdfadmission.ErrDocumentPackagePendingPrivacyV1) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) {
			writeError(w, http.StatusConflict, "Send attempt cannot be inspected; refresh or contact an administrator")
		} else {
			s.writeSendError(w, err)
		}
		return
	}
	err = result.WithObservationV1(func(observation pdfadmission.HTMLSendPackageAttemptObservationV1) error {
		outcome := ""
		switch observation.Outcome {
		case pdfadmission.HTMLSendPackageAttemptActiveV1:
			outcome = "active"
		case pdfadmission.HTMLSendPackageAttemptCompletedV1:
			outcome = "completed"
		case pdfadmission.HTMLSendPackageAttemptAbortedV1:
			outcome = "aborted"
		case pdfadmission.HTMLSendPackageAttemptNotRecordedV1:
			outcome = "not_recorded"
		default:
			return pdfadmission.ErrHTMLSendPackageInspectionV1
		}
		// No key, recipient, report, credential or current-source body is exposed.
		writeJSON(w, http.StatusOK, struct {
			AttemptID       string `json:"attempt_id"`
			Outcome         string `json:"outcome"`
			RetryAuthorized bool   `json:"retry_authorized"`
		}{observation.AttemptID.String(), outcome, false})
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, "Send inspection ended before delivery")
	}
}
