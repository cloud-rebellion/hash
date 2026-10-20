// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/go-chi/chi/v5"
)

// GET /sign/{token}/package returns only the authenticated current ceremony's
// frozen public descriptors. Storage locators and editable attachment rows never
// enter the response. This endpoint grants no consent, signature or Send power.
func (s *Server) handleSignerPackageReadV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	token := chi.URLParam(r, "token")
	if token == "" {
		writeError(w, http.StatusBadRequest, "missing token")
		return
	}
	rc, err := s.Sign.LookupSignerPackageByTokenV1(r.Context(), auth.HashMagicToken(token))
	if err != nil {
		switch {
		case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
			writeError(w, http.StatusServiceUnavailable, "signer access is temporarily unavailable")
		case errors.Is(err, sign.ErrMagicLinkExpired):
			writeError(w, http.StatusGone, "magic link expired")
		default:
			writeError(w, http.StatusNotFound, "invalid or expired link")
		}
		return
	}
	defer closeSignerReadConsumerV1(rc)
	observed, err := s.captureSignerReadObservation(r, rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	result, err := s.Sign.SignerPackagePresentationV1(r.Context(), rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	defer result.CloseConsumerV1()
	if err = s.recheckSignerRead(r, rc, observed); err != nil {
		writeSignerReadError(w, err)
		return
	}
	writing := false
	err = result.WithJSONV1(func(body []byte) error {
		writing = true
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Hash-Document-Id", rc.Document.ID.String())
		w.Header().Set("X-Hash-Recipient-Id", rc.Recipient.ID.String())
		w.Header().Set("X-Hash-Notice-Digest", observed.notice.NoticeDigest)
		w.WriteHeader(http.StatusOK)
		_, err := w.Write(body)
		return err
	})
	if err != nil && !writing {
		writeSignerReadError(w, err)
	}
}
