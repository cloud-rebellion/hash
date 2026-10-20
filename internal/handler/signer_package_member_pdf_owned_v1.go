// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/go-chi/chi/v5"
)

// GET /sign/{token}/package/members/{position}/pdf returns only the frozen
// member of this recipient's current package. A download records no consent.
func (s *Server) handleSignerPackageMemberPDFReadV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	expected, status := signerPackageMemberExpectedV1(chi.URLParam(r, "position"), r.Header)
	if status != 0 {
		if status == http.StatusPreconditionRequired {
			writeError(w, status, "the package commitments are required in If-Match")
		} else {
			writeError(w, status, "invalid package member or If-Match")
		}
		return
	}
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
	result, err := s.Sign.SignerPackageMemberPDFV1(r.Context(), rc, expected)
	if err != nil {
		writeSignerPackageMemberPDFErrorV1(w, err)
		return
	}
	defer result.CloseConsumerV1()
	if err = s.recheckSignerRead(r, rc, observed); err != nil {
		writeSignerReadError(w, err)
		return
	}
	writing := false
	err = result.WithPDFV1(func(metadata pdfadmission.SignerPackageMemberPDFMetadataV1, body []byte) error {
		if int64(len(body)) != metadata.PDFBytes || metadata.Position != expected.Position || metadata.Observation.Capture.CanonicalSHA256 != expected.ManifestSHA256 || metadata.Observation.Capture.CommitmentSHA256 != expected.LegalCommitmentSHA256 {
			return sign.ErrSigningAdmissionUnavailableV1
		}
		if metadata.Position == 0 {
			setSignerPDFObservationHeaders(w, observed.pdf)
		} else {
			w.Header().Set("X-Hash-Document-Id", rc.Document.ID.String())
			w.Header().Set("X-Hash-Recipient-Id", rc.Recipient.ID.String())
		}
		w.Header().Set("X-Hash-Notice-Digest", observed.notice.NoticeDigest)
		w.Header().Set("X-Hash-Package-Manifest-SHA256", hex.EncodeToString(expected.ManifestSHA256[:]))
		w.Header().Set("X-Hash-Package-Legal-Commitment-SHA256", hex.EncodeToString(expected.LegalCommitmentSHA256[:]))
		w.Header().Set("X-Hash-Package-Member-Position", strconv.Itoa(int(metadata.Position)))
		w.Header().Set("X-Hash-PDF-SHA256", metadata.PDFSHA256)
		w.Header().Set("X-Hash-PDF-Bytes", strconv.FormatInt(metadata.PDFBytes, 10))
		w.Header().Set("X-Hash-PDF-Pages", strconv.Itoa(int(metadata.PDFPages)))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Length", strconv.FormatInt(metadata.PDFBytes, 10))
		w.Header().Set("ETag", `"`+hex.EncodeToString(expected.ManifestSHA256[:])+"."+hex.EncodeToString(expected.LegalCommitmentSHA256[:])+`"`)
		writing = true
		w.WriteHeader(http.StatusOK)
		n, err := w.Write(body)
		if err == nil && n != len(body) {
			return io.ErrShortWrite
		}
		return err
	})
	if err != nil && !writing {
		writeSignerPackageMemberPDFErrorV1(w, err)
	}
}

func writeSignerPackageMemberPDFErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sign.ErrSignerPackagePreconditionV1):
		writeError(w, http.StatusPreconditionFailed, "the package changed; reload before continuing")
	case errors.Is(err, sign.ErrSignerPackageAbsentV1):
		writeError(w, http.StatusNotFound, "package member unavailable")
	default:
		writeSignerReadError(w, err)
	}
}
