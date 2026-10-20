// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/go-chi/chi/v5"
	"io"
	"net/http"
	"strconv"
)

func writeCompletedPackageErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, sign.ErrSignerPackagePreconditionV1):
		writeError(w, http.StatusPreconditionFailed, "the archived package observations differ")
	case errors.Is(err, sign.ErrSignerPackageAbsentV1):
		writeError(w, http.StatusNotFound, "archived package member unavailable")
	case errors.Is(err, sign.ErrSigningAdmissionUnavailableV1):
		writeError(w, http.StatusServiceUnavailable, "archived files are temporarily unavailable")
	default:
		writeError(w, http.StatusNotFound, "invalid or expired completion link")
	}
}
func (s *Server) handleCompletedSignerPackageV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	hash := auth.HashMagicToken(chi.URLParam(r, "token"))
	rc, err := s.Sign.LookupCompletedArtifactByToken(r.Context(), hash)
	if err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	defer closeSignerReadConsumerV1(rc)
	result, err := s.Sign.CompletedSignerPackagePresentationV1(r.Context(), rc)
	if err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	defer result.CloseConsumerV1()
	if err = s.Sign.RecheckCompletedPackageByTokenV1(r.Context(), hash, rc); err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	writing := false
	err = result.WithJSONV1(func(body []byte) error {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Hash-Document-Id", rc.Document.ID.String())
		w.Header().Set("X-Hash-Recipient-Id", rc.Recipient.ID.String())
		writing = true
		w.WriteHeader(http.StatusOK)
		n, err := w.Write(body)
		if err == nil && n != len(body) {
			return io.ErrShortWrite
		}
		return err
	})
	if err != nil && !writing {
		writeCompletedPackageErrorV1(w, err)
	}
}
func (s *Server) handleCompletedSignerPackageMemberV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	expected, status := signerPackageMemberExpectedV1(chi.URLParam(r, "position"), r.Header)
	if status != 0 {
		writeError(w, status, "one exact package commitment pair is required in If-Match")
		return
	}
	hash := auth.HashMagicToken(chi.URLParam(r, "token"))
	rc, err := s.Sign.LookupCompletedArtifactByToken(r.Context(), hash)
	if err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	defer closeSignerReadConsumerV1(rc)
	result, err := s.Sign.CompletedSignerPackageMemberPDFV1(r.Context(), rc, expected)
	if err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	defer result.CloseConsumerV1()
	if err = s.Sign.RecheckCompletedPackageByTokenV1(r.Context(), hash, rc); err != nil {
		writeCompletedPackageErrorV1(w, err)
		return
	}
	writing := false
	err = result.WithPDFV1(func(metadata pdfadmission.SignerPackageMemberPDFMetadataV1, body []byte) error {
		if int64(len(body)) != metadata.PDFBytes || metadata.Position != expected.Position || metadata.Observation.Capture.CanonicalSHA256 != expected.ManifestSHA256 || metadata.Observation.Capture.CommitmentSHA256 != expected.LegalCommitmentSHA256 {
			return sign.ErrSigningAdmissionUnavailableV1
		}
		w.Header().Set("X-Hash-Document-Id", rc.Document.ID.String())
		w.Header().Set("X-Hash-Recipient-Id", rc.Recipient.ID.String())
		w.Header().Set("X-Hash-Package-Manifest-SHA256", hex.EncodeToString(expected.ManifestSHA256[:]))
		w.Header().Set("X-Hash-Package-Legal-Commitment-SHA256", hex.EncodeToString(expected.LegalCommitmentSHA256[:]))
		w.Header().Set("X-Hash-Package-Member-Position", strconv.Itoa(int(metadata.Position)))
		w.Header().Set("X-Hash-PDF-SHA256", metadata.PDFSHA256)
		w.Header().Set("X-Hash-PDF-Bytes", strconv.FormatInt(metadata.PDFBytes, 10))
		w.Header().Set("X-Hash-PDF-Pages", strconv.Itoa(int(metadata.PDFPages)))
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Length", strconv.FormatInt(metadata.PDFBytes, 10))
		w.Header().Set("Content-Disposition", "attachment; filename=\"contract-original-"+strconv.Itoa(int(metadata.Position))+".pdf\"")
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
		writeCompletedPackageErrorV1(w, err)
	}
}
