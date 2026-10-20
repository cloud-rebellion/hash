// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"io"
	"net/http"
)

func decodePlainDraftInputV1(input *pdfadmission.ApplicationBlocksInputV1, r *http.Request, dst any) error {
	return input.WithHTTPBodyV1(r.Context(), r.Body, func(raw []byte) error {
		copy := r.Clone(r.Context())
		copy.Body = io.NopCloser(bytes.NewReader(raw))
		return decodeSignerJSON(copy, dst)
	})
}
func (s *Server) finishOwnedPlainDraftPatchV1(w http.ResponseWriter, r *http.Request, org, user, id uuid.UUID, authorize auth.TransactionAuthorization, in updateDocumentInput) {
	result, err := blockauthoring.MutatePlainDraftV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, SnapshotMutation: s.Versions != nil}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize, Via: "rest", Tool: "update_document"}, id, versions.ViaHuman, in.ExpectedUpdatedAt, checkRESTBlockObservationV1, blockauthoring.PlainDraftMutationInputV1{Patch: pdfadmission.PlainDraftPatchV1{Name: in.Name, BlocksJSON: in.BlocksJSON, VariablesJSON: in.VariablesJSON, ExpiresAt: in.ExpiresAt, DefaultLocale: in.DefaultLocale, RequiresSignature: in.RequiresSignature}})
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeOwnedPlainDraftErrorV1(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(result.Document))
}
func (s *Server) writeOwnedPlainDraftErrorV1(w http.ResponseWriter, err error) {
	if errors.Is(err, auth.ErrMutationCredentialExpired) || errors.Is(err, auth.ErrMutationPermissionRevoked) {
		s.writeDraftAuthoringError(w, "authorize document update", err)
		return
	}
	if errors.Is(err, errBlockObservationStale) {
		writeError(w, http.StatusPreconditionFailed, "Document changed since this edit began. Download your local draft, then reload and review the latest document.")
		return
	}
	if errors.Is(err, blockauthoring.ErrDraftSignatureRequiredV1) {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if errors.Is(err, pdfadmission.ErrPlainDraftBlockInputV1) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var source pdfadmission.BlocksCreationInputErrorV1
	if errors.As(err, &source) {
		writeError(w, http.StatusBadRequest, "invalid "+source.Field+": "+source.Cause.Error())
		return
	}
	var input pdfadmission.PlainDraftInputErrorV1
	if errors.As(err, &input) {
		if input.Field == "expires_at" {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid "+input.Field+": "+input.Cause.Error())
		return
	}
	if errors.Is(err, pdfadmission.ErrBlocksWriterV1) || errors.Is(err, pdfadmission.ErrPlainDraftSourceKindV1) || errors.Is(err, pdfadmission.ErrHTMLRevisionReadV1) {
		writeError(w, http.StatusServiceUnavailable, "draft source capacity unavailable")
		return
	}
	s.writeDraftAuthoringError(w, "update document failed", err)
}
