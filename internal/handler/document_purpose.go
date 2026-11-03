// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"net/http"
)

func (s *Server) finishOwnedDocumentPurposeV1(w http.ResponseWriter, r *http.Request, org, user, id uuid.UUID, authorize auth.TransactionAuthorization, in updateDocumentInput, purpose documentpurpose.Purpose) {
	if in.ExpectedUpdatedAt == "" {
		writeError(w, http.StatusPreconditionRequired, "expected_updated_at is required")
		return
	}
	result, err := blockauthoring.MutateDocumentPurposeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize, Via: "rest", Tool: "set_document_purpose"}, id, versions.ViaHuman, in.ExpectedUpdatedAt, checkRESTBlockObservationV1, purpose)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		if errors.Is(err, documentpurpose.ErrTransition) {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		if errors.Is(err, documentpurpose.ErrInvalid) {
			writeError(w, http.StatusConflict, "stored or requested document purpose is invalid")
			return
		}
		s.writeOwnedPlainDraftErrorV1(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDocumentResponse(result.Document))
}

func documentPurposeEditInputV1(in updateDocumentInput) (documentpurpose.Purpose, bool, error) {
	if len(in.Purpose) == 0 {
		return "", false, nil
	}
	var p documentpurpose.Purpose
	if json.Unmarshal(in.Purpose, &p) != nil || in.Name != "" || len(in.BlocksJSON) > 0 || len(in.VariablesJSON) > 0 || in.ExpiresAt != "" || in.DefaultLocale != "" || in.RequiresSignature != nil {
		return "", true, documentpurpose.ErrInvalid
	}
	return p, true, nil
}

func validateHTMLDocumentPurposeV1(p documentpurpose.Purpose, hasSigningProfile bool) error {
	if p == "" || p == documentpurpose.Signing {
		return nil
	}
	if documentpurpose.Validate(p) != nil {
		return documentpurpose.ErrInvalid
	}
	if hasSigningProfile {
		return documentpurpose.ErrSigningRequired
	}
	return nil
}
