// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/hex"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"net/http"
)

func (s *Server) listOwnedTemplatesV1(w http.ResponseWriter, r *http.Request, user, org uuid.UUID, limit, offset int32) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		s.writeTemplateMutationError(w, "list templates failed", err)
		return
	}
	result, err := blockauthoring.ListTemplatesV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize}, limit, offset, true)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		if errors.Is(err, auth.ErrMutationCredentialExpired) || errors.Is(err, auth.ErrMutationPermissionRevoked) {
			s.writeDraftAuthoringError(w, "list templates failed", err)
			return
		}
		if errors.Is(err, pdfadmission.ErrTemplateListSourceV1) || errors.Is(err, pdfadmission.ErrBlocksWriterV1) {
			writeError(w, http.StatusServiceUnavailable, "template list source capacity unavailable")
			return
		}
		writeError(w, http.StatusInternalServerError, "list templates failed")
		return
	}
	out := make([]templateResponse, 0, len(result.Rows))
	for i, row := range result.Rows {
		response, err := nativeTemplateListResponseV1(row, result.Digests[i])
		if err != nil {
			writeInternalErrorMsg(w, "template has invalid canonical content", err)
			return
		}
		out = append(out, response)
	}
	writeJSON(w, http.StatusOK, map[string]any{"templates": out, "total": result.Total, "limit": limit, "offset": offset})
}

// This is the existing list-only public metadata projection. It never creates
// a partial full Template model or supplies source/write/approval authority.
func nativeTemplateListResponseV1(row *generated.ReadNativeTemplateListProjectionV1Row, blocksDigest string) (templateResponse, error) {
	if row == nil {
		return templateResponse{}, errors.New("template list row missing")
	}
	out := templateResponse{ID: row.ID, OrgID: row.OrgID, Name: row.Name, SourceKind: row.SourceKind, BlocksJSON: row.BlocksJson, VariablesJSON: row.VariablesJson, FieldsJSON: row.FieldsJson, Version: row.Version, CreatedBy: row.CreatedBy, CreatedAt: row.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"), UpdatedAt: row.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")}
	if row.PdfStorageKey.Valid {
		out.PDFStorageKey = row.PdfStorageKey.String
	}
	if len(row.PdfSha256) > 0 {
		out.PDFSHA256 = hex.EncodeToString(row.PdfSha256)
	}
	if row.PageCount.Valid {
		out.PageCount = row.PageCount.Int32
	}
	if row.SourceKind == "blocks" {
		if len(blocksDigest) != 64 {
			return templateResponse{}, errors.New("canonical block template digest missing")
		}
		out.ContentSHA256 = blocksDigest
	}
	if row.SourceKind == "html" {
		if len(row.HtmlContentSha256) != 32 {
			return templateResponse{}, errors.New("HTML template has no canonical content commitment")
		}
		out.ContentSHA256 = hex.EncodeToString(row.HtmlContentSha256)
	}
	return out, nil
}
