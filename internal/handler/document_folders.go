// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/documentfolders"
	"github.com/google/uuid"
)

type documentWithFolderResponse struct {
	documentResponse
	FolderID *uuid.UUID `json:"folder_id"`
}

func (s *Server) folderService() documentfolders.Service {
	return documentfolders.Service{Pool: s.Pool, Audit: s.Audit}
}
func (s *Server) writeFolderError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, documentfolders.ErrInput):
		writeError(w, http.StatusBadRequest, "a folder name must have 1–80 characters; folder IDs must be valid")
	case errors.Is(err, documentfolders.ErrNotFound):
		writeError(w, http.StatusNotFound, "folder or document not found")
	case errors.Is(err, documentfolders.ErrNameConflict), errors.Is(err, documentfolders.ErrNotEmpty):
		writeError(w, http.StatusConflict, err.Error())
	default:
		s.writeDraftAuthoringError(w, "folder operation failed", err)
	}
}

func (s *Server) handleListDocumentFolders(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	limit, offset := paginationFromQuery(r, 100, 500)
	page, err := s.folderService().List(r.Context(), u.OrgID, limit, offset)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
func (s *Server) handleCreateDocumentFolder(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	name, ok := decodeFolderName(w, r)
	if !ok {
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	folder, err := s.folderService().Create(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, name)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"folder": folder})
}
func (s *Server) handleRenameDocumentFolder(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "folderId")
	if !ok {
		return
	}
	name, ok := decodeFolderName(w, r)
	if !ok {
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	folder, err := s.folderService().Rename(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, name)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"folder": folder})
}
func (s *Server) handleDeleteDocumentFolder(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "folderId")
	if !ok {
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	err = s.folderService().Delete(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodeFolderName(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		Name string `json:"name"`
	}
	// Folder bodies contain scalars only. Keep duplicate/unknown-field and
	// trailing-value refusal while bounding their entire input at 4 KiB.
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid folder name request")
		return "", false
	}
	name, err := documentfolders.NormalizeName(in.Name)
	if err != nil {
		writeError(w, http.StatusBadRequest, "a folder name must have 1–80 characters without control characters")
		return "", false
	}
	return name, true
}

func (s *Server) handleMoveDocumentFolder(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in struct {
		FolderID json.RawMessage `json:"folder_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := decodeSignerJSON(r, &in); err != nil || len(in.FolderID) == 0 {
		writeError(w, http.StatusBadRequest, "folder_id is required; use null to unfile a document")
		return
	}
	var folder *uuid.UUID
	if err := json.Unmarshal(in.FolderID, &folder); err != nil || (folder != nil && *folder == uuid.Nil) {
		writeError(w, http.StatusBadRequest, "invalid folder_id")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	err = s.folderService().Move(r.Context(), authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, folder)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"document_id": id, "folder_id": folder})
}

func (s *Server) handleListDocumentsWithFolders(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	filter, err := documentfolders.ParseFilter(r.URL.Query()["folder_id"])
	if err != nil {
		writeError(w, http.StatusBadRequest, "folder_id must be one folder UUID or unfiled; omit it for all documents")
		return
	}
	limit, offset := paginationFromQuery(r, 50, 500)
	var statuses []string
	if values, ok := r.URL.Query()["status"]; ok && len(values) > 0 {
		statuses = values
	}
	page, err := s.folderService().ListDocuments(r.Context(), u.OrgID, statuses, filter, limit, offset)
	if err != nil {
		s.writeFolderError(w, err)
		return
	}
	out := make([]documentWithFolderResponse, 0, len(page.Documents))
	for _, row := range page.Documents {
		out = append(out, documentWithFolderResponse{documentResponse: toDocumentMetadataResponse(&row.Metadata), FolderID: row.FolderID})
	}
	writeJSON(w, http.StatusOK, map[string]any{"documents": out, "total": page.Total, "limit": page.Limit, "offset": page.Offset})
}
