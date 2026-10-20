// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"fmt"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"log/slog"
	"mime"
	"net/http"
	"time"
)

func (s *Server) handleSelectDocumentAttachmentV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if s.HTMLCreationSessions == nil || s.Storage == nil || s.Audit == nil {
		writeError(w, http.StatusServiceUnavailable, "attachment processing is unavailable")
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "use application/json")
		return
	}
	// One original overall deadline; SQL stage deadlines remain independently10s.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, sess.OrgID, sess.UserID)
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	input, e := s.HTMLCreationSessions.NewDocumentPackageHTTPInputV1(ctx, sess.OrgID)
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "attachment input capacity is unavailable")
		return
	}
	defer input.CloseConsumerV1()
	if e = input.ReadHTTPV1(ctx, root, r.Body); e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	out, e := packageauthoring.SelectV1(ctx, packageauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Storage: s.Storage, Audit: s.Audit},
		authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, input, firstIPFromHeader(r), r.UserAgent())
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	if out.Cause != nil {
		slog.Warn("Hash attachment selection requires reconciliation", "state", out.State, "error_type", fmt.Sprintf("%T", out.Cause))
		out.Cause = nil
	}
	status := http.StatusCreated
	if out.State == "unknown" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, out)
}

func (s *Server) handleDocumentAttachmentsV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if s.HTMLCreationSessions == nil {
		writeError(w, http.StatusServiceUnavailable, "attachment processing is unavailable")
		return
	}
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, sess.OrgID, sess.UserID)
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	result, e := packageauthoring.InventoryV1(ctx, packageauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions},
		authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, root)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSaveDocumentAttachmentLayoutV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	root, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil {
		writeError(w, http.StatusServiceUnavailable, "attachment processing is unavailable")
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "use application/json")
		return
	}
	// One original overall deadline; SQL stage deadlines remain independently10s.
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, sess.OrgID, sess.UserID)
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	input, e := s.HTMLCreationSessions.NewDocumentPackageLayoutHTTPInputV1(ctx, sess.OrgID)
	if e != nil {
		writeError(w, http.StatusServiceUnavailable, "attachment input capacity is unavailable")
		return
	}
	defer input.CloseConsumerV1()
	if e = input.ReadLayoutHTTPV1(ctx, root, r.Body); e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	out, e := packageauthoring.SaveLayoutV1(ctx, packageauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Storage: s.Storage, Audit: s.Audit},
		authoring.Actor{OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize}, input, firstIPFromHeader(r), r.UserAgent())
	if e != nil {
		status, message := packageauthoring.PublicErrorV1(e)
		writeError(w, status, message)
		return
	}
	if out.Cause != nil {
		slog.Warn("Hash attachment layout requires reconciliation", "state", out.State, "error_type", fmt.Sprintf("%T", out.Cause))
		out.Cause = nil
	}
	status := http.StatusOK
	if out.State == "unknown" {
		status = http.StatusAccepted
	}
	writeJSON(w, status, out)
}
