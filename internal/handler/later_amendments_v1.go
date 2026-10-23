// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/amendmentauthoring"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5"
	"mime"
	"net/http"
	"time"
)

func writeLaterAmendmentErrorV1(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, auth.ErrMutationCredentialExpired):
		writeError(w, 401, "the original login has expired")
	case errors.Is(e, auth.ErrMutationPermissionRevoked), errors.Is(e, auth.ErrDocScopeMismatch):
		writeError(w, 403, "later amendment access is not permitted")
	case errors.Is(e, pgx.ErrNoRows), errors.Is(e, authoring.ErrDocumentNotFound):
		writeError(w, 404, "agreement or amendment not found")
	case errors.Is(e, amendments.ErrInputV1):
		writeError(w, 400, "invalid reviewed amendment request")
	case errors.Is(e, amendments.ErrChangedV1), errors.Is(e, authoring.ErrPendingPrivacyReview), errors.Is(e, authoring.ErrPrivacyReviewChanging):
		writeError(w, 409, "agreement, head or reviewed proposal changed; reload and review")
	case errors.Is(e, workguard.ErrUnavailableV1), errors.Is(e, pdfadmission.ErrBlocksInputV1):
		writeError(w, 503, "amendment processing capacity is unavailable")
	default:
		writeError(w, 503, "later amendment could not be completed")
	}
}
func (s *Server) handleLaterAmendmentsV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	out, e := amendmentauthoring.InventoryV1(ctx, amendmentauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, PublicURL: s.PublicURL}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleLaterAmendmentRelationV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	out, e := amendmentauthoring.RelationV1(ctx, amendmentauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, PublicURL: s.PublicURL}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleCreateLaterAmendmentV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		writeError(w, 415, "use application/json")
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil {
		writeLaterAmendmentErrorV1(w, amendments.ErrUnavailableV1)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	input, e := s.HTMLCreationSessions.NewBlocksHTTPInputV1(ctx, u.OrgID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	defer input.CloseConsumerV1()
	var in amendments.CreateV1
	if e = input.WithHTTPBodyV1(ctx, r.Body, func(raw []byte) error {
		if len(raw) > 32768 {
			return amendments.ErrInputV1
		}
		return decodeSignerJSONBytesV1(raw, &in)
	}); e != nil {
		writeLaterAmendmentErrorV1(w, errors.Join(amendments.ErrInputV1, e))
		return
	}
	out, e := amendmentauthoring.CreateV1(ctx, amendmentauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, PublicURL: s.PublicURL}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, in, firstIPFromHeader(r), r.UserAgent())
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	status := http.StatusCreated
	if out.UnknownV1() {
		status = http.StatusAccepted
	}
	writeJSON(w, status, out)
}
func (s *Server) handleIssueLaterAmendmentNoticeV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	amendmentID, ok := parseUUIDParam(w, r, "amendmentId")
	if !ok {
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/json" {
		writeError(w, 415, "use application/json")
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil || s.NoticeAccess == nil {
		writeLaterAmendmentErrorV1(w, amendments.ErrUnavailableV1)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	input, e := s.HTMLCreationSessions.NewBlocksHTTPInputV1(ctx, u.OrgID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	defer input.CloseConsumerV1()
	var in amendments.IssueNoticeV1
	if e = input.WithHTTPBodyV1(ctx, r.Body, func(raw []byte) error {
		if len(raw) > 32768 {
			return amendments.ErrInputV1
		}
		return decodeSignerJSONBytesV1(raw, &in)
	}); e != nil {
		writeLaterAmendmentErrorV1(w, errors.Join(amendments.ErrInputV1, e))
		return
	}
	out, e := amendmentauthoring.IssueNoticeV1(ctx, amendmentauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, PublicURL: s.PublicURL}, s.NoticeAccess, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, amendmentID, in, firstIPFromHeader(r), r.UserAgent())
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	status := 201
	if out.UnknownV1() {
		status = 202
	}
	writeJSON(w, status, out)
}
func (s *Server) handleRevokeLaterAmendmentNoticeAccessV1(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	amendmentID, ok := parseUUIDParam(w, r, "amendmentId")
	if !ok {
		return
	}
	accessID, ok := parseUUIDParam(w, r, "accessId")
	if !ok {
		return
	}
	if s.HTMLCreationSessions == nil || s.Audit == nil {
		writeLaterAmendmentErrorV1(w, amendments.ErrUnavailableV1)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	authorize, e := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	if r.ContentLength != 0 {
		input, e := s.HTMLCreationSessions.NewBlocksHTTPInputV1(ctx, u.OrgID)
		if e != nil {
			writeLaterAmendmentErrorV1(w, e)
			return
		}
		defer input.CloseConsumerV1()
		if e = input.WithHTTPBodyV1(ctx, r.Body, func(raw []byte) error {
			if len(raw) > 16 {
				return amendments.ErrInputV1
			}
			return decodeSignerJSONBytesV1(raw, &struct{}{})
		}); e != nil {
			writeLaterAmendmentErrorV1(w, amendments.ErrInputV1)
			return
		}
	}
	out, e := amendmentauthoring.RevokeV1(ctx, amendmentauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, PublicURL: s.PublicURL}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, amendmentID, accessID, firstIPFromHeader(r), r.UserAgent())
	if out != nil {
		defer out.CloseConsumerV1()
	}
	if e != nil {
		writeLaterAmendmentErrorV1(w, e)
		return
	}
	status := 200
	if out.UnknownV1() {
		status = 202
	}
	writeJSON(w, status, out)
}
