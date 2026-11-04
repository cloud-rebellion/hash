// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/workspacesmtp"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) workspaceSMTPService() workspacesmtp.Service {
	return workspacesmtp.Service{Pool: s.Pool, Audit: s.Audit, Box: s.StaffAuthMailBox}
}
func (s *Server) workspaceSMTPActor(w http.ResponseWriter, r *http.Request) (authoring.Actor, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, false
	}
	a, e := s.sessionOwnerActor(r, u)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return authoring.Actor{}, false
	}
	return a, true
}
func (s *Server) writeWorkspaceSMTPError(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, workspacesmtp.ErrInput):
		writeError(w, http.StatusBadRequest, "Check SMTP host, TLS mode/port, sender and credential action.")
	case errors.Is(e, workspacesmtp.ErrStale):
		writeError(w, http.StatusConflict, "SMTP revision changed. Reload and review.")
	case errors.Is(e, workspacesmtp.ErrTestBusy):
		writeError(w, http.StatusTooManyRequests, "An SMTP test is pending or was requested recently.")
	case errors.Is(e, workspacesmtp.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "Workspace SMTP unavailable or not configured.")
	default:
		s.writeDraftAuthoringError(w, "workspace SMTP operation", e)
	}
}
func (s *Server) handleGetWorkspaceSMTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	v, e := s.workspaceSMTPService().Get(r.Context(), a)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) handleSaveWorkspaceSMTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	raw, e := readHTMLAuthoringInputJSONV1(r, 32<<10)
	if e != nil {
		s.writeWorkspaceSMTPError(w, workspacesmtp.ErrInput)
		return
	}
	in, e := decodeWorkspaceSMTPInputJSON(raw)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}

	v, e := s.workspaceSMTPService().Save(r.Context(), a, in)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func decodeWorkspaceSMTPInputJSON(raw []byte) (workspacesmtp.Input, error) {
	var wire struct {
		ExpectedRevision  *int64          `json:"expected_revision"`
		Host              *string         `json:"host"`
		Port              *int            `json:"port"`
		TLSMode           *string         `json:"tls_mode"`
		SenderName        *string         `json:"sender_name"`
		SenderEmail       *string         `json:"sender_email"`
		CredentialsAction *string         `json:"credentials_action"`
		Username          json.RawMessage `json:"username"`
		Password          json.RawMessage `json:"password"`
	}
	if len(raw) > 32<<10 || decodeSignerJSONBytesV1(raw, &wire) != nil || wire.ExpectedRevision == nil || wire.Host == nil || wire.Port == nil || wire.TLSMode == nil || wire.SenderName == nil || wire.SenderEmail == nil || wire.CredentialsAction == nil {
		return workspacesmtp.Input{}, workspacesmtp.ErrInput
	}
	in := workspacesmtp.Input{ExpectedRevision: *wire.ExpectedRevision, Host: *wire.Host, Port: *wire.Port, TLSMode: *wire.TLSMode, SenderName: *wire.SenderName, SenderEmail: *wire.SenderEmail, CredentialsAction: *wire.CredentialsAction}
	for _, field := range []struct {
		raw    json.RawMessage
		target **string
	}{{wire.Username, &in.Username}, {wire.Password, &in.Password}} {
		if field.raw != nil {
			var value string
			if bytes.Equal(bytes.TrimSpace(field.raw), []byte("null")) || json.Unmarshal(field.raw, &value) != nil {
				return workspacesmtp.Input{}, workspacesmtp.ErrInput
			}
			*field.target = &value
		}
	}
	if in.CredentialsAction == "keep" && (wire.Username != nil || wire.Password != nil) {
		return workspacesmtp.Input{}, workspacesmtp.ErrInput
	}
	return in, nil
}
func (s *Server) workspaceSMTPRevision(w http.ResponseWriter, r *http.Request) (int64, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var in struct {
		ExpectedRevision *int64 `json:"expected_revision"`
	}
	if decodeSignerJSON(r, &in) != nil || in.ExpectedRevision == nil {
		s.writeWorkspaceSMTPError(w, workspacesmtp.ErrInput)
		return 0, false
	}
	return *in.ExpectedRevision, true
}
func (s *Server) handleDeleteWorkspaceSMTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	revision, ok := s.workspaceSMTPRevision(w, r)
	if !ok {
		return
	}
	v, e := s.workspaceSMTPService().Disable(r.Context(), a, revision)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
func (s *Server) handleTestWorkspaceSMTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	revision, ok := s.workspaceSMTPRevision(w, r)
	if !ok {
		return
	}
	v, e := s.workspaceSMTPService().Test(r.Context(), a, revision)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}
	writeJSON(w, http.StatusAccepted, v)
}
func (s *Server) handleWorkspaceSMTPTestStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	a, ok := s.workspaceSMTPActor(w, r)
	if !ok {
		return
	}
	id, e := uuid.Parse(chi.URLParam(r, "id"))
	if e != nil {
		s.writeWorkspaceSMTPError(w, workspacesmtp.ErrInput)
		return
	}
	v, e := s.workspaceSMTPService().TestStatus(r.Context(), a, id)
	if e != nil {
		s.writeWorkspaceSMTPError(w, e)
		return
	}
	writeJSON(w, http.StatusOK, v)
}
