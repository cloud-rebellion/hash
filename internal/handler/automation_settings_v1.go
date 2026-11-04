// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) CloudRebellion
package handler

import (
	"errors"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/remindercadence"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) automationActorV1(w http.ResponseWriter, r *http.Request) (authoring.Actor, bool) {
	w.Header().Set("Cache-Control", "no-store")
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, false
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeAutomationErrorV1(w, err)
		return authoring.Actor{}, false
	}
	if s.Send == nil {
		s.writeAutomationErrorV1(w, send.ErrAutomationUnavailableV1)
		return authoring.Actor{}, false
	}
	return authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, true
}
func (s *Server) writeAutomationErrorV1(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, send.ErrAutomationUnavailableV1):
		writeError(w, 503, "Automation settings are unavailable. Reload and inspect before repeating an uncertain save.")
	case errors.Is(err, send.ErrAutomationInputV1), errors.Is(err, remindercadence.ErrPolicyV1):
		writeError(w, 400, "Check the required automation fields and finite day/count limits.")
	case errors.Is(err, send.ErrAutomationNotFoundV1):
		writeError(w, 404, "Automation target not found.")
	case errors.Is(err, send.ErrAutomationStaleV1):
		writeError(w, 409, "Automation settings changed. Reload and review before saving.")
	case errors.Is(err, send.ErrAutomationNotEditableV1):
		writeError(w, 409, "Only an editable signing draft can change its reminder policy.")
	case errors.Is(err, send.ErrAutomationObservationV1):
		writeError(w, 412, "The document changed. Reload and review before saving its reminder policy.")
	default:
		if status, known := draftAuthoringErrorStatus(err); known {
			writeError(w, status, "Automation authorization or editability changed.")
		} else {
			writeError(w, 503, "Automation settings are unavailable. Reload and inspect before repeating an uncertain save.")
		}
	}
}
func (s *Server) handleGetAutomationPreferencesV1(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.automationActorV1(w, r)
	if !ok {
		return
	}
	out, err := s.Send.AutomationPreferencesV1(r.Context(), actor, nil)
	if err != nil {
		s.writeAutomationErrorV1(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleSaveAutomationPreferencesV1(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.automationActorV1(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var in struct {
		ExpectedRevision *int64 `json:"expected_revision"`
		NotifyViewed     *bool  `json:"notify_viewed"`
		NotifySigned     *bool  `json:"notify_signed"`
	}
	if decodeSignerJSON(r, &in) != nil || in.ExpectedRevision == nil || in.NotifyViewed == nil || in.NotifySigned == nil {
		s.writeAutomationErrorV1(w, send.ErrAutomationInputV1)
		return
	}
	out, err := s.Send.AutomationPreferencesV1(r.Context(), actor, &send.AutomationPreferencesInputV1{ExpectedRevision: *in.ExpectedRevision, NotifyViewed: *in.NotifyViewed, NotifySigned: *in.NotifySigned})
	if err != nil {
		s.writeAutomationErrorV1(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func decodeReminderPolicyV1(w http.ResponseWriter, r *http.Request, document bool) (send.ReminderPolicyInputV1, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 2048)
	var base struct {
		ExpectedRevision *int64  `json:"expected_revision"`
		Mode             *string `json:"mode"`
		IntervalDays     *int    `json:"interval_days"`
		MaxFires         *int    `json:"max_fires"`
	}
	var observed *time.Time
	if document {
		var wire struct {
			ExpectedRevision  *int64     `json:"expected_revision"`
			ExpectedUpdatedAt *time.Time `json:"expected_updated_at"`
			Mode              *string    `json:"mode"`
			IntervalDays      *int       `json:"interval_days"`
			MaxFires          *int       `json:"max_fires"`
		}
		if decodeSignerJSON(r, &wire) != nil || wire.ExpectedUpdatedAt == nil {
			return send.ReminderPolicyInputV1{}, send.ErrAutomationInputV1
		}
		base.ExpectedRevision = wire.ExpectedRevision
		base.Mode = wire.Mode
		base.IntervalDays = wire.IntervalDays
		base.MaxFires = wire.MaxFires
		observed = wire.ExpectedUpdatedAt
	} else if decodeSignerJSON(r, &base) != nil {
		return send.ReminderPolicyInputV1{}, send.ErrAutomationInputV1
	}
	if base.ExpectedRevision == nil || base.Mode == nil || base.IntervalDays == nil || base.MaxFires == nil {
		return send.ReminderPolicyInputV1{}, send.ErrAutomationInputV1
	}
	out := send.ReminderPolicyInputV1{ExpectedRevision: *base.ExpectedRevision, PolicyV1: remindercadence.PolicyV1{Mode: *base.Mode, IntervalDays: *base.IntervalDays, MaxFires: *base.MaxFires}}
	if observed != nil {
		out.ExpectedUpdatedAt = *observed
	}
	return out, nil
}
func (s *Server) handleTemplateReminderPolicyV1(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.automationActorV1(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeAutomationErrorV1(w, send.ErrAutomationInputV1)
		return
	}
	var in *send.ReminderPolicyInputV1
	if r.Method == http.MethodPut {
		value, err := decodeReminderPolicyV1(w, r, false)
		if err != nil {
			s.writeAutomationErrorV1(w, err)
			return
		}
		in = &value
	}
	out, err := s.Send.TemplateReminderPolicyV1(r.Context(), actor, id, in)
	if err != nil {
		s.writeAutomationErrorV1(w, err)
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) handleDocumentReminderPolicyV1(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.automationActorV1(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		s.writeAutomationErrorV1(w, send.ErrAutomationInputV1)
		return
	}
	var in *send.ReminderPolicyInputV1
	if r.Method == http.MethodPut {
		value, err := decodeReminderPolicyV1(w, r, true)
		if err != nil {
			s.writeAutomationErrorV1(w, err)
			return
		}
		in = &value
	}
	out, err := s.Send.DocumentReminderPolicyV1(r.Context(), actor, id, in)
	if err != nil {
		s.writeAutomationErrorV1(w, err)
		return
	}
	writeJSON(w, 200, out)
}
