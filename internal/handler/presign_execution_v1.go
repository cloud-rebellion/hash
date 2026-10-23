// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

func (s *Server) mountPresignExecutionRoutesV1(r chi.Router, api bool) {
	r.Route("/executions", func(r chi.Router) {
		r.Use(crmDocumentRateLimit(15))
		r.Get("/documents/{document_id}/eligibility", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignEligibilityV1(w, r, api) })
		r.Post("/preview", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignPreviewV1(w, r, api) })
		r.Post("/", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignConfirmV1(w, r, api) })
		r.Get("/requests/{request_id}", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignRecoverV1(w, r, api) })
		r.Post("/requests/{request_id}/close", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignCloseV1(w, r, api) })
	})
	// Exact no-trailing-slash POST remains the advertised request URI.
	r.Post("/executions", func(w http.ResponseWriter, r *http.Request) { s.handlePreSignConfirmV1(w, r, api) })
}
func (s *Server) preSignExecutionAvailableV1() bool {
	return s != nil && s.PreSignExecutionEnabled && s.Send != nil && s.Sign != nil && s.Sign.PDF != nil && s.Storage != nil && s.Cookies != nil && s.Audit != nil && s.Pool != nil
}
func (s *Server) preSignExecutionServiceV1(r *http.Request, api bool, document uuid.UUID) (*send.PreSignServiceV1, presignregistry.ExecutionActorV1, error) {
	var actor presignregistry.ExecutionActorV1
	if !s.preSignExecutionAvailableV1() {
		return nil, actor, presignregistry.ErrUnavailable
	}
	var err error
	if api {
		var credential auth.PreSignAPIAdmissionV1
		credential, err = auth.NewPreSignAPIAdmissionV1(r.Context(), document)
		if err == nil {
			actor, err = presignregistry.NewAPIExecutionActorV1(credential)
		}
	} else {
		var session presignregistry.SessionActor
		session, err = s.presignActor(r)
		if err == nil {
			actor, err = presignregistry.NewSessionExecutionActorV1(session)
		}
	}
	if err != nil {
		return nil, actor, err
	}
	return &send.PreSignServiceV1{Send: s.Send, Registry: presignregistry.NewEngine(s.Pool, s.Audit, s.Cookies), Storage: s.Storage, PDF: s.Sign.PDF, Receipts: s.Cookies}, actor, nil
}
func writePreSignExecutionErrorV1(w http.ResponseWriter, err error) {
	if stage := send.PreSignFailureStageV1(err); stage != "" {
		slog.Warn("pre-sign execution refused", "stage", stage)
	}
	switch {
	case errors.Is(err, presignexecute.ErrInvalid):
		writePresignError(w, presignregistry.ErrInvalid)
	case errors.Is(err, presignexecute.ErrConflict):
		writePresignError(w, presignregistry.ErrConflict)
	case errors.Is(err, pdfadmission.ErrPackageSendSelectionRequiredV1):
		writePresignError(w, presignregistry.ErrConflict)
	case errors.Is(err, presignexecute.ErrIntegrity):
		writePresignError(w, presignregistry.ErrUnavailable)
	case errors.Is(err, presignexecute.ErrPreparationPendingV1):
		writePresignError(w, presignregistry.ErrUnavailable)
	default:
		writePresignError(w, err)
	}
}
func preSignResponseV1(w http.ResponseWriter, value any) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, value)
}
func (s *Server) handlePreSignEligibilityV1(w http.ResponseWriter, r *http.Request, api bool) {
	document, err := presignUUIDParam(r, "document_id")
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	service, actor, err := s.preSignExecutionServiceV1(r, api, document)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := service.EligibilityV1(ctx, actor, document)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	preSignResponseV1(w, out)
}
func (s *Server) handlePreSignPreviewV1(w http.ResponseWriter, r *http.Request, api bool) {
	var in presignexecute.IntentV1
	if decodePresignJSON(r, &in) != nil {
		writePreSignExecutionErrorV1(w, presignexecute.ErrInvalid)
		return
	}
	service, actor, err := s.preSignExecutionServiceV1(r, api, in.DocumentID)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := service.PreviewV1(ctx, actor, in)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	preSignResponseV1(w, out)
}
func (s *Server) handlePreSignConfirmV1(w http.ResponseWriter, r *http.Request, api bool) {
	var in presignexecute.ConfirmV1
	if decodePresignJSON(r, &in) != nil {
		writePreSignExecutionErrorV1(w, presignexecute.ErrInvalid)
		return
	}
	service, actor, err := s.preSignExecutionServiceV1(r, api, in.Intent.DocumentID)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := service.ConfirmV1(ctx, actor, in)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	preSignResponseV1(w, out)
}
func (s *Server) handlePreSignRecoverV1(w http.ResponseWriter, r *http.Request, api bool) {
	request, err := presignUUIDParam(r, "request_id")
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	service, actor, err := s.preSignExecutionServiceV1(r, api, uuid.Nil)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := service.RecoverV1(ctx, actor, request)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	preSignResponseV1(w, out)
}
func (s *Server) handlePreSignCloseV1(w http.ResponseWriter, r *http.Request, api bool) {
	var in presignexecute.CloseV1
	request, err := presignUUIDParam(r, "request_id")
	if err != nil || decodePresignJSON(r, &in) != nil || in.RequestID != request {
		writePreSignExecutionErrorV1(w, presignexecute.ErrInvalid)
		return
	}
	service, actor, err := s.preSignExecutionServiceV1(r, api, uuid.Nil)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := service.CloseV1(ctx, actor, in)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return
	}
	preSignResponseV1(w, out)
}
