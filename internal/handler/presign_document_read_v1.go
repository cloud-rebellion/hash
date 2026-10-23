// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presignexecute"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
)

// A missing optional relation retains the historical route. Once an explicit
// execution exists, all errors are handled here; none can select the base PDF.
// Turning off new execution cannot erase retained published evidence access.
func (s *Server) tryStaffPreSignDocumentV1(w http.ResponseWriter, r *http.Request, org, document uuid.UUID, pdf bool) bool {
	if s.Pool == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	exists, err := generated.New(s.Pool).HasPresignExecutionForDocumentV1(ctx, generated.HasPresignExecutionForDocumentV1Params{OrgID: org, DocumentID: document})
	if err != nil {
		writePreSignExecutionErrorV1(w, presignregistry.ErrUnavailable)
		return true
	}
	if !exists {
		return false
	}
	if s.Send == nil || s.Sign == nil || s.Sign.PDF == nil || s.Storage == nil || s.Cookies == nil || s.Audit == nil {
		writePreSignExecutionErrorV1(w, presignregistry.ErrUnavailable)
		return true
	}
	session, err := s.presignActor(r)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return true
	}
	actor, err := presignregistry.NewSessionExecutionActorV1(session)
	if err != nil {
		writePreSignExecutionErrorV1(w, err)
		return true
	}
	service := &send.PreSignServiceV1{Send: s.Send, Registry: presignregistry.NewEngine(s.Pool, s.Audit, s.Cookies), Storage: s.Storage, PDF: s.Sign.PDF, Receipts: s.Cookies}
	wrote := false
	err = service.WithStaffPreSignV1(ctx, actor, document, pdf, func(d *generated.Document, view *presignexecute.DocumentViewV1, raw []byte) error {
		if !pdf {
			out := toDocumentResponse(d)
			out.PreSign = view
			wrote = true
			preSignResponseV1(w, out)
			return nil
		}
		setDocumentPreviewHeaders(w, false)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Disposition", "inline")
		wrote = true
		_, err := w.Write(raw)
		return err
	})
	if err != nil && !wrote {
		writePreSignExecutionErrorV1(w, err)
	}
	return true
}
