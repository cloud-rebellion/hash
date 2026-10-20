// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/pdftemplateauthoring"
	"net/http"
	"strings"
	"time"
)

type savePDFTemplateInput = pdflayout.ExportInputV1
type savePDFTemplateParty = pdflayout.ExportPartyV1

// Original public input, import guard, pre-inspection and locked draft policies
// are preserved by the fixed native producer; reusable layout contains no IDs,
// tokens, captured values or recipient identities.
func (s *Server) handleSavePDFTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	input, err := s.HTMLCreationSessions.NewBlocksHTTPInputV1(r.Context(), u.OrgID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "PDF layout input capacity unavailable")
		return
	}
	defer input.CloseConsumerV1()
	var in savePDFTemplateInput
	r.Body = http.MaxBytesReader(w, r.Body, 128*1024)
	if err = input.WithHTTPBodyV1(r.Context(), r.Body, func(raw []byte) error { return decodeSignerJSONBytesV1(raw, &in) }); err != nil {
		if errors.Is(err, pdfadmission.ErrBlocksInputV1) {
			writeError(w, http.StatusServiceUnavailable, "PDF layout input capacity unavailable")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > 800 {
		writeError(w, http.StatusBadRequest, "template name is required and must be at most 800 bytes")
		return
	}
	if in.ExpectedUpdatedAt == "" {
		writeError(w, http.StatusPreconditionRequired, "expected_updated_at is required")
		return
	}
	expected, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil {
		writeError(w, http.StatusBadRequest, "expected_updated_at must be RFC3339")
		return
	}
	if len(in.ExpectedFieldIDs) == 0 || len(in.ExpectedFieldIDs) > pdflayout.MaxFields || len(in.Parties) == 0 || len(in.Parties) > pdflayout.MaxParties {
		writeError(w, http.StatusBadRequest, "provide the observed signature field IDs and complete party slots")
		return
	}
	authorize, err := s.sessionDraftAuthorization(r, u.OrgID, u.UserID)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize PDF layout", err)
		return
	}
	if s.Pool == nil || s.Audit == nil || s.Storage == nil {
		writeInternalErrorMsg(w, "save PDF layout", errors.New("PDF layout dependencies unavailable"))
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		writeError(w, http.StatusTooManyRequests, "PDF layout inspection is busy; retry later")
		return
	}
	defer release()
	result, err := pdftemplateauthoring.CaptureV1(r.Context(), pdftemplateauthoring.CaptureDependenciesV1{Sessions: s.HTMLCreationSessions, Audit: s.Audit, Storage: s.Storage}, pdftemplateauthoring.CaptureActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, expected, in)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		switch {
		case errors.Is(err, pdflayout.ErrPrecondition), errors.Is(err, pdfadmission.ErrPDFLayoutSourceChangedV1), errors.Is(err, pdfadmission.ErrPDFLayoutInspectionChangedV1):
			writeError(w, http.StatusPreconditionFailed, err.Error())
		case errors.Is(err, pdflayout.ErrInvalid):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, pdfadmission.ErrPDFLayoutNotEditableV1), errors.Is(err, pdfadmission.ErrPDFLayoutHTMLSourceV1), errors.Is(err, pdfadmission.ErrPDFLayoutCommitmentV1):
			writeError(w, http.StatusConflict, err.Error())
		case errors.Is(err, pdfadmission.ErrPDFLayoutInspectionV1), errors.Is(err, pdfadmission.ErrPDFLayoutCaptureV1), errors.Is(err, pdfadmission.ErrApplicationSessionV1), errors.Is(err, pdfadmission.ErrApplicationAdmissionV1), errors.Is(err, pdfadmission.ErrHTMLRevisionReadV1), errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1):
			writeError(w, http.StatusServiceUnavailable, "PDF layout temporarily unavailable")
		default:
			s.writeDraftAuthoringError(w, "save PDF layout", err)
		}
		return
	}
	writeTemplateResponse(w, http.StatusCreated, result.Template)
}
func samePDFTemplateSource(a, b *generated.Document) bool {
	return pdflayout.SamePDFTemplateSourceV1(a, b)
}
func exportPDFLayout(doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, in savePDFTemplateInput, pages int32) (*pdflayout.Layout, error) {
	return pdflayout.ExportDocumentLayoutV1(doc, recs, fields, in, pages)
}
