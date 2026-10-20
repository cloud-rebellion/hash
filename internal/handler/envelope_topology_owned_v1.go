// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
)

func decodeEnvelopeStreamingInputV1(input *pdfadmission.ApplicationBlocksInputV1, r *http.Request, dst any) error {
	return input.WithStreamingBodyV1(r.Context(), r.Body, func(raw []byte) error { return json.NewDecoder(bytes.NewReader(raw)).Decode(dst) })
}
func (s *Server) mutateEnvelopeOwnedV1(r *http.Request, org, user uuid.UUID, tool string, input blockauthoring.EnvelopeInputV1) (*blockauthoring.EnvelopeResultV1, error) {
	authorize, err := s.sessionDraftAuthorization(r, org, user)
	if err != nil {
		return nil, err
	}
	return blockauthoring.EnvelopeV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions, Billing: s.Billing, Audit: s.Audit}, blockauthoring.ActorV1{OrgID: org, UserID: user, Authorize: authorize, Via: "rest", Tool: tool, IP: firstIPFromHeader(r), UserAgent: r.UserAgent()}, input)
}
func (s *Server) writeEnvelopeOwnedErrorV1(w http.ResponseWriter, tool string, err error) {
	if errors.Is(err, pdfadmission.ErrEnvelopeTopologyV1) || errors.Is(err, pdfadmission.ErrBlocksWriterV1) || errors.Is(err, pdfadmission.ErrBlocksInputV1) || errors.Is(err, pdfadmission.ErrApplicationAdmissionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionV1) || errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
		writeError(w, http.StatusServiceUnavailable, "envelope editing capacity unavailable; retry later")
		return
	}
	if tool == "promote_to_envelope" && (errors.Is(err, pgx.ErrNoRows) || errors.Is(err, blockauthoring.ErrEnvelopeTargetV1) || errors.Is(err, authoring.ErrDocumentNotFound) || errors.Is(err, authoring.ErrDocumentNotDraft)) {
		writeError(w, http.StatusNotFound, "document not found or not eligible (must be draft + blocks-source + not a child)")
		return
	}
	if status, ok := draftAuthoringErrorStatus(err); ok {
		writeError(w, status, err.Error())
		return
	}
	if tool == "promote_to_envelope" || tool == "attach_to_envelope" {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeInternalError(w, err)
}
