// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/json"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"net/http"
)

func (s *Server) newBlocksHTTPInputV1(w http.ResponseWriter, r *http.Request, org uuid.UUID) (*pdfadmission.ApplicationBlocksInputV1, bool) {
	input, err := s.HTMLCreationSessions.NewBlocksHTTPInputV1(r.Context(), org)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "block input capacity unavailable")
		return nil, false
	}
	return input, true
}
func decodeBlocksStreamingInputV1(input *pdfadmission.ApplicationBlocksInputV1, r *http.Request, dst any) error {
	return input.WithStreamingBodyV1(r.Context(), r.Body, func(raw []byte) error {
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		return decoder.Decode(dst)
	})
}
