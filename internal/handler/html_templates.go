// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

var errHTMLTemplateConflict = errors.New("HTML template revision changed or is not approved")

type htmlTemplateInput struct {
	Name            string          `json:"name"`
	HTMLMasterJSON  json.RawMessage `json:"html_master_json"`
	VariablesJSON   json.RawMessage `json:"variables_json"`
	ExpectedVersion int32           `json:"expected_version,omitempty"`
}

// decodeHTMLMasterJSON retains the same strict interpretation as legal JSON
// while permitting the separately bounded inline assets of an HTML design.
func decodeHTMLMasterJSON(r *http.Request, dst any) error {
	raw, err := readHTMLAuthoringInputJSONV1(r, htmlmaster.MaxMasterJSONBytes+(2<<20))
	if err != nil {
		return err
	}
	if err := validateUniqueJSONObject(raw); err != nil {
		return err
	}
	if err := validateExactJSONFieldNames(raw, dst); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func parseHTMLTemplateInput(r *http.Request) (htmlTemplateInput, htmlmaster.TemplateCommitment, error) {
	var in htmlTemplateInput
	var committed htmlmaster.TemplateCommitment
	if err := decodeHTMLMasterJSON(r, &in); err != nil {
		return in, committed, err
	}
	if strings.TrimSpace(in.Name) == "" || utf8.RuneCountInString(in.Name) > 200 || strings.ContainsRune(in.Name, '\x00') {
		return in, committed, errors.New("name must contain 1 to 200 characters")
	}
	if len(in.VariablesJSON) == 0 {
		in.VariablesJSON = json.RawMessage("{}")
	}
	committed, err := canonicalHTMLAuthoringInputV1(r, in.HTMLMasterJSON, in.VariablesJSON)
	return in, committed, err
}

// Scan the actual embedded resources, not merely their base64 representation.
// Structural validation has already bounded and checked these bytes.
func scanHTMLMaster(ctx context.Context, canonical []byte) error {
	if err := malwarescan.ScanActive(ctx, canonical); err != nil {
		return err
	}
	master, err := htmlmaster.Decode(canonical)
	if err != nil {
		return err
	}
	for _, asset := range master.Assets {
		raw, err := base64.StdEncoding.Strict().DecodeString(asset.DataBase64)
		if err != nil {
			return err
		}
		if err := malwarescan.ScanActive(ctx, raw); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) handleCreateHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLTemplateMasterInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	in, content, err := parseHTMLTemplateInput(r)
	if err != nil {
		if writeHTMLAuthoringInputFailureV1(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.ExpectedVersion != 0 {
		writeError(w, http.StatusBadRequest, "expected_version is only valid when editing a template")
		return
	}
	if err := scanHTMLMaster(r.Context(), content.MasterJSON); err != nil {
		writeScanError(w, err)
		return
	}
	t, closeConsumer, err := s.writeHTMLTemplateOwnedV1(r, u.UserID, u.OrgID, uuid.Nil, in, content)

	if err != nil {
		s.writeHTMLTemplateError(w, "create HTML template", err)
		return
	}
	defer closeConsumer()
	writeTemplateResponse(w, http.StatusCreated, t)
}

func (s *Server) handleUpdateHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLTemplateMasterInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	in, content, err := parseHTMLTemplateInput(r)
	if err != nil {
		if writeHTMLAuthoringInputFailureV1(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.ExpectedVersion <= 0 {
		writeError(w, http.StatusPreconditionRequired, "expected_version is required")
		return
	}
	if err := scanHTMLMaster(r.Context(), content.MasterJSON); err != nil {
		writeScanError(w, err)
		return
	}
	t, closeConsumer, err := s.writeHTMLTemplateOwnedV1(r, u.UserID, u.OrgID, id, in, content)

	if err != nil {
		s.writeHTMLTemplateError(w, "update HTML template", err)
		return
	}
	defer closeConsumer()
	writeTemplateResponse(w, http.StatusOK, t)
}

type htmlTemplateApprovalInput struct {
	ExpectedVersion          int32  `json:"expected_version"`
	ExpectedContentSHA256    string `json:"expected_content_sha256"`
	PreviewReceipt           string `json:"preview_receipt"`
	ExpectedPreviewPDFSHA256 string `json:"expected_preview_pdf_sha256"`
}

func (s *Server) handleApproveHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	if !s.requireHTMLAuthoringRuntimeV1(w) {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r, closeInput, inputOK := s.beginHTMLAuthoringInputV1(w, r, u.OrgID, pdfadmission.HTMLTemplateApprovalInputV1)
	if !inputOK {
		return
	}
	defer closeInput()
	var in htmlTemplateApprovalInput
	if err := decodeSignerJSON(r, &in); err != nil {
		if writeHTMLAuthoringInputFailureV1(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := hex.DecodeString(in.ExpectedContentSHA256)
	if err != nil || len(digest) != 32 || in.ExpectedVersion <= 0 || in.ExpectedContentSHA256 != strings.ToLower(in.ExpectedContentSHA256) {
		writeError(w, http.StatusBadRequest, "expected_version and lowercase content SHA-256 are required")
		return
	}
	pdfDigest, err := hex.DecodeString(in.ExpectedPreviewPDFSHA256)
	if err != nil || len(pdfDigest) != 32 || in.ExpectedPreviewPDFSHA256 != strings.ToLower(in.ExpectedPreviewPDFSHA256) ||
		in.PreviewReceipt == "" || len(in.PreviewReceipt) > 8192 {
		writeError(w, http.StatusBadRequest, "a saved-design preview receipt and lowercase preview PDF SHA-256 are required")
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML template approval", err)
		return
	}
	preview, err := s.validateHTMLTemplatePreviewReceipt(r, u, id, in.ExpectedVersion, in.ExpectedContentSHA256, in.ExpectedPreviewPDFSHA256, in.PreviewReceipt)
	if err != nil {
		s.writeHTMLTemplateError(w, "verify HTML template preview", err)
		return
	}
	// The same proof deadline is checked when retaining the live owner and after
	// the chained audit append. Expiry during an audit lock wait rolls back the
	// approval and audit together.
	actor.Authorize = htmlTemplatePreviewReceiptAuthorization(actor.Authorize, preview)
	revision, closeConsumer, err := s.approveHTMLTemplateOwnedV1(r.Context(), actor, id, in, digest, preview)

	if err != nil {
		s.writeHTMLTemplateError(w, "approve HTML template", err)
		return
	}
	defer closeConsumer()
	writeJSON(w, http.StatusOK, map[string]any{
		"template_id": id, "version": revision.Version, "content_sha256": in.ExpectedContentSHA256,
		"approved_by": uuid.UUID(revision.ApprovedBy.Bytes), "approved_at": revision.ApprovedAt.Time,
	})
}

func (s *Server) writeHTMLTemplateError(w http.ResponseWriter, operation string, err error) {
	if observed, captured := pdfadmission.ApplicationSessionStartObservationForV1(err); captured {
		slog.Warn("owned application session startup failed", "phase", int(observed.Phase),
			"error_class", int(observed.ErrorClass), "start_context_state", int(observed.ContextState))
	}
	if errors.Is(err, pdfadmission.ErrHTMLAuthoringReadV1) {
		writeError(w, http.StatusServiceUnavailable, "HTML authoring is temporarily unavailable")
		return
	}
	if errors.Is(err, errHTMLTemplatePreviewReceipt) {
		writeError(w, http.StatusConflict, "saved-design preview is invalid, changed or expired; preview and review it again")
		return
	}
	if errors.Is(err, errHTMLTemplateConflict) || errors.Is(err, pdfadmission.ErrHTMLAuthoringKindV1) || errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "HTML template revision changed or is unavailable; refresh and review it again")
		return
	}
	if errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrMissingValues) || errors.Is(err, htmlmaster.ErrContractIncomplete) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeTemplateMutationError(w, operation, err)
}
