// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package handler ,  fields.go ships v1.2 fillable-field support beyond
// signatures. The document_fields schema (00004) already supports text,
// date, checkbox, dropdown, initial. This file adds:
//
//	,  sender REST + MCP to add/list/delete fields on a document
//	,  signer REST to fetch + submit field values via the magic-token surface
//	,  validation that required fields are filled before the sign step
//
// Field values land in `value` + `completed_at` columns and are surfaced
// via the existing audit timeline as `document.field_filled` events so
// the evidence bundle includes them automatically.
package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	fieldmutations "github.com/bright-interaction/hash/internal/fields"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/sign"
)

// pctToNumeric encodes a 0..100 percent-of-page coordinate as a
// pgtype.Numeric with 4 fractional digits (basis-point precision).
// document_fields stores NUMERIC(7,4); rounding past the 4th decimal
// is acceptable for PDF stamp coordinates.
func pctToNumeric(f float64) pgtype.Numeric {
	scaled := int64(f * 10000)
	return pgtype.Numeric{Int: big.NewInt(scaled), Exp: -4, Valid: true}
}

// numericToFloat reverses pctToNumeric for JSON responses. Returns 0
// when invalid so the client never sees null in a coordinate slot.
func numericToFloat(n pgtype.Numeric) float64 {
	if !n.Valid || n.Int == nil {
		return 0
	}
	f, _ := new(big.Float).SetInt(n.Int).Float64()
	return f * pow10(int(n.Exp))
}

func pow10(e int) float64 {
	p := 1.0
	switch {
	case e >= 0:
		for i := 0; i < e; i++ {
			p *= 10
		}
	default:
		for i := 0; i < -e; i++ {
			p /= 10
		}
	}
	return p
}

// textOrNull returns an empty pgtype.Text when s is empty so we keep
// NULL semantics for optional columns.
func textOrNull(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

// sha256Hex hashes a value for audit logs so we record that the field
// was filled (and what hash to compare against on dispute) without
// putting PII in the events stream.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fieldKindAllowed restricts the field types that a sender may add via
// the REST surface. The 'signature' + 'date_signed' + 'name_auto' kinds
// are managed by the sign engine itself; senders must not insert them
// by hand or the audit cert will diverge.
func fieldKindAllowed(kind string) bool {
	switch kind {
	case "text", "date", "checkbox", "dropdown", "initial":
		return true
	}
	return false
}

type addFieldInput struct {
	ExpectedPDFSHA256            string         `json:"expected_pdf_sha256,omitempty"`
	ExpectedHTMLSourceCommitment string         `json:"expected_html_source_commitment,omitempty"`
	RecipientID                  string         `json:"recipient_id"`
	Type                         string         `json:"type"`
	Page                         int            `json:"page"`
	XPct                         float64        `json:"x_pct"`
	YPct                         float64        `json:"y_pct"`
	WPct                         float64        `json:"w_pct"`
	HPct                         float64        `json:"h_pct"`
	Required                     *bool          `json:"required"`
	Label                        string         `json:"label"`
	Options                      map[string]any `json:"options"`
}

// POST /api/v1/documents/{id}/fields
//
// Sender adds a fillable field overlay (text/date/checkbox/dropdown/initial)
// to the document. Coordinates are page-percentage so the same field
// renders correctly across PDF page sizes. Recipient assignment is
// optional; nil means "any recipient".
func (s *Server) handleAddField(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
	var in addFieldInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	var recipientID *uuid.UUID
	if in.RecipientID != "" {
		id, err := uuid.Parse(in.RecipientID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "recipient_id must be a uuid")
			return
		}
		recipientID = &id
	}
	required := true
	if in.Required != nil {
		required = *in.Required
	}
	optionsJSON := json.RawMessage(`{}`)
	if in.Options != nil {
		raw, err := json.Marshal(in.Options)
		if err != nil {
			writeInternalErrorMsg(w, "encode field options", err)
			return
		}
		optionsJSON = raw
	}
	actor, ok := s.fieldMutationActor(w, r, sess)
	if !ok {
		return
	}
	actor.ExpectedPDFSHA256 = in.ExpectedPDFSHA256
	actor.ExpectedHTMLSourceCommitment = in.ExpectedHTMLSourceCommitment
	engine := fieldmutations.MutationEngine{Pool: s.Pool, Audit: s.Audit}
	owned, err := engine.CreateOwnedV1(r.Context(), s.HTMLCreationSessions, actor, docID, fieldmutations.CreateInput{
		RecipientID: recipientID, Type: in.Type, Page: in.Page,
		XPct: in.XPct, YPct: in.YPct, WPct: in.WPct, HPct: in.HPct,
		Required: required, Label: in.Label, Options: optionsJSON,
	})
	if owned != nil {
		defer owned.CloseConsumerV1()
	}
	if err != nil {
		s.writeFieldMutationError(w, "create field", err)
		return
	}
	writeJSON(w, http.StatusCreated, fieldToDTO(owned.Field))
}

// GET /api/v1/documents/{id}/fields
func (s *Server) handleListFields(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	docID, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if _, err := s.Queries.GetActiveDocumentIdentity(r.Context(), generated.GetActiveDocumentIdentityParams{ID: docID, OrgID: sess.OrgID}); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "document not found")
			return
		}
		writeInternalError(w, err)
		return
	}
	rows, err := s.Queries.ListFieldsByDocument(r.Context(), docID)
	if err != nil {
		writeInternalError(w, err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, f := range rows {
		out = append(out, fieldToDTO(f))
	}
	writeJSON(w, http.StatusOK, map[string]any{"fields": out, "count": len(out)})
}

// DELETE /api/v1/fields/{id}
func (s *Server) handleDeleteField(w http.ResponseWriter, r *http.Request) {
	sess, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ownerDoc, err := s.Queries.GetFieldOwnerDoc(r.Context(), generated.GetFieldOwnerDocParams{ID: id, OrgID: sess.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "field not found")
		return
	}
	if err != nil {
		writeInternalError(w, err)
		return
	}
	var in struct {
		ExpectedPDFSHA256            string `json:"expected_pdf_sha256,omitempty"`
		ExpectedHTMLSourceCommitment string `json:"expected_html_source_commitment,omitempty"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 16*1024)
		if err := decodeSignerJSON(r, &in); err != nil {
			writeError(w, http.StatusBadRequest, "invalid field deletion proof: "+err.Error())
			return
		}
	}
	actor, ok := s.fieldMutationActor(w, r, sess)
	if !ok {
		return
	}
	actor.ExpectedPDFSHA256 = in.ExpectedPDFSHA256
	actor.ExpectedHTMLSourceCommitment = in.ExpectedHTMLSourceCommitment
	engine := fieldmutations.MutationEngine{Pool: s.Pool, Audit: s.Audit}
	if _, err := engine.Delete(r.Context(), actor, ownerDoc, id); err != nil {
		s.writeFieldMutationError(w, "delete field", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) fieldMutationActor(w http.ResponseWriter, r *http.Request, sess auth.SessionUser) (fieldmutations.Actor, bool) {
	authorize, ok := s.sessionMutationAuthorization(w, r, sess)
	if !ok {
		return fieldmutations.Actor{}, false
	}
	return fieldmutations.Actor{
		OrgID: sess.OrgID, UserID: sess.UserID, Authorize: authorize,
		Via: "rest", IP: clientIP(r), UserAgent: r.UserAgent(),
	}, true
}

func (s *Server) writeFieldMutationError(w http.ResponseWriter, operation string, err error) {
	var validationErr *fieldmutations.ValidationError
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, http.StatusUnauthorized, "credential expired before transaction committed")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, http.StatusForbidden, "permission or credential revoked")
	case errors.Is(err, fieldmutations.ErrDocumentNotFound):
		writeError(w, http.StatusNotFound, "document not found")
	case errors.Is(err, fieldmutations.ErrFieldNotFound):
		writeError(w, http.StatusNotFound, "field not found")
	case errors.Is(err, fieldmutations.ErrRecipientNotFound):
		writeError(w, http.StatusNotFound, "recipient not found in document")
	case errors.Is(err, fieldmutations.ErrDocumentNotDraft):
		writeError(w, http.StatusConflict, "document not editable (must be draft)")
	case errors.Is(err, fieldmutations.ErrHTMLArtifactChanged):
		writeError(w, http.StatusConflict, fieldmutations.ErrHTMLArtifactChanged.Error())
	case errors.Is(err, fieldmutations.ErrDocumentHasEvidence):
		writeError(w, http.StatusConflict, "document contains retained signing evidence or sealing state; review before editing fields")
	case errors.Is(err, fieldmutations.ErrFieldLimitReached):
		writeError(w, http.StatusConflict, "document field limit reached")
	case errors.Is(err, fieldmutations.ErrPrivacyReviewChanging):
		writeError(w, http.StatusConflict, "privacy review is changing; retry after it completes")
	case errors.Is(err, fieldmutations.ErrPendingPrivacyReview):
		writeError(w, http.StatusConflict, "field changes await the open privacy request review")
	case errors.As(err, &validationErr):
		writeError(w, http.StatusBadRequest, validationErr.Error())
	default:
		writeInternalErrorMsg(w, operation, err)
	}
}

// GET /sign/{token}/fields
//
// Signer fetches the fillable fields scoped to their recipient row
// (plus any unassigned fields). Used by the signer page to render input
// widgets above the document body.
func (s *Server) handleSignerListFields(w http.ResponseWriter, r *http.Request) {
	rc, ok := s.lookupTokenOrErrorV1(w, r, pdfadmission.SignerReadDiagnosticFieldsV1)
	if !ok {
		return
	}
	defer closeSignerReadConsumerV1(rc)
	observation, err := s.captureSignerReadObservation(r, rc)
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	page, err := s.Sign.SignerFieldListV1(r.Context(), rc, func(fresh *sign.RecipientContext) error {
		return s.validateSignerReadObservation(r, rc, observation, fresh)
	})
	if err != nil {
		writeSignerReadError(w, err)
		return
	}
	defer page.CloseConsumerV1()
	setSignerPDFObservationHeaders(w, observation.pdf)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page.JSON)
}

type submitFieldValueInput = pdfadmission.SignerFieldValueInputV1

type submitFieldsInput struct {
	Values []submitFieldValueInput `json:"values"`
}

type preparedSignerFieldValue struct {
	field *generated.DocumentField
	value string
}

type signerFieldValidationError struct {
	status  int
	message string
}

const maxSignerFieldValueBytes = 4096

func validateSignerFieldValue(field *generated.DocumentField, value string) error {
	if field == nil {
		return errors.New("field is unavailable")
	}
	if len(value) > maxSignerFieldValueBytes || !utf8.ValidString(value) {
		return fmt.Errorf("must be valid UTF-8 and at most %d bytes", maxSignerFieldValueBytes)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return errors.New("must not contain control characters")
		}
	}
	if value == "" {
		return nil
	}

	switch field.Type {
	case "text":
		return nil
	case "initial":
		if utf8.RuneCountInString(value) > 6 {
			return errors.New("must contain at most 6 characters")
		}
		return nil
	case "date":
		parsed, err := time.Parse("2006-01-02", value)
		if err != nil || parsed.Format("2006-01-02") != value {
			return errors.New("must use YYYY-MM-DD")
		}
		return nil
	case "checkbox":
		if value != "true" && value != "false" {
			return errors.New("must be true or false")
		}
		return nil
	case "dropdown":
		var options struct {
			Choices []string `json:"choices"`
		}
		if err := json.Unmarshal(field.OptionsJson, &options); err != nil {
			return errors.New("has invalid configured choices")
		}
		for _, choice := range options.Choices {
			if value == choice {
				return nil
			}
		}
		return errors.New("must match a configured choice")
	default:
		return errors.New("has unsupported field type")
	}
}

func prepareSignerFieldValues(allowed []*generated.DocumentField, values []submitFieldValueInput) ([]preparedSignerFieldValue, *signerFieldValidationError) {
	allowedSet := make(map[string]*generated.DocumentField, len(allowed))
	for _, field := range allowed {
		if field != nil {
			allowedSet[field.ID.String()] = field
		}
	}
	seen := make(map[string]struct{}, len(values))
	prepared := make([]preparedSignerFieldValue, 0, len(values))
	for _, input := range values {
		if _, duplicate := seen[input.FieldID]; duplicate {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "duplicate field_id: " + input.FieldID}
		}
		seen[input.FieldID] = struct{}{}
		field, ok := allowedSet[input.FieldID]
		if !ok {
			return nil, &signerFieldValidationError{status: http.StatusForbidden, message: "field_id not assigned to this recipient: " + input.FieldID}
		}
		if field.Type == "signature" {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "signature fields are signed, not filled: " + input.FieldID}
		}
		value := strings.TrimSpace(input.Value)
		if field.Required && value == "" {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "field is required: " + input.FieldID}
		}
		if err := validateSignerFieldValue(field, value); err != nil {
			return nil, &signerFieldValidationError{status: http.StatusBadRequest, message: "invalid " + field.Type + " field value: " + err.Error()}
		}
		prepared = append(prepared, preparedSignerFieldValue{field: field, value: value})
	}
	return prepared, nil
}

// POST /sign/{token}/fields
//
// Signer submits one or more field values. The handler validates each
// field belongs to either this recipient or is unassigned, then updates
// `value` + `completed_at`. Emits document.field_filled for each value
// so the audit timeline reflects the submission.
func (s *Server) handleSignerSubmitFields(w http.ResponseWriter, r *http.Request) {
	s.handleSignerSubmitFieldsOwnedV1(w, r)
}

func recipientCanFillFields(status string) bool {
	switch status {
	case "pending", "sent", "viewed":
		return true
	default:
		return false
	}
}

// fieldToDTO renders one document_fields row for the JSON API. The
// `value` column is included so the sender + signer pages can show
// previously-submitted values; `completed_at` lets the UI badge a
// field as already-filled.
func fieldToDTO(f *generated.DocumentField) map[string]any {
	return pdfadmission.DocumentFieldDTOV1(f)
}

// audit log records the SHA-256 hash of the submitted value, never the
// value itself, so PII (names, addresses, free-text answers) doesn't
// leak into the audit trail. The full value lives in document_fields
// where org-scoped reads gate it.
func hashFieldValueForAudit(v string) string {
	if v == "" {
		return ""
	}
	return sha256Hex(v)
}
