// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blockauthoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/pdftemplateauthoring"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const automationDocumentBodyLimit = 8 << 10

// These are organization machine operations, independent of MCP entitlement.
// A document agent or a cookie identity cannot become an organization API actor
// by supplying context-shaped fields: require the original private API receipt.
func requireAutomationDocumentScope(scope string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := automationDocumentActor(w, r, scope); !ok {
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requireAutomationDocumentRead(next http.Handler) http.Handler {
	return requireAutomationDocumentScope("read", next)
}

func requireAutomationDocumentWorkflow(next http.Handler) http.Handler {
	return requireAutomationDocumentScope("write:workflow", next)
}

func automationDocumentActor(w http.ResponseWriter, r *http.Request, scope string) (auth.SessionUser, bool) {
	u, ok := auth.FromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "not authenticated")
		return u, false
	}
	scopes, token := auth.TokenScopesFromContext(r.Context())
	if !token {
		writeError(w, http.StatusUnauthorized, "organization API key required")
		return u, false
	}
	if _, document := auth.DocumentScopeFromContext(r.Context()); document {
		writeError(w, http.StatusForbidden, "organization API key required")
		return u, false
	}
	explicit := false
	for _, granted := range scopes {
		if granted == scope {
			explicit = true
		}
	}
	if !explicit {
		writeError(w, http.StatusForbidden, "API key does not grant the required scope")
		return u, false
	}
	if _, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, scope); err != nil {
		writeError(w, http.StatusForbidden, "API key does not grant the required scope")
		return u, false
	}
	return u, true
}

// A short final read fence rechecks the same issuer and admitted key after a
// storage wait. The artifact body is neither copied nor buffered a second time.
func (s *Server) authorizeAutomationDocumentRead(ctx context.Context, u auth.SessionUser) error {
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, uuid.Nil, "read")
	if err != nil {
		return err
	}
	if s.Pool == nil {
		return errors.New("machine read authorization unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, sessionTransactionTimeout)
	defer cancel()
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer rollbackSessionTransaction(ctx, tx)
	user, err := s.Queries.WithTx(tx).GetUserForShare(ctx, generated.GetUserForShareParams{ID: u.UserID, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && user.Role != string(auth.RoleViewer) && user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner)) {
		return auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return err
	}
	if err = authorize(ctx, tx, user); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func writeAutomationDocumentReadError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, http.StatusUnauthorized, "credential expired")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, http.StatusForbidden, "permission or credential revoked")
	default:
		writeError(w, http.StatusServiceUnavailable, "document authorization temporarily unavailable")
	}
}

func (s *Server) handleAutomationListDocuments(w http.ResponseWriter, r *http.Request) {
	if _, ok := automationDocumentActor(w, r, "read"); !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.handleListDocuments(w, r)
}

func (s *Server) handleAutomationGetDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), sessionTransactionTimeout)
	defer cancel()
	delegated, err := s.Queries.HasPresignExecutionForDocumentV1(ctx, generated.HasPresignExecutionForDocumentV1Params{OrgID: u.OrgID, DocumentID: id})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "document metadata temporarily unavailable")
		return
	}
	if delegated {
		writeError(w, http.StatusConflict, "delegated document requires its publication workflow")
		return
	}
	s.handleGetDocument(w, r)
}

// Source PDF is the saved source, not the executed contract. Preserve the
// existing preview snapshot and live-credential checks with API provenance.
func (s *Server) handleAutomationDocumentPDF(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resolver.PreviewTimeout)
	defer cancel()
	// Delegated publication has a separate verified visible-PDF reader. Never
	// fall back to its pre-execution base PDF through an ordinary machine read.
	delegated, err := s.Queries.HasPresignExecutionForDocumentV1(ctx, generated.HasPresignExecutionForDocumentV1Params{OrgID: u.OrgID, DocumentID: id})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "document source temporarily unavailable")
		return
	}
	if delegated {
		writeError(w, http.StatusConflict, "delegated document source requires its publication workflow")
		return
	}
	doc, err := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "get machine source document failed", err)
		return
	}
	if !doc.PdfStorageKey.Valid || doc.PdfStorageKey.String == "" {
		writeError(w, http.StatusNotFound, "document has no source pdf")
		return
	}
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, id, "read")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	body, err := readDocumentArtifact(ctx, s.Storage, doc, doc.PdfStorageKey.String, doc.PdfSha256, doc.PdfStorageVersionID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "load pdf failed")
		return
	}
	if err = resolver.CheckPreview(ctx, s.Pool, doc, nil, u.UserID, authorize); err != nil {
		s.writePreviewError(w, err)
		return
	}
	setDocumentPreviewHeaders(w, false)
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	_, _ = w.Write(body)
}

func (s *Server) handleAutomationFinalPDF(w http.ResponseWriter, r *http.Request) {
	s.handleAutomationCompletedArtifact(w, r, false)
}

func (s *Server) handleAutomationAuditCert(w http.ResponseWriter, r *http.Request) {
	s.handleAutomationCompletedArtifact(w, r, true)
}

func (s *Server) handleAutomationCompletedArtifact(w http.ResponseWriter, r *http.Request, certificate bool) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), resolver.PreviewTimeout)
	defer cancel()
	doc, err := s.Queries.GetDocument(ctx, generated.GetDocumentParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "document not found")
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "get machine completed document failed", err)
		return
	}
	if doc.Status != "completed" {
		writeError(w, http.StatusConflict, "document is not completed")
		return
	}
	key, version, digest, suffix := doc.FinalPdfKey, doc.FinalPdfVersionID, doc.FinalPdfSha, ".pdf"
	if certificate {
		key, version, digest, suffix = doc.AuditCertKey, doc.AuditCertVersionID, doc.AuditCertSha256, "-audit.pdf"
		if len(digest) != sha256.Size && !doc.EvidenceVersionPinsRequired {
			digest = contentAddressedDigest(key.String, "audit", ".pdf")
		}
	}
	if !key.Valid || key.String == "" {
		writeError(w, http.StatusNotFound, "completed artifact is not available")
		return
	}
	body, err := readDocumentArtifact(ctx, s.Storage, doc, key.String, digest, version)
	if err != nil {
		writeInternalErrorMsg(w, "read machine completed artifact failed", err)
		return
	}
	if certificate && !contentAddressedArtifactMatches(body, key.String, "audit", ".pdf") {
		writeInternalErrorMsg(w, "machine certificate commitment mismatch", errors.New("stored audit certificate digest differs from its immutable key"))
		return
	}
	if err = s.authorizeAutomationDocumentRead(ctx, u); err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+sanitizeFileName(doc.Name)+suffix+`"`)
	_, _ = w.Write(body)
}

type automationDocumentSendResponse struct {
	DocumentID  uuid.UUID              `json:"document_id"`
	Status      string                 `json:"status"`
	PackageSend *packageSendResponseV1 `json:"package_send,omitempty"`
}

func decodeAutomationDocumentSend(w http.ResponseWriter, r *http.Request) (sendDocumentInput, error) {
	var in sendDocumentInput
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, automationDocumentBodyLimit))
	if err != nil {
		return in, err
	}
	defer clear(raw)
	if err = decodeSignerJSONBytesV1(raw, &in); err != nil {
		return in, err
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || string(fields["lawful_basis"]) == "null" || string(fields["package_send"]) == "null" {
		return in, errors.New("Send requires non-null exact inputs")
	}
	return in, nil
}

func (s *Server) handleAutomationSendDocument(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "write:workflow")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	if err := requireAutomationJSONContentType(r.Header.Values("Content-Type")); err != nil {
		writeError(w, http.StatusUnsupportedMediaType, "use application/json")
		return
	}
	in, err := decodeAutomationDocumentSend(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid exact Send input")
		return
	}
	if err = send.ValidateLawfulBasis(in.LawfulBasis); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	selection, err := in.PackageSend.observationV1()
	if err != nil {
		writeError(w, http.StatusBadRequest, "package_send must identify the exact reviewed document and attachment selection")
		return
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), id, "write:workflow")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	s.dispatchDocumentSend(w, r, id, send.Actor{UserID: &u.UserID, OrgID: u.OrgID, Email: u.Email, IP: clientIP(r), Via: "automation", Tool: "send_document", Authorize: authorize, LawfulBasis: in.LawfulBasis, PackageSend: selection}, true)
}

func (s *Server) handleAutomationDocumentAttachments(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, id, "read")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	result, err := packageauthoring.InventoryV1(ctx, packageauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions}, authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		status, message := packageauthoring.PublicErrorV1(err)
		writeError(w, status, message)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAutomationSendAttempt(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	attempt, ok := parseUUIDParam(w, r, "attempt_id")
	if !ok {
		return
	}
	if s.Send == nil {
		writeError(w, http.StatusServiceUnavailable, "Send inspection is unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	authorize, err := auth.APIKeyTransactionAuthorization(ctx, id, "read")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	result, err := s.Send.InspectPackageSendAttemptV1(ctx, send.Actor{OrgID: u.OrgID, UserID: &u.UserID, Authorize: authorize, Via: "automation", Tool: "get_document_send_attempt"}, id, attempt)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeSendError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	err = result.WithObservationV1(func(observation pdfadmission.HTMLSendPackageAttemptObservationV1) error {
		outcome := ""
		switch observation.Outcome {
		case pdfadmission.HTMLSendPackageAttemptActiveV1:
			outcome = "active"
		case pdfadmission.HTMLSendPackageAttemptCompletedV1:
			outcome = "completed"
		case pdfadmission.HTMLSendPackageAttemptAbortedV1:
			outcome = "aborted"
		case pdfadmission.HTMLSendPackageAttemptNotRecordedV1:
			outcome = "not_recorded"
		default:
			return pdfadmission.ErrHTMLSendPackageInspectionV1
		}
		writeJSON(w, http.StatusOK, struct {
			AttemptID       string `json:"attempt_id"`
			Outcome         string `json:"outcome"`
			RetryAuthorized bool   `json:"retry_authorized"`
		}{observation.AttemptID.String(), outcome, false})
		return nil
	})
	if err != nil {
		writeError(w, http.StatusConflict, "Send inspection ended before delivery")
	}
}

func (s *Server) handleAutomationListTemplates(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, "read")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	limit, offset := paginationFromQuery(r, 50, 500)
	result, err := blockauthoring.ListTemplatesV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions}, blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "automation", Tool: "list_templates"}, limit, offset, true)
	if result != nil {
		defer result.CloseConsumerV1()
	}
	if err != nil {
		s.writeOwnedBlocksTemplateErrorV1(w, "list machine templates failed", err)
		return
	}
	out := make([]templateResponse, 0, len(result.Rows))
	for i, row := range result.Rows {
		response, err := nativeTemplateListResponseV1(row, result.Digests[i])
		if err != nil {
			writeInternalErrorMsg(w, "invalid machine template content", err)
			return
		}
		out = append(out, response)
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{"templates": out, "total": result.Total, "limit": limit, "offset": offset})
}

func (s *Server) handleAutomationGetTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := automationDocumentActor(w, r, "read")
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, "read")
	if err != nil {
		writeAutomationDocumentReadError(w, err)
		return
	}
	header, err := s.Queries.GetNonHTMLTemplateSourceHeaderForShareV1(r.Context(), generated.GetNonHTMLTemplateSourceHeaderForShareV1Params{TemplateID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if err != nil {
		writeInternalErrorMsg(w, "get machine template failed", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if header.SourceKind == "blocks" {
		result, err := blockauthoring.ReadTemplateV1(r.Context(), blockauthoring.DependenciesV1{Sessions: s.HTMLCreationSessions}, blockauthoring.ActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize, Via: "automation", Tool: "get_template"}, id)
		if result != nil {
			defer result.CloseConsumerV1()
		}
		if err != nil {
			s.writeOwnedBlocksTemplateErrorV1(w, "get machine template failed", err)
			return
		}
		response := toTemplateResponseBaseV1(result.Template)
		response.ContentSHA256 = result.Content.SHA256Hex()
		writeJSON(w, http.StatusOK, response)
		return
	}
	if header.SourceKind == "pdf" {
		result, err := pdftemplateauthoring.ReadV1(r.Context(), s.HTMLCreationSessions, pdftemplateauthoring.ReadActorV1{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id)
		if result != nil {
			defer result.CloseConsumerV1()
		}
		if err != nil {
			if errors.Is(err, pdftemplateauthoring.ErrTemplateNotFoundV1) {
				writeError(w, http.StatusNotFound, "template not found")
			} else {
				writeAutomationDocumentReadError(w, err)
			}
			return
		}
		writeTemplateResponse(w, http.StatusOK, result.Template)
		return
	}
	if header.SourceKind != "html" {
		writeError(w, http.StatusServiceUnavailable, "template source is unavailable")
		return
	}
	response, closeConsumer, err := s.readHTMLTemplateDetailOwnedV1(r.Context(), u.OrgID, u.UserID, id, authorize)
	if err != nil {
		s.writeHTMLTemplateError(w, "get machine template failed", err)
		return
	}
	defer closeConsumer()
	writeJSON(w, http.StatusOK, response)
}
