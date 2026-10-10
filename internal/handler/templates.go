// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/agreement"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	blockschema "github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/templatepin"
)

const maxPDFUpload = 50 << 20 // 50 MB

// templateResponse is what we return on the API. We translate sqlc's pgtype.*
// fields into JSON-friendly nullables.
type templateResponse struct {
	ID             uuid.UUID                     `json:"id"`
	OrgID          uuid.UUID                     `json:"org_id"`
	Name           string                        `json:"name"`
	SourceKind     string                        `json:"source_kind"`
	BlocksJSON     json.RawMessage               `json:"blocks_json,omitempty"`
	VariablesJSON  json.RawMessage               `json:"variables_json"`
	PDFStorageKey  string                        `json:"pdf_storage_key,omitempty"`
	PDFSHA256      string                        `json:"pdf_sha256,omitempty"`
	PageCount      int32                         `json:"page_count,omitempty"`
	FieldsJSON     json.RawMessage               `json:"fields_json"`
	Version        int32                         `json:"version"`
	ContentSHA256  string                        `json:"content_sha256,omitempty"`
	HTMLMasterJSON json.RawMessage               `json:"html_master_json,omitempty"`
	HTMLApproval   *htmlTemplateApprovalResponse `json:"html_approval,omitempty"`
	CreatedBy      uuid.UUID                     `json:"created_by"`
	CreatedAt      string                        `json:"created_at"`
	UpdatedAt      string                        `json:"updated_at"`
}

func toTemplateResponse(t *generated.Template) (templateResponse, error) {
	resp := templateResponse{
		ID:            t.ID,
		OrgID:         t.OrgID,
		Name:          t.Name,
		SourceKind:    t.SourceKind,
		BlocksJSON:    t.BlocksJson,
		VariablesJSON: t.VariablesJson,
		FieldsJSON:    t.FieldsJson,
		Version:       t.Version,
		CreatedBy:     t.CreatedBy,
		CreatedAt:     t.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:     t.UpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00"),
	}
	if t.PdfStorageKey.Valid {
		resp.PDFStorageKey = t.PdfStorageKey.String
	}
	if len(t.PdfSha256) > 0 {
		resp.PDFSHA256 = hex.EncodeToString(t.PdfSha256)
	}
	if t.PageCount.Valid {
		resp.PageCount = t.PageCount.Int32
	}
	if t.SourceKind == "blocks" {
		content, err := templatepin.Canonicalize(t.BlocksJson, t.VariablesJson)
		if err != nil {
			return templateResponse{}, fmt.Errorf("compute template content digest: %w", err)
		}
		resp.ContentSHA256 = content.SHA256Hex()
	}
	if t.SourceKind == "html" {
		if len(t.HtmlContentSha256) != 32 {
			return templateResponse{}, errors.New("HTML template has no canonical content commitment")
		}
		resp.ContentSHA256 = hex.EncodeToString(t.HtmlContentSha256)
	}
	return resp, nil
}

func writeTemplateResponse(w http.ResponseWriter, status int, template *generated.Template) {
	response, err := toTemplateResponse(template)
	if err != nil {
		writeInternalErrorMsg(w, "template has invalid canonical content", err)
		return
	}
	if template.SourceKind == "html" {
		response.HTMLMasterJSON = template.HtmlMasterJson
	}
	writeJSON(w, status, response)
}

// handleListTemplates returns a paginated list of non-archived templates for
// the caller's org.
func (s *Server) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	limit, offset := paginationFromQuery(r, 50, 500)
	rows, err := s.Queries.ListTemplates(r.Context(), generated.ListTemplatesParams{
		OrgID:  u.OrgID,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list templates failed")
		return
	}
	out := make([]templateResponse, 0, len(rows))
	for _, t := range rows {
		// Map only public list metadata. Nullable cold JSON projections can
		// have different generated Go types from a full template row.
		response, err := toTemplateResponse(&generated.Template{
			ID: t.ID, OrgID: t.OrgID, Name: t.Name, SourceKind: t.SourceKind,
			BlocksJson: t.BlocksJson, VariablesJson: t.VariablesJson, FieldsJson: t.FieldsJson,
			Version: t.Version, CreatedBy: t.CreatedBy, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt,
			PdfStorageKey: t.PdfStorageKey, PdfSha256: t.PdfSha256, PageCount: t.PageCount,
			HtmlContentSha256: t.HtmlContentSha256,
		})
		if err != nil {
			writeInternalErrorMsg(w, "template has invalid canonical content", err)
			return
		}
		out = append(out, response)
	}
	total, _ := s.Queries.CountTemplates(r.Context(), u.OrgID)
	writeJSON(w, http.StatusOK, map[string]any{
		"templates": out,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

// createBlocksTemplateInput is the JSON body for the blocks-source path.
type createBlocksTemplateInput struct {
	Name          string          `json:"name"`
	BlocksJSON    json.RawMessage `json:"blocks_json"`
	VariablesJSON json.RawMessage `json:"variables_json"`
}

// handleCreateTemplate dispatches by Content-Type:
//   - application/json: blocks-source template
//   - multipart/form-data with "pdf" file part: pdf-source template
func (s *Server) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	ct := r.Header.Get("Content-Type")
	switch {
	case ct == "application/json" || ct == "application/json; charset=utf-8":
		s.createBlocksTemplate(w, r, u.UserID, u.OrgID)
	default:
		s.createPDFTemplate(w, r, u.UserID, u.OrgID)
	}
}

func (s *Server) createBlocksTemplate(w http.ResponseWriter, r *http.Request, userID, orgID uuid.UUID) {
	var in createBlocksTemplateInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	if len(in.BlocksJSON) == 0 {
		in.BlocksJSON = json.RawMessage(`{"version":1,"blocks":[]}`)
	}
	if len(in.VariablesJSON) == 0 {
		in.VariablesJSON = json.RawMessage(`{}`)
	}
	normalizedBlocks, err := blockschema.NormalizeTreeJSON(in.BlocksJSON)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
		return
	}
	if _, err := blockschema.ParseVariableValues(in.VariablesJSON); err != nil {
		writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
		return
	}
	in.BlocksJSON = normalizedBlocks
	t, err := s.createTemplateAuthorized(r, userID, orgID,
		func(ctx context.Context, q *generated.Queries) (*generated.Template, error) {
			return q.CreateBlocksTemplate(ctx, generated.CreateBlocksTemplateParams{
				OrgID:         orgID,
				Name:          in.Name,
				BlocksJson:    in.BlocksJSON,
				VariablesJson: in.VariablesJSON,
				CreatedBy:     userID,
			})
		},
		func(t *generated.Template) audit.Entry {
			return audit.Entry{
				OrgID:       orgID,
				ActorUserID: &userID,
				Kind:        audit.KindTemplateCreated,
				Payload:     map[string]any{"template_id": t.ID, "source_kind": "blocks", "name": t.Name},
			}
		},
	)
	if err != nil {
		s.writeTemplateMutationError(w, "create template failed", err)
		return
	}
	writeTemplateResponse(w, http.StatusCreated, t)
}

type createStarterTemplateInput struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// handleCreateStarterTemplate seeds one of Hash's built-in starter documents
// (e.g. the Swedish services agreement) as a blocks template in the tenant's
// library, so a non-developer gets a complete, table-rich, placeholder-driven
// agreement to clone per client without authoring it from scratch.
func (s *Server) handleCreateStarterTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	var in createStarterTemplateInput
	if err := decodeJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if s.Environment == "production" {
		writeError(w, http.StatusServiceUnavailable, "built-in legal starters are unavailable pending counsel approval")
		return
	}
	st, found := agreement.Get(in.Key)
	if !found {
		writeError(w, http.StatusBadRequest, "unknown starter key")
		return
	}
	name := in.Name
	if name == "" {
		name = st.Name
	}
	t, err := s.createTemplateAuthorized(r, u.UserID, u.OrgID,
		func(ctx context.Context, q *generated.Queries) (*generated.Template, error) {
			return q.CreateBlocksTemplate(ctx, generated.CreateBlocksTemplateParams{
				OrgID:         u.OrgID,
				Name:          name,
				BlocksJson:    st.BlocksJSON(),
				VariablesJson: st.VariablesJSON(),
				CreatedBy:     u.UserID,
			})
		},
		func(t *generated.Template) audit.Entry {
			return audit.Entry{
				OrgID:       u.OrgID,
				ActorUserID: &u.UserID,
				Kind:        audit.KindTemplateCreated,
				Payload:     map[string]any{"template_id": t.ID, "source_kind": "blocks", "name": t.Name, "starter": st.Key},
			}
		},
	)
	if err != nil {
		s.writeTemplateMutationError(w, "create template failed", err)
		return
	}
	writeTemplateResponse(w, http.StatusCreated, t)
}

func (s *Server) createPDFTemplate(w http.ResponseWriter, r *http.Request, userID, orgID uuid.UUID) {
	release, err := importguard.Shared.Acquire(orgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	r.Body = http.MaxBytesReader(w, r.Body, maxPDFUpload+(1<<20))
	defer cleanupMultipart(r)
	if err := r.ParseMultipartForm(multipartFileMemory); err != nil {
		writeError(w, http.StatusBadRequest, "could not parse upload: "+err.Error())
		return
	}
	name := r.FormValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	file, hdr, err := r.FormFile("pdf")
	if err != nil {
		writeError(w, http.StatusBadRequest, "pdf file required (form field 'pdf')")
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read upload failed")
		return
	}
	if !looksLikePDF(data) {
		writeError(w, http.StatusBadRequest, "uploaded file is not a PDF (magic bytes mismatch)")
		return
	}
	templateID := uuid.New()
	key := path.Join("org", orgID.String(), "templates", templateID.String()+".pdf")

	// Remove and verify source metadata in the bounded worker before storage.
	// Active content is rejected. The report records observed categories and
	// permitted newly generated Info, rather than claiming blanket GDPR cleanup.
	cleaned, err := sanitize.CleanWithContext(r.Context(), "template-pdf", "application/pdf", data)
	if err != nil {
		if errors.Is(err, malwarescan.ErrUnavailable) {
			writeScanError(w, err)
			return
		}
		if writePDFWorkerError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "sanitize PDF: "+err.Error())
		return
	}
	// A template must have a known valid page count before any object write.
	// Production parsing runs through the bounded isolated PDF worker.
	pageCount, err := sanitize.PageCountWithContext(r.Context(), cleaned.Bytes)
	if err != nil || pageCount < 1 {
		if writePDFWorkerError(w, err) {
			return
		}
		writeError(w, http.StatusBadRequest, "invalid PDF page count")
		return
	}
	stored, err := s.Storage.PutVersioned(r.Context(), key, "application/pdf", cleaned.Bytes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "storage write failed")
		return
	}

	t, err := s.createTemplateAuthorized(r, userID, orgID,
		func(ctx context.Context, q *generated.Queries) (*generated.Template, error) {
			proof, err := authoring.BindPDFTemplateSanitization(cleaned.Report, key, stored.SHA256[:], stored.VersionID, int32(pageCount))
			if err != nil {
				return nil, err
			}
			return q.CreatePDFTemplate(ctx, generated.CreatePDFTemplateParams{
				OrgID:                      orgID,
				Name:                       name,
				PdfStorageKey:              pgtype.Text{String: key, Valid: true},
				PdfSha256:                  stored.SHA256[:],
				PdfStorageVersionID:        pgtype.Text{String: stored.VersionID, Valid: true},
				EvidenceVersionPinRequired: true,
				PageCount:                  pgtype.Int4{Int32: int32(pageCount), Valid: true},
				FieldsJson:                 json.RawMessage(`[]`),
				CreatedBy:                  userID,
				PdfSanitizationReport:      proof,
			})
		},
		func(t *generated.Template) audit.Entry {
			return audit.Entry{
				OrgID:       orgID,
				ActorUserID: &userID,
				Kind:        audit.KindTemplateCreated,
				Payload: map[string]any{
					"template_id": t.ID,
					"source_kind": "pdf",
					"name":        t.Name,
					"size_bytes":  hdr.Size,
				},
			}
		},
	)
	if err != nil {
		// Compensate for the successful object write. Without this, every DB
		// failure after upload leaves an unreferenced customer PDF in MinIO.
		cleanupErr := errors.New("storage unavailable for orphan cleanup")
		if s.Storage != nil {
			cleanupErr = deleteObjectDetached(r.Context(), s.Storage, cleanupObjectVersion{
				Key: key, VersionID: stored.VersionID, SHA256: stored.SHA256[:],
			})
		}
		if cleanupErr != nil {
			writeInternalErrorMsg(w, "create template failed; orphan cleanup failed", errors.Join(err, cleanupErr))
		} else {
			s.writeDraftAuthoringError(w, "create template failed", err)
		}
		return
	}

	writeTemplateResponse(w, http.StatusCreated, t)
}

func looksLikePDF(data []byte) bool {
	return len(data) >= 4 && data[0] == '%' && data[1] == 'P' && data[2] == 'D' && data[3] == 'F'
}

func (s *Server) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	t, err := s.Queries.GetTemplate(r.Context(), generated.GetTemplateParams{ID: id, OrgID: u.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "template not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "get template failed")
		return
	}
	if t.SourceKind == "html" {
		revision, err := s.Queries.GetHTMLTemplateRevision(r.Context(), generated.GetHTMLTemplateRevisionParams{TemplateID: t.ID, OrgID: u.OrgID, Version: t.Version})
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "template revision not found")
			return
		}
		if err != nil {
			writeInternalErrorMsg(w, "load template approval failed", err)
			return
		}
		response, err := toHTMLTemplateDetailResponse(t, revision)
		if err != nil {
			writeInternalErrorMsg(w, "template approval is invalid", err)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	writeTemplateResponse(w, http.StatusOK, t)
}

type updateTemplateInput struct {
	Name          string          `json:"name"`
	BlocksJSON    json.RawMessage `json:"blocks_json,omitempty"`
	VariablesJSON json.RawMessage `json:"variables_json,omitempty"`
	FieldsJSON    json.RawMessage `json:"fields_json,omitempty"`
}

func (s *Server) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in updateTemplateInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	// Validate supplied content before locking. Missing values are resolved
	// later from the locked current template, so a concurrent edit is retained.
	if len(in.BlocksJSON) != 0 {
		normalized, err := blockschema.NormalizeTreeJSON(in.BlocksJSON)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid blocks_json: "+err.Error())
			return
		}
		in.BlocksJSON = normalized
	}
	if len(in.VariablesJSON) != 0 {
		if _, err := blockschema.ParseVariableValues(in.VariablesJSON); err != nil {
			writeError(w, http.StatusBadRequest, "invalid variables_json: "+err.Error())
			return
		}
	}

	t, err := s.mutateTemplateAuthorized(r, u.UserID, u.OrgID, id,
		func(ctx context.Context, q *generated.Queries, current *generated.Template) (*generated.Template, error) {
			switch current.SourceKind {
			case "blocks":
				blocks := in.BlocksJSON
				if len(blocks) == 0 {
					blocks = current.BlocksJson
				}
				blocks, err := blockschema.NormalizeTreeJSON(blocks)
				if err != nil {
					return nil, fmt.Errorf("invalid current blocks_json: %w", err)
				}
				vars := in.VariablesJSON
				if len(vars) == 0 {
					vars = current.VariablesJson
				}
				if _, err := blockschema.ParseVariableValues(vars); err != nil {
					return nil, fmt.Errorf("invalid current variables_json: %w", err)
				}
				name := in.Name
				if name == "" {
					name = current.Name
				}
				return q.UpdateBlocksTemplate(ctx, generated.UpdateBlocksTemplateParams{
					ID: id, OrgID: u.OrgID, Name: name, BlocksJson: blocks, VariablesJson: vars,
				})
			case "pdf":
				fields := in.FieldsJSON
				if len(fields) == 0 {
					fields = current.FieldsJson
				}
				if len(in.FieldsJSON) > 0 {
					var err error
					fields, err = pdflayout.CanonicalForUpdate(fields, current.PageCount.Int32)
					if err != nil {
						return nil, err
					}
				}
				return q.UpdatePDFTemplateFields(ctx, generated.UpdatePDFTemplateFieldsParams{
					ID: id, OrgID: u.OrgID, FieldsJson: fields,
				})
			default:
				return nil, errors.New("unknown template source kind")
			}
		},
		func(t *generated.Template) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindTemplateUpdated,
				Payload: map[string]any{"template_id": id, "source_kind": t.SourceKind},
			}
		},
	)
	if err != nil {
		if errors.Is(err, pdflayout.ErrInvalid) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.writeTemplateMutationError(w, "update template failed", err)
		return
	}
	writeTemplateResponse(w, http.StatusOK, t)
}

func (s *Server) handleArchiveTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	_, err := s.mutateTemplateAuthorized(r, u.UserID, u.OrgID, id,
		func(ctx context.Context, q *generated.Queries, current *generated.Template) (*generated.Template, error) {
			if err := q.ArchiveTemplate(ctx, generated.ArchiveTemplateParams{ID: id, OrgID: u.OrgID}); err != nil {
				return nil, err
			}
			return current, nil
		},
		func(*generated.Template) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind:    audit.KindTemplateArchived,
				Payload: map[string]any{"template_id": id},
			}
		},
	)
	if err != nil {
		s.writeTemplateMutationError(w, "archive template failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// paginationFromQuery reads ?limit and ?offset, applying caller-provided
// defaults and a hard cap.
func paginationFromQuery(r *http.Request, defaultLimit, maxLimit int32) (limit, offset int32) {
	limit = defaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if int32(n) > maxLimit {
				limit = maxLimit
			} else {
				limit = int32(n)
			}
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = int32(n)
		}
	}
	return limit, offset
}
