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
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/importguard"
	"github.com/bright-interaction/hash/internal/malwarescan"
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
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, htmlmaster.MaxMasterJSONBytes+(2<<20)))
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
	committed, err := htmlmaster.CanonicalTemplate(in.HTMLMasterJSON, in.VariablesJSON)
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
	release, err := importguard.Shared.Acquire(u.OrgID)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return
	}
	defer release()
	in, content, err := parseHTMLTemplateInput(r)
	if err != nil {
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
	digest, _ := hex.DecodeString(content.SHA256)
	t, err := s.createTemplateAuthorized(r, u.UserID, u.OrgID,
		func(ctx context.Context, q *generated.Queries) (*generated.Template, error) {
			t, err := q.CreateHTMLTemplate(ctx, generated.CreateHTMLTemplateParams{
				OrgID: u.OrgID, Name: in.Name, HtmlMasterJson: content.MasterJSON,
				VariablesJson: content.DefaultsJSON, HtmlContentSha256: digest, CreatedBy: u.UserID,
			})
			if err != nil {
				return nil, err
			}
			_, err = q.InsertHTMLTemplateRevision(ctx, generated.InsertHTMLTemplateRevisionParams{
				TemplateID: t.ID, OrgID: u.OrgID, ExpectedVersion: t.Version,
				HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON,
				ContentSha256: digest, CreatedBy: u.UserID,
			})
			return t, err
		}, func(t *generated.Template) audit.Entry {
			return audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindTemplateCreated,
				Payload: map[string]any{"template_id": t.ID, "source_kind": "html", "version": t.Version, "content_sha256": content.SHA256, "approved": false}}
		})
	if err != nil {
		s.writeHTMLTemplateError(w, "create HTML template", err)
		return
	}
	writeTemplateResponse(w, http.StatusCreated, t)
}

func (s *Server) handleUpdateHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
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
	in, content, err := parseHTMLTemplateInput(r)
	if err != nil {
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
	digest, _ := hex.DecodeString(content.SHA256)
	t, err := s.mutateTemplateAuthorized(r, u.UserID, u.OrgID, id,
		func(ctx context.Context, q *generated.Queries, current *generated.Template) (*generated.Template, error) {
			if current.SourceKind != "html" || current.Version != in.ExpectedVersion {
				return nil, errHTMLTemplateConflict
			}
			t, err := q.UpdateHTMLTemplate(ctx, generated.UpdateHTMLTemplateParams{
				ID: id, OrgID: u.OrgID, Name: in.Name, HtmlMasterJson: content.MasterJSON,
				VariablesJson: content.DefaultsJSON, HtmlContentSha256: digest, ExpectedVersion: in.ExpectedVersion,
			})
			if err != nil {
				return nil, err
			}
			_, err = q.InsertHTMLTemplateRevision(ctx, generated.InsertHTMLTemplateRevisionParams{
				TemplateID: id, OrgID: u.OrgID, ExpectedVersion: t.Version,
				HtmlMasterJson: content.MasterJSON, VariablesJson: content.DefaultsJSON,
				ContentSha256: digest, CreatedBy: u.UserID,
			})
			return t, err
		}, func(t *generated.Template) audit.Entry {
			return audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindTemplateUpdated,
				Payload: map[string]any{"template_id": id, "source_kind": "html", "version": t.Version, "content_sha256": content.SHA256, "approved": false}}
		})
	if err != nil {
		s.writeHTMLTemplateError(w, "update HTML template", err)
		return
	}
	writeTemplateResponse(w, http.StatusOK, t)
}

type htmlTemplateApprovalInput struct {
	ExpectedVersion       int32  `json:"expected_version"`
	ExpectedContentSHA256 string `json:"expected_content_sha256"`
}

func (s *Server) handleApproveHTMLTemplate(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	var in htmlTemplateApprovalInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	digest, err := hex.DecodeString(in.ExpectedContentSHA256)
	if err != nil || len(digest) != 32 || in.ExpectedVersion <= 0 || in.ExpectedContentSHA256 != strings.ToLower(in.ExpectedContentSHA256) {
		writeError(w, http.StatusBadRequest, "expected_version and lowercase content SHA-256 are required")
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize HTML template approval", err)
		return
	}
	revision, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (*generated.HtmlTemplateRevision, error) {
			t, err := q.GetHTMLTemplateForUpdate(ctx, generated.GetHTMLTemplateForUpdateParams{ID: id, OrgID: u.OrgID})
			if err != nil {
				return nil, err
			}
			if t.Version != in.ExpectedVersion || !bytes.Equal(t.HtmlContentSha256, digest) {
				return nil, errHTMLTemplateConflict
			}
			current, err := q.GetHTMLTemplateRevision(ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: id, OrgID: u.OrgID, Version: in.ExpectedVersion})
			if err != nil {
				return nil, err
			}
			content, err := htmlmaster.CanonicalTemplate(current.HtmlMasterJson, current.VariablesJson)
			if err != nil || content.SHA256 != in.ExpectedContentSHA256 || !bytes.Equal(current.ContentSha256, digest) {
				return nil, errHTMLTemplateConflict
			}
			if current.ApprovedBy.Valid && current.ApprovedAt.Valid {
				return current, nil
			}
			return q.ApproveHTMLTemplateRevision(ctx, generated.ApproveHTMLTemplateRevisionParams{
				TemplateID: id, OrgID: u.OrgID, ExpectedVersion: in.ExpectedVersion, ExpectedContentSha256: digest, ApprovedBy: u.UserID,
			})
		}, func(revision *generated.HtmlTemplateRevision) audit.Entry {
			return audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindTemplateUpdated,
				Payload: map[string]any{"template_id": id, "source_kind": "html", "version": revision.Version, "content_sha256": in.ExpectedContentSHA256, "approved": true}}
		})
	if err != nil {
		s.writeHTMLTemplateError(w, "approve HTML template", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"template_id": id, "version": revision.Version, "content_sha256": in.ExpectedContentSHA256,
		"approved_by": uuid.UUID(revision.ApprovedBy.Bytes), "approved_at": revision.ApprovedAt.Time,
	})
}

func (s *Server) writeHTMLTemplateError(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, errHTMLTemplateConflict) || errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusConflict, "HTML template revision changed or is unavailable; refresh and review it again")
		return
	}
	if errors.Is(err, htmlmaster.ErrInvalid) || errors.Is(err, htmlmaster.ErrLimit) || errors.Is(err, htmlmaster.ErrMissingValues) {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.writeTemplateMutationError(w, operation, err)
}
