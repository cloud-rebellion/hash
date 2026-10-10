// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var errCRMTemplateInput = errors.New("invalid CRM template population input")
var errCRMTemplateChanged = errors.New("template, approval, CRM account or reviewed information changed; refresh and review before creating")

// These commands have no nullable input members: omission supplies defaults,
// while an explicit null must never silently become an empty string or false.
func decodeCRMTemplateJSON(r *http.Request, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxSignerJSONBody))
	if err != nil {
		return errCRMTemplateInput
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || crmTemplateHasNull(value) {
		return errCRMTemplateInput
	}
	copy := r.Clone(r.Context())
	copy.Body = io.NopCloser(bytes.NewReader(raw))
	return decodeSignerJSON(copy, dst)
}

func crmTemplateHasNull(value any) bool {
	if value == nil {
		return true
	}
	switch typed := value.(type) {
	case map[string]any:
		for _, child := range typed {
			if crmTemplateHasNull(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if crmTemplateHasNull(child) {
				return true
			}
		}
	}
	return false
}

// Exported embedded request types keep exact-field JSON validation reachable.
// Discovery is bound to a saved, approved template, never a placeholder document.
type CRMTemplateWitness struct {
	ExpectedOrgID                 uuid.UUID `json:"expected_org_id"`
	ExpectedUserID                uuid.UUID `json:"expected_user_id"`
	ExpectedTemplateVersion       int32     `json:"expected_template_version"`
	ExpectedTemplateContentSHA256 string    `json:"expected_template_content_sha256"`
	ExpectedTemplateApprovedBy    uuid.UUID `json:"expected_template_approved_by"`
	ExpectedTemplateApprovedAt    string    `json:"expected_template_approved_at"`
	ExpectedConnectionID          string    `json:"expected_connection_id"`
	ExpectedConnectionGeneration  string    `json:"expected_connection_generation"`
}

type crmTemplateResponseWitness struct {
	OrgID                 uuid.UUID                 `json:"org_id"`
	UserID                uuid.UUID                 `json:"user_id"`
	TemplateID            uuid.UUID                 `json:"template_id"`
	TemplateVersion       int32                     `json:"template_version"`
	TemplateContentSHA256 string                    `json:"template_content_sha256"`
	TemplateApprovedBy    uuid.UUID                 `json:"template_approved_by"`
	TemplateApprovedAt    string                    `json:"template_approved_at"`
	Connection            *crmDocumentConnectionDTO `json:"connection"`
}

type crmTemplateVariable struct {
	Name           string `json:"name"`
	Required       bool   `json:"required"`
	MaxChars       int    `json:"max_chars"`
	CurrentPresent bool   `json:"current_present"`
	CurrentValue   string `json:"current_value"`
}

type crmTemplateContext struct {
	template   *generated.Template
	revision   *generated.HtmlTemplateRevision
	content    htmlmaster.TemplateCommitment
	compiled   *htmlmaster.Compiled
	connection *generated.CrmConnection
	defaults   map[string]string
	variables  []crmTemplateVariable
	response   crmTemplateResponseWitness
}

func (in CRMTemplateWitness) validate(actor authoring.Actor) error {
	if in.ExpectedOrgID == uuid.Nil || in.ExpectedUserID == uuid.Nil || in.ExpectedTemplateVersion <= 0 ||
		!htmlPreviewSHA256(in.ExpectedTemplateContentSHA256) || in.ExpectedTemplateApprovedBy == uuid.Nil {
		return errCRMTemplateInput
	}
	if actor.OrgID != in.ExpectedOrgID || actor.UserID != in.ExpectedUserID {
		return errCRMTemplateChanged
	}
	at, err := time.Parse(time.RFC3339Nano, in.ExpectedTemplateApprovedAt)
	if err != nil || at.IsZero() {
		return errCRMTemplateInput
	}
	generation, err := crmGeneration(in.ExpectedConnectionGeneration, true)
	if err != nil {
		return errCRMTemplateInput
	}
	if in.ExpectedConnectionID == "" {
		if generation != 0 {
			return errCRMTemplateInput
		}
	} else {
		id, err := uuid.Parse(in.ExpectedConnectionID)
		if err != nil || id == uuid.Nil || id.String() != in.ExpectedConnectionID || generation == 0 {
			return errCRMTemplateInput
		}
	}
	return nil
}

func (in CRMTemplateWitness) matches(current *crmTemplateContext) error {
	if current == nil || current.template == nil || current.revision == nil {
		return errCRMTemplateChanged
	}
	at, err := time.Parse(time.RFC3339Nano, in.ExpectedTemplateApprovedAt)
	if err != nil || current.response.OrgID != in.ExpectedOrgID || current.response.UserID != in.ExpectedUserID ||
		current.response.TemplateVersion != in.ExpectedTemplateVersion || current.response.TemplateContentSHA256 != in.ExpectedTemplateContentSHA256 ||
		current.response.TemplateApprovedBy != in.ExpectedTemplateApprovedBy || !current.revision.ApprovedAt.Time.Equal(at) {
		return errCRMTemplateChanged
	}
	if current.connection == nil {
		if in.ExpectedConnectionID != "" || in.ExpectedConnectionGeneration != "0" {
			return errCRMTemplateChanged
		}
	} else if in.ExpectedConnectionID != current.connection.ID.String() || in.ExpectedConnectionGeneration != strconv.FormatInt(current.connection.Generation, 10) {
		return errCRMTemplateChanged
	}
	return nil
}

// The prepare/read transaction holds only saved template, approval, member and
// account locks. Its caller commits before network, renderer or storage work.
// Creation's final transaction takes the quota lock before entering this helper.
func (s *Server) lockCRMTemplate(ctx context.Context, tx pgx.Tx, actor authoring.Actor, templateID uuid.UUID, version int32, contentSHA string) (*authoring.MemberGuard, *crmTemplateContext, error) {
	if tx == nil || templateID == uuid.Nil || version <= 0 || !htmlPreviewSHA256(contentSHA) {
		return nil, nil, errCRMTemplateInput
	}
	q := generated.New(tx)
	template, err := q.GetHTMLTemplateForShare(ctx, generated.GetHTMLTemplateForShareParams{ID: templateID, OrgID: actor.OrgID})
	if err != nil {
		return nil, nil, err
	}
	digest, _ := hex.DecodeString(contentSHA)
	if template.SourceKind != "html" || template.ID != templateID || template.OrgID != actor.OrgID || template.Version != version || !bytes.Equal(template.HtmlContentSha256, digest) {
		return nil, nil, errCRMTemplateChanged
	}
	revision, err := q.GetHTMLTemplateRevisionForShare(ctx, generated.GetHTMLTemplateRevisionForShareParams{TemplateID: templateID, OrgID: actor.OrgID, Version: version})
	if err != nil {
		return nil, nil, err
	}
	if revision.TemplateID != templateID || revision.OrgID != actor.OrgID || revision.Version != version ||
		!revision.ApprovedBy.Valid || uuid.UUID(revision.ApprovedBy.Bytes) == uuid.Nil || !revision.ApprovedAt.Valid || revision.ApprovedAt.Time.IsZero() ||
		revision.ApprovedAt.InfinityModifier != pgtype.Finite || !bytes.Equal(revision.ContentSha256, digest) {
		return nil, nil, errCRMTemplateChanged
	}
	guard, err := authoring.LockAuthor(ctx, tx, actor)
	if err != nil {
		return nil, nil, err
	}
	content, err := htmlmaster.CanonicalTemplate(revision.HtmlMasterJson, revision.VariablesJson)
	if err != nil || content.SHA256 != contentSHA {
		return nil, nil, errCRMTemplateChanged
	}
	master, err := htmlmaster.Decode(content.MasterJSON)
	if err != nil {
		return nil, nil, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return nil, nil, err
	}
	defaults := map[string]string{}
	if json.Unmarshal(content.DefaultsJSON, &defaults) != nil || defaults == nil {
		return nil, nil, errCRMTemplateChanged
	}
	connection, err := q.GetCRMConnectionByOrgForShare(ctx, actor.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		connection, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if connection != nil && connection.OrgID != actor.OrgID {
		return nil, nil, errCRMTemplateChanged
	}
	result := &crmTemplateContext{template: template, revision: revision, content: content, compiled: compiled, connection: connection,
		defaults: defaults, variables: []crmTemplateVariable{}, response: crmTemplateResponseWitness{OrgID: actor.OrgID, UserID: actor.UserID,
			TemplateID: templateID, TemplateVersion: version, TemplateContentSHA256: contentSHA,
			TemplateApprovedBy: uuid.UUID(revision.ApprovedBy.Bytes), TemplateApprovedAt: revision.ApprovedAt.Time.UTC().Format(time.RFC3339Nano)}}
	for _, definition := range master.Values {
		value, exists := defaults[definition.Name]
		result.variables = append(result.variables, crmTemplateVariable{Name: definition.Name, Required: definition.Required, MaxChars: definition.MaxChars, CurrentPresent: exists, CurrentValue: value})
	}
	if connection != nil {
		result.response.Connection = &crmDocumentConnectionDTO{ID: connection.ID, Generation: strconv.FormatInt(connection.Generation, 10), Status: connection.Status, Origin: connection.Origin, CRMTeamID: connection.CrmTeamID, CRMUserID: connection.CrmUserID}
	}
	return guard, result, nil
}

func (s *Server) readCRMTemplate(ctx context.Context, actor authoring.Actor, templateID uuid.UUID, version int32, digest string, expected *CRMTemplateWitness) (*crmTemplateContext, error) {
	if s.Pool == nil {
		return nil, crmconnection.ErrNotConfigured
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	guard, current, err := s.lockCRMTemplate(ctx, tx, actor, templateID, version, digest)
	if err != nil {
		return nil, err
	}
	if expected != nil {
		if err = expected.matches(current); err != nil {
			return nil, err
		}
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return current, nil
}

func (s *Server) crmTemplateActor(w http.ResponseWriter, r *http.Request) (authoring.Actor, uuid.UUID, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, uuid.Nil, false
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return authoring.Actor{}, uuid.Nil, false
	}
	if id == uuid.Nil {
		writeError(w, 400, "invalid template id")
		return authoring.Actor{}, uuid.Nil, false
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return authoring.Actor{}, uuid.Nil, false
	}
	return authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, true
}

func (s *Server) writeCRMTemplateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, 401, "original session expired")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, 403, "CRM template population requires authoring permission")
	case errors.Is(err, pgx.ErrNoRows):
		writeError(w, 404, "approved template not found")
	case errors.Is(err, errCRMTemplateInput), errors.Is(err, errCRMDocumentInput), errors.Is(err, crmconnection.ErrSearchInput), errors.Is(err, htmlmaster.ErrInvalid), errors.Is(err, htmlmaster.ErrLimit), errors.Is(err, htmlmaster.ErrMissingValues), errors.Is(err, htmlmaster.ErrContractIncomplete):
		writeError(w, 400, "invalid CRM template population input")
	case errors.Is(err, errCRMTemplateChanged), errors.Is(err, errCRMTemplateReceipt), errors.Is(err, errCRMDocumentChanged), errors.Is(err, errHTMLTemplateConflict), errors.Is(err, crmconnection.ErrIdentity):
		writeError(w, 409, errCRMTemplateChanged.Error())
	default:
		writeError(w, 503, "CRM information temporarily unavailable; refresh before trying again")
	}
}

func (s *Server) handleCRMTemplateContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmTemplateActor(w, r)
	if !ok {
		return
	}
	query := r.URL.Query()
	version, err := strconv.ParseInt(query.Get("expected_template_version"), 10, 32)
	digest := query.Get("expected_template_content_sha256")
	if err != nil || version <= 0 || strconv.FormatInt(version, 10) != query.Get("expected_template_version") || !htmlPreviewSHA256(digest) ||
		len(query) != 2 || len(query["expected_template_version"]) != 1 || len(query["expected_template_content_sha256"]) != 1 {
		s.writeCRMTemplateError(w, errCRMTemplateInput)
		return
	}
	current, err := s.readCRMTemplate(r.Context(), actor, id, int32(version), digest, nil)
	if err != nil {
		s.writeCRMTemplateError(w, err)
		return
	}
	_, activeErr := s.crmActiveConnection(&crmDocumentContext{connection: current.connection})
	writeJSON(w, 200, struct {
		crmTemplateResponseWitness
		Available bool                                                         `json:"available"`
		Variables []crmTemplateVariable                                        `json:"variables"`
		Catalog   map[crmconnection.RecordKind][]crmconnection.FieldDefinition `json:"catalog"`
	}{current.response, activeErr == nil, current.variables, map[crmconnection.RecordKind][]crmconnection.FieldDefinition{
		crmconnection.Deal: crmconnection.Catalog(crmconnection.Deal), crmconnection.Contact: crmconnection.Catalog(crmconnection.Contact), crmconnection.Company: crmconnection.Catalog(crmconnection.Company)}})
}
