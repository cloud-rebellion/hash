// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
)

var errCRMDocumentChanged = errors.New("document, CRM mappings or source account changed; refresh and review CRM information")
var errCRMDocumentInput = errors.New("invalid CRM document input")
var errCRMDocumentUnsupported = errors.New("CRM values require an editable HTML or block document")

type CRMDocumentWitness struct {
	ExpectedOrgID                uuid.UUID `json:"expected_org_id"`
	ExpectedUserID               uuid.UUID `json:"expected_user_id"`
	ExpectedUpdatedAt            string    `json:"expected_updated_at"`
	ExpectedHTMLSourceCommitment string    `json:"expected_html_source_commitment"`
	ExpectedBindingFingerprint   string    `json:"expected_binding_fingerprint"`
	ExpectedConnectionID         string    `json:"expected_connection_id"`
	ExpectedConnectionGeneration string    `json:"expected_connection_generation"`
}

type crmDocumentConnectionDTO struct {
	ID         uuid.UUID `json:"id"`
	Generation string    `json:"generation"`
	Status     string    `json:"status"`
	Origin     string    `json:"origin"`
	CRMTeamID  string    `json:"crm_team_id"`
	CRMUserID  string    `json:"crm_user_id"`
}

type crmDocumentResponseWitness struct {
	OrgID                uuid.UUID                 `json:"org_id"`
	UserID               uuid.UUID                 `json:"user_id"`
	DocumentID           uuid.UUID                 `json:"document_id"`
	UpdatedAt            string                    `json:"updated_at"`
	HTMLSourceCommitment string                    `json:"html_source_commitment"`
	BindingFingerprint   string                    `json:"binding_fingerprint"`
	Connection           *crmDocumentConnectionDTO `json:"connection"`
}

type crmDocumentVariable struct {
	Name         string `json:"name"`
	Required     bool   `json:"required"`
	MaxChars     int    `json:"max_chars"`
	CurrentValue string `json:"current_value"`
}

type crmDocumentContext struct {
	doc            *generated.Document
	bindings       []*generated.DocumentVariableBinding
	connection     *generated.CrmConnection
	variables      []crmDocumentVariable
	response       crmDocumentResponseWitness
	supported      bool
	reviewRequired bool
}

func crmDocumentVariables(doc *generated.Document) ([]crmDocumentVariable, bool, error) {
	values, err := blocks.ParseVariableValues(doc.VariablesJson)
	if err != nil {
		return nil, false, err
	}
	variables := []crmDocumentVariable{}
	if len(doc.HtmlSourceJson) != 0 {
		input, err := htmlsource.InputForCurrent(doc)
		if err != nil {
			return nil, false, err
		}
		master, err := htmlmaster.Decode(input.MasterJSON)
		if err != nil {
			return nil, false, err
		}
		if _, err := htmlmaster.Compile(master); err != nil {
			return nil, false, err
		}
		for _, field := range master.Values {
			if input.Values[field.Name] != values[field.Name] {
				return nil, false, errCRMDocumentChanged
			}
			variables = append(variables, crmDocumentVariable{Name: field.Name, Required: field.Required, MaxChars: field.MaxChars, CurrentValue: values[field.Name]})
		}
	} else if doc.SourceKind == "blocks" {
		tree, err := blocks.ParseCanonicalTree(doc.BlocksJson)
		if err != nil {
			return nil, false, err
		}
		names := blocks.ExtractVariableNames(tree)
		if len(names) > crmconnection.MaxRecordReferences {
			return nil, false, crmconnection.ErrLimit
		}
		for _, name := range names {
			variables = append(variables, crmDocumentVariable{Name: name, MaxChars: htmlmaster.MaxValueChars, CurrentValue: values[name]})
		}
	} else {
		return variables, false, nil
	}
	sort.Slice(variables, func(i, j int) bool { return variables[i].Name < variables[j].Name })
	return variables, true, nil
}

// Both initial admission and readback use short parent/member/credential locks.
// They release every database lock before any CRM or rendering request.
func (s *Server) lockCRMDocument(ctx context.Context, tx pgx.Tx, actor authoring.Actor, id uuid.UUID) (*authoring.DraftGuard, *crmDocumentContext, error) {
	guard, err := authoring.LockDraft(ctx, tx, actor, id)
	if err != nil {
		return nil, nil, err
	}
	q := generated.New(tx)
	user, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
	if err != nil {
		return nil, nil, err
	}
	if user.Role != string(auth.RoleOwner) && guard.Document.SenderID != actor.UserID {
		return nil, nil, auth.ErrMutationPermissionRevoked
	}
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: id, OrgID: actor.OrgID})
	if err != nil {
		return nil, nil, err
	}
	fingerprint, err := crmreview.FullBindingFingerprint(bindings)
	if err != nil {
		return nil, nil, err
	}
	row, err := q.GetCRMConnectionByOrgForShare(ctx, actor.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		row, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	variables, supported, err := crmDocumentVariables(guard.Document)
	if err != nil {
		return nil, nil, err
	}
	result := &crmDocumentContext{doc: guard.Document, bindings: bindings, connection: row, variables: variables, supported: supported}
	result.response = crmDocumentResponseWitness{OrgID: actor.OrgID, UserID: actor.UserID, DocumentID: id,
		UpdatedAt: guard.Document.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), BindingFingerprint: fingerprint}
	if len(guard.Document.HtmlSourceJson) != 0 {
		result.response.HTMLSourceCommitment, err = htmlsource.Commitment(guard.Document)
		if err != nil {
			return nil, nil, err
		}
	}
	if row != nil {
		result.response.Connection = &crmDocumentConnectionDTO{ID: row.ID, Generation: strconv.FormatInt(row.Generation, 10), Status: row.Status, Origin: row.Origin, CRMTeamID: row.CrmTeamID, CRMUserID: row.CrmUserID}
	}
	if supported {
		review, err := q.GetDocumentCRMMappingReviewForShare(ctx, generated.GetDocumentCRMMappingReviewForShareParams{DocumentID: id, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			review, err = nil, nil
		}
		if err != nil {
			return nil, nil, err
		}
		matched, err := crmreview.ReviewMatches(guard.Document, bindings, review, row)
		if err != nil {
			return nil, nil, err
		}
		result.reviewRequired = !matched
	}
	return guard, result, nil
}

func (in CRMDocumentWitness) validate(actor authoring.Actor) error {
	if in.ExpectedOrgID == uuid.Nil || in.ExpectedUserID == uuid.Nil {
		return errCRMDocumentInput
	}
	if in.ExpectedOrgID != actor.OrgID || in.ExpectedUserID != actor.UserID {
		return errCRMDocumentChanged
	}
	at, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || at.IsZero() || !htmlPreviewSHA256(in.ExpectedBindingFingerprint) {
		return errCRMDocumentInput
	}
	if in.ExpectedHTMLSourceCommitment != "" && !htmlPreviewSHA256(in.ExpectedHTMLSourceCommitment) {
		return errCRMDocumentInput
	}
	n, err := crmGeneration(in.ExpectedConnectionGeneration, true)
	if err != nil {
		return errCRMDocumentInput
	}
	if in.ExpectedConnectionID == "" {
		if n != 0 {
			return errCRMDocumentInput
		}
	} else {
		id, err := uuid.Parse(in.ExpectedConnectionID)
		if err != nil || id == uuid.Nil || id.String() != in.ExpectedConnectionID || n == 0 {
			return errCRMDocumentInput
		}
	}
	return nil
}

func (in CRMDocumentWitness) matches(current *crmDocumentContext) error {
	if current == nil || !current.supported {
		return errCRMDocumentUnsupported
	}
	at, err := time.Parse(time.RFC3339Nano, in.ExpectedUpdatedAt)
	if err != nil || !current.doc.UpdatedAt.Time.Equal(at) || in.ExpectedHTMLSourceCommitment != current.response.HTMLSourceCommitment || in.ExpectedBindingFingerprint != current.response.BindingFingerprint {
		return errCRMDocumentChanged
	}
	if current.connection == nil {
		if in.ExpectedConnectionID != "" || in.ExpectedConnectionGeneration != "0" {
			return errCRMDocumentChanged
		}
	} else if in.ExpectedConnectionID != current.connection.ID.String() || in.ExpectedConnectionGeneration != strconv.FormatInt(current.connection.Generation, 10) {
		return errCRMDocumentChanged
	}
	return nil
}

func (s *Server) readCRMDocument(ctx context.Context, actor authoring.Actor, id uuid.UUID, expected *CRMDocumentWitness) (*crmDocumentContext, error) {
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
	guard, result, err := s.lockCRMDocument(ctx, tx, actor, id)
	if err != nil {
		return nil, err
	}
	if expected != nil {
		if err = expected.matches(result); err != nil {
			return nil, err
		}
	}
	if err = guard.Recheck(ctx); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Server) crmDocumentActor(w http.ResponseWriter, r *http.Request) (authoring.Actor, uuid.UUID, bool) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return authoring.Actor{}, uuid.Nil, false
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil || id == uuid.Nil {
		writeError(w, 400, "invalid document id")
		return authoring.Actor{}, uuid.Nil, false
	}
	authorize, ok := s.sessionMutationAuthorization(w, r, u)
	if !ok {
		return authoring.Actor{}, uuid.Nil, false
	}
	return authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id, true
}

func (s *Server) writeCRMDocumentError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, 401, "original session expired")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, 403, "only the document author or an organization owner can use CRM information")
	case errors.Is(err, authoring.ErrDocumentNotFound):
		writeError(w, 404, "document not found")
	case errors.Is(err, errCRMDocumentInput), errors.Is(err, errCRMDocumentUnsupported), errors.Is(err, crmconnection.ErrSearchInput), errors.Is(err, htmlmaster.ErrInvalid), errors.Is(err, htmlmaster.ErrLimit), errors.Is(err, htmlmaster.ErrMissingValues), errors.Is(err, htmlmaster.ErrContractIncomplete):
		writeError(w, 400, "invalid or unsupported CRM document input")
	case errors.Is(err, errCRMDocumentChanged), errors.Is(err, errHTMLDocumentRevisionConflict), errors.Is(err, htmlsource.ErrInvalid), errors.Is(err, crmconnection.ErrIdentity), errors.Is(err, crmreview.ErrReviewRequired), errors.Is(err, authoring.ErrDocumentNotDraft), errors.Is(err, authoring.ErrDocumentHasEvidence), errors.Is(err, authoring.ErrPrivacyReviewChanging), errors.Is(err, authoring.ErrPendingPrivacyReview):
		writeError(w, 409, errCRMDocumentChanged.Error())
	default:
		writeError(w, 503, "CRM information temporarily unavailable; refresh before trying again")
	}
}

func (s *Server) handleCRMDocumentContext(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor, id, ok := s.crmDocumentActor(w, r)
	if !ok {
		return
	}
	current, err := s.readCRMDocument(r.Context(), actor, id, nil)
	if err != nil {
		s.writeCRMDocumentError(w, err)
		return
	}
	bindings := make([]bindingDTO, 0, len(current.bindings))
	for _, b := range current.bindings {
		dto := bindingToDTO(b)
		// Discovery needs mapping definitions, not historical values or provider diagnostics.
		dto.LastValue, dto.LastResolved, dto.LastError = "", "", ""
		bindings = append(bindings, dto)
	}
	writeJSON(w, 200, struct {
		crmDocumentResponseWitness
		Supported             bool                                                         `json:"supported"`
		Available             bool                                                         `json:"available"`
		Variables             []crmDocumentVariable                                        `json:"variables"`
		Bindings              []bindingDTO                                                 `json:"bindings"`
		Catalog               map[crmconnection.RecordKind][]crmconnection.FieldDefinition `json:"catalog"`
		MappingReviewRequired bool                                                         `json:"mapping_review_required"`
	}{current.response, current.supported, s.CRMClient != nil && s.CRMKeys != nil, current.variables, bindings, map[crmconnection.RecordKind][]crmconnection.FieldDefinition{
		crmconnection.Deal: crmconnection.Catalog(crmconnection.Deal), crmconnection.Contact: crmconnection.Catalog(crmconnection.Contact), crmconnection.Company: crmconnection.Catalog(crmconnection.Company)}, current.reviewRequired})
}
