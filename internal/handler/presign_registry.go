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
	"net/url"
	"reflect"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Server) presignActor(r *http.Request) (presignregistry.SessionActor, error) {
	u, ok := auth.FromContext(r.Context())
	if !ok || u.OrgID == uuid.Nil || u.UserID == uuid.Nil {
		return presignregistry.SessionActor{}, auth.ErrMutationPermissionRevoked
	}
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return presignregistry.SessionActor{}, auth.ErrMutationCredentialExpired
	}
	return presignregistry.NewSessionActor(s.Cookies, cookie.Value, u.OrgID, u.UserID)
}

func (s *Server) presignEngine(r *http.Request) (*presignregistry.Engine, presignregistry.SessionActor, error) {
	a, err := s.presignActor(r)
	if err != nil {
		return nil, a, err
	}
	if s.Pool == nil || s.Audit == nil || s.Cookies == nil {
		return nil, a, presignregistry.ErrUnavailable
	}
	return presignregistry.NewEngine(s.Pool, s.Audit, s.Cookies), a, nil
}

func writePresignError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, presignregistry.ErrAudit):
		writeInternalErrorMsg(w, "signing authority operation failed", err)
	case errors.Is(err, auth.ErrMutationCredentialExpired):
		writeError(w, http.StatusUnauthorized, "original session expired")
	case errors.Is(err, auth.ErrMutationPermissionRevoked):
		writeError(w, http.StatusForbidden, "signing authority permission unavailable")
	case errors.Is(err, presignregistry.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid signing authority input")
	case errors.Is(err, presignregistry.ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		writeError(w, http.StatusNotFound, "signing authority or confirmed request not found")
	case errors.Is(err, presignregistry.ErrConflict):
		writeError(w, http.StatusConflict, "signing authority or reviewed information changed; review again")
	case errors.Is(err, presignregistry.ErrUnavailable):
		writeError(w, http.StatusServiceUnavailable, "signing authority temporarily unavailable; recover the original request before retrying")
	default:
		writeInternalErrorMsg(w, "signing authority operation failed", err)
	}
}

// Preserve the legal-response decoder's duplicate/case/Unicode/trailing-value
// checks and reject deep nulls and alternate UUID/decimal spellings as well.
func decodePresignJSON(r *http.Request, dst any) error {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxSignerJSONBody))
	if err != nil {
		return presignregistry.ErrInvalid
	}
	copy := r.Clone(r.Context())
	copy.Body = io.NopCloser(bytes.NewReader(raw))
	if decodeCRMTemplateJSON(copy, dst) != nil {
		return presignregistry.ErrInvalid
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || validatePresignScalarSpellings(value, reflect.TypeOf(dst)) != nil {
		return presignregistry.ErrInvalid
	}
	return nil
}

func validatePresignScalarSpellings(value any, target reflect.Type) error {
	for target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == reflect.TypeFor[uuid.UUID]() {
		raw, ok := value.(string)
		id, err := uuid.Parse(raw)
		if !ok || err != nil || id.String() != raw {
			return presignregistry.ErrInvalid
		}
		return nil
	}
	switch target.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return nil // time.Time and other scalar marshalers were typed-decoded.
		}
		fields := exactJSONStructFields(target)
		for name, child := range object {
			if err := validatePresignScalarSpellings(child, fields[name]); err != nil {
				return err
			}
		}
	case reflect.Array, reflect.Slice:
		if values, ok := value.([]any); ok {
			for _, child := range values {
				if err := validatePresignScalarSpellings(child, target.Elem()); err != nil {
					return err
				}
			}
		}
	case reflect.Int, reflect.Int32, reflect.Int64:
		if raw, ok := value.(string); ok {
			n, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || strconv.FormatInt(n, 10) != raw {
				return presignregistry.ErrInvalid
			}
		}
	}
	return nil
}

func presignUUIDParam(r *http.Request, name string) (uuid.UUID, error) {
	raw := chi.URLParam(r, name)
	id, err := uuid.Parse(raw)
	if err != nil || id == uuid.Nil || id.String() != raw {
		return uuid.Nil, presignregistry.ErrInvalid
	}
	return id, nil
}

func presignRevision(r *http.Request) (int64, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, presignregistry.ErrInvalid
	}
	if len(query) == 0 {
		return 0, nil // Explicit service meaning: current locked head.
	}
	values, ok := query["revision"]
	if !ok || len(query) != 1 || len(values) != 1 {
		return 0, presignregistry.ErrInvalid
	}
	n, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil || n < 1 || n > presign.MaxRevision || strconv.FormatInt(n, 10) != values[0] {
		return 0, presignregistry.ErrInvalid
	}
	return n, nil
}

func servePresignInput[T, R any](s *Server, w http.ResponseWriter, r *http.Request,
	call func(context.Context, *presignregistry.Engine, presignregistry.SessionActor, T) (R, error),
	check func(T) error,
) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	var in T
	if decodePresignJSON(r, &in) != nil {
		writePresignError(w, presignregistry.ErrInvalid)
		return
	}
	if check != nil {
		if err := check(in); err != nil {
			writePresignError(w, err)
			return
		}
	}
	value, err := call(r.Context(), e, a, in)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func presignPathReference(r *http.Request) func(presignregistry.ResourceMutationInput) error {
	return func(in presignregistry.ResourceMutationInput) error {
		id, err := presignUUIDParam(r, "id")
		if err != nil || in.Reference.ID != id {
			return presignregistry.ErrInvalid
		}
		return nil
	}
}

func (s *Server) handlePresignWorkflowPreview(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.WorkflowIntent) (presignregistry.WorkflowPreview, error) {
		return e.PreviewWorkflow(ctx, a, in)
	}, nil)
}
func (s *Server) handlePresignWorkflowApprove(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ConfirmWorkflowInput) (presignregistry.Outcome, error) {
		return e.ApproveWorkflow(ctx, a, in)
	}, nil)
}
func (s *Server) handlePresignWorkflowRetire(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ResourceMutationInput) (presignregistry.Outcome, error) {
		return e.RetireWorkflow(ctx, a, in)
	}, presignPathReference(r))
}
func (s *Server) handlePresignWorkflowArchive(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ResourceMutationInput) (presignregistry.Outcome, error) {
		return e.ArchiveWorkflow(ctx, a, in)
	}, presignPathReference(r))
}
func (s *Server) handlePresignGrantPreview(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.GrantIntent) (presignregistry.GrantPreview, error) {
		return e.PreviewSelfGrant(ctx, a, in)
	}, nil)
}
func (s *Server) handlePresignGrantCreate(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ConfirmGrantInput) (presignregistry.Outcome, error) {
		return e.CreateSelfGrant(ctx, a, in)
	}, nil)
}
func (s *Server) handlePresignGrantRevise(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ConfirmGrantInput) (presignregistry.Outcome, error) {
		return e.ReviseSelfGrant(ctx, a, in)
	}, func(in presignregistry.ConfirmGrantInput) error {
		id, err := presignUUIDParam(r, "id")
		if err != nil || in.Intent.GrantID != id {
			return presignregistry.ErrInvalid
		}
		return nil
	})
}
func (s *Server) handlePresignOwnRevoke(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ResourceMutationInput) (presignregistry.Outcome, error) {
		return e.RevokeOwnGrant(ctx, a, in)
	}, presignPathReference(r))
}
func (s *Server) handlePresignOwnerRevoke(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.ResourceMutationInput) (presignregistry.Outcome, error) {
		return e.RevokeGrantAsOwner(ctx, a, in)
	}, presignPathReference(r))
}
func (s *Server) handlePresignRequestClose(w http.ResponseWriter, r *http.Request) {
	servePresignInput(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, in presignregistry.CloseRequestInput) (presignregistry.Outcome, error) {
		return e.CloseOwnRequest(ctx, a, in)
	}, func(in presignregistry.CloseRequestInput) error {
		id, err := presignUUIDParam(r, "request_id")
		if err != nil || in.RequestID != id {
			return presignregistry.ErrInvalid
		}
		return nil
	})
}

type presignItems[T any] struct {
	OrgID  uuid.UUID `json:"org_id"`
	UserID uuid.UUID `json:"user_id"`
	Items  []T       `json:"items"`
}

func (s *Server) handlePresignWorkflows(w http.ResponseWriter, r *http.Request) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	items, err := e.ListWorkflows(r.Context(), a)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, presignItems[presignregistry.WorkflowView]{a.OrgID(), a.UserID(), items})
}
func (s *Server) handlePresignOwnGrants(w http.ResponseWriter, r *http.Request) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	items, err := e.ListOwnGrants(r.Context(), a)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, presignItems[presignregistry.GrantView]{a.OrgID(), a.UserID(), items})
}
func (s *Server) handlePresignOwnerGrants(w http.ResponseWriter, r *http.Request) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	items, err := e.ListGrantsAsOwner(r.Context(), a)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, presignItems[presignregistry.GrantView]{a.OrgID(), a.UserID(), items})
}
func servePresignDetail[T any](s *Server, w http.ResponseWriter, r *http.Request, call func(context.Context, *presignregistry.Engine, presignregistry.SessionActor, uuid.UUID, int64) (T, error)) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	id, err := presignUUIDParam(r, "id")
	if err != nil {
		writePresignError(w, err)
		return
	}
	rev, err := presignRevision(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	value, err := call(r.Context(), e, a, id, rev)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (s *Server) handlePresignWorkflow(w http.ResponseWriter, r *http.Request) {
	servePresignDetail(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, id uuid.UUID, revision int64) (presignregistry.WorkflowView, error) {
		return e.GetWorkflow(ctx, a, id, revision)
	})
}
func (s *Server) handlePresignOwnGrant(w http.ResponseWriter, r *http.Request) {
	servePresignDetail(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, id uuid.UUID, revision int64) (presignregistry.GrantView, error) {
		return e.GetOwnGrant(ctx, a, id, revision)
	})
}
func (s *Server) handlePresignOwnerGrant(w http.ResponseWriter, r *http.Request) {
	servePresignDetail(s, w, r, func(ctx context.Context, e *presignregistry.Engine, a presignregistry.SessionActor, id uuid.UUID, revision int64) (presignregistry.GrantView, error) {
		return e.GetGrantAsOwner(ctx, a, id, revision)
	})
}
func (s *Server) handlePresignRequest(w http.ResponseWriter, r *http.Request) {
	e, a, err := s.presignEngine(r)
	if err != nil {
		writePresignError(w, err)
		return
	}
	id, err := presignUUIDParam(r, "request_id")
	if err != nil {
		writePresignError(w, err)
		return
	}
	value, err := e.GetOwnRequest(r.Context(), a, id)
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}

// Even discovery retains current membership and the original session while
// constructing its actor witness. It exposes no grant, credential or document.
func (s *Server) withPresignMember(r *http.Request, owner bool, read func(context.Context, *generated.Queries, *generated.User) (any, error)) (any, error) {
	a, err := s.presignActor(r)
	if err != nil {
		return nil, err
	}
	if s.Pool == nil {
		return nil, presignregistry.ErrUnavailable
	}
	authorize, err := s.sessionDraftAuthorization(r, a.OrgID(), a.UserID())
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(r.Context(), presignregistry.MutationTimeout)
	defer cancel()
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, presignregistry.ErrUnavailable
	}
	defer func() { _ = authoring.Rollback(ctx, tx) }()
	q := generated.New(tx)
	if _, err = q.GetOrgForOwnerMutation(ctx, a.OrgID()); err != nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	u, err := q.GetUserForShare(ctx, generated.GetUserForShareParams{ID: a.UserID(), OrgID: a.OrgID()})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err != nil {
		return nil, err
	}
	if owner && u.Role != string(auth.RoleOwner) {
		return nil, auth.ErrMutationPermissionRevoked
	}
	if err = authorize(ctx, tx, u); err != nil {
		return nil, err
	}
	value, err := read(ctx, q, u)
	if err != nil {
		return nil, err
	}
	if err = authorize(ctx, tx, u); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, presignregistry.ErrUnavailable
	}
	return value, nil
}

func (s *Server) handlePresignContext(w http.ResponseWriter, r *http.Request) {
	value, err := s.withPresignMember(r, false, func(_ context.Context, _ *generated.Queries, u *generated.User) (any, error) {
		styles, err := presignregistry.SignatureStyles()
		if err != nil {
			return nil, presignregistry.ErrUnavailable
		}
		return map[string]any{"org_id": u.OrgID, "user_id": u.ID, "self": map[string]any{"id": u.ID, "name": u.Name, "email": u.Email, "role": u.Role}, "execution_available": false, "fonts": styles, "disclosure": presignregistry.Disclosure()}, nil
	})
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func (s *Server) handlePresignFont(w http.ResponseWriter, r *http.Request) {
	font := chi.URLParam(r, "font")
	if _, err := render.SignatureFontSHA256(font); err != nil {
		writePresignError(w, presignregistry.ErrNotFound)
		return
	}
	value, err := s.withPresignMember(r, false, func(_ context.Context, _ *generated.Queries, _ *generated.User) (any, error) {
		for _, asset := range render.FontAssets() {
			if asset.Filename == strings.ReplaceAll(font, " ", "")+".woff2" {
				return asset.Bytes, nil
			}
		}
		return nil, presignregistry.ErrUnavailable
	})
	if err != nil {
		writePresignError(w, err)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(value.([]byte))
}

type presignTemplateDescriptor struct {
	Name            string                      `json:"name"`
	Template        presign.TemplatePin         `json:"template"`
	Values          []htmlmaster.Value          `json:"values"`
	Sections        []htmlmaster.Section        `json:"sections"`
	Defaults        map[string]string           `json:"defaults"`
	ContractProfile *htmlmaster.ContractProfile `json:"contract_profile"`
}

func (s *Server) handlePresignTemplates(w http.ResponseWriter, r *http.Request) {
	value, err := s.withPresignMember(r, true, func(ctx context.Context, q *generated.Queries, u *generated.User) (any, error) {
		rows, err := q.ListPresignApprovedTemplateDescriptors(ctx, u.OrgID)
		if err != nil {
			return nil, err
		}
		items := []presignTemplateDescriptor{}
		truncated := len(rows) > 20
		inputBytes, outputBytes := int64(0), 0
		for _, row := range rows {
			if len(items) >= 20 {
				break
			}
			if row.SourceBytes < 1 || row.SourceBytes > 24<<20 || inputBytes > (24<<20)-row.SourceBytes {
				truncated = true
				break
			}
			inputBytes += row.SourceBytes
			revision, err := q.GetHTMLTemplateRevision(ctx, generated.GetHTMLTemplateRevisionParams{TemplateID: row.TemplateID, OrgID: u.OrgID, Version: row.Version})
			if err != nil || !bytes.Equal(row.ContentSha256, revision.ContentSha256) || !row.ApprovedBy.Valid || !revision.ApprovedBy.Valid || row.ApprovedBy.Bytes != revision.ApprovedBy.Bytes || !row.ApprovedAt.Valid || !revision.ApprovedAt.Valid || !row.ApprovedAt.Time.Equal(revision.ApprovedAt.Time) {
				return nil, presignregistry.ErrConflict
			}
			commitment, err := htmlmaster.CanonicalTemplate(revision.HtmlMasterJson, revision.VariablesJson)
			if err != nil || !bytes.Equal(row.ContentSha256, mustDecodePresignSHA(commitment.SHA256)) {
				return nil, presignregistry.ErrConflict
			}
			master, err := htmlmaster.Decode(commitment.MasterJSON)
			if err != nil || master.SchemaVersion != htmlmaster.SigningPageSchemaVersion || master.ContractProfile == nil || master.SigningPage == nil {
				return nil, presignregistry.ErrConflict
			}
			defaults := map[string]string{}
			if json.Unmarshal(commitment.DefaultsJSON, &defaults) != nil {
				return nil, presignregistry.ErrConflict
			}
			desc := presignTemplateDescriptor{Name: row.Name, Template: presign.TemplatePin{ID: row.TemplateID, Version: int64(row.Version), ContentSHA256: commitment.SHA256, ApprovedBy: uuid.UUID(row.ApprovedBy.Bytes), ApprovedAt: row.ApprovedAt.Time}, Values: master.Values, Sections: master.Sections, Defaults: defaults, ContractProfile: master.ContractProfile}
			if desc.Values == nil {
				desc.Values = []htmlmaster.Value{}
			}
			if desc.Sections == nil {
				desc.Sections = []htmlmaster.Section{}
			}
			encoded, err := json.Marshal(desc)
			if err != nil {
				return nil, err
			}
			outputBytes += len(encoded)
			if outputBytes > 512<<10 {
				truncated = true
				break
			}
			items = append(items, desc)
		}
		return map[string]any{"org_id": u.OrgID, "user_id": u.ID, "items": items, "truncated": truncated}, nil
	})
	if err != nil {
		writePresignError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, value)
}
func mustDecodePresignSHA(raw string) []byte { value, _ := hex.DecodeString(raw); return value }
