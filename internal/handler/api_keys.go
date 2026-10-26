// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
)

var errAPIKeyNotFound = errors.New("api key not found")

type apiKeyResponse struct {
	ID         uuid.UUID `json:"id"`
	Name       string    `json:"name"`
	Prefix     string    `json:"key_prefix"`
	Scopes     []string  `json:"scopes"`
	ExpiresAt  string    `json:"expires_at,omitempty"`
	LastUsedAt string    `json:"last_used_at,omitempty"`
	CreatedAt  string    `json:"created_at"`
	// Plaintext is only set on the response from POST /api-keys.
	// Subsequent GETs never return it.
	Plaintext string `json:"plaintext,omitempty"`
}

type listAPIKeysRow struct {
	ID         uuid.UUID
	Name       string
	KeyPrefix  string
	Scopes     []string
	ExpiresAt  pgtype.Timestamptz
	LastUsedAt pgtype.Timestamptz
	CreatedAt  pgtype.Timestamptz
}

func toAPIKeyResponse(r *generated.ListAPIKeysByUserRow) apiKeyResponse {
	out := apiKeyResponse{
		ID:        r.ID,
		Name:      r.Name,
		Prefix:    r.KeyPrefix,
		Scopes:    append([]string{}, r.Scopes...),
		CreatedAt: r.CreatedAt.Time.Format(time.RFC3339),
	}
	if r.ExpiresAt.Valid {
		out.ExpiresAt = r.ExpiresAt.Time.Format(time.RFC3339)
	}
	if r.LastUsedAt.Valid {
		out.LastUsedAt = r.LastUsedAt.Time.Format(time.RFC3339)
	}
	return out
}

type createAPIKeyInput struct {
	Name string `json:"name"`
	// Omission selects authoring defaults; an explicit null/empty array must
	// never be expanded into write permissions by a len(scopes)==0 fallback.
	Scopes    json.RawMessage `json:"scopes"`
	ExpiresAt string          `json:"expires_at,omitempty"`
}

func apiKeyCreationScopes(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 {
		return []string{"read", "write:authoring"}, nil
	}
	var scopes []string
	if err := json.Unmarshal(raw, &scopes); err != nil || len(scopes) == 0 {
		return nil, errors.New("scopes must be a nonempty array of permissions")
	}
	for _, scope := range scopes {
		switch scope {
		case "read", "write:authoring", "write:workflow":
		default:
			return nil, errors.New("scopes must be a subset of [read, write:authoring, write:workflow]")
		}
	}
	return scopes, nil
}

// handleCreateAPIKey mints a fresh `mth_<prefix>_<secret>` key, hashes it,
// stores the hash, and returns the plaintext exactly once. Caller is
// responsible for displaying + copying the plaintext immediately; it can
// never be retrieved again.
func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	// API keys also authenticate the core standalone automation endpoint. Key
	// issuance therefore cannot inherit MCP's plan entitlement: /mcp rechecks
	// its own feature gate on every use, while the same credential remains valid
	// for /api/automation/v1/signature-requests when it has both write scopes.
	var in createAPIKeyInput
	if err := decodeSignerJSON(r, &in); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.Name == "" {
		writeError(w, http.StatusBadRequest, "name required")
		return
	}
	scopes, err := apiKeyCreationScopes(in.Scopes)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var expires pgtype.Timestamptz
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeError(w, http.StatusBadRequest, "expires_at must be RFC3339")
			return
		}
		expires = pgtype.Timestamptz{Time: t, Valid: true}
	}

	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize credential creation", err)
		return
	}
	key, err := auth.MintAPIKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key mint failed")
		return
	}

	row, err := authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (*generated.ApiKey, error) {
			return q.CreateAPIKey(ctx, generated.CreateAPIKeyParams{
				OrgID:     u.OrgID,
				UserID:    u.UserID,
				KeyPrefix: key.Prefix,
				KeyHash:   key.Hash,
				Name:      in.Name,
				Scopes:    scopes,
				ExpiresAt: expires,
			})
		},
		func(created *generated.ApiKey) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind: "api_key.created",
				IP:   clientIP(r),
				Payload: map[string]any{
					"key_id":     created.ID,
					"key_prefix": created.KeyPrefix,
					"name":       in.Name,
					"scopes":     scopes,
				},
			}
		},
	)
	if err != nil {
		s.writeDraftAuthoringError(w, "create api key failed", err)
		return
	}

	out := apiKeyResponse{
		ID:        row.ID,
		Name:      row.Name,
		Prefix:    row.KeyPrefix,
		Scopes:    append([]string{}, row.Scopes...),
		CreatedAt: row.CreatedAt.Time.Format(time.RFC3339),
		Plaintext: key.Plaintext,
	}
	if row.ExpiresAt.Valid {
		out.ExpiresAt = row.ExpiresAt.Time.Format(time.RFC3339)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusCreated, out)
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	rows, err := s.Queries.ListAPIKeysByUser(r.Context(), u.UserID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list keys failed")
		return
	}
	out := make([]apiKeyResponse, 0, len(rows))
	for _, row := range rows {
		out = append(out, toAPIKeyResponse(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"api_keys": out})
}

func (s *Server) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	u, ok := requireSessionUser(w, r.Context())
	if !ok {
		return
	}
	id, ok := parseUUIDParam(w, r, "id")
	if !ok {
		return
	}
	actor, err := s.sessionOwnerActor(r, u)
	if err != nil {
		s.writeDraftAuthoringError(w, "authorize credential deletion", err)
		return
	}
	_, err = authoring.CommitOwnerMutation(r.Context(), s.Pool, s.Audit, actor,
		func(ctx context.Context, q *generated.Queries) (uuid.UUID, error) {
			deleted, err := q.DeleteAPIKey(ctx, generated.DeleteAPIKeyParams{ID: id, UserID: u.UserID})
			if errors.Is(err, pgx.ErrNoRows) {
				return uuid.Nil, errAPIKeyNotFound
			}
			return deleted, err
		},
		func(deletedID uuid.UUID) audit.Entry {
			return audit.Entry{
				OrgID: u.OrgID, ActorUserID: &u.UserID,
				Kind:    "api_key.revoked",
				IP:      clientIP(r),
				Payload: map[string]any{"key_id": deletedID},
			}
		},
	)
	if errors.Is(err, errAPIKeyNotFound) {
		writeError(w, http.StatusNotFound, "api key not found")
		return
	}
	if err != nil {
		s.writeDraftAuthoringError(w, "delete failed", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
