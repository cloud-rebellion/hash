// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/catalogrules"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This exact result lives through handleToolsCall's original map marshal AND
// writeRPCResult serialization. Copies share its original last-use release;
// no copied-result capability or generic resource framework is claimed.
type catalogRuleOwnedResultV1 struct {
	state *catalogRuleOwnedResultStateV1
}
type catalogRuleOwnedResultStateV1 struct {
	mu      sync.Mutex
	value   any
	input   *pdfadmission.ApplicationCatalogRuleInputV1
	release func()
	closed  bool
}

func (h *catalogRuleOwnedResultV1) MarshalJSON() ([]byte, error) {
	if h == nil || h.state == nil {
		return []byte("null"), nil
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, pdfadmission.ErrCatalogRuleInputV1
	}
	return json.Marshal(s.value)
}
func (h *catalogRuleOwnedResultV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.value = nil
	release, input := s.release, s.input
	s.release = nil
	s.input = nil
	s.mu.Unlock()
	if release != nil {
		release()
	}
	if input != nil {
		input.CloseConsumerV1()
	}
}

func catalogRuleSessionsV1(d Deps) (*pdfadmission.ApplicationSessionFactoryV1, error) {
	if d.Send == nil || d.Send.WorkRuntime == nil || !d.Send.WorkRuntime.MatchesPoolV1(d.Pool) {
		return nil, pdfadmission.ErrWorkRuntimeV1
	}
	f := d.Send.WorkRuntime.SessionsV1()
	if f == nil {
		return nil, pdfadmission.ErrWorkRuntimeV1
	}
	return f, nil
}
func createCatalogRuleOwnedV1(r *http.Request, args json.RawMessage, d Deps) (any, error) {
	u, _ := auth.FromContext(r.Context())
	f, err := catalogRuleSessionsV1(d)
	if err != nil {
		return nil, err
	}
	input, err := f.NewCatalogRuleArgumentsV1(r.Context(), u.OrgID, args)
	if err != nil {
		return nil, err
	}
	owned := &catalogRuleOwnedResultV1{state: &catalogRuleOwnedResultStateV1{input: input}}
	var p pdfadmission.CatalogRuleCreateInputV1
	if err = MustParseArgs(args, &p); err != nil {
		return owned, err
	}
	if !eidas.Tier(p.RequiredTier).Valid() {
		return owned, errors.New("required_tier must be SES, AES, or QES")
	}
	if err = input.ValidateRuleV1(r.Context(), p.Predicate, eidas.Tier(p.RequiredTier)); err != nil {
		return owned, fmt.Errorf("invalid eIDAS rule: %w", err)
	}
	active := true
	if p.Active != nil {
		active = *p.Active
	}
	if err = eidas.ValidateRuleActivation(eidas.Tier(p.RequiredTier), active); err != nil {
		return owned, err
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, mcpScopeWriteAuthoring)
	if err != nil {
		return owned, err
	}
	row, release, err := catalogrules.CommitCatalogOwnerMutationV1(r.Context(), f, d.Audit,
		authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, uuid.New(),
		func(ctx context.Context, q *generated.Queries, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1) (*generated.EidasRoutingRule, error) {
			return reader.CreateCatalogRuleV1(ctx, generated.InsertEIDASRuleParams{OrgID: u.OrgID, Name: p.Name, Priority: p.Priority, PredicateJson: p.Predicate, RequiredTier: p.RequiredTier, Reason: p.Reason, Active: active})
		},
		func(row *generated.EidasRoutingRule) audit.Entry {
			return audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"via": "mcp", "tool": "create_eidas_rule", "rule_id": row.ID.String()}}
		},
	)
	if err != nil {
		return owned, err
	}
	owned.state.value = ruleRow(row)
	owned.state.release = release
	return owned, nil
}

func deleteCatalogRuleOwnedV1(r *http.Request, args json.RawMessage, d Deps) (any, error) {
	u, _ := auth.FromContext(r.Context())
	var p struct {
		RuleID string `json:"rule_id"`
	}
	if err := MustParseArgs(args, &p); err != nil {
		return nil, err
	}
	id, err := uuid.Parse(p.RuleID)
	if err != nil {
		return nil, errors.New("rule_id must be a uuid")
	}
	authorize, err := auth.APIKeyTransactionAuthorization(r.Context(), uuid.Nil, mcpScopeWriteAuthoring)
	if err != nil {
		return nil, err
	}
	f, err := catalogRuleSessionsV1(d)
	if err != nil {
		return nil, err
	}
	_, release, err := catalogrules.CommitCatalogOwnerMutationV1(r.Context(), f, d.Audit,
		authoring.Actor{OrgID: u.OrgID, UserID: u.UserID, Authorize: authorize}, id,
		func(ctx context.Context, q *generated.Queries, reader *pdfadmission.ApplicationHTMLAuthoringReaderV1) (uuid.UUID, error) {
			if err := reader.DeleteCatalogRuleV1(ctx, id); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return uuid.Nil, errEIDASRuleNotFound
				}
				return uuid.Nil, err
			}
			return id, nil
		},
		func(uuid.UUID) audit.Entry {
			return audit.Entry{OrgID: u.OrgID, ActorUserID: &u.UserID, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"via": "mcp", "tool": "delete_eidas_rule", "rule_id": id.String()}}
		},
	)
	if err != nil {
		return nil, err
	}
	return &catalogRuleOwnedResultV1{state: &catalogRuleOwnedResultStateV1{value: map[string]any{"deleted": id.String()}, release: release}}, nil
}
