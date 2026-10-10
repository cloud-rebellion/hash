// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

var (
	ErrCreationTemplateNotFound = errors.New("template not found")
	ErrCreationInput            = errors.New("invalid document input")
)

type DocumentSeed struct {
	Template      *generated.Template
	BlocksJSON    json.RawMessage
	VariablesJSON json.RawMessage
}

// ResolveDocumentSeed reads a fresh active tenant template under a SHARE lock
// in the caller's bounded READ COMMITTED transaction. Even complete overrides
// must validate their template reference. The lock keeps defaults and PDF
// object/version pins stable until the new document commits.
func ResolveDocumentSeed(ctx context.Context, q *generated.Queries, orgID uuid.UUID, templateID pgtype.UUID,
	sourceKind string, blockTree, variables json.RawMessage,
) (*DocumentSeed, error) {
	seed := &DocumentSeed{}
	if templateID.Valid {
		var err error
		seed.Template, err = q.GetTemplateForShare(ctx, generated.GetTemplateForShareParams{ID: uuid.UUID(templateID.Bytes), OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrCreationTemplateNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("lock document creation template: %w", err)
		}
		if seed.Template.SourceKind != sourceKind {
			return nil, fmt.Errorf("%w: template is not a %s-source template", ErrCreationInput, sourceKind)
		}
	}
	switch sourceKind {
	case "blocks":
		if seed.Template != nil {
			if len(blockTree) == 0 {
				blockTree = seed.Template.BlocksJson
			}
		}
		if len(blockTree) == 0 {
			blockTree = json.RawMessage(`{"version":1,"blocks":[]}`)
		}
		normalized, err := blocks.NormalizeTreeJSON(blockTree)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid blocks_json: %v", ErrCreationInput, err)
		}
		seed.BlocksJSON = normalized
	case "pdf":
		if seed.Template == nil {
			return nil, fmt.Errorf("%w: template_id required when source_kind=pdf", ErrCreationInput)
		}
		if !seed.Template.PdfStorageKey.Valid || seed.Template.PdfStorageKey.String == "" {
			return nil, fmt.Errorf("%w: template has no PDF source", ErrCreationInput)
		}
	default:
		return nil, fmt.Errorf("%w: source_kind must be blocks or pdf", ErrCreationInput)
	}
	if len(variables) == 0 && seed.Template != nil {
		variables = seed.Template.VariablesJson
	}
	if len(variables) == 0 {
		variables = json.RawMessage(`{}`)
	}
	if _, err := blocks.ParseVariableValues(variables); err != nil {
		return nil, fmt.Errorf("%w: invalid variables_json: %v", ErrCreationInput, err)
	}
	seed.VariablesJSON = variables
	return seed, nil
}
