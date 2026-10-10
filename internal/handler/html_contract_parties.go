// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"context"
	"fmt"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/recipients"
)

// The enclosing HTML transaction holds the organization quota and document
// locks. Both named recipients are derived from the same values that were
// rendered; a second independent set of caller-supplied identities is refused.
func createHTMLContractParties(ctx context.Context, q *generated.Queries, doc *generated.Document, compiled *htmlmaster.Compiled, input htmlmaster.Input) ([]htmlsource.PartyBinding, error) {
	readiness, err := compiled.ContractReadiness(input)
	if err != nil || compiled.ContractProfile() == nil {
		return nil, err
	}
	if !readiness.Complete || len(readiness.Parties) != 2 {
		return nil, htmlmaster.ErrContractIncomplete
	}
	bindings := make([]htmlsource.PartyBinding, 0, 2)
	for _, party := range readiness.Parties {
		values, err := recipients.Normalize(recipients.Values{Role: party.Slot, Name: party.RepresentativeName,
			Email: party.RepresentativeEmail, Locale: doc.DefaultLocale})
		if err != nil {
			return nil, err
		}
		_, tokenHash, err := auth.MintMagicToken()
		if err != nil {
			return nil, fmt.Errorf("mint contract recipient token: %w", err)
		}
		recipient, err := q.CreateRecipient(ctx, generated.CreateRecipientParams{DocumentID: doc.ID,
			Role: values.Role, Name: values.Name, Email: values.Email, OrderIndex: 0, Locale: values.Locale,
			MagicTokenHash: tokenHash, MagicTokenExpiresAt: magictoken.Expiry(doc.ExpiresAt, time.Now())})
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, htmlsource.PartyBinding{Slot: party.Slot, RecipientID: recipient.ID})
	}
	return bindings, nil
}

// Representative changes use the same authorized draft transaction as the
// fresh PDF projection. Keep each intended UUID, routing locale and order;
// reset old placement/review at the materialization append boundary.
func updateHTMLContractParties(ctx context.Context, q *generated.Queries, before *generated.Document, input htmlsource.Input) (bool, error) {
	parties, err := htmlsource.ContractParties(before)
	if err != nil || len(parties) == 0 {
		return false, err
	}
	rows, err := q.ListRecipientsByDocument(ctx, before.ID)
	if err != nil {
		return false, err
	}
	if err := htmlsource.ValidateContractParties(before, rows); err != nil {
		return false, err
	}
	master, err := htmlmaster.Decode(input.MasterJSON)
	if err != nil {
		return false, err
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		return false, err
	}
	readiness, err := compiled.ContractReadiness(htmlmaster.Input{Values: input.Values, Sections: input.Sections})
	if err != nil || !readiness.Complete || len(readiness.Parties) != 2 {
		return false, htmlmaster.ErrContractIncomplete
	}
	changed := false
	for _, next := range readiness.Parties {
		for _, party := range parties {
			if next.Slot != party.Slot {
				continue
			}
			for _, row := range rows {
				if row.ID != party.RecipientID {
					continue
				}
				values, err := recipients.Normalize(recipients.Values{Role: next.Slot, Name: next.RepresentativeName,
					Email: next.RepresentativeEmail, OrderIndex: row.OrderIndex, Locale: row.Locale})
				if err != nil {
					return false, err
				}
				if row.Name == values.Name && row.Email == values.Email && row.Role == values.Role {
					continue
				}
				if _, err := q.UpdateRecipient(ctx, generated.UpdateRecipientParams{ID: row.ID, DocumentID: before.ID,
					Name: values.Name, Email: values.Email, Role: values.Role, OrderIndex: values.OrderIndex, Locale: values.Locale}); err != nil {
					return false, err
				}
				changed = true
			}
		}
	}
	if changed {
		if err := q.InvalidateRecipientTokens(ctx, before.ID); err != nil {
			return false, err
		}
	}
	return changed, nil
}
