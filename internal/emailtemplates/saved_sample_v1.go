// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion

package emailtemplates

import (
	"context"
	"math"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ReadSavedForOwnerTestV1 participates in the caller's original owner mutation
// transaction. The retained template-head locks span rendering and enqueue;
// delivery consumes frozen bytes and never rereads the mutable template head.
func ReadSavedForOwnerTestV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, guard *authoring.MemberGuard, kind string, expected int64) (dispatch.ServiceEmailTemplateV1, error) {
	if tx == nil || guard == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || !dispatch.ServiceEmailKindV1(kind) || expected < 0 || expected == math.MaxInt64 {
		return dispatch.ServiceEmailTemplateV1{}, ErrInput
	}
	if err := guard.Recheck(ctx); err != nil {
		return dispatch.ServiceEmailTemplateV1{}, err
	}
	control := pdfadmission.ServiceEmailControlFromContextV1(ctx)
	if control == nil {
		return dispatch.ServiceEmailTemplateV1{}, pdfadmission.ErrServiceEmailControlV1
	}
	if err := control.ReserveSampleOutputV1(ctx); err != nil {
		return dispatch.ServiceEmailTemplateV1{}, err
	}
	tpl, err := read(ctx, tx, kind, actor)
	if err != nil {
		return dispatch.ServiceEmailTemplateV1{}, err
	}
	if tpl.Revision != expected {
		return dispatch.ServiceEmailTemplateV1{}, ErrStale
	}
	return tpl.ServiceEmailTemplateV1, nil
}
