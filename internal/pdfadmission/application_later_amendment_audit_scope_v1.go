// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type laterAmendmentAuditKeyV1 struct{}

// Only the actual paired reader can bind the new document's origin event into
// its own ordinary report. The session still physically belongs to the original
// root; both sorted subjects and bodies remain admitted by this SAME owner.
type applicationLaterAmendmentAuditScopeV1 struct {
	source *applicationDocumentPackageSelectionStateV1
	call   context.Context
	actor  uuid.UUID
}

func (a *applicationLaterAmendmentAuditScopeV1) validV1(ctx context.Context) bool {
	if a == nil || a.source == nil || a.call == nil || ctx == nil {
		return false
	}
	s := a.source
	return !s.closed.Load() && s.attempted && s.readActor == a.actor && s.readers[0] != nil && s.readers[1] != nil && s.readers[0].snapshot != nil && s.readers[1].snapshot != nil && ctx.Value(applicationSessionCallbackKeyV1{}) == s.session.state && s.call == a.call
}
func (a *applicationLaterAmendmentAuditScopeV1) matchesV1(ctx context.Context, h *ApplicationSessionV1, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID) bool {
	return a.validV1(ctx) && h == a.source.session && purpose == HTMLAuditLaterAmendmentV1 && org == a.source.session.state.org && document == a.source.ids[1] && !recipient.Valid && actor.Valid && uuid.UUID(actor.Bytes) == a.actor
}
