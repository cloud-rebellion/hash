// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"sync"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PackageSendAttemptInspectionV1 owns a single copied historical observation.
// It exposes neither native SQL/Work nor links, retry or mutation authority.
// Close after response serialization, including when WithObservationV1 refuses.
// Copies share the same one-shot delivery and last-use consumer.
type PackageSendAttemptInspectionV1 struct {
	state *packageSendAttemptInspectionStateV1
}
type packageSendAttemptInspectionStateV1 struct {
	mu                sync.Mutex
	owner             *ownedSendOperationV1
	observation       pdfadmission.HTMLSendPackageAttemptObservationV1
	delivered, closed bool
	borrowers         int
}

// WithObservationV1 joins actual response use. Closing any copied handle while
// the callback is active retains all original Work loans until that use ends.
func (r *PackageSendAttemptInspectionV1) WithObservationV1(fn func(pdfadmission.HTMLSendPackageAttemptObservationV1) error) error {
	if r == nil || r.state == nil || fn == nil {
		return pdfadmission.ErrHTMLSendPackageInspectionV1
	}
	s := r.state
	s.mu.Lock()
	if s.closed || s.delivered || s.owner == nil || !s.owner.valid(s.owner.original) {
		s.mu.Unlock()
		return pdfadmission.ErrHTMLSendPackageInspectionV1
	}
	s.delivered = true
	s.borrowers++
	view := s.observation
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.borrowers--
		var owner *ownedSendOperationV1
		if s.closed && s.borrowers == 0 {
			owner, s.owner, s.observation = s.owner, nil, pdfadmission.HTMLSendPackageAttemptObservationV1{}
		}
		s.mu.Unlock()
		if owner != nil {
			owner.closeConsumerV1()
		}
	}()
	return fn(view)
}

func (r *PackageSendAttemptInspectionV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.mu.Lock()
	s.closed = true
	var owner *ownedSendOperationV1
	if s.borrowers == 0 {
		owner, s.owner, s.observation = s.owner, nil, pdfadmission.HTMLSendPackageAttemptObservationV1{}
	}
	s.mu.Unlock()
	if owner != nil {
		owner.closeConsumerV1()
	}
}

// InspectPackageSendAttemptV1 is a fresh-request policy boundary, independent
// of the original Send request's context and credential. The current owner or
// assigned sender may inspect persisted history; the initiating actor remains
// immutable provenance, not a substitute for authentication. Background recovery
// must use a separate process scope and may not fabricate an Actor for this API.
func (e *Engine) InspectPackageSendAttemptV1(ctx context.Context, actor Actor, documentID, attemptID uuid.UUID) (out *PackageSendAttemptInspectionV1, failure error) {
	if actor.Authorize == nil || actor.UserID == nil || *actor.UserID == uuid.Nil || actor.OrgID == uuid.Nil || documentID == uuid.Nil || attemptID == uuid.Nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	op, err := e.newOwnedSendOperationV1(ctx, actor.OrgID, documentID)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			op.closeConsumerV1()
		}
	}()
	var observation pdfadmission.HTMLSendPackageAttemptObservationV1
	var phase *ownedSendPhaseV1
	err = op.phaseV1(pdfadmission.HTMLSendIntentReadV1, func(call context.Context, p *ownedSendPhaseV1, _ *generated.Queries, tx pgx.Tx) error {
		phase = p
		state, err := p.work.StateV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		user, err := authorizeOwnedLifecycleActorV1(call, p, tx, &actor)
		if err != nil {
			return err
		}
		if state.OrgID != actor.OrgID || !state.IsPdfSource || state.IsEnvelope || state.ParentEnvelopeID.Valid || (user.Role != string(auth.RoleOwner) && state.SenderID != user.ID) {
			return auth.ErrMutationPermissionRevoked
		}
		observation, err = p.work.InspectDurablePackageSendAttemptV1(call, attemptID)
		if err != nil {
			return err
		}
		return reauthorizeLifecycleActor(call, tx, actor, user)
	})
	// phaseV1's generic deferred cleanup is best-effort. This delivery boundary
	// explicitly joins the same actual native stage and refuses unretired SQL.
	if phase != nil {
		err = errors.Join(err, phase.stage.CloseSQLV1())
		if phase.session == nil || !phase.session.RetiredV1() {
			err = errors.Join(err, pdfadmission.ErrApplicationSessionUnknownV1)
		}
	}
	if err != nil {
		return nil, err
	}
	if !op.valid(ctx) {
		return nil, pdfadmission.ErrHTMLSendPackageInspectionV1
	}
	out = &PackageSendAttemptInspectionV1{state: &packageSendAttemptInspectionStateV1{owner: op, observation: observation}}
	transferred = true
	return out, nil
}
