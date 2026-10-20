// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// One actual direct factory owner, not an adopted Pool transaction. A retained
// reader consumer can outlive SQL cleanup and remains in the factory registry.
type htmlOwnedAuthoringSessionV1 struct {
	session      *pdfadmission.ApplicationSessionV1
	admission    *pdfadmission.ApplicationAdmissionV1
	reader       *pdfadmission.ApplicationHTMLAuthoringReaderV1
	factory      *pdfadmission.ApplicationSessionFactoryV1
	consumerOnce sync.Once
}

func (s *Server) openHTMLAuthoringV1(ctx context.Context, org, scope uuid.UUID) (*htmlOwnedAuthoringSessionV1, error) {
	if s.HTMLCreationSessions == nil || org == uuid.Nil || scope == uuid.Nil {
		return nil, pdfadmission.ErrHTMLAuthoringReadV1
	}
	o := &htmlOwnedAuthoringSessionV1{factory: s.HTMLCreationSessions}
	var err error
	o.session, err = o.factory.OpenV1(ctx, org, scope)
	if err != nil {
		_ = o.closeSQLV1(ctx)
		return nil, err
	}
	o.admission, err = o.session.NewAdmissionV1(ctx)
	if err == nil {
		err = o.session.WithTxV1(ctx, func(ownedCtx context.Context, _ generated.DBTX) error {
			o.reader, err = o.session.NewHTMLAuthoringReaderV1(ownedCtx)
			return err
		})
	}
	if err != nil {
		o.closeConsumerV1(ctx)
		_ = o.closeSQLV1(ctx)
		return nil, err
	}
	return o, nil
}
func (o *htmlOwnedAuthoringSessionV1) closeSQLV1(ctx context.Context) error {
	if o == nil || o.session == nil {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := o.session.CloseV1(cleanup)
	if o.admission != nil {
		_, reconcile := o.admission.ReconcileCleanupV1(cleanup)
		err = errors.Join(err, reconcile)
	}
	return err
}
func (o *htmlOwnedAuthoringSessionV1) closeConsumerV1(ctx context.Context) {
	if o == nil {
		return
	}
	o.consumerOnce.Do(func() {
		if o.reader != nil {
			o.reader.CloseConsumerV1()
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if o.factory != nil {
			_ = o.factory.ReconcileCleanupV1(cleanup)
		}
	})
}
func htmlAuthoringReaderV1(tx any) (*pdfadmission.ApplicationHTMLAuthoringReaderV1, error) {
	native, ok := tx.(*htmlCreationPolicyTxV1)
	if !ok || native == nil || native.reader == nil {
		return nil, pdfadmission.ErrHTMLAuthoringReadV1
	}
	return native.reader, nil
}

func lockHTMLAuthorV1(ctx context.Context, tx pgx.Tx, actor authoring.Actor, owner bool) (*authoring.MemberGuard, error) {
	reader, err := htmlAuthoringReaderV1(tx)
	if err != nil {
		return nil, err
	}
	if err = reader.AcquireActorV1(ctx, actor.OrgID, actor.UserID, owner); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, auth.ErrMutationPermissionRevoked
		}
		return nil, err
	}
	if owner {
		return authoring.LockOwner(ctx, tx, actor)
	}
	return authoring.LockAuthor(ctx, tx, actor)
}

// Cheap disabled-config refusal only; a nonnil pointer supplies no admission,
// connection/profile/credential/READY proof. Every real constructor still runs.
func (s *Server) requireHTMLAuthoringRuntimeV1(w http.ResponseWriter) bool {
	if s.HTMLCreationSessions == nil {
		writeError(w, http.StatusServiceUnavailable, "HTML authoring is temporarily unavailable")
		return false
	}
	return true
}
