// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdftemplateauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

var ErrTemplateNotFoundV1 = errors.New("template not found")

type ReadActorV1 struct {
	OrgID, UserID uuid.UUID
	Authorize     auth.TransactionAuthorization
}
type ReadResultV1 struct {
	Template *generated.Template
	state    *readStateV1
}
type readStateV1 struct {
	once    sync.Once
	factory *pdfadmission.ApplicationSessionFactoryV1
	reader  *pdfadmission.ApplicationHTMLAuthoringReaderV1
	source  *pdfadmission.ApplicationPDFTemplateSourceV1
}

func (r *ReadResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.Template)
}
func (r *ReadResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.source != nil {
			s.source.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		if s.factory != nil {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.factory.ReconcileCleanupV1(cleanup)
		}
	})
}

// Fixed real REST/MCP PDF source read. A genuine locked scalar parent precedes
// the original live member/credential; M97 validates before any full5JSON read.
// Viewer reads remain reads; no sender/owner write role is invented here.
func ReadV1(parent context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, actor ReadActorV1, id uuid.UUID) (result *ReadResultV1, failure error) {
	if factory == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || id == uuid.Nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	session, err := factory.OpenV1(ctx, actor.OrgID, id)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &readStateV1{factory: factory}
	result = &ReadResultV1{state: state}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, session.CloseV1(cleanup))
		_, e := admission.ReconcileCleanupV1(cleanup)
		failure = errors.Join(failure, e)
	}()
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.source, err = session.NewPDFTemplateSourceV1(call, state.reader)
		if err != nil {
			return err
		}
		if err = state.source.LockShareHeaderV1(call, id); errors.Is(err, pgx.ErrNoRows) {
			return ErrTemplateNotFoundV1
		}
		if err != nil {
			return err
		}
		if err = state.reader.AcquireActorV1(call, actor.OrgID, actor.UserID, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		tx := &nativePDFTemplateReadTxV1{DBTX: db}
		user, err := generated.New(tx).GetUserForShare(call, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
		if err != nil {
			return err
		}
		if user == nil || user.ID != actor.UserID || user.OrgID != actor.OrgID {
			return auth.ErrMutationPermissionRevoked
		}
		member := *user
		if err = actor.Authorize(call, tx, &member); err != nil {
			return err
		}
		result.Template, err = state.source.ReadLockedShareV1(call)
		if err != nil {
			return err
		}
		member = *user
		return actor.Authorize(call, tx, &member)
	})
	return result, err
}
