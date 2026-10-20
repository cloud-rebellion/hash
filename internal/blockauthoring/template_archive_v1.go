// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

type TemplateArchiveResultV1 struct{ state *templateArchiveResultStateV1 }
type templateArchiveResultStateV1 struct {
	once    sync.Once
	writer  *pdfadmission.ApplicationTemplateArchiveV1
	reader  *pdfadmission.ApplicationHTMLAuthoringReaderV1
	factory *pdfadmission.ApplicationSessionFactoryV1
}

func (r *TemplateArchiveResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(ctx)
		}
	})
}

// Archiving needs only the actual active parent identity/version/stamp. No
// archived body is returned, no missing source cache is repaired, and the
// original live author and original credential remain locked through commit.
func ArchiveTemplateV1(ctx context.Context, d DependenciesV1, actor ActorV1, id uuid.UUID) (result *TemplateArchiveResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || id == uuid.Nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("native template archive dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, id)
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
	state := &templateArchiveResultStateV1{factory: d.Sessions}
	result = &TemplateArchiveResultV1{state: state}
	committed := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
	}()
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.writer, err = session.NewTemplateArchiveV1(call, state.reader)
		if err != nil {
			return err
		}
		if err = state.writer.LockTargetV1(call); errors.Is(err, pgx.ErrNoRows) {
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
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		guard, err := authoring.LockAuthor(call, tx, authoring.Actor{OrgID: actor.OrgID, UserID: actor.UserID, Authorize: actor.Authorize})
		if err != nil {
			return err
		}
		if err = state.writer.ArchiveV1(call); err != nil {
			return err
		}
		if err = state.writer.LogArchivedV1(call, d.Audit, actor.UserID); err != nil {
			return err
		}
		return guard.Recheck(call)
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, err
	}
	committed = true
	if err = state.writer.PublishV1(d.Audit); err != nil {
		return result, err
	}
	return result, nil
}
