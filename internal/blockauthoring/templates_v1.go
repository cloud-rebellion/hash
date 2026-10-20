// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/templatepin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

var ErrTemplateNotFoundV1 = errors.New("template not found")

type TemplateInputV1 struct {
	ID                        uuid.UUID
	Name, Starter             string
	BlocksJSON, VariablesJSON json.RawMessage
}
type TemplateResultV1 struct {
	Template *generated.Template
	Content  templatepin.Content
	state    *templateResultStateV1
}
type templateResultStateV1 struct {
	once    sync.Once
	source  *pdfadmission.ApplicationBlocksTemplateSourceV1
	writer  *pdfadmission.ApplicationBlocksTemplateWriterV1
	reader  *pdfadmission.ApplicationHTMLAuthoringReaderV1
	factory *pdfadmission.ApplicationSessionFactoryV1
}

func (r *TemplateResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.Template)
}
func (r *TemplateResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.source != nil {
			s.source.CloseConsumerV1()
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

// WriteTemplateV1 only creates a fresh blocks row or updates the actual locked
// M97 blocks source. No public Template, UUID, cached count or caller Tx can
// supply body/write authority. The original parent->member lock order remains.
func WriteTemplateV1(ctx context.Context, d DependenciesV1, actor ActorV1, in TemplateInputV1) (result *TemplateResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("native block template mutation unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	scope := in.ID
	if scope == uuid.Nil {
		scope = uuid.New()
	}
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, scope)
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
	state := &templateResultStateV1{factory: d.Sessions}
	result = &TemplateResultV1{state: state}
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
		state.writer, err = session.NewBlocksTemplateWriterV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		var guard *authoring.MemberGuard
		lockAuthor := func(guardctx context.Context) error {
			if err := state.reader.AcquireActorV1(guardctx, actor.OrgID, actor.UserID, false); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.ErrMutationPermissionRevoked
				}
				return err
			}
			var e error
			guard, e = authoring.LockAuthor(guardctx, tx, authoring.Actor{OrgID: actor.OrgID, UserID: actor.UserID, Authorize: actor.Authorize})
			return e
		}
		raw, variables := in.BlocksJSON, in.VariablesJSON
		if in.ID != uuid.Nil {
			state.source, err = session.NewBlocksTemplateSourceV1(call, state.reader)
			if err != nil {
				return err
			}
			current, e := state.source.GetTemplateForUpdateAfterHeaderV1(call, generated.GetTemplateForUpdateParams{ID: in.ID, OrgID: actor.OrgID}, lockAuthor)
			if errors.Is(e, pgx.ErrNoRows) {
				return ErrTemplateNotFoundV1
			}
			if e != nil {
				return e
			}
			if len(raw) == 0 {
				raw = current.BlocksJson
			}
			if len(variables) == 0 {
				variables = current.VariablesJson
			}
			if err = state.writer.BindCurrentV1(call, state.source); err != nil {
				return err
			}
		} else {
			if err = lockAuthor(call); err != nil {
				return err
			}
		}
		if in.Starter != "" {
			if err = state.writer.PrepareStarterSourceV1(call, in.Starter); err != nil {
				return err
			}
		} else if err = state.writer.PrepareSourceV1(call, raw, variables); err != nil {
			return err
		}
		result.Template, err = state.writer.WriteV1(call, in.Name, actor.UserID)
		if err != nil {
			return err
		}
		if err = state.writer.MeasureFreshSourceV1(call); err != nil {
			return err
		}
		result.Content, err = state.writer.CanonicalContentV1(call)
		if err != nil {
			return err
		}
		if err = state.writer.LogMutationV1(call, d.Audit, actor.UserID, in.Starter); err != nil {
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

// ReadTemplateV1 retains the actual blocks source and canonical response work
// through the real caller's serialization. Viewers keep their existing read
// access; live original credential checks do not grant sender-only mutation.
func ReadTemplateV1(ctx context.Context, d DependenciesV1, actor ActorV1, id uuid.UUID) (result *TemplateResultV1, failure error) {
	if d.Sessions == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || id == uuid.Nil {
		return nil, errors.New("native block template read unavailable")
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
	state := &templateResultStateV1{factory: d.Sessions}
	result = &TemplateResultV1{state: state}
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
		state.source, err = session.NewBlocksTemplateSourceV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		var member *generated.User
		guard := func(c context.Context) error {
			if err := state.reader.AcquireActorV1(c, actor.OrgID, actor.UserID, false); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.ErrMutationPermissionRevoked
				}
				return err
			}
			var e error
			member, e = generated.New(tx).GetUserForShare(c, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
			if e != nil {
				return e
			}
			copy := *member
			return actor.Authorize(c, tx, &copy)
		}
		result.Template, err = state.source.GetTemplateForShareAfterHeaderV1(call, generated.GetTemplateForShareParams{ID: id, OrgID: actor.OrgID}, guard)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTemplateNotFoundV1
		}
		if err != nil {
			return err
		}
		result.Content, err = state.source.CanonicalContentV1(call)
		if err != nil {
			return err
		}
		copy := *member
		return actor.Authorize(call, tx, &copy)
	})
	if err != nil {
		return result, err
	}
	return result, nil
}
