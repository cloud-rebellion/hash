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
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sync"
	"time"
)

type TemplateListResultV1 struct {
	Rows    []*generated.ReadNativeTemplateListProjectionV1Row
	Digests []string
	Total   int64
	state   *templateListResultStateV1
}
type templateListResultStateV1 struct {
	once    sync.Once
	source  *pdfadmission.ApplicationTemplateListSourceV1
	reader  *pdfadmission.ApplicationHTMLAuthoringReaderV1
	factory *pdfadmission.ApplicationSessionFactoryV1
}

func (r *TemplateListResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Templates []*generated.ReadNativeTemplateListProjectionV1Row `json:"templates"`
		Count     int                                                `json:"count"`
	}{Templates: r.Rows, Count: len(r.Rows)})
}
func (r *TemplateListResultV1) CloseConsumerV1() {
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
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(ctx)
		}
	})
}

// One protected scalar page and one aggregate body/parse owner retain the
// original list projection. HTML authority remains M92, nonHTML remains M97;
// this read never measures/repairs a template or returns HTML inline masters.
func ListTemplatesV1(ctx context.Context, d DependenciesV1, actor ActorV1, limit, offset int32, total bool) (result *TemplateListResultV1, failure error) {
	if d.Sessions == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("native template list dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, uuid.New())
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
	state := &templateListResultStateV1{factory: d.Sessions}
	result = &TemplateListResultV1{state: state}
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
		state.source, err = session.NewTemplateListSourceV1(call, state.reader, limit, offset)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		var member *generated.User
		guard := func(c context.Context) error {
			if err := state.reader.AcquireActorV1(c, actor.OrgID, actor.UserID, false); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return auth.ErrMutationPermissionRevoked
				}
				return err
			}
			var e error
			member, e = q.GetUserForShare(c, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
			if e != nil {
				return e
			}
			copy := *member
			return actor.Authorize(c, tx, &copy)
		}
		result.Rows, result.Digests, err = state.source.ReadPageAfterHeaderV1(call, guard)
		if err != nil {
			return err
		}
		if total {
			result.Total, _ = q.CountTemplates(call, actor.OrgID)
		}
		copy := *member
		return actor.Authorize(call, tx, &copy)
	})
	if err != nil {
		return result, err
	}
	return result, nil
}
