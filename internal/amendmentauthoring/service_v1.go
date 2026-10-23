// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package amendmentauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"sync"
	"time"
)

type DependenciesV1 struct {
	Sessions  *pdfadmission.ApplicationSessionFactoryV1
	Audit     *audit.Logger
	PublicURL string
}
type ResultV1 struct{ state *resultStateV1 }
type resultStateV1 struct {
	mu               sync.Mutex
	value            any
	reader           *pdfadmission.ApplicationHTMLRevisionReaderV1
	pair             *pdfadmission.ApplicationDocumentPackageSelectionV1
	admissionCleanup *resultAdmissionCleanupV1
	closed           bool
}

func newResultV1() *ResultV1 { return &ResultV1{state: &resultStateV1{}} }
func (r *ResultV1) MarshalJSON() ([]byte, error) {
	if r == nil || r.state == nil {
		return []byte("null"), nil
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	if r.state.closed {
		return nil, amendments.ErrUnavailableV1
	}
	return json.Marshal(r.state.value)
}
func (r *ResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	r.state.mu.Lock()
	if r.state.closed {
		r.state.mu.Unlock()
		return
	}
	r.state.closed = true
	r.state.value = nil
	reader, pair, cleanup := r.state.reader, r.state.pair, r.state.admissionCleanup
	r.state.reader = nil
	r.state.pair = nil
	r.state.admissionCleanup = nil
	r.state.mu.Unlock()
	if reader != nil {
		reader.CloseConsumerV1()
	}
	if pair != nil {
		pair.CloseConsumerV1()
	}
	if cleanup != nil {
		cleanup.closeV1()
	}
}
func (r *ResultV1) UnknownV1() bool {
	if r == nil || r.state == nil {
		return false
	}
	r.state.mu.Lock()
	defer r.state.mu.Unlock()
	switch v := r.state.value.(type) {
	case amendments.OutcomeV1:
		return v.State == "unknown"
	case amendments.RevokeOutcomeV1:
		return v.State == "unknown"
	default:
		return false
	}
}

type guardV1 struct {
	actor authoring.Actor
	user  generated.User
	tx    *nativePolicyTxV1
}

func (g *guardV1) recheck(ctx context.Context) error {
	if g == nil || g.actor.Authorize == nil {
		return auth.ErrMutationPermissionRevoked
	}
	u := g.user
	return g.actor.Authorize(ctx, g.tx, &u)
}
func readGateV1(ctx context.Context, db generated.DBTX, actor authoring.Actor, ownerOnly bool) (func(pdfadmission.HTMLRevisionReadAccessV1, *generated.User) error, **guardV1) {
	var guard *guardV1
	return func(a pdfadmission.HTMLRevisionReadAccessV1, u *generated.User) error {
		if u == nil || u.ID != actor.UserID || u.OrgID != actor.OrgID || a.OrgID != actor.OrgID || (u.Role != "owner" && (ownerOnly || u.Role != "sender" || a.SenderID != actor.UserID)) {
			return auth.ErrMutationPermissionRevoked
		}
		guard = &guardV1{actor: actor, user: *u, tx: &nativePolicyTxV1{DBTX: db}}
		if e := guard.recheck(ctx); e != nil {
			return e
		}
		q := generated.New(db)
		fence, e := q.TryCollabArchivePrivacyFence(ctx, actor.OrgID)
		if e != nil {
			return e
		}
		if !fence {
			return authoring.ErrPrivacyReviewChanging
		}
		pending, e := q.HasPendingDocumentPrivacyRequests(ctx, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: a.DocumentID, OrgID: actor.OrgID})
		if e != nil {
			return e
		}
		if pending {
			return authoring.ErrPendingPrivacyReview
		}
		return ctx.Err()
	}, &guard
}
func CreateV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, original uuid.UUID, in amendments.CreateV1, ip, ua string) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.Authorize == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil {
		return nil, amendments.ErrUnavailableV1
	}
	if e := in.ValidateV1(original); e != nil {
		return nil, e
	}
	result = newResultV1()
	session, e := d.Sessions.OpenV1(ctx, actor.OrgID, original)
	var admission *pdfadmission.ApplicationAdmissionV1
	var event *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var pending audit.PendingEvent
	defer func() {
		if event != nil {
			event.CloseConsumerV1()
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		var closeErr error
		if session != nil {
			closeErr = session.CloseV1(cleanup)
		}
		if admission != nil {
			_, e := admission.ReconcileCleanupV1(cleanup)
			closeErr = errors.Join(closeErr, e)
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
		if closeErr != nil {
			if out, ok := result.state.value.(amendments.OutcomeV1); ok && (out.State == "committed" || out.State == "unknown") {
				out.ReconciliationRequired = true
				result.state.value = out
			} else {
				failure = errors.Join(failure, closeErr)
				result.CloseConsumerV1()
			}
		}
	}()
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	var out amendments.OutcomeV1
	e = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		pair, e := session.NewDocumentPackageSelectionV1(call, in.AmendmentDocumentID)
		result.state.pair = pair
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, true)
		_, e = pair.ReadDocumentsV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.OrgID != actor.OrgID || (a.DocumentID != original && a.DocumentID != in.AmendmentDocumentID) {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		out, e = pair.LinkLaterAmendmentV1(call, in, actor.UserID, ip, ua, d.PublicURL, func(c context.Context, actual *pdfadmission.ApplicationHTMLAuditEventConsumerV1) error {
			var e error
			pending, event, e = ownedaudit.AppendLaterAmendmentV1(d.Audit, c, actual, audit.Entry{OrgID: actor.OrgID, DocumentID: &in.AmendmentDocumentID})
			return e
		})
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		return (*guard).recheck(call)
	})
	if e != nil {
		return result, e
	}
	if out.State == "unchanged" {
		result.state.value = out
		return result, nil
	}
	if e = session.CommitV1(ctx); e != nil {
		if !session.CommitDispatchObservationV1().NeverDispatchedV1() {
			out = amendments.OutcomeV1{State: "unknown", RequestID: in.RequestID, ReconciliationRequired: true}
			result.state.value = out
			return result, nil
		}
		return result, e
	}
	if event == nil {
		return result, amendments.ErrUnavailableV1
	}
	if e = ownedaudit.PublishV1(d.Audit, pending, event); e != nil {
		out.ReconciliationRequired = true
	}
	result.state.value = out
	return result, nil
}
func InventoryV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, original uuid.UUID) (result *ResultV1, failure error) {
	if d.Sessions == nil || actor.Authorize == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || original == uuid.Nil {
		return nil, amendments.ErrUnavailableV1
	}
	result = newResultV1()
	session, e := d.Sessions.OpenV1(ctx, actor.OrgID, original)
	var admission *pdfadmission.ApplicationAdmissionV1
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if session != nil {
			failure = errors.Join(failure, session.CloseV1(cleanup))
		}
		if admission != nil {
			_, e := admission.ReconcileCleanupV1(cleanup)
			failure = errors.Join(failure, e)
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
	}()
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	failure = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		reader, e := session.NewHTMLRevisionReaderV1(call)
		result.state.reader = reader
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, false)
		_, e = reader.ReadDocumentWithActorV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.DocumentID != original || a.OrgID != actor.OrgID {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		out, e := reader.ReadLaterAmendmentInventoryV1(call)
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		out.CanCreate = (*guard).user.Role == "owner"
		result.state.value = out
		return (*guard).recheck(call)
	})
	return result, failure
}
func RelationV1(ctx context.Context, d DependenciesV1, actor authoring.Actor, candidate uuid.UUID) (result *ResultV1, failure error) {
	if d.Sessions == nil || actor.Authorize == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || candidate == uuid.Nil {
		return nil, amendments.ErrUnavailableV1
	}
	result = newResultV1()
	session, e := d.Sessions.OpenV1(ctx, actor.OrgID, candidate)
	var admission *pdfadmission.ApplicationAdmissionV1
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if session != nil {
			failure = errors.Join(failure, session.CloseV1(cleanup))
		}
		if admission != nil {
			_, e := admission.ReconcileCleanupV1(cleanup)
			failure = errors.Join(failure, e)
		}
		if failure != nil {
			result.CloseConsumerV1()
		}
	}()
	if e != nil {
		return result, e
	}
	admission, e = session.NewAdmissionV1(ctx)
	if e != nil {
		return result, e
	}
	if e = result.bindAdmissionV1(ctx, admission); e != nil {
		return result, e
	}
	failure = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		reader, e := session.NewHTMLRevisionReaderV1(call)
		result.state.reader = reader
		if e != nil {
			return e
		}
		gate, guard := readGateV1(call, db, actor, false)
		_, e = reader.ReadDocumentWithActorV1(call, actor.UserID, func(a pdfadmission.HTMLRevisionReadAccessV1) error {
			if a.DocumentID != candidate || a.OrgID != actor.OrgID {
				return authoring.ErrDocumentNotFound
			}
			return nil
		}, gate)
		if e != nil {
			return e
		}
		out, e := reader.ReadLaterAmendmentRelationV1(call)
		if e != nil {
			return e
		}
		if *guard == nil {
			return auth.ErrMutationPermissionRevoked
		}
		result.state.value = out
		return (*guard).recheck(call)
	})
	return result, failure
}
