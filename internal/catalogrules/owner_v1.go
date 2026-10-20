// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package catalogrules

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// CommitCatalogOwnerMutationV1 owns the actual direct SQL session and exposes
// results only after the original credential, live owner, body loan, mutation,
// intrinsic measurement, audit and final credential recheck have committed.
// scope is the actual rule UUID for update/delete; create allocates only a fresh
// capacity identity and lets INSERT generate the genuine new source identity.
// The returned release must survive the real response/MCP serialization.
func CommitCatalogOwnerMutationV1[T any](ctx context.Context, factory *pdfadmission.ApplicationSessionFactoryV1, logger *audit.Logger, actor authoring.Actor, scope uuid.UUID,
	mutate func(context.Context, *generated.Queries, *pdfadmission.ApplicationHTMLAuthoringReaderV1) (T, error), event func(T) audit.Entry,
) (value T, release func(), failure error) {
	var zero T
	if factory == nil || logger == nil || mutate == nil || event == nil || scope == uuid.Nil {
		return zero, nil, errors.New("owner mutation dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := factory.OpenV1(ctx, actor.OrgID, scope)
	var admission *pdfadmission.ApplicationAdmissionV1
	var reader *pdfadmission.ApplicationHTMLAuthoringReaderV1
	closeSQL := func() error {
		if session == nil {
			return nil
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		e := session.CloseV1(cleanup)
		if admission != nil {
			_, e2 := admission.ReconcileCleanupV1(cleanup)
			e = errors.Join(e, e2)
		}
		return e
	}
	closeConsumer := func() {
		if reader != nil {
			reader.CloseConsumerV1()
		}
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = factory.ReconcileCleanupV1(cleanup)
	}
	if err != nil {
		_ = closeSQL()
		return zero, nil, err
	}
	admission, err = session.NewAdmissionV1(ctx)
	if err != nil {
		_ = closeSQL()
		return zero, nil, err
	}
	var pending audit.PendingEvent
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var e error
		reader, e = session.NewHTMLAuthoringReaderV1(call)
		if e != nil {
			return e
		}
		if e = reader.AcquireCatalogOwnerV1(call, actor.OrgID, actor.UserID); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return e
		}
		bridge := &catalogRulePolicyTxV1{DBTX: db}
		guard, e := authoring.LockCatalogOwnerV1(call, bridge, actor)
		if e != nil {
			return e
		}
		value, e = mutate(call, generated.New(db), reader)
		if e != nil {
			return e
		}
		entry := event(value)
		if entry.OrgID != actor.OrgID || entry.ActorUserID == nil || *entry.ActorUserID != actor.UserID {
			return errors.New("owner mutation audit identity mismatch")
		}
		pending, e = logger.LogTx(call, bridge, entry)
		if e != nil {
			return e
		}
		return guard.Recheck(call)
	})
	if err == nil {
		err = session.CommitV1(ctx)
	}
	clean := closeSQL()
	if err == nil {
		err = clean
	}
	if err != nil {
		closeConsumer()
		return zero, nil, err
	}
	consumers := &catalogRuleConsumersV1{release: closeConsumer}
	logger.PublishJoinedV1(pending, consumers.auditFinishedV1)
	return value, consumers.responseFinishedV1, nil
}

// Original credential/audit helpers receive only the native tracked DBTX.
// They cannot adopt, commit, roll back, prepare or escape its actual session.
type catalogRulePolicyTxV1 struct{ generated.DBTX }

var errCatalogRulePolicyControlV1 = errors.New("catalog rule transaction control belongs to its native session")

func (*catalogRulePolicyTxV1) Begin(context.Context) (pgx.Tx, error) {
	return nil, errCatalogRulePolicyControlV1
}
func (*catalogRulePolicyTxV1) Commit(context.Context) error   { return errCatalogRulePolicyControlV1 }
func (*catalogRulePolicyTxV1) Rollback(context.Context) error { return errCatalogRulePolicyControlV1 }
func (*catalogRulePolicyTxV1) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	return 0, errCatalogRulePolicyControlV1
}
func (*catalogRulePolicyTxV1) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults {
	return catalogRuleRefusedBatchV1{}
}
func (*catalogRulePolicyTxV1) LargeObjects() pgx.LargeObjects { return pgx.LargeObjects{} }
func (*catalogRulePolicyTxV1) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	return nil, errCatalogRulePolicyControlV1
}
func (*catalogRulePolicyTxV1) Conn() *pgx.Conn { return nil }

type catalogRuleRefusedBatchV1 struct{}

func (catalogRuleRefusedBatchV1) Exec() (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errCatalogRulePolicyControlV1
}
func (catalogRuleRefusedBatchV1) Query() (pgx.Rows, error) { return nil, errCatalogRulePolicyControlV1 }
func (catalogRuleRefusedBatchV1) QueryRow() pgx.Row        { return catalogRuleRefusedRowV1{} }
func (catalogRuleRefusedBatchV1) Close() error             { return errCatalogRulePolicyControlV1 }

type catalogRuleRefusedRowV1 struct{}

func (catalogRuleRefusedRowV1) Scan(...any) error { return errCatalogRulePolicyControlV1 }

var _ pgx.Tx = (*catalogRulePolicyTxV1)(nil)

// Exactly two actual borrowers: the response serializer and ALL original audit
// hooks. A request cancellation or hook context timeout does not close either
// borrower; PublishJoinedV1 signals only after the actual hook calls return.
// Keep the same native reader registry and original physical fence throughout.
type catalogRuleConsumersV1 struct {
	mu                      sync.Mutex
	response, audit, closed bool
	release                 func()
}

func (c *catalogRuleConsumersV1) responseFinishedV1() { c.finishV1(false) }
func (c *catalogRuleConsumersV1) auditFinishedV1()    { c.finishV1(true) }
func (c *catalogRuleConsumersV1) finishV1(audit bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if audit {
		c.audit = true
	} else {
		c.response = true
	}
	if c.closed || !c.response || !c.audit {
		c.mu.Unlock()
		return
	}
	c.closed = true
	release := c.release
	c.release = nil
	c.mu.Unlock()
	if release != nil {
		release()
	}
}
