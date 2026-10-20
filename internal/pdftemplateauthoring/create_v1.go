// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdftemplateauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"time"
)

type CreateDependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Billing  *billing.Engine
	Audit    *audit.Logger
}
type CreateActorV1 struct {
	OrgID, UserID uuid.UUID
	Authorize     auth.TransactionAuthorization
	Via, Tool     string
}
type CreateInputV1 struct {
	TemplateID pgtype.UUID
	Source     pdfadmission.PDFTemplateDocumentInputV1
}
type CreateResultV1 struct {
	Document *generated.Document
	state    *createStateV1
}
type createStateV1 struct {
	once     sync.Once
	factory  *pdfadmission.ApplicationSessionFactoryV1
	reader   *pdfadmission.ApplicationHTMLAuthoringReaderV1
	source   *pdfadmission.ApplicationPDFTemplateSourceV1
	producer *pdfadmission.ApplicationPDFTemplateDocumentV1
}

func (r *CreateResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.Document)
}
func (r *CreateResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.producer != nil {
			s.producer.CloseConsumerV1()
		} else if s.source != nil {
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

// Same actual REST/MCP PDF template producer. Original quota→template/values→
// member/credential→source report/layout→fresh document+values→quota→each party
// quota/audit→each field/audit→document audit→credential→commit order is kept.
// No caller transaction/model, native-to-pool retry or read-size repair exists.
func CreateV1(parent context.Context, d CreateDependenciesV1, actor CreateActorV1, input CreateInputV1) (result *CreateResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil {
		return nil, pdfadmission.ErrPDFTemplateDocumentV1
	}
	if actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, auth.ErrMutationPermissionRevoked
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	defer cancel()
	documentID := uuid.New()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, documentID)
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
	state := &createStateV1{factory: d.Sessions}
	result = &CreateResultV1{state: state}
	committed := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			// Preserve ordinary acknowledged PostgreSQL statement failures only
			// after THIS real native client/backend and admission cleanup join.
			// Unknown, timeout, admission and source-capacity errors keep503.
			if closeErr == nil && reconcileErr == nil && session.RetiredV1() && ordinaryPDFCreateStatementV1(ctx, failure) {
				failure = &retiredPDFCreateStatementFailureV1{cause: failure}
			}
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
	}()
	var pending []audit.PendingEvent
	var owners []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		tx := &nativePDFTemplateReadTxV1{DBTX: db}
		queries := generated.New(tx)
		if err = d.Billing.LockDocumentQuotaMutation(call, queries, actor.OrgID); err != nil {
			return err
		}
		if !input.TemplateID.Valid {
			return fmt.Errorf("%w: template_id required when source_kind=pdf", authoring.ErrCreationInput)
		}
		state.source, err = session.NewPDFTemplateSourceV1(call, state.reader)
		if err != nil {
			return err
		}
		_, err = state.source.GetTemplateForShare(call, generated.GetTemplateForShareParams{ID: uuid.UUID(input.TemplateID.Bytes), OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return authoring.ErrCreationTemplateNotFound
		}
		if errors.Is(err, pdfadmission.ErrPDFTemplateSourceKindV1) {
			return fmt.Errorf("%w: template is not a pdf-source template", authoring.ErrCreationInput)
		}
		if err != nil {
			return fmt.Errorf("lock document creation template: %w", err)
		}
		source := input.Source
		source.Via = actor.Via
		source.Tool = actor.Tool
		state.producer, err = session.NewPDFTemplateDocumentV1(call, state.reader, state.source, actor.UserID, source)
		if err != nil {
			return err
		}
		if err = state.producer.SeedVariablesV1(call); err != nil {
			return err
		}
		if err = state.reader.AcquireActorV1(call, actor.OrgID, actor.UserID, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		guard, err := authoring.LockAuthor(call, tx, authoring.Actor{OrgID: actor.OrgID, UserID: actor.UserID, Authorize: actor.Authorize})
		if err != nil {
			return err
		}
		if err = state.producer.PrepareSigningV1(call); err != nil {
			return err
		}
		result.Document, err = state.producer.CreateDocumentV1(call)
		if err != nil {
			return err
		}
		if err = state.producer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
			return err
		}
		parties, fields, err := state.producer.CountsV1(call)
		if err != nil {
			return err
		}
		// These bounded result/header slices are part of the genuine aggregate audit
		// control inventory; no event map/result/RETURNING is allocated before it.
		pending = make([]audit.PendingEvent, 0, parties+fields+1)
		owners = make([]*pdfadmission.ApplicationHTMLAuditEventConsumerV1, 0, parties+fields+1)
		logNext := func() error {
			event, owner, err := ownedaudit.LogPDFTemplateDocumentV1(d.Audit, call, state.producer, audit.Entry{OrgID: actor.OrgID, DocumentID: &documentID})
			if err != nil {
				return err
			}
			pending = append(pending, event)
			owners = append(owners, owner)
			return nil
		}
		for range parties {
			if err = d.Billing.LockDocumentQuotaMutation(call, queries, actor.OrgID); err != nil {
				return err
			}
			if _, err = state.producer.NextRecipientV1(call); err != nil {
				return err
			}
			if err = state.producer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
				return err
			}
			if err = logNext(); err != nil {
				return err
			}
		}
		for range fields {
			if _, err = state.producer.NextFieldV1(call); err != nil {
				return err
			}
			if err = logNext(); err != nil {
				return err
			}
		}
		if err = state.producer.MeasureFreshSourceV1(call); err != nil {
			return err
		}
		if err = logNext(); err != nil {
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
	// Preserve original publication order: layout recipient/field events first,
	// then the document event, matching their transaction append order.
	for i := range pending {
		if err = ownedaudit.PublishV1(d.Audit, pending[i], owners[i]); err != nil {
			return result, err
		}
	}
	return result, nil
}

// Error classification only: the private marker supplies no source, SQL or
// retirement authority. The fixed route receives it only from CreateV1 after
// that actual native statement failed and the same client/backend retired.
type retiredPDFCreateStatementFailureV1 struct{ cause error }

func (e *retiredPDFCreateStatementFailureV1) Error() string { return e.cause.Error() }
func (e *retiredPDFCreateStatementFailureV1) Unwrap() error { return e.cause }
func IsRetiredCreateStatementFailureV1(err error) bool {
	var known *retiredPDFCreateStatementFailureV1
	return errors.As(err, &known) && known != nil && !errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) && !errors.Is(err, pdfadmission.ErrApplicationAdmissionV1)
}
func ordinaryPDFCreateStatementV1(ctx context.Context, err error) bool {
	if err == nil || ctx == nil || ctx.Err() != nil || !errors.Is(err, pdfadmission.ErrApplicationSessionV1) || errors.Is(err, pdfadmission.ErrApplicationSessionUnknownV1) || errors.Is(err, pdfadmission.ErrApplicationAdmissionV1) {
		return false
	}
	var statement *pgconn.PgError
	if !errors.As(err, &statement) || statement == nil || statement.Severity != "ERROR" || len(statement.Code) != 5 {
		return false
	}
	// These structured server classes describe connection, resource, limit,
	// lock/state, shutdown/cancel and system conditions, not an ordinary failed
	// statement. They retain the existing fail-closed native availability path.
	switch statement.Code[:2] {
	case "08", "53", "54", "55", "57", "58", "XX":
		return false
	}
	return true
}
