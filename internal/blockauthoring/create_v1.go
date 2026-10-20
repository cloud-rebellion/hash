// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type DependenciesV1 struct {
	Sessions                           *pdfadmission.ApplicationSessionFactoryV1
	Billing                            *billing.Engine
	Audit                              *audit.Logger
	SnapshotCreation, SnapshotMutation bool
}
type ActorV1 struct {
	OrgID, UserID            uuid.UUID
	Authorize                auth.TransactionAuthorization
	Via, Tool, IP, UserAgent string
}
type CreateInputV1 struct {
	Name                      string
	TemplateID                pgtype.UUID
	BlocksJSON, VariablesJSON json.RawMessage
	ExpiresAt                 pgtype.Timestamptz
}
type ResultV1 struct {
	Document *generated.Document
	state    *resultStateV1
}
type resultStateV1 struct {
	once                sync.Once
	blockTemplateSource *pdfadmission.ApplicationBlocksTemplateSourceV1
	plainDraftWriter    *pdfadmission.ApplicationPlainDraftMutationWriterV1
	topology            *pdfadmission.ApplicationEnvelopeTopologyV1
	revisionReader      *pdfadmission.ApplicationHTMLRevisionReaderV1
	mutationWriter      *pdfadmission.ApplicationBlocksMutationWriterV1
	writer              *pdfadmission.ApplicationBlocksCreationWriterV1
	reader              *pdfadmission.ApplicationHTMLAuthoringReaderV1
	events              []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	factory             *pdfadmission.ApplicationSessionFactoryV1
}

func (r *ResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(r.Document)
}
func (r *ResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		for _, event := range s.events {
			event.CloseConsumerV1()
		}
		s.events = nil
		if s.topology != nil {
			s.topology.CloseConsumerV1()
		}
		if s.plainDraftWriter != nil {
			s.plainDraftWriter.CloseConsumerV1()
		}
		if s.mutationWriter != nil {
			s.mutationWriter.CloseConsumerV1()
		}
		if s.revisionReader != nil {
			s.revisionReader.CloseConsumerV1()
		}
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.blockTemplateSource != nil {
			s.blockTemplateSource.CloseConsumerV1()
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

// CreateV1 is the finite block producer used by existing REST and
// MCP create_document. It preserves quota lock -> original normalization ->
// original live member/credential -> fresh INSERT -> MCP optional snapshot ->
// original quota enforcement -> audit -> final credential -> commit ordering.
// Referenced blocks templates are read through their separate genuine M97 source
// and bound privately; a UUID or absent cache never authorizes a full old body.
func CreateV1(ctx context.Context, d DependenciesV1, actor ActorV1, in CreateInputV1) (result *ResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("owned block creation dependencies unavailable")
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
	state := &resultStateV1{factory: d.Sessions}
	result = &ResultV1{state: state}
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
	var doc *generated.Document
	var pending audit.PendingEvent
	var eventOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.writer, err = session.NewBlocksCreationWriterV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		if err = d.Billing.LockDocumentQuotaMutation(call, q, actor.OrgID); err != nil {
			return err
		}
		if in.TemplateID.Valid {
			if uuid.UUID(in.TemplateID.Bytes) == uuid.Nil {
				return authoring.ErrCreationTemplateNotFound
			}
			state.blockTemplateSource, err = session.NewBlocksTemplateSourceV1(call, state.reader)
			if err != nil {
				return err
			}
			if _, err = state.blockTemplateSource.GetTemplateForShare(call, generated.GetTemplateForShareParams{ID: uuid.UUID(in.TemplateID.Bytes), OrgID: actor.OrgID}); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return authoring.ErrCreationTemplateNotFound
				}
				if errors.Is(err, pdfadmission.ErrBlocksTemplateSourceKindV1) {
					return fmt.Errorf("%w: template is not a blocks-source template", authoring.ErrCreationInput)
				}
				return err
			}
			if err = state.writer.BindTemplateV1(call, state.blockTemplateSource); err != nil {
				return err
			}
		}
		if err = state.writer.PrepareSourceV1(call, in.BlocksJSON, in.VariablesJSON); err != nil {
			var input pdfadmission.BlocksCreationInputErrorV1
			if errors.As(err, &input) {
				return fmt.Errorf("%w: invalid %s: %v", authoring.ErrCreationInput, input.Field, input.Cause)
			}
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
		doc, err = state.writer.CreateBlocksDocument(call, generated.CreateBlocksDocumentParams{OrgID: actor.OrgID, TemplateID: in.TemplateID, Name: in.Name, SenderID: actor.UserID, ExpiresAt: in.ExpiresAt})
		if err != nil {
			return err
		}
		if d.SnapshotCreation {
			if _, err = versions.New(q).Snapshot(call, versions.SnapshotInput{DocumentID: doc.ID, OrgID: doc.OrgID, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &actor.UserID, Via: versions.ViaMCP, Summary: "create_document"}); err != nil {
				return err
			}
		}
		if err = state.writer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
			return err
		}
		if err = state.writer.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		payload := map[string]any{"name": doc.Name, "source_kind": doc.SourceKind}
		if actor.Via == "mcp" {
			payload["via"] = "mcp"
			payload["tool"] = "create_document"
		}
		id, user := doc.ID, actor.UserID
		pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditBlocksCreatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &user, DocumentID: &id, Kind: audit.KindDocumentCreated, Payload: payload})
		if eventOwner != nil {
			state.events = append(state.events, eventOwner)
		}
		if err != nil {
			return err
		}
		pending = detachEventIDsV1(pending)
		return guard.Recheck(call)
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, err
	}
	committed = true
	result.Document = doc
	if err = ownedaudit.PublishV1(d.Audit, pending, eventOwner); err != nil {
		return result, err
	}
	return result, nil
}
func detachEventIDsV1(event audit.PendingEvent) audit.PendingEvent {
	if event.Entry.DocumentID != nil {
		id := *event.Entry.DocumentID
		event.Entry.DocumentID = &id
	}
	if event.Entry.RecipientID != nil {
		id := *event.Entry.RecipientID
		event.Entry.RecipientID = &id
	}
	if event.Entry.ActorUserID != nil {
		id := *event.Entry.ActorUserID
		event.Entry.ActorUserID = &id
	}
	return event
}
