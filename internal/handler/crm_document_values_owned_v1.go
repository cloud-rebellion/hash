// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
)

// Block-value changes and mapping-only/unlink use one original native
// transaction. HTML content changes continue through their native PDF revision
// writer. Both paths consume the SAME admitted Apply body/protected snapshot;
// existing measurements can never trigger a repair/backfill operation.
func (s *Server) commitCRMDocumentValuesOwnedV1(parent context.Context, actor authoring.Actor, id uuid.UUID, admission *crmMappingAdmission, input *pdfadmission.ApplicationHTMLAuthoringInputV1) (doc *generated.Document, finish func(), failure error) {
	if s.HTMLCreationSessions == nil || admission == nil || admission.observation == nil || input == nil {
		return nil, nil, pdfadmission.ErrHTMLRevisionOperationV1
	}
	ctx, cancel := context.WithTimeout(parent, authoring.MutationTimeout)
	op, err := s.HTMLCreationSessions.NewCRMDocumentValuesOperationV1(ctx, actor.OrgID, id, actor.UserID, input, admission.observation.snapshot)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	var writer *pdfadmission.ApplicationCRMApplyWriterV1
	var pending, changedPending audit.PendingEvent
	var event, changedEvent *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	close := func() error {
		if event != nil {
			event.CloseConsumerV1()
		}
		if changedEvent != nil {
			changedEvent.CloseConsumerV1()
		}
		if writer != nil {
			writer.CloseConsumerV1()
		}
		cancel()
		cleanup, stop := revisionCleanupContextV1(parent)
		defer stop()
		return op.CloseV1(cleanup)
	}
	transferred := false
	defer func() {
		if !transferred {
			failure = errors.Join(failure, close())
		}
	}()
	stage, err := op.OpenSQLV1(pdfadmission.HTMLRevisionMutationV1)
	if err != nil {
		return nil, nil, err
	}
	expected, err := time.Parse(time.RFC3339Nano, admission.witness.ExpectedUpdatedAt)
	if err != nil {
		return nil, nil, errCRMDocumentInput
	}
	err = stage.WithTxV1(func(call context.Context, db generated.DBTX, reader *pdfadmission.ApplicationHTMLRevisionReaderV1) error {
		var guard *htmlRevisionPolicyGuardV1
		var original *generated.Document
		if len(admission.source.doc.HtmlSourceJson) > 0 {
			loaded, e := readOwnedHTMLRevisionV1(call, db, reader, stage, actor, id, htmlDocumentRevisionInput{ExpectedUpdatedAt: admission.witness.ExpectedUpdatedAt, ExpectedHTMLSourceCommitment: admission.witness.ExpectedHTMLSourceCommitment}, expected, admission)
			if e != nil {
				return e
			}
			defer loaded.source.CloseConsumerV1()
			defer loaded.collections.CloseConsumerV1()
			original, guard = loaded.document, loaded.guard
		} else {
			models, g, e := htmlRevisionPolicyReadV1(call, db, reader, actor, id, expected)
			if e != nil {
				return e
			}
			original, guard = models.Document, g
			if e = admission.checkOwnedLockedV1(call, db, actor, original, ""); e != nil {
				return e
			}
		}
		session, e := stage.AuditSessionV1(call)
		if e != nil {
			return e
		}
		writer, e = session.NewCRMApplyWriterV1(call, reader)
		if e != nil {
			return e
		}
		var changed bool
		doc, changed, e = writer.ApplyV1(call, op)
		if e != nil {
			return e
		}
		if changed != admission.observation.ContentChanged {
			return errCRMDocumentChanged
		}
		tx := &htmlCreationPolicyTxV1{DBTX: db}
		if changed {
			if _, e = versions.New(generated.New(tx)).SnapshotWithParentIdentityV1(call, versions.SnapshotInput{DocumentID: id, OrgID: actor.OrgID, Name: doc.Name, SourceKind: doc.SourceKind, BlocksJSON: doc.BlocksJson, VariablesJS: doc.VariablesJson, CreatedBy: &actor.UserID, Via: versions.ViaHuman, Summary: "Reviewed CRM information applied"}); e != nil {
				return e
			}
		}
		if e = writer.MeasureFreshPolicyV1(call); e != nil {
			return e
		}
		pending, event, e = admission.persistOwnedV1(call, s, tx, actor, doc, session)
		if e != nil {
			return e
		}
		if changed {
			changedPending, changedEvent, e = ownedaudit.LogV1(s.Audit, call, session, pdfadmission.HTMLAuditPlainDraftUpdatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &actor.UserID, DocumentID: &id, Kind: audit.KindDocumentUpdated, Payload: map[string]any{"via": "crm", "tool": "apply_reviewed_values"}})
			if e != nil {
				return e
			}
		}
		if e = guard.Recheck(call); e != nil {
			return e
		}
		return admission.checkDeadline()
	})
	if err != nil {
		return nil, nil, err
	}
	if err = stage.CommitV1(); err != nil {
		return nil, nil, err
	}
	if err = ownedaudit.PublishV1(s.Audit, pending, event); err != nil {
		return nil, nil, err
	}
	if changedEvent != nil {
		if err = ownedaudit.PublishV1(s.Audit, changedPending, changedEvent); err != nil {
			return nil, nil, err
		}
	}
	transferred = true
	return doc, func() { _ = close() }, nil
}
