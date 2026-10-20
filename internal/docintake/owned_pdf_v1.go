// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package docintake

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type OwnedPDFDependenciesV1 struct {
	Sessions *pdfadmission.ApplicationSessionFactoryV1
	Billing  *billing.Engine
	Audit    *audit.Logger
	Store    objectStore
}
type OwnedPDFActorV1 struct {
	OrgID, UserID uuid.UUID
	Authorize     auth.TransactionAuthorization
	Via, Tool     string
}

// Both actual transports retain this owner through their real response
// serialization. SQL closes before return; retained source/result loans end
// only at this consumer's final use and native backend reconciliation.
type OwnedPDFDocumentResultV1 struct {
	Document  *generated.Document
	PageCount int
	state     *ownedPDFDocumentResultStateV1
}
type ownedPDFDocumentResultStateV1 struct {
	once       sync.Once
	auditOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	writer     *pdfadmission.ApplicationPlainPDFCreationWriterV1
	reader     *pdfadmission.ApplicationHTMLAuthoringReaderV1
	factory    *pdfadmission.ApplicationSessionFactoryV1
}

func (r *OwnedPDFDocumentResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.auditOwner != nil {
			s.auditOwner.CloseConsumerV1()
		}
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
func (r *OwnedPDFDocumentResultV1) MarshalJSON() ([]byte, error) {
	if r == nil {
		return []byte("null"), nil
	}
	return json.Marshal(struct {
		Document  *generated.Document `json:"document"`
		PageCount int                 `json:"page_count"`
	}{r.Document, r.PageCount})
}

// CreateOwnedPDFSourceDocumentV1 is the shared fixed REST/MCP upload producer.
// Original quota->member/credential->sanitize/store->INSERT->quota->audit->
// original credential recheck ordering is retained. The optional acknowledgement
// switch remains between quota enforcement and audit, as in the MCP surface.
// The one-shot preparation owns real sanitized bytes/report/storage identity;
// native measurement is exclusively for the actual fresh INSERT in this Tx.
func CreateOwnedPDFSourceDocumentV1(ctx context.Context, d OwnedPDFDependenciesV1, actor OwnedPDFActorV1, name string, data []byte, requiresSignature *bool) (result *OwnedPDFDocumentResultV1, failure error) {
	if d.Sessions == nil || nilOwnedPDFDependencyV1(d.Audit) || nilOwnedPDFDependencyV1(d.Store) || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("owned PDF creation dependencies unavailable")
	}
	documentID := uuid.New()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, documentID)
	if err != nil {
		if session != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &ownedPDFDocumentResultStateV1{factory: d.Sessions}
	result = &OwnedPDFDocumentResultV1{state: state}
	committed := false
	var owned OwnedPDFSource
	var pending audit.PendingEvent
	var doc *generated.Document
	var pages int
	commitAttempted := false
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
		// An attempted COMMIT can have succeeded despite a lost acknowledgement.
		// Preserve that exact version until reconciliation; do not destroy evidence.
		if !committed && !commitAttempted && owned.Key != "" {
			failure = errors.Join(failure, deleteAfterFailedWrite(ctx, d.Store, owned.Key, storage.StoredObject{VersionID: owned.VersionID, SHA256: owned.SHA256}))
		}
	}()
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.writer, err = session.NewPlainPDFCreationWriterV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativePDFPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		if err = d.Billing.LockDocumentQuotaMutation(call, q, actor.OrgID); err != nil {
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
		prepared, err := PreparePDFTemplateSource(call, d.Store, actor.OrgID, data)
		if err != nil {
			return err
		}
		owned = prepared.OwnedSource()
		pages = prepared.PageCount()
		doc, err = prepared.attach(call, state.writer, actor.OrgID, actor.UserID, name, pgtype.UUID{}, pgtype.Timestamptz{})
		if err != nil {
			return err
		}
		if err = state.writer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
			return err
		}
		if requiresSignature != nil && !*requiresSignature {
			doc, err = state.writer.SetRequiresSignatureV1(call, false)
			if err != nil {
				return err
			}
		}
		if err = state.writer.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		doc, err = state.writer.CurrentDocumentV1(call)
		if err != nil {
			return err
		}
		payload := map[string]any{"name": name, "source_kind": "pdf"}
		if actor.Via == "mcp" {
			payload["via"] = "mcp"
			payload["tool"] = actor.Tool
		} else {
			payload["intake"] = "import"
		}
		id, user := doc.ID, actor.UserID
		pending, state.auditOwner, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditPlainPDFCreatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &user, DocumentID: &id, Kind: audit.KindDocumentCreated, Payload: payload})
		if err != nil {
			return err
		}
		// Tiny event identifiers do not retain a whole source/result backing object.
		pending = detachPDFEventIDsV1(pending)
		return guard.Recheck(call)
	})
	if err != nil {
		return result, err
	}
	commitAttempted = true
	if err = session.CommitV1(ctx); err != nil {
		return result, err
	}
	committed = true
	result.Document = doc
	result.PageCount = pages
	if err = ownedaudit.PublishV1(d.Audit, pending, state.auditOwner); err != nil {
		return result, err
	}
	return result, nil
}
func detachPDFEventIDsV1(event audit.PendingEvent) audit.PendingEvent {
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

func nilOwnedPDFDependencyV1(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Func, reflect.Chan, reflect.Slice:
		return v.IsNil()
	}
	return false
}
