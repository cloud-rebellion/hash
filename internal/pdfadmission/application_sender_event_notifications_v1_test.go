// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Genuine session callback/coordinator and producer execute; ONLY the already
// opened SQL/backend, private mutation and appended event witness are synthetic.
// This is bookkeeping/dispatch-bound evidence, not real PG/audit/commit proof.
type senderEventTxTestV1 struct {
	*applicationSessionTxTestV1
	org, document, sender, recipient, event, signature, email uuid.UUID
	kind, mode                                                string
	stamp                                                     pgtype.Timestamptz
	coordinator                                               *workguard.CoordinatorV1
	calls, enqueues, identityReads                            int
	granted                                                   bool
	auditAppended                                             bool
}

func (x *senderEventTxTestV1) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	x.calls++
	source := strings.Contains(sql, "GetSenderAutomationRecipientV1") || strings.Contains(sql, "GetSenderAutomationPreferenceV1")
	if source == x.auditAppended {
		return htmlRevisionReadRowTestV1{err: errors.New("sender source/event query crossed audit phase")}
	}
	snapshot := x.coordinator.SnapshotV1(x.org)
	x.granted = x.granted && snapshot.Global.ParentBytes > 0 && snapshot.Global.DBStagingBytes > 0
	row := func(record any) pgx.Row { return htmlRevisionReadRowTestV1{record: record} }
	switch {
	case strings.Contains(sql, "GetSenderAutomationPreferenceV1"):
		if x.mode == "absent" || x.mode == "legacy-absent" {
			return htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}
		}
		return row(struct {
			OrgID, SenderUserID        uuid.UUID
			Revision                   int64
			NotifyViewed, NotifySigned bool
		}{x.org, x.sender, 1, x.mode != "off", x.mode != "off"})
	case strings.Contains(sql, "GetSenderAutomationEventIdentityV1"):
		x.identityReads++
		event := x.event
		if x.mode == "foreign-event" {
			event = uuid.New()
		}
		sig := uuid.Nil
		if x.kind == "document.signed" {
			sig = x.signature
		}
		return row(struct {
			AuditEventID uuid.UUID
			SentAt       pgtype.Timestamptz
			SignatureID  uuid.UUID
		}{event, x.stamp, sig})
	case strings.Contains(sql, "GetSenderAutomationRecipientV1"):
		if x.mode == "missing-sender" {
			return htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}
		}
		return row(struct {
			ID, OrgID uuid.UUID
			Email     string
		}{x.sender, x.org, "sender@example.test"})
	case strings.Contains(sql, "TryClaimSenderEventNoticeV1"):
		if x.mode == "duplicate" {
			return htmlRevisionReadRowTestV1{err: pgx.ErrNoRows}
		}
		x.email = args[8].(uuid.UUID)
		if x.email == uuid.Nil {
			return htmlRevisionReadRowTestV1{err: errors.New("no private email identity")}
		}
		return row(struct{ ID uuid.UUID }{x.event})
	case strings.Contains(sql, "EnqueueSenderEventNoticeV1"):
		x.enqueues++
		if args[0].(uuid.UUID) != x.email || args[1].(uuid.UUID) != x.org {
			return htmlRevisionReadRowTestV1{err: errors.New("receipt/outbox identity diverged")}
		}
		r := generated.EmailDelivery{ID: x.email, ToEmail: args[2].(string), Subject: args[3].(string), HtmlBody: args[4].(string), TextBody: args[5].(string), FromName: args[6].(string), HeadersJson: []byte("{}"), Status: "pending", CreatedAt: x.stamp, NextAttemptAt: x.stamp, SmtpOrgID: pgtype.UUID{Bytes: x.org, Valid: true}, SmtpPurpose: "workspace"}
		if x.mode == "foreign-route" {
			r.SmtpOrgID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}
		return row(r)
	default:
		return htmlRevisionReadRowTestV1{err: errors.New("unexpected source dispatch")}
	}
}

func TestSenderEventNoticeActualNativeProducerDecisionsAndRetirementV1(t *testing.T) {
	for _, kind := range []string{"document.viewed", "document.signed"} {
		for _, mode := range []string{"queued", "absent", "legacy-absent", "off", "duplicate", "missing-sender", "foreign-event", "foreign-route", "unmarked", "copied-audit", "not-appended", "acknowledged", "copied-source"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f, session, coordinator := applicationRequestLoanFixtureV1(t)
				session.state.factory.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
				factory := &ApplicationSessionFactoryV1{state: session.state.factory}
				ctx := applicationTestContextV1(t)
				op, err := factory.NewHTMLSendOperationV1(ctx, f.scope.OrgID, f.scope.DocumentID)
				if err != nil {
					t.Fatal(err)
				}
				purpose, auditPurpose := HTMLSignerViewMutationV1, HTMLAuditSignerViewedV1
				if kind == "document.signed" {
					purpose, auditPurpose = HTMLBlockSignMutationV1, HTMLAuditBlockSignedV1
				}
				stage := &ApplicationHTMLSendSQLStageV1{operation: op, purpose: purpose, ctx: ctx, cancel: func() {}, session: session, active: true}
				stage.self = stage
				op.stages = append(op.stages, stage)
				stamp := pgtype.Timestamptz{Time: time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC), Valid: true}
				x := &senderEventTxTestV1{applicationSessionTxTestV1: &applicationSessionTxTestV1{}, org: f.scope.OrgID, document: f.scope.DocumentID, sender: uuid.New(), recipient: uuid.New(), event: uuid.New(), signature: uuid.New(), kind: kind, mode: mode, stamp: stamp, coordinator: coordinator, granted: true}
				session.state.tx = x
				var work *ApplicationHTMLSendWorkV1
				t.Cleanup(func() {
					if work != nil {
						work.CloseConsumerV1()
					}
					op.CloseConsumerV1()
					if !applicationDoneV1(f.done) {
						close(f.done)
					}
					cleanup, stop := context.WithTimeout(context.Background(), time.Second)
					defer stop()
					_ = f.adapter.CloseV1(cleanup)
				})
				err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
					var e error
					work, e = session.NewHTMLSendWorkV1(call, stage)
					if e != nil {
						return e
					}
					work.sourceDocument = &generated.Document{ID: x.document, OrgID: x.org, SenderID: x.sender, Name: "Synthetic document", Status: "in_progress", SourceKind: "pdf", SentAt: stamp}
					if mode == "legacy-absent" {
						work.sourceDocument.SentAt = pgtype.Timestamptz{}
					}
					rec := &generated.Recipient{ID: x.recipient, DocumentID: x.document, Name: "Synthetic recipient", Status: "sent"}
					if kind == "document.viewed" {
						work.signerView = &applicationSignerViewMutationV1{request: &applicationSignerViewRequestV1{}, recipient: rec, marked: mode != "unmarked"}
					} else {
						work.blockSignature = &applicationBlockSignatureMutationV1{request: &applicationBlockSignatureRequestV1{}, recipient: rec, marked: mode != "unmarked", signature: &generated.Signature{ID: x.signature, DocumentID: x.document, RecipientID: x.recipient}}
					}
					prepared, err := work.PrepareSenderEventNoticeV1(call, "https://hash.example.test")
					if err != nil {
						return err
					}
					defer prepared.CloseConsumerV1()
					a := &ApplicationHTMLAuditEventConsumerV1{session: session, queries: work.queries, physicalDocument: x.document, org: x.org, document: x.document, recipient: pgtype.UUID{Bytes: x.recipient, Valid: true}, purpose: auditPurpose, kind: kind, eventID: x.event, closeConsumer: func() {}, used: true, attempted: true}
					a.self = a
					if mode == "not-appended" {
						a.attempted = false
					}
					if mode == "acknowledged" {
						a.kind = "document.acknowledged"
					}
					if mode == "copied-audit" {
						a = &ApplicationHTMLAuditEventConsumerV1{self: a, session: a.session, queries: a.queries, org: a.org, document: a.document, recipient: a.recipient, kind: a.kind, eventID: a.eventID}
					}
					x.auditAppended = true
					if mode == "copied-source" {
						copy := &ApplicationSenderEventNoticeV1{self: prepared, work: prepared.work, org: prepared.org, document: prepared.document, sender: prepared.sender, recipient: prepared.recipient, sentAt: prepared.sentAt, signature: prepared.signature, kind: prepared.kind, message: prepared.message, enabled: prepared.enabled}
						before := coordinator.SnapshotV1(x.org)
						copy.CloseConsumerV1()
						if coordinator.SnapshotV1(x.org) != before {
							t.Fatal("copied source credited original loan")
						}
						return copy.EnqueueV1(call, a)
					}
					err = prepared.EnqueueV1(call, a)
					if err == nil {
						before := x.calls
						if prepared.EnqueueV1(call, a) == nil || x.calls != before {
							t.Fatal("prepared event was reused or dispatched again")
						}
					}
					return err
				})
				if work == nil {
					t.Fatal("native work constructor failed", err)
				}
				wantErr := mode == "foreign-event" || mode == "foreign-route" || mode == "unmarked" || mode == "copied-audit" || mode == "not-appended" || mode == "acknowledged" || mode == "copied-source"
				if (err != nil) != wantErr {
					t.Fatal("wrong native decision", err)
				}
				wantQueue := mode == "queued" || mode == "foreign-route"
				if (x.enqueues == 1) != wantQueue || x.enqueues > 1 || !x.granted || work.sourceBorrowers != 0 {
					t.Fatal("unfunded/duplicate dispatch or source borrow leak", x.calls, x.enqueues, x.granted, work.sourceBorrowers)
				}
				if mode == "unmarked" && x.calls != 0 {
					t.Fatal("unmarked mutation reached source SQL")
				}
				if (mode == "copied-audit" || mode == "not-appended" || mode == "acknowledged" || mode == "copied-source") && x.identityReads != 0 {
					t.Fatal("invalid native event reached event SQL")
				}
				work.CloseConsumerV1()
				op.CloseConsumerV1()
				if x.calls > 0 && coordinator.SnapshotV1(x.org).Global.ParentBytes == 0 {
					t.Fatal("consumer close credited live synthetic backend")
				}
				close(f.done)
				if e := f.adapter.CloseV1(ctx); e != nil {
					t.Fatal(e)
				}
				if coordinator.SnapshotV1(x.org) != (workguard.SnapshotV1{}) {
					t.Fatal("joined synthetic fixture did not drain")
				}
			})
		}
	}
}

func TestSenderEventNoticeRejectsAbsentNativeWorkV1(t *testing.T) {
	ctx := applicationTestContextV1(t)
	var work ApplicationHTMLSendWorkV1
	if prepared, err := work.PrepareSenderEventNoticeV1(ctx, "https://hash.example.test"); !errors.Is(err, dispatch.ErrSenderEventNoticeV1) || prepared != nil {
		t.Fatal("invented native work prepared source", err)
	}
	var prepared ApplicationSenderEventNoticeV1
	if err := prepared.EnqueueV1(ctx, &ApplicationHTMLAuditEventConsumerV1{}); !errors.Is(err, dispatch.ErrSenderEventNoticeV1) {
		t.Fatal("invented prepared source accepted", err)
	}
}
