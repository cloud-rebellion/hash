// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fixed producer costs include detached concrete maps/strings, map sort and
// Marshal scratch, exact payload+hash input+pgx copies and the DB JSONB/cache
// producer. They are dispatch bounds, not measured heap/RSS or durable storage.
func htmlAuditResourcesV1(raw, wire, nodes int64) (ApplicationRequestPayloadResourcesV1, error) {
	base, err := htmlAuditFixedResourcesV1()
	if err != nil {
		return ApplicationRequestPayloadResourcesV1{}, err
	}
	if raw < 0 || wire < 2 || nodes < 1 || wire > (math.MaxInt64-base)/32 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	parent := 32*wire + base
	if raw > (math.MaxInt64-parent)/16 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	parent += 16 * raw
	if nodes > (math.MaxInt64-parent)/256 {
		return ApplicationRequestPayloadResourcesV1{}, workguard.ErrUnavailableV1
	}
	parent += 256 * nodes
	return ApplicationRequestPayloadResourcesV1{WorkingBytes: parent, DBStagingBytes: 16*wire + base}, nil
}

// Public only to the fixed in-process audit adapter. A caller may inspect this
// borrow synchronously, and retain its detached Payload solely in PendingEvent
// while retaining the SAME consumer through every hook's actual last use.
// Raw is immutable; neither bytes nor map may be modified by the callback.
type ApplicationHTMLAuditPreparedV1 struct {
	OrgID, DocumentID        uuid.UUID
	RecipientID, ActorUserID pgtype.UUID
	Kind, IP, UserAgent      string
	Payload                  map[string]any
	Raw                      []byte
	PreviousHash             []byte
	PreviousCreatedAt        pgtype.Timestamptz
}

type ApplicationHTMLAuditEventConsumerV1 struct {
	mu                                                  sync.Mutex
	self                                                *ApplicationHTMLAuditEventConsumerV1
	session                                             *ApplicationSessionV1
	member                                              *ApplicationHTMLSendWorkV1
	documentAI                                          *applicationDocumentAIAuditScopeV1
	physicalDocument                                    uuid.UUID
	queries                                             *generated.Queries
	org, document                                       uuid.UUID
	recipient, actor                                    pgtype.UUID
	purpose                                             HTMLAuditPurposeV1
	kind, ip, ua                                        string
	parsedIP                                            *netip.Addr
	payload                                             map[string]any
	raw                                                 []byte
	resources                                           ApplicationRequestPayloadResourcesV1
	shape                                               htmlAuditShapeV1
	closeConsumer                                       func()
	eventID                                             uuid.UUID
	used, attempted, published, publicationDone, closed bool
}

func (h *ApplicationSessionV1) NewHTMLAuditEventV1(ctx context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any) (*ApplicationHTMLAuditEventConsumerV1, error) {
	return h.newHTMLAuditEventV1(ctx, purpose, org, document, recipient, actor, kind, ip, ua, payload, nil)
}
func (h *ApplicationSessionV1) newHTMLAuditEventV1(ctx context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any, member *ApplicationHTMLSendWorkV1, layoutSlots ...*applicationPDFLayoutAuditSlotV1) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if len(layoutSlots) > 1 {
		return nil, ErrHTMLAuditEventV1
	}
	var layout *applicationPDFLayoutAuditSlotV1
	if len(layoutSlots) == 1 {
		layout = layoutSlots[0]
		if layout == nil {
			return nil, ErrHTMLAuditEventV1
		}
	}
	return h.newHTMLAuditEventCoreV1(ctx, purpose, org, document, recipient, actor, kind, ip, ua, payload, member, layout, nil, nil)
}
func (h *ApplicationSessionV1) newAutomationHTMLAuditEventV1(ctx context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any, slot *applicationAutomationAuditSlotV1) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if slot == nil {
		return nil, ErrHTMLAuditEventV1
	}
	return h.newHTMLAuditEventCoreV1(ctx, purpose, org, document, recipient, actor, kind, ip, ua, payload, nil, nil, slot, nil)
}
func (h *ApplicationSessionV1) newHTMLAuditEventCoreV1(ctx context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any, member *ApplicationHTMLSendWorkV1, layoutSlot *applicationPDFLayoutAuditSlotV1, automationSlot *applicationAutomationAuditSlotV1, packageSlot *applicationPackageSendAuditSlotV1, responseWorks ...*ApplicationHTMLSendWorkV1) (*ApplicationHTMLAuditEventConsumerV1, error) {
	return h.newHTMLAuditEventCoreReminderV1(ctx, purpose, org, document, recipient, actor, kind, ip, ua, payload, member, layoutSlot, automationSlot, packageSlot, nil, responseWorks...)
}
func (h *ApplicationSessionV1) newHTMLAuditEventCoreReminderV1(ctx context.Context, purpose HTMLAuditPurposeV1, org, document uuid.UUID, recipient, actor pgtype.UUID, kind, ip, ua string, payload map[string]any, member *ApplicationHTMLSendWorkV1, layoutSlot *applicationPDFLayoutAuditSlotV1, automationSlot *applicationAutomationAuditSlotV1, packageSlot *applicationPackageSendAuditSlotV1, reminderSlot *applicationReminderAuditSlotV1, responseWorks ...*ApplicationHTMLSendWorkV1) (*ApplicationHTMLAuditEventConsumerV1, error) {
	if !applicationContextV1(ctx) {
		return nil, ErrHTMLAuditEventV1
	}
	aiScope, _ := ctx.Value(applicationDocumentAIAuditKeyV1{}).(*applicationDocumentAIAuditScopeV1)
	if documentAIAuditPurposeV1(purpose) != (aiScope != nil) || (aiScope != nil && !aiScope.matchesV1(ctx, h, purpose, org, document, recipient, actor, kind, ip, ua, payload)) {
		return nil, ErrHTMLAuditEventV1
	}
	reminderPurpose := purpose == HTMLAuditReminderManualV1 || purpose == HTMLAuditReminderAutomaticV1
	if reminderPurpose != (reminderSlot != nil) || (reminderSlot != nil && (member != nil || layoutSlot != nil || automationSlot != nil || packageSlot != nil || len(responseWorks) != 0)) {
		return nil, ErrHTMLAuditEventV1
	}
	packagePurpose := purpose == HTMLAuditPackageRecipientInvitedV1 || purpose == HTMLAuditPackageDocumentSentV1 || purpose == HTMLAuditPackageDocumentExpiredV1 || purpose == HTMLAuditPackageSendAbortedV1
	if packagePurpose != (packageSlot != nil) {
		return nil, ErrHTMLAuditEventV1
	}
	if h == nil || h.state == nil || !applicationContextV1(ctx) || org == uuid.Nil || document == uuid.Nil || kind != purpose.KindV1() || (layoutSlot != nil && automationSlot != nil) || (packageSlot != nil && (layoutSlot != nil || automationSlot != nil)) || ((layoutSlot != nil || automationSlot != nil || packageSlot != nil) && member != nil) {
		return nil, ErrHTMLAuditEventV1
	}
	responsePurpose := purpose == HTMLAuditPackageSignedV1 || purpose == HTMLAuditPackageAcknowledgedV1
	if len(responseWorks) > 1 || responsePurpose != (len(responseWorks) == 1) {
		return nil, ErrHTMLAuditEventV1
	}
	if responsePurpose && (member != nil || layoutSlot != nil || automationSlot != nil || packageSlot != nil || !responseWorks[0].packageResponseAuditScopeMatchesV1(ctx, h, purpose, org, document, recipient, actor, payload)) {
		return nil, ErrHTMLAuditEventV1
	}
	physicalDocument := document
	if reminderSlot != nil {
		physicalDocument = h.state.document
	}
	if member != nil {
		if member.session != h || !member.memberAuditScopeMatchesV1(ctx, purpose, org, document) {
			return nil, ErrHTMLAuditEventV1
		}
		physicalDocument = h.state.document
	}
	shape, err := htmlAuditPayloadShapeV1(ctx, purpose, payload)
	if err != nil {
		return nil, err
	}
	for _, v := range [...]string{kind, ip, ua} {
		if err = shape.text(v, false); err != nil {
			return nil, err
		}
	}
	// Fixed scalar row/hash/timestamp and cache identity overhead.
	if err = shape.add(192, 4096, 16); err != nil {
		return nil, err
	}
	resources, err := htmlAuditResourcesV1(shape.raw, shape.wire, shape.nodes)
	if err != nil {
		return nil, err
	}
	s := h.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLAuditEventV1
	}
	// Same identity-safe registry-before-grant and factory->session->admission
	// order as the actual fresh creation writer. This is not a borrowed tx bridge.
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil || s.observer ||
		s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.tx == nil || s.conn == nil || !s.dialed ||
		s.org != org || s.document != physicalDocument || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) ||
		a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone ||
		!s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s ||
		(p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLAuditEventV1
	}
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	var closeConsumer func()
	if reminderSlot != nil {
		closeConsumer, err = reminderSlot.acquireV1(ctx, h, purpose, org, document, recipient, actor, kind, ip, ua, shape)
	} else if packageSlot != nil {
		closeConsumer, err = packageSlot.acquireV1(ctx, h, purpose, org, document, recipient, actor, kind, ip, ua, shape)
	} else if automationSlot != nil {
		closeConsumer, err = automationSlot.acquireV1(ctx, h, purpose, org, document, recipient, actor, kind, ip, ua, shape)
	} else if layoutSlot != nil {
		closeConsumer, err = layoutSlot.acquireV1(ctx, h, purpose, org, document, recipient, actor, kind, ip, ua, shape)
	} else {
		closeConsumer, err = a.admit(ctx, ApplicationBudgetV1{Phase: "locked-html-fresh-event", OrgID: org, DocumentID: physicalDocument,
			HTMLAuditRawBytes: shape.raw, HTMLAuditWireBytes: shape.wire, HTMLAuditNodes: shape.nodes, WorkingBytes: resources.WorkingBytes, DBStagingBytes: resources.DBStagingBytes})
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, errors.Join(ErrHTMLAuditEventV1, err)
	}
	out := &ApplicationHTMLAuditEventConsumerV1{session: h, documentAI: aiScope, member: member, physicalDocument: physicalDocument, org: org, document: document, recipient: recipient, actor: actor, purpose: purpose, resources: resources, shape: shape, closeConsumer: closeConsumer}
	out.self = out
	out.queries = generated.New(&applicationOwnedDBTXV1{session: s})
	// Every post-grant refusal returns the original real consumer closure, never
	// its coordinator credit. Physical session/registry retirement remains owed.
	if payload == nil {
		payload = map[string]any{}
	}
	cloned, err := htmlAuditCloneValueV1(ctx, payload, 0)
	if err != nil {
		out.CloseConsumerV1()
		return nil, err
	}
	out.payload = cloned.(map[string]any)
	if ip != "" {
		if addr, parseErr := netip.ParseAddr(ip); parseErr == nil {
			out.parsedIP = &addr
		}
	}
	out.kind = strings.Clone(kind)
	out.ip = strings.Clone(ip)
	out.ua = strings.Clone(ua)
	out.raw, err = json.Marshal(out.payload)
	if err != nil || ctx.Err() != nil || int64(len(out.raw)) > shape.wire {
		out.CloseConsumerV1()
		return nil, ErrHTMLAuditEventV1
	}
	return out, nil
}
func (o *ApplicationHTMLAuditEventConsumerV1) valid(ctx context.Context) bool {
	if o == nil || o.self != o || o.closed || o.session == nil || o.session.state == nil || o.queries == nil || o.closeConsumer == nil || !applicationContextV1(ctx) {
		return false
	}
	s := o.session.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.unknown && !s.ended && !s.retired && !s.sqlActive && s.callbackActive && ctx.Value(applicationSessionCallbackKeyV1{}) == s && s.org == o.org && s.document == o.physicalDocument
}

// A valid hash with a non-finite/unrepresentable timestamp is not a usable
// predecessor. It must never become a new genesis or sort behind a new append.
func htmlAuditHeadValidV1(head *generated.GetOwnedHTMLAuditChainHeadV1Row) bool {
	return head != nil && head.IsValidHash && len(head.RowHash) == 32 && applicationStampV1(head.CreatedAt)
}

const htmlAuditDocumentScopeSQLV1 = `SELECT d.id,d.org_id FROM documents d WHERE d.id=$1 AND d.org_id=$2 AND d.deleted_at IS NULL FOR UPDATE OF d`

// WithPreparedV1 is a one-shot native audit append. Its append closure exposes
// ONLY the existing identity-only insert, exact owned payload and immediate
// fresh cache derivation. It cannot execute arbitrary SQL, grant another scope,
// measure an old event or survive this borrow. Unknown mutation is never replayed.
func (o *ApplicationHTMLAuditEventConsumerV1) WithPreparedV1(ctx context.Context, consume func(ApplicationHTMLAuditPreparedV1, func(generated.InsertEventIdentityV1Params) (uuid.UUID, error)) error) error {
	if o == nil || o.self != o || consume == nil {
		return ErrHTMLAuditEventV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.valid(ctx) || o.used {
		return ErrHTMLAuditEventV1
	}
	o.used = true
	// Actual fixed scoped parent proof, without full Document or cache/body
	// expansion. It runs through THIS tracked native DBTX under the event loan
	// before org chain acquisition. Session metadata alone is not a row receipt.
	var document, org uuid.UUID
	db := &applicationOwnedDBTXV1{session: o.session.state}
	if o.documentAI != nil {
		if !o.documentAI.matchesV1(ctx, o.session, o.purpose, o.org, o.document, o.recipient, o.actor, o.kind, o.ip, o.ua, o.payload) {
			return ErrHTMLAuditEventV1
		}
		if err := o.documentAI.lockScopeV1(ctx); err != nil {
			return err
		}
		document, org = o.document, o.org
	} else if err := db.QueryRow(ctx, htmlAuditDocumentScopeSQLV1, o.document, o.org).Scan(&document, &org); err != nil {
		return err
	}
	if document != o.document || org != o.org {
		return ErrHTMLAuditEventV1
	}
	if err := o.queries.AcquireOrgChainLock(ctx, o.org.String()); err != nil {
		return err
	}
	head, err := o.queries.GetOwnedHTMLAuditChainHeadV1(ctx, o.org)
	var previous []byte
	var stamp pgtype.Timestamptz
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	} else {
		if !htmlAuditHeadValidV1(head) {
			return ErrHTMLAuditEventV1
		}
		previous = bytes.Clone(head.RowHash)
		stamp = head.CreatedAt
	}
	prepared := ApplicationHTMLAuditPreparedV1{OrgID: o.org, DocumentID: o.document, RecipientID: o.recipient, ActorUserID: o.actor, Kind: o.kind, IP: o.ip, UserAgent: o.ua, Payload: o.payload, Raw: o.raw, PreviousHash: previous, PreviousCreatedAt: stamp}
	// A retained closure is inert after the callback. Join any in-flight original
	// call before leaving the borrow; a second or future call always refuses.
	var appendMu sync.Mutex
	active := true
	appendOne := func(p generated.InsertEventIdentityV1Params) (uuid.UUID, error) {
		appendMu.Lock()
		defer appendMu.Unlock()
		if !active || !o.valid(ctx) || o.attempted || p.OrgID != o.org || !p.DocumentID.Valid || uuid.UUID(p.DocumentID.Bytes) != o.document ||
			p.RecipientID != o.recipient || p.ActorUserID != o.actor || p.Kind != o.kind || p.Ua.Valid != (o.ua != "") || p.Ua.String != o.ua || !bytes.Equal(p.PayloadJson, o.raw) || !bytes.Equal(p.PayloadHashed, o.raw) ||
			!bytes.Equal(p.PrevHash, previous) || len(p.RowHash) != 32 || !applicationStampV1(p.CreatedAt) {
			return uuid.Nil, ErrHTMLAuditEventV1
		}
		if stamp.Valid && !p.CreatedAt.Time.After(stamp.Time) {
			return uuid.Nil, ErrHTMLAuditEventV1
		}
		// Do not permit IP replacement after the immutable original Entry snapshot.
		if (o.parsedIP == nil) != (p.Ip == nil) || (o.parsedIP != nil && *o.parsedIP != *p.Ip) {
			return uuid.Nil, ErrHTMLAuditEventV1
		}
		o.attempted = true
		id, err := o.queries.InsertEventIdentityV1(ctx, p)
		if err != nil {
			return uuid.Nil, applicationInternalWriteErrorV1(ctx, applicationAuditIdentityWriteV1, err)
		}
		if id == uuid.Nil {
			return uuid.Nil, ErrHTMLAuditEventV1
		}
		cache, err := o.queries.MeasureHTMLSnapshotEventPayloadV1(ctx, generated.MeasureHTMLSnapshotEventPayloadV1Params{EventID: id, DocumentID: o.document, OrgID: o.org})
		if err != nil || cache == nil {
			return uuid.Nil, errors.Join(ErrHTMLAuditEventV1, err)
		}
		if cache.EventID != id || cache.DocumentID != o.document || cache.OrgID != o.org || cache.PayloadWireBytes < 2 || cache.PayloadWireBytes > o.shape.wire || cache.MeasurementServerVersionNum <= 0 || !applicationStampV1(cache.MeasuredAt) {
			return uuid.Nil, ErrHTMLAuditEventV1
		}
		o.eventID = id
		return id, nil
	}
	defer func() { appendMu.Lock(); active = false; appendMu.Unlock() }()
	err = consume(prepared, appendOne)
	appendMu.Lock()
	active = false
	appendMu.Unlock()
	if err != nil {
		return err
	}
	if ctx.Err() != nil || !o.attempted || o.eventID == uuid.Nil {
		return ErrHTMLAuditEventV1
	}
	return nil
}

// CloseConsumerV1 ends only this exact detached-payload consumer. The actual
// native admission/factory retains DB/parent loans until consumer AND physical
// client/backend AND registry retirement. Copying/zeroing a shell cannot close it.
func (o *ApplicationHTMLAuditEventConsumerV1) CloseConsumerV1() {
	if o == nil || o.self != o {
		return
	}
	o.mu.Lock()
	if o.closed || (o.published && !o.publicationDone) {
		o.mu.Unlock()
		return
	}
	o.closed = true
	closeConsumer := o.closeConsumer
	o.closeConsumer = nil
	o.member = nil
	o.payload = nil
	o.raw = nil
	o.parsedIP = nil
	o.kind = ""
	o.ip = ""
	o.ua = ""
	o.mu.Unlock()
	if closeConsumer != nil {
		closeConsumer()
	}
}

// BeginPublicationV1 is a one-shot observation of THIS actual session's
// acknowledged commit, not a caller boolean or an independent row read. Unknown
// commit has no new post-commit dispatch authority. This does not refund debt.
func (o *ApplicationHTMLAuditEventConsumerV1) BeginPublicationV1(id uuid.UUID) (ApplicationHTMLAuditPreparedV1, func(), error) {
	if o == nil || o.self != o {
		return ApplicationHTMLAuditPreparedV1{}, nil, ErrHTMLAuditEventV1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.published || o.eventID == uuid.Nil || id != o.eventID || o.session == nil || o.session.state == nil {
		return ApplicationHTMLAuditPreparedV1{}, nil, ErrHTMLAuditEventV1
	}
	s := o.session.state
	s.mu.Lock()
	ack := s.commitAttempted && s.ended && !s.commitUnknown
	s.mu.Unlock()
	if !ack {
		return ApplicationHTMLAuditPreparedV1{}, nil, ErrHTMLAuditEventV1
	}
	o.published = true
	var once sync.Once
	finished := func() { once.Do(func() { o.mu.Lock(); o.publicationDone = true; o.mu.Unlock(); o.CloseConsumerV1() }) }
	return ApplicationHTMLAuditPreparedV1{OrgID: o.org, DocumentID: o.document, RecipientID: o.recipient, ActorUserID: o.actor, Kind: o.kind, IP: o.ip, UserAgent: o.ua, Payload: o.payload, Raw: o.raw}, finished, nil
}
