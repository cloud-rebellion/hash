// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/netip"
	"time"
	"unsafe"
)

const historicalCertificateEventLimitV1 = 10000

var ErrHistoricalCertificateEventLimitV1 = errors.New("pdfadmission: certificate document event limit exceeded")

type applicationHistoricalCertificateReadV1 struct {
	head                                       *generated.LatestEventChainHeadForOrgRow
	events                                     []*generated.Event
	reportEvents                               []*generated.Event
	reportHTML, reportSHA256, reportSchema     string
	reportCutoff                               pgtype.Timestamptz
	reportRows                                 int64
	reportAttempted                            bool
	headAttempted, eventsAttempted, authorized bool
}

// Positive concrete capacity for certificateEvidenceClaims' historical output:
// sixteen string fields plus count; UUIDs, SHA-256 hex, UTC timestamps and the
// two literal scopes. Fitted optional fields are empty on this closed route.
// This is fixed output pricing, never a caller-supplied input or size bound.
func historicalCertificateClaimsOutputResourcesV1() int64 {
	return 4*int64(unsafe.Sizeof(render.CertificateEvidenceClaimsV1{})) + 4*int64(unsafe.Sizeof(int(0))) + 4*int64(2*36+7*64+3*len(time.RFC3339Nano)+len("organizationceremony-root")+len(render.ParticipantReportSchemaV2))
}

func (w *ApplicationHTMLSendWorkV1) historicalCertificateStateV1(call context.Context) (*applicationHistoricalCertificateReadV1, error) {
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLHistoricalFinalizationCertificateDataV1 || w.familyRoot != nil || w.state == nil || w.state.BoundedStatus != "finalizing" || w.state.ParentEnvelopeID.Valid {
		return nil, ErrHTMLSendWorkV1
	}
	if w.certificateRead != nil {
		return w.certificateRead, nil
	}
	// The canonical claim output retains only UUID/digest/UTC strings and a count.
	// Price that fixed output together with the actual event/chain views until
	// certificate rendering consumes it; no claim keeps an event-body alias.
	raw := historicalCertificateClaimsOutputResourcesV1() + 2*int64(unsafe.Sizeof(applicationHistoricalCertificateReadV1{})) + 4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationCertificateChainHeadHeaderV1Params{})) + 4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationCertificateChainHeadHeaderV1Row{})) + 4*int64(unsafe.Sizeof(generated.ReadHistoricalFinalizationCertificateChainHeadV1Params{})) + 4*int64(unsafe.Sizeof(generated.ReadHistoricalFinalizationCertificateChainHeadV1Row{})) + 4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationCertificateEventReadHeaderV1Params{})) + 4*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationCertificateEventReadHeaderV1Row{})) + 4*int64(unsafe.Sizeof(generated.ListEventsByDocumentParams{})) + 4*int64(unsafe.Sizeof(generated.LatestEventChainHeadForOrgRow{})) + 16*int64(unsafe.Sizeof(uintptr(0)))
	closeState, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeState)
	w.certificateRead = &applicationHistoricalCertificateReadV1{}
	return w.certificateRead, nil
}

func (w *ApplicationHTMLSendWorkV1) ValidateHistoricalCertificateReferenceV1(call context.Context, reference *ApplicationHistoricalFinalizationStageReferenceV1) error {
	if w == nil || w.self != w || reference == nil || w.stage == nil || w.stage.operation == nil {
		return ErrHTMLSendWorkV1
	}
	owner, err := reference.ownerV1(w.stage.operation.factory)
	if err != nil {
		return err
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	w.mu.Lock()
	defer w.mu.Unlock()
	if owner.closed || !owner.stagePrepared || !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationCertificateDataV1 || w.familyRoot != nil || w.state == nil || w.state.OrgID != owner.org || w.state.ID != owner.document || w.state.BoundedStatus != "finalizing" || w.state.ParentEnvelopeID.Valid || w.state.RequiresSignature != owner.stageCommitment.requiresSignature {
		return ErrHTMLSendWorkV1
	}
	state, err := w.historicalCertificateStateV1(call)
	if err != nil {
		return err
	}
	if state.authorized {
		return ErrHTMLSendWorkV1
	}
	state.authorized = true
	return nil
}

// Pin the original captured organization prefix before reading its body. An
// append on another document may advance the org head without changing this
// immutable event; no unpriced newer head is fetched by the second query.
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalCertificateChainHeadV1(call context.Context) (*generated.LatestEventChainHeadForOrgRow, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalCertificateStateV1(call)
	if err != nil {
		return nil, err
	}
	if !state.authorized || state.headAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	state.headAttempted = true
	header, err := w.queries.GetHistoricalFinalizationCertificateChainHeadHeaderV1(call, generated.GetHistoricalFinalizationCertificateChainHeadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil {
		return nil, err
	}
	if header == nil || header.EventID == uuid.Nil || header.OrgID != w.session.state.org || header.RowHashBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw, err := htmlAuthoringSumV1(header.RowHashBytes, 4*int64(unsafe.Sizeof(generated.LatestEventChainHeadForOrgRow{})))
	if err != nil {
		return nil, err
	}
	closeHead, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeHead)
	row, err := w.queries.ReadHistoricalFinalizationCertificateChainHeadV1(call, generated.ReadHistoricalFinalizationCertificateChainHeadV1Params{EventID: header.EventID, OrgID: header.OrgID, ExpectedCreatedAt: header.CreatedAt, ExpectedRowHashBytes: header.RowHashBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.CreatedAt != header.CreatedAt || int64(len(row.RowHash)) != header.RowHashBytes {
		return nil, ErrHTMLSendWorkV1
	}
	state.head = &generated.LatestEventChainHeadForOrgRow{RowHash: bytes.Clone(row.RowHash), CreatedAt: row.CreatedAt}
	return &generated.LatestEventChainHeadForOrgRow{RowHash: row.RowHash, CreatedAt: row.CreatedAt}, nil
}

func historicalCertificateEventRawV1(event *generated.Event) (int64, error) {
	if event == nil {
		return 0, ErrHTMLSendWorkV1
	}
	return htmlAuthoringSumV1(int64(len(event.Kind)), int64(len(event.Ua.String)), int64(len(event.PrevHash)), int64(len(event.RowHash)), int64(len(event.PayloadHashed)))
}

// The existing M94 subject fence covers the COMPLETE original document-ID
// event set. Missing/stale producer measurements refuse; this reader never
// derives measurements by expanding payload_json or repairs a cache.
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalCertificateEventsV1(call context.Context) ([]*generated.Event, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalCertificateStateV1(call)
	if err != nil {
		return nil, err
	}
	if !state.authorized || !state.headAttempted || state.head == nil || state.eventsAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	state.eventsAttempted = true
	params := generated.GetHistoricalFinalizationCertificateEventReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org}
	header, err := w.queries.GetHistoricalFinalizationCertificateEventReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != w.logicalDocumentV1() || header.OrgID != w.session.state.org || header.UpdatedAt != w.state.UpdatedAt || header.EventCount < 0 || header.RawBytes < 0 || header.PayloadWireBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	if header.EventCount > historicalCertificateEventLimitV1 {
		return nil, ErrHistoricalCertificateEventLimitV1
	}
	if header.MissingSizeCount != 0 || header.ServerMismatchCount != 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw := header.RawBytes
	per := 5*int64(unsafe.Sizeof(generated.Event{})) + 8*int64(unsafe.Sizeof((*generated.Event)(nil))) + 4*int64(unsafe.Sizeof(netip.Addr{})) + 8*int64(unsafe.Sizeof(uuid.UUID{}))
	if !htmlInputAddV1(&raw, header.EventCount, per) {
		return nil, ErrHTMLSendWorkV1
	}
	closeEvents, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, header.PayloadWireBytes)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeEvents)
	fresh, err := w.queries.GetHistoricalFinalizationCertificateEventReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *header {
		return nil, ErrHTMLSendWorkV1
	}
	rows, err := w.queries.ListEventsByDocument(call, generated.ListEventsByDocumentParams{DocumentID: pgtype.UUID{Bytes: w.logicalDocumentV1(), Valid: true}, Limit: historicalCertificateEventLimitV1 + 1})
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != header.EventCount {
		return nil, ErrHTMLSendWorkV1
	}
	actualRaw, actualWire := int64(0), int64(0)
	for _, row := range rows {
		if row == nil || !row.DocumentID.Valid || uuid.UUID(row.DocumentID.Bytes) != w.logicalDocumentV1() {
			return nil, ErrHTMLSendWorkV1
		}
		n, err := historicalCertificateEventRawV1(row)
		if err != nil || !htmlInputAddV1(&actualRaw, n, 1) || !htmlInputAddV1(&actualWire, int64(len(row.PayloadJson)), 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if actualRaw != header.RawBytes || actualWire != header.PayloadWireBytes {
		return nil, ErrHTMLSendWorkV1
	}
	// Legal org scope, exact hash lengths and row-hash recomputation keep their
	// original later position in newCertificateEvidenceClaims.
	state.events = make([]*generated.Event, len(rows))
	for i, row := range rows {
		state.events[i] = historicalCertificateCloneEventV1(row)
	}
	if err := w.readParticipantReportLockedV1(call, state); err != nil {
		return nil, err
	}
	return rows, nil
}

func historicalCertificateCloneEventV1(row *generated.Event) *generated.Event {
	if row == nil {
		return nil
	}
	copy := *row
	copy.PayloadJson = bytes.Clone(row.PayloadJson)
	copy.PayloadHashed = bytes.Clone(row.PayloadHashed)
	copy.PrevHash = bytes.Clone(row.PrevHash)
	copy.RowHash = bytes.Clone(row.RowHash)
	if row.Ip != nil {
		ip := *row.Ip
		copy.Ip = &ip
	}
	return &copy
}
