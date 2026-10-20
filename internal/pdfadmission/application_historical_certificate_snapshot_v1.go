// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

// This independent immutable output can only be issued inside the genuine
// authorized CertificateData callback after its actual native chain/event
// reads. It keeps no old SQL Work/admission/context/body borrower. Independent
// Parent precedes every clone and canonical claim, so the old metadata reader
// can retire after this actual copy consumer returns and its COMMIT joins.
type ApplicationHistoricalCertificateSnapshotV1 struct {
	activityMutex                          sync.Mutex
	activity                               applicationJoinedActivityV1
	self                                   *ApplicationHistoricalCertificateSnapshotV1
	closeRequested                         atomic.Bool
	grant                                  *workguard.GrantV1
	factory                                *ApplicationSessionFactoryV1
	org, document                          uuid.UUID
	updated                                pgtype.Timestamptz
	head                                   *generated.LatestEventChainHeadForOrgRow
	events                                 []*generated.Event
	claims                                 render.CertificateEvidenceClaimsV1
	reportHTML, reportSHA256, reportSchema string
	reportCutoff                           pgtype.Timestamptz
	reportRows                             int64
	claimAttempted, claimed                bool
}

// Activity is admitted before waiting and remains owned through every actual
// callback/consumer completion. Closed admission never discards a prior finish.
func (s *ApplicationHistoricalCertificateSnapshotV1) lockV1() bool {
	if !s.activity.enterV1() {
		return false
	}
	s.activityMutex.Lock()
	return true
}
func (s *ApplicationHistoricalCertificateSnapshotV1) finishActivityV1() {
	if s.activity.leaveV1() {
		s.retireClosedV1()
	}
}
func (s *ApplicationHistoricalCertificateSnapshotV1) unlockV1() {
	s.activityMutex.Unlock()
	s.finishActivityV1()
}
func (s *ApplicationHistoricalCertificateSnapshotV1) retireClosedV1() {
	if !s.closeRequested.Load() {
		return
	}
	s.head = nil
	s.events = nil
	s.claims = render.CertificateEvidenceClaimsV1{}
	s.reportHTML = ""
	s.reportSHA256 = ""
	s.reportSchema = ""
	s.factory = nil
	g := s.grant
	s.grant = nil
	if g != nil {
		g.Close()
	}
}

func (s *ApplicationHistoricalCertificateSnapshotV1) CloseConsumerV1() {
	if s == nil || s.self != s {
		return
	}
	s.closeRequested.Store(true)
	if s.activity.closeV1() {
		s.retireClosedV1()
	}
}

func (w *ApplicationHTMLSendWorkV1) SnapshotHistoricalCertificateDataV1(call context.Context) (*ApplicationHistoricalCertificateSnapshotV1, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalCertificateStateV1(call)
	if err != nil {
		return nil, err
	}
	if !state.authorized || !state.headAttempted || state.head == nil || !state.eventsAttempted || state.events == nil || w.state == nil || w.stage == nil || w.stage.operation == nil || w.stage.operation.factory == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if !state.reportAttempted || state.reportHTML == "" || state.reportSHA256 == "" || !participantReportSchemaKnownV1(state.reportSchema) {
		return nil, ErrHTMLSendWorkV1
	}
	raw := 8*int64(len(state.reportHTML)) + historicalCertificateClaimsOutputResourcesV1() + 4*int64(unsafe.Sizeof(ApplicationHistoricalCertificateSnapshotV1{})) + 4*int64(unsafe.Sizeof(generated.LatestEventChainHeadForOrgRow{})) + 4*int64(unsafe.Sizeof(sync.Once{})) + 4*int64(len(state.head.RowHash))
	for _, event := range state.events {
		n, err := historicalCertificateEventRawV1(event)
		if err != nil || !htmlInputAddV1(&raw, n, 8) || !htmlInputAddV1(&raw, int64(len(event.PayloadJson)), 8) || !htmlInputAddV1(&raw, 1, 8*int64(unsafe.Sizeof(generated.Event{}))+8*int64(unsafe.Sizeof((*generated.Event)(nil)))) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	factory := w.stage.operation.factory
	p := factory.state
	p.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !p.closing && p.work != nil {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHTMLSendWorkV1
	}
	grant, err := coordinator.TryAcquireV1(w.stage.operation.original, w.session.state.org, workguard.VectorV1{ParentBytes: raw})
	if err != nil {
		return nil, err
	}
	snapshot := &ApplicationHistoricalCertificateSnapshotV1{grant: grant, factory: factory, org: w.session.state.org, document: w.logicalDocumentV1(), updated: w.state.UpdatedAt, head: &generated.LatestEventChainHeadForOrgRow{RowHash: append([]byte(nil), state.head.RowHash...), CreatedAt: state.head.CreatedAt}, events: make([]*generated.Event, len(state.events)), reportHTML: strings.Clone(state.reportHTML), reportSHA256: strings.Clone(state.reportSHA256), reportSchema: state.reportSchema, reportCutoff: state.reportCutoff, reportRows: state.reportRows}
	snapshot.self = snapshot
	for i, event := range state.events {
		copy := historicalCertificateCloneEventV1(event)
		copy.Kind = strings.Clone(event.Kind)
		copy.Ua.String = strings.Clone(event.Ua.String)
		snapshot.events[i] = copy
	}
	return snapshot, nil
}

// Original newCertificateEvidenceClaims validation and hash production occurs
// only here at its original adapter point. A caller digest/row/claims string
// cannot become native output authority: final is the genuine final-body
// owner, and source is the original same-document checked native snapshot.
func (s *ApplicationHistoricalCertificateSnapshotV1) PrepareClaimsV1(source *ApplicationHistoricalFinalizationSourceEvidenceV1, final *ApplicationHistoricalFinalizationPDFV1) error {
	if s == nil || s.self != s || source == nil || final == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !s.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.grant == nil || s.claimAttempted || s.factory == nil {
		return ErrHistoricalFinalizationSourceV1
	}
	if !source.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	sourceLocked := true
	defer func() {
		if sourceLocked {
			source.unlockV1()
		}
	}()
	if !source.validV1() || !source.sourceChecked || source.document == nil || source.work.stage.operation.factory != s.factory || source.document.ID != s.document || source.document.OrgID != s.org || source.document.UpdatedAt != s.updated {
		return ErrHistoricalFinalizationSourceV1
	}
	if !final.lockV1() {
		return ErrHistoricalFinalizationSourceV1
	}
	sourceLocked = false
	defer final.unlockSourceConsumerV1(source)
	if !final.validScopeLockedV1(source) || !final.hashAttempted || final.hashFailure != nil {
		return ErrHistoricalFinalizationSourceV1
	}
	return s.prepareClaimsFromFinalSHA256V1(source, final.sum[:])
}

// Caller holds both genuine source and snapshot activity locks. The digest
// comes only from its native final producer or immutable native preparation.
func (s *ApplicationHistoricalCertificateSnapshotV1) prepareClaimsFromFinalSHA256V1(source *ApplicationHistoricalFinalizationSourceEvidenceV1, finalSHA []byte) error {
	s.claimAttempted = true
	// SHA name input/canonical sorting scratch is positively funded before its
	// one actual claims producer, independently of the retired metadata Work.
	if err := s.grant.TryGrowParentV1(source.ctx, 8*int64(len(source.document.Name))+4096); err != nil {
		return err
	}
	claims, err := render.NewCertificateEvidenceClaimsV1(source.document, finalSHA, s.head, s.events)
	if err != nil {
		return err
	}
	if claims.DocumentID != s.document.String() || claims.OrgID != s.org.String() {
		return errors.New("audit certificate: native claim scope changed")
	}
	if !participantReportSchemaKnownV1(s.reportSchema) || source.document.ParticipantReportSchema != s.reportSchema {
		return ErrHistoricalFinalizationSourceV1
	}
	claims.ParticipantReportSchema = s.reportSchema
	claims.ParticipantReportSHA256 = s.reportSHA256
	claims.ParticipantReportCutoff = s.reportCutoff.Time.UTC().Format(time.RFC3339Nano)
	claims.ParticipantReportRows = s.reportRows
	claims.ParticipantReportHTML = s.reportHTML
	s.claims = claims
	s.claimed = true
	return nil
}
