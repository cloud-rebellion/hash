// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/pdflayout"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Only deterministic measured report/canonical/payload limits use this error.
// Missing measurements, malformed history, unavailable funding, DB errors and
// cancellation retain their original errors and are not reported as capacity.
var ErrParticipantReportCapacityV1 = errors.New("pdfadmission: participant report capacity exceeded")

// These are PRIVATE formatter reservations, never evidence, source selection,
// persisted claims or signatures. UTC RFC3339Nano uses at most this many bytes
// for supported four-digit years; a future SHA-256 hex always uses 64 safe bytes.
const responseCertificateSizingTimestampV1 = "9999-12-31T23:59:59.999999999Z"
const responseCertificateSizingDigestV1 = "0000000000000000000000000000000000000000000000000000000000000000"

// Select only the Work's existing private request owners. Their mutexes remain
// held across the native consumer, preventing a copied Close from retiring a
// signature snapshot or acknowledgement reader while it is being inspected.
func (w *ApplicationHTMLSendWorkV1) responseReportRequestOwnersV1() (*applicationBlockSignatureRequestV1, *applicationAcknowledgementRequestV1) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var b *applicationBlockSignatureRequestV1
	var a *applicationAcknowledgementRequestV1
	if w.blockSignature != nil {
		b = w.blockSignature.request
	}
	if w.acknowledgement != nil {
		a = w.acknowledgement.request
	}
	return b, a
}

// Caller holds the original bound package and mutation-request and Work mutexes.
// No caller UUID, cached remaining count or boolean grants response authority.
func (w *ApplicationHTMLSendWorkV1) responseReportFactsLockedV1(call context.Context, s *applicationPackageResponseRequestV1, after bool) bool {
	m := w.packageResponse
	if !w.valid(call) || s == nil || s.self != s || s.consumerClosed || s.closed || !s.bound || s.active <= 0 || s.ctx == nil || s.ctx.Err() != nil || s.grant == nil || s.reader == nil || w.stage == nil || w.stage.operation == nil || w.stage.operation.factory != s.factory || w.familyRoot != nil || w.sourceDocument == nil || w.sourceDocument.ParentEnvelopeID.Valid || w.sourceDocument.ID != s.scope.document || w.sourceDocument.OrgID != s.scope.org || m == nil || m.request != s || m.done || !m.validated || m.recorded != after || m.retryMatched || w.responseReportAttempted {
		return false
	}
	if s.kind == "signed" {
		b := w.blockSignature
		return w.stage.purpose == HTMLBlockSignMutationV1 && w.sourceDocument.RequiresSignature && b != nil && b.request != nil && b.request.self == b.request && !b.request.closed && b.request.prepared && b.request.ctx != nil && b.request.ctx.Err() == nil && b.request.grant != nil && b.request.reader != nil && b.request.snapshot != nil && b.request.snapshot.document == s.scope.document && b.request.snapshot.org == s.scope.org && b.request.snapshot.recipient == s.scope.recipient && b.rolesAttempted && len(b.roles) > 0 && b.recipient != nil && b.recipient.ID == s.scope.recipient && (!after || (b.marked && b.signature != nil && b.signature.ID != uuid.Nil && b.signature.DocumentID == s.scope.document && b.signature.RecipientID == s.scope.recipient))
	}
	if s.kind == "accepted" {
		a := w.acknowledgement
		return w.stage.purpose == HTMLAcknowledgementMutationV1 && !w.sourceDocument.RequiresSignature && a != nil && a.request != nil && a.request.self == a.request && !a.request.consumerClosed && !a.request.closed && a.request.bound && a.request.active > 0 && a.request.ctx != nil && a.request.ctx.Err() == nil && a.request.grant != nil && a.request.reader != nil && a.request.factory == s.factory && !a.done && a.request.document == s.scope.document && a.request.org == s.scope.org && a.request.recipient == s.scope.recipient && a.recipient != nil && a.recipient.ID == s.scope.recipient && (!after || (a.marked && a.counted))
	}
	return false
}

// Acquire all actual family locks ROOT FIRST, before the response mutation and
// org-audit append. Sign has already read its genuine role family; acceptance
// obtains the same original family here. No child can append a comment between
// the final readiness/capacity read and its same-transaction family freeze.
func (w *ApplicationHTMLSendWorkV1) PrepareResponseReportFamilyV1(call context.Context) error {
	s := w.packageResponseRequestV1()
	if s == nil {
		return ErrHTMLSendWorkV1
	}
	b, a := w.responseReportRequestOwnersV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	if a != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	w.mu.Lock()
	if !w.responseReportFactsLockedV1(call, s, false) || w.responseReportFamilyPrepared || (w.sourceDocument.Status != "sent" && w.sourceDocument.Status != "in_progress") {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	envelope, attempted := w.sourceDocument.IsEnvelope, w.familyMembersAttempted
	w.mu.Unlock()
	if envelope && !attempted {
		if _, err := w.ReadEnvelopeMembersV1(call); err != nil {
			return err
		}
	}
	w.mu.Lock()
	members := w.familyMembers
	if envelope && (!w.familyMembersAttempted || len(members) == 0) {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	w.mu.Unlock()
	for _, member := range members {
		if member == nil {
			return ErrHTMLSendWorkV1
		}
		member.mu.Lock()
		read := member.modelsRead
		member.mu.Unlock()
		if !read {
			if _, err := member.ReadModelsV1(call); err != nil {
				return err
			}
		}
		member.mu.Lock()
		d := member.sourceDocument
		valid := member.valid(call) && member.familyRoot == w && d != nil && !d.IsEnvelope && d.OrgID == s.scope.org && d.ParentEnvelopeID.Valid && uuid.UUID(d.ParentEnvelopeID.Bytes) == s.scope.document && (d.Status == "sent" || d.Status == "in_progress")
		member.mu.Unlock()
		if !valid {
			return ErrHTMLSendWorkV1
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.responseReportFactsLockedV1(call, s, false) {
		return ErrHTMLSendWorkV1
	}
	w.responseReportFamilyPrepared = true
	return nil
}

// Fresh independently funded typed rows; never reuse the pre-mutation cached
// recipient status or let new views retire an older consumer's source loans.
// Caller holds Work.mu and the real callback/request borrower remains live.
func (w *ApplicationHTMLSendWorkV1) responseReportRowsLockedV1(call context.Context) ([]*generated.Recipient, []*generated.DocumentField, error) {
	h, err := w.collectionHeaderAndPinsV1(call, htmlSendRecipientCollectionV1)
	if err != nil {
		return nil, nil, err
	}
	recs, err := w.listCollectionRecipientsForPurposeV1(call, h)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(recs)) != h.RecipientCount {
		return nil, nil, ErrHTMLSendWorkV1
	}
	raw := int64(0)
	for _, r := range recs {
		if r == nil || r.DocumentID != w.logicalDocumentV1() {
			return nil, nil, ErrHTMLSendWorkV1
		}
		n, err := htmlAuthoringSumV1(int64(len(r.Role)), int64(len(r.Email)), int64(len(r.Name)), int64(len(r.Status)), int64(len(r.Locale)), int64(len(r.DeclinedReason.String)), int64(len(r.MagicTokenHash)))
		if err != nil || !htmlInputAddV1(&raw, n, 1) {
			return nil, nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.RecipientRawBytes {
		return nil, nil, ErrHTMLSendWorkV1
	}
	h, err = w.collectionHeaderAndPinsV1(call, htmlSendFieldCollectionV1)
	if err != nil {
		return nil, nil, err
	}
	fields, err := w.listCollectionFieldsForPurposeV1(call, h)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(fields)) != h.FieldCount {
		return nil, nil, ErrHTMLSendWorkV1
	}
	raw, wire := int64(0), int64(0)
	for _, f := range fields {
		if f == nil || f.DocumentID != w.logicalDocumentV1() {
			return nil, nil, ErrHTMLSendWorkV1
		}
		n, err := htmlAuthoringSumV1(int64(len(f.Type)), int64(len(f.Label.String)), int64(len(f.Value.String)))
		if err != nil || !htmlInputAddV1(&raw, n, 1) || !htmlInputAddV1(&wire, int64(len(f.OptionsJson)), 1) {
			return nil, nil, ErrHTMLSendWorkV1
		}
	}
	if raw != h.FieldRawBytes || wire != h.FieldOptionsWireBytes {
		return nil, nil, ErrHTMLSendWorkV1
	}
	return recs, fields, nil
}

// Readiness comes from actual roles and fresh original rows, not the adapter's
// earlier CountRemaining. Pending responses still receive capacity admission.
func (w *ApplicationHTMLSendWorkV1) responseReportReadyLockedV1(call context.Context, recs []*generated.Recipient) (bool, error) {
	if !w.valid(call) || w.packageResponse == nil || w.packageResponse.request == nil {
		return false, ErrHTMLSendWorkV1
	}
	var roles []string
	if w.blockSignature != nil {
		roles = w.blockSignature.roles
	}
	return responseReportRecipientsReadyV1(w.packageResponse.request.kind, roles, recs)
}

// Pure readiness comparison only: this function issues no authority. Its sole
// production caller supplies the freshly measured original native row graph.
func responseReportRecipientsReadyV1(kind string, roles []string, recs []*generated.Recipient) (bool, error) {
	for _, r := range recs {
		if r == nil {
			return false, ErrHTMLSendWorkV1
		}
	}
	if kind == "accepted" {
		found, ready := false, true
		for _, r := range recs {
			if r.Role != "cc" {
				found = true
				ready = ready && r.Status == "accepted"
			}
		}
		if !found {
			return false, ErrHTMLSendWorkV1
		}
		return ready, nil
	}
	if kind != "signed" || len(roles) == 0 {
		return false, ErrHTMLSendWorkV1
	}
	// Allocation-free comparison also handles duplicate recipients per role:
	// every recipient for a required role must have actually signed.
	ready := true
	for _, role := range roles {
		found := false
		for _, r := range recs {
			if r.Role == role {
				found = true
				ready = ready && r.Status == "signed"
			}
		}
		if !found {
			return false, ErrHTMLSendWorkV1
		}
	}
	return ready, nil
}

func (w *ApplicationHTMLSendWorkV1) responseReportSourceV1(call context.Context) (*ApplicationHTMLSendSourceV1, error) {
	w.mu.Lock()
	if !w.valid(call) {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	state, started := w.sourceState, w.sourceStarted
	w.mu.Unlock()
	if state != nil {
		return &ApplicationHTMLSendSourceV1{state: state}, nil
	}
	if started {
		return nil, ErrHTMLSendWorkV1
	}
	return w.NewSourceV1(call)
}

func (w *ApplicationHTMLSendWorkV1) validateResponsePDFReadyV1(call context.Context, recs []*generated.Recipient, fields []*generated.DocumentField, sigs []*generated.Signature) error {
	source, err := w.responseReportSourceV1(call)
	if err != nil {
		return err
	}
	s := source.state
	if s == nil || !s.lockV1() {
		return ErrHTMLSendWorkV1
	}
	defer s.unlockV1()
	if s.closeRequested.Load() || s.owner == nil {
		return ErrHTMLSendWorkV1
	}
	owner := s.owner
	if err = owner.beginV1(); err != nil {
		return err
	}
	defer owner.finishV1()
	validation, err := s.prepareValidationV1()
	if err != nil {
		return err
	}
	if err = s.holdPolicyV1(); err != nil {
		return err
	}
	if err = owner.fieldOptionsComponentsV1(fields); err != nil {
		return err
	}
	return pdflayout.ValidateSignatureRowsPreparedHTMLV1(owner.snapshot.document, recs, fields, sigs, 0, validation)
}

// Complete actual unsigned-payload admission occurs after the real response
// audit and optional immutable package receipt, before their COMMIT. A refusal
// rolls back those SQL effects; the external signature-object PUT has its own
// existing lifecycle and is deliberately not claimed to be rolled back.
// This is NOT a promise of headroom after a partial response: later writers
// still require separate growth admission. The final response atomically
// freezes the locked family against native interaction writes. Generic late
// audit writers and all-writer growth admission remain a separate open boundary.
func (w *ApplicationHTMLSendWorkV1) AdmitResponseReportV1(call context.Context, audit *ApplicationHTMLAuditEventConsumerV1) error {
	s := w.packageResponseRequestV1()
	if s == nil || audit == nil || audit.self != audit {
		return ErrHTMLSendWorkV1
	}
	b, a := w.responseReportRequestOwnersV1()
	s.mu.Lock()
	defer s.mu.Unlock()
	if b != nil {
		b.mu.Lock()
		defer b.mu.Unlock()
	}
	if a != nil {
		a.mu.Lock()
		defer a.mu.Unlock()
	}
	w.mu.Lock()
	if !w.responseReportFactsLockedV1(call, s, true) || !w.responseReportFamilyPrepared || w.sourceDocument.Status != "in_progress" {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	audit.mu.Lock()
	purpose, kind := HTMLAuditBlockSignedV1, "document.signed"
	if s.kind == "accepted" {
		purpose, kind = HTMLAuditAcknowledgedV1, "document.accepted"
	}
	if w.packageResponse.present {
		purpose = HTMLAuditPackageSignedV1
		if s.kind == "accepted" {
			purpose = HTMLAuditPackageAcknowledgedV1
		}
	}
	if audit.closed || audit.session != w.session || audit.purpose != purpose || audit.org != s.scope.org || audit.document != s.scope.document || !audit.recipient.Valid || uuid.UUID(audit.recipient.Bytes) != s.scope.recipient || audit.actor.Valid || audit.kind != kind || !audit.used || !audit.attempted || audit.eventID == uuid.Nil {
		audit.mu.Unlock()
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	// Keep this original audit consumer alive until all event/head consumers
	// have joined. The normal publisher runs only after the transaction commits.
	defer audit.mu.Unlock()
	w.responseReportAttempted = true
	fixed := int64(65536) + 4*int64(unsafe.Sizeof(applicationHistoricalFinalizationV1{})) + 4*int64(unsafe.Sizeof(applicationHistoricalCertificateReadV1{})) + historicalCertificateClaimsOutputResourcesV1()
	closeFixed, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, 0)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	w.closes = append(w.closes, closeFixed)
	recs, fields, err := w.responseReportRowsLockedV1(call)
	if err != nil {
		w.mu.Unlock()
		return err
	}
	responded := false
	for _, r := range recs {
		if r.ID == s.scope.recipient {
			responded = (s.kind == "signed" && r.Status == "signed") || (s.kind == "accepted" && r.Status == "accepted")
		}
	}
	if !responded {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	signatures := &applicationHistoricalFinalizationV1{}
	if _, err = w.readFinalizationSignaturesLockedV1(call, signatures); err != nil {
		w.mu.Unlock()
		return err
	}
	ready, err := w.responseReportReadyLockedV1(call, recs)
	before, members := w.sourceDocument, w.familyMembers
	memberResources := int64(0)
	if !htmlInputAddV1(&memberResources, int64(len(members)), 8*int64(unsafe.Sizeof(bool(false)))) {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	closeMemberBorrows, borrowErr := w.actor.acquireOwnedRetainedBodyV1(call, memberResources, 0)
	if borrowErr != nil {
		w.mu.Unlock()
		return borrowErr
	}
	w.closes = append(w.closes, closeMemberBorrows)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	// Root's bound-request borrower retains its registry, but a copied root
	// Close also requests every child's close. Keep EACH actual child's body
	// until snapshot hashing, manifest formatting and payload sizing join.
	borrowed := make([]bool, len(members))
	defer func() {
		for i, m := range members {
			if !borrowed[i] {
				continue
			}
			m.mu.Lock()
			m.sourceBorrowers--
			closes, actor := m.retireSourcesLockedV1()
			m.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			m.releaseFamilyRootIfRetiredV1()
		}
	}()
	for i, m := range members {
		if m == nil {
			return ErrHTMLSendWorkV1
		}
		m.mu.Lock()
		if !m.valid(call) || m.familyRoot != w || m.sourceDocument == nil {
			m.mu.Unlock()
			return ErrHTMLSendWorkV1
		}
		m.sourceBorrowers++
		borrowed[i] = true
		m.mu.Unlock()
	}
	if ready && before.RequiresSignature && before.SourceKind == "pdf" {
		if err = w.validateResponsePDFReadyV1(call, recs, fields, signatures.signatures); err != nil {
			return err
		}
	}
	doc := before
	var frozen []*generated.Document
	if ready {
		doc, frozen, err = w.beginHistoricalFinalizingRowsV1(call, before, members)
		if err != nil {
			return err
		}
	}
	w.mu.Lock()
	if !w.valid(call) || w.sourceDocument != before {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	clock, err := w.queries.GetResponseReportClockV1(call, generated.GetResponseReportClockV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		w.mu.Unlock()
		return err
	}
	if clock == nil || clock.DocumentID != doc.ID || clock.OrgID != doc.OrgID || clock.SourceUpdatedAt != doc.UpdatedAt || !applicationStampV1(clock.Cutoff) {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	cutoff := clock.Cutoff
	if ready {
		// The freeze SQL's family high-water covers all report producers. Use
		// its exact original returned clock, never the later clock_timestamp().
		cutoff = doc.UpdatedAt
	}
	projection := &applicationHistoricalCertificateReadV1{}
	// Legacy source-VersionId pinning can later advance root.updated_at even
	// though this genuine family freeze has closed native interaction writes.
	// Reserve its encoding on every sizing projection, while selecting all rows
	// using only the actual original cutoff above.
	if err = w.projectParticipantReportForSizingLockedV1(call, cutoff, projection, true, doc); err != nil {
		w.mu.Unlock()
		return err
	}
	claims, err := w.responseSizingClaimsLockedV1(call, doc, projection)
	w.mu.Unlock()
	if err != nil {
		return err
	}
	manifestHTML, err := w.responseSizingManifestV1(call, doc, members, frozen)
	if err != nil {
		return err
	}
	return w.measureResponsePayloadV1(call, doc, recs, fields, signatures.signatures, projection, claims, manifestHTML, ready)
}

// Actual root event/header comparison prevents an org-filtered family query
// from silently omitting an inconsistent event that the final reader rejects.
func (w *ApplicationHTMLSendWorkV1) responseSizingClaimsLockedV1(call context.Context, doc *generated.Document, p *applicationHistoricalCertificateReadV1) (render.CertificateEvidenceClaimsV1, error) {
	var empty render.CertificateEvidenceClaimsV1
	h, err := w.queries.GetHistoricalFinalizationCertificateEventReadHeaderV1(call, generated.GetHistoricalFinalizationCertificateEventReadHeaderV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return empty, err
	}
	if h == nil || h.DocumentID != doc.ID || h.OrgID != doc.OrgID || h.UpdatedAt != doc.UpdatedAt || h.EventCount < 0 || h.RawBytes < 0 || h.PayloadWireBytes < 0 || h.MissingSizeCount != 0 || h.ServerMismatchCount != 0 {
		return empty, ErrHTMLSendWorkV1
	}
	if h.EventCount > render.MaxCertificateDocumentEventsV1 {
		return empty, ErrParticipantReportCapacityV1
	}
	resource := int64(16384)
	if !htmlInputAddV1(&resource, h.EventCount, 16*int64(unsafe.Sizeof((*generated.Event)(nil)))+128) {
		return empty, ErrHTMLSendWorkV1
	}
	closeEvents, err := w.actor.acquireOwnedRetainedBodyV1(call, resource, 0)
	if err != nil {
		return empty, err
	}
	w.closes = append(w.closes, closeEvents)
	events := make([]*generated.Event, 0, h.EventCount)
	raw, wire := int64(0), int64(0)
	for _, e := range p.reportEvents {
		if e == nil || !e.DocumentID.Valid || uuid.UUID(e.DocumentID.Bytes) != doc.ID {
			continue
		}
		if e.OrgID != doc.OrgID {
			return empty, ErrHTMLSendWorkV1
		}
		n, err := historicalCertificateEventRawV1(e)
		if err != nil || !htmlInputAddV1(&raw, n, 1) || !htmlInputAddV1(&wire, int64(len(e.PayloadJson)), 1) {
			return empty, ErrHTMLSendWorkV1
		}
		events = append(events, e)
	}
	if int64(len(events)) != h.EventCount || raw != h.RawBytes || wire != h.PayloadWireBytes {
		return empty, ErrHTMLSendWorkV1
	}
	eventSHA, _, err := render.CertificateDocumentEventsCommitmentV1(events)
	if err != nil {
		return empty, err
	}
	head, err := w.queries.GetHistoricalFinalizationCertificateChainHeadHeaderV1(call, generated.GetHistoricalFinalizationCertificateChainHeadHeaderV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return empty, err
	}
	if head == nil || head.OrgID != doc.OrgID || head.EventID == uuid.Nil || head.RowHashBytes != sha256.Size || !applicationStampV1(head.CreatedAt) {
		return empty, ErrHTMLSendWorkV1
	}
	row, err := w.queries.ReadHistoricalFinalizationCertificateChainHeadV1(call, generated.ReadHistoricalFinalizationCertificateChainHeadV1Params{EventID: head.EventID, OrgID: doc.OrgID, ExpectedCreatedAt: head.CreatedAt, ExpectedRowHashBytes: head.RowHashBytes})
	if err != nil {
		return empty, err
	}
	if row == nil || row.CreatedAt != head.CreatedAt || len(row.RowHash) != sha256.Size {
		return empty, ErrHTMLSendWorkV1
	}
	nameSHA := sha256.Sum256([]byte(doc.Name))
	// Sizing-only value. In particular the reserved final-PDF hex is NOT passed
	// to NewCertificateEvidenceClaimsV1 and cannot authorize any certificate.
	// Other-document appends can advance the organization head before the later
	// certificate read. The actual head was validated above; only formatter width
	// is reserved here. The event count similarly reserves the existing cap's
	// decimal width without raising that cap or inventing event evidence.
	return render.CertificateEvidenceClaimsV1{DocumentID: doc.ID.String(), OrgID: doc.OrgID.String(), DocumentNameSHA256: hex.EncodeToString(nameSHA[:]), FinalPDFSHA256: responseCertificateSizingDigestV1, PreFinalChainHeadSHA256: hex.EncodeToString(row.RowHash), PreFinalChainHeadCreatedAt: responseCertificateSizingTimestampV1, PreFinalChainScope: "organization", DocumentEventsSHA256: eventSHA, DocumentEventsCount: render.MaxCertificateDocumentEventsV1, DocumentEventsScope: "ceremony-root", ParticipantReportSchema: p.reportSchema, ParticipantReportSHA256: p.reportSHA256, ParticipantReportRows: p.reportRows, ParticipantReportHTML: p.reportHTML}, nil
}

func (w *ApplicationHTMLSendWorkV1) responseSizingManifestV1(call context.Context, doc *generated.Document, members []*ApplicationHTMLSendWorkV1, frozen []*generated.Document) (*string, error) {
	if !doc.IsEnvelope {
		if len(members) != 0 || len(frozen) != 0 {
			return nil, ErrHTMLSendWorkV1
		}
		return nil, nil
	}
	resource := int64(65536)
	if !htmlInputAddV1(&resource, int64(len(members)), 8192+8*int64(unsafe.Sizeof(generated.Document{}))) || !htmlInputAddV1(&resource, int64(len(doc.Name)), 64) {
		return nil, ErrHTMLSendWorkV1
	}
	for _, m := range members {
		m.mu.Lock()
		d := m.sourceDocument
		valid := m.valid(call) && m.familyRoot == w && d != nil && d.SourceKind == "blocks"
		if valid {
			valid = htmlInputAddV1(&resource, int64(len(d.Name)), 64)
		}
		m.mu.Unlock()
		if !valid {
			return nil, ErrHTMLSendWorkV1
		}
	}
	w.mu.Lock()
	if !w.valid(call) {
		w.mu.Unlock()
		return nil, ErrHTMLSendWorkV1
	}
	closeManifest, err := w.actor.acquireOwnedRetainedBodyV1(call, resource, 0)
	if err == nil {
		w.closes = append(w.closes, closeManifest)
	}
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	children, snapshots := make([]*generated.Document, len(members)), make([]string, len(members))
	for i, m := range members {
		source, err := m.responseReportSourceV1(call)
		if err != nil {
			return nil, err
		}
		if err = source.prepareHistoricalManifestTreeV1(); err != nil {
			return nil, err
		}
		m.mu.Lock()
		d := m.sourceDocument
		if !m.valid(call) || m.familyRoot != w || d == nil || d.SourceKind != "blocks" {
			m.mu.Unlock()
			return nil, ErrHTMLSendWorkV1
		}
		// The real source owner funded and parsed this exact immutable content.
		snapshots[i] = envelopes.FrozenContentSnapshotDigestV1(d)
		copy := *d
		m.mu.Unlock()
		if len(frozen) != 0 {
			index := -1
			for j, f := range frozen {
				if f != nil && f.ID == copy.ID {
					index = j
				}
			}
			if index < 0 {
				return nil, ErrHTMLSendWorkV1
			}
			children[i] = frozen[index]
		} else {
			// Formatter-only projection for a pending response, never a returned
			// DB row or native frozen-family proof.
			copy.Status = "finalizing"
			children[i] = &copy
		}
	}
	manifest, err := envelopes.BuildTerminalManifestFromSnapshotsV1(doc, children, snapshots)
	if err != nil {
		return nil, err
	}
	section := manifest.HTMLSection()
	if section == "" {
		return nil, ErrHTMLSendWorkV1
	}
	return &section, nil
}

func (w *ApplicationHTMLSendWorkV1) measureResponsePayloadV1(call context.Context, doc *generated.Document, recs []*generated.Recipient, fields []*generated.DocumentField, sigs []*generated.Signature, p *applicationHistoricalCertificateReadV1, claims render.CertificateEvidenceClaimsV1, manifest *string, ready bool) error {
	resource := int64(65536) + historicalCertificateClaimsOutputResourcesV1()
	if !htmlInputAddV1(&resource, int64(len(p.reportHTML)), 8) || !htmlInputAddV1(&resource, int64(len(doc.Name)), 48) || !htmlInputAddV1(&resource, int64(len(recs)+len(sigs)), 4096) || (p.reportSchema == render.ParticipantReportSchemaV1 && !htmlInputAddV1(&resource, int64(len(doc.MetadataRedactionReport)), 8192)) {
		return ErrHTMLSendWorkV1
	}
	if (p.reportSchema == render.ParticipantReportSchemaV2 || p.reportSchema == render.ParticipantReportSchemaV3) && !participantReportParserQuoteV2(&resource, len(p.reportHTML), p.reportRows) {
		return ErrHTMLSendWorkV1
	}
	for _, r := range recs {
		for _, text := range []string{r.Role, r.Name, r.Email, r.Status} {
			if !htmlInputAddV1(&resource, int64(len(text)), 48) {
				return ErrHTMLSendWorkV1
			}
		}
	}
	for _, s := range sigs {
		if !htmlInputAddV1(&resource, int64(len(s.Font)), 48) || !htmlInputAddV1(&resource, int64(len(s.ImageSha256)), 16) {
			return ErrHTMLSendWorkV1
		}
	}
	for _, f := range fields {
		if !htmlInputAddV1(&resource, 1, 4096) || !htmlInputAddV1(&resource, int64(len(f.Type)+len(f.Label.String)+len(f.Value.String)), 48) {
			return ErrHTMLSendWorkV1
		}
	}
	if manifest != nil && !htmlInputAddV1(&resource, int64(len(*manifest)), 8) {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	if !w.valid(call) || !w.responseReportAttempted {
		w.mu.Unlock()
		return ErrHTMLSendWorkV1
	}
	closeFormatter, err := w.actor.acquireOwnedRetainedBodyV1(call, resource, 0)
	if err == nil {
		w.closes = append(w.closes, closeFormatter)
	}
	w.mu.Unlock()
	if err != nil {
		return err
	}
	// No native claims constructor sees this sizing-only shallow projection.
	// Source bodies stay owned by their real Work until callback retirement.
	copy := *doc
	if !ready {
		clock, err := time.Parse(time.RFC3339Nano, responseCertificateSizingTimestampV1)
		if err != nil {
			return err
		}
		copy.CompletionEffectiveAtBound = true
		copy.CompletionEffectiveAt = pgtype.Timestamptz{Time: clock, Valid: true}
	}
	if !copy.CompletionEffectiveAtBound || !applicationStampV1(copy.CompletionEffectiveAt) {
		return ErrHTMLSendWorkV1
	}
	claims.CompletionEffectiveAt = copy.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)
	claims.ParticipantReportCutoff = responseCertificateSizingTimestampV1
	prefix, err := render.CertificatePrefixV1(&copy, recs, sigs, claims)
	if err != nil {
		return err
	}
	switch p.reportSchema {
	case render.ParticipantReportSchemaV1:
		_, err = render.CertificatePayloadV1(prefix, &copy, fields, claims, manifest)
	case render.ParticipantReportSchemaV2, render.ParticipantReportSchemaV3:
		_, err = render.CertificatePayloadV2(prefix, &copy, fields, claims, manifest)
	default:
		return ErrHTMLSendWorkV1
	}
	if errors.Is(err, render.ErrCertificatePayloadCapacityV1) {
		return ErrParticipantReportCapacityV1
	}
	if err != nil {
		return fmt.Errorf("response report payload: %w", err)
	}
	return nil
}
