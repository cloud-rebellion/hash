// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This purpose grants no public mutation API. Only a genuine registered batch's
// private current slot can enter the fixed retention program below.
const htmlSendPackageRetentionPurposeV1 HTMLSendSQLPurposeV1 = HTMLSignerFieldListReadV1 + 1

var ErrHTMLSendPackageRetentionV1 = errors.New("pdfadmission: exact package retention unavailable")

type HTMLSendPackageRetentionObservationV1 struct {
	Attempt           HTMLSendPackageAttemptObservationV1
	RetentionVerified bool
}

type applicationPackageSendRetentionMemberV1 struct {
	document     uuid.UUID
	key, version string
	digest       [32]byte
	bytes        int64
	pages        int32
	verified     bool
}

// The private plan owns its copied descriptors independently of short SQL
// phases and per-call provider receipts. It accepts no caller pins or costs.
type applicationPackageSendRetentionPlanV1 struct {
	batch                    *applicationPackageSendRecoveryBatchStateV1
	entry                    applicationPackageSendRecoveryEntryV1
	ctx                      context.Context
	client                   *storage.Client
	coordinator              *workguard.CoordinatorV1
	grant                    *workguard.GrantV1
	provider                 *storage.PackagePDFLocalRetentionV1
	completion               *PackageSendCompletionConfigV1
	namespace                [32]byte
	observation              HTMLSendPackageAttemptObservationV1
	current                  HTMLSendPackageAttemptObservationV1
	main                     documentpackage.MemberV1
	members                  [documentpackage.MaxAnnexesV1 + 1]applicationPackageSendRetentionMemberV1
	count                    int
	loaded                   bool
	effectStatus             string
	effectVerified           bool
	pendingAudits            []applicationPackageSendPendingAuditV1
	pendingAuditCount        int
	completionControls       *workguard.GrantV1
	completionRecipientCount int
}

// WithNextRetentionV1 consumes one actual private queue slot. It can establish
// retention only; it never sends invitations, signs, finalizes or replays Send.
// A terminal race is delivered as historical observation without a new receipt.
func (h *ApplicationPackageSendRecoveryBatchV1) WithNextRetentionV1(client *storage.Client, fn func(HTMLSendPackageRetentionObservationV1) error) (more bool, failure error) {
	if fn == nil {
		return false, ErrHTMLSendPackageRetentionV1
	}
	return h.withNextPackageSendV1(client, nil, func(o HTMLSendPackageSendObservationV1) error {
		return fn(HTMLSendPackageRetentionObservationV1{Attempt: o.Attempt, RetentionVerified: o.RetentionVerified})
	})
}

func (h *ApplicationPackageSendRecoveryBatchV1) withNextPackageSendV1(client *storage.Client, completion *PackageSendCompletionConfigV1, fn func(HTMLSendPackageSendObservationV1) error) (more bool, failure error) {
	if h == nil || h.state == nil || client == nil || fn == nil {
		return false, ErrHTMLSendPackageRetentionV1
	}
	s := h.state
	if !s.registeredV1() {
		return false, ErrHTMLSendPackageRetentionV1
	}
	s.mu.Lock()
	if s.closed || s.released || s.active || !s.resolved || s.operation != nil || s.retention != nil || s.ctx == nil || s.ctx.Err() != nil || s.scan == nil || !s.scan.RetiredV1() {
		s.mu.Unlock()
		return false, ErrHTMLSendPackageRetentionV1
	}
	if s.next == s.count {
		s.mu.Unlock()
		return false, nil
	}
	entry := s.entries[s.next]
	s.next++
	s.cursor = PackageSendRecoveryCursorV1{CreatedAt: entry.createdAt.Time.UTC(), AttemptID: entry.attempt}
	s.active = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active = false
		s.mu.Unlock()
		s.reconcileV1(nil)
	}()
	call, cancel := context.WithTimeout(s.ctx, 2*time.Minute)
	defer cancel()
	f := s.factory.state
	f.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !f.closing && f.work != nil {
		coordinator = f.work.coordinator
	}
	f.mu.Unlock()
	if coordinator == nil {
		return true, ErrHTMLSendPackageRetentionV1
	}
	// Cover bounded canonical decoding, all scalar/wire rows, independent string
	// copies, result/state controls and every statement frame before allocation.
	// This is a logical live-memory envelope, not physical RSS retirement proof.
	fixed := 16*int64(documentpackage.MaxManifestBytesV1) + 32*int64(documentpackage.MaxAnnexesV1+1)*(2*int64(documentpackage.MaxObjectTextBytesV1)+256) + 8*int64(unsafe.Sizeof(applicationPackageSendRetentionPlanV1{})) + 16384
	if completion != nil {
		if e := htmlSendResolverAddV1(&fixed, int64(len(completion.PublicURL)+len(completion.OrgName)), 8); e != nil {
			return true, ErrHTMLSendPackageRetentionV1
		}
	}
	grant, err := coordinator.TryAcquireV1(call, entry.org, workguard.VectorV1{ParentBytes: fixed, DBStagingBytes: fixed})
	if err != nil {
		return true, ErrHTMLSendPackageRetentionV1
	}
	p := &applicationPackageSendRetentionPlanV1{batch: s, entry: entry, ctx: call, client: client, coordinator: coordinator, grant: grant}
	if completion != nil {
		owned := *completion
		owned.PublicURL, owned.OrgName = strings.Clone(completion.PublicURL), strings.Clone(completion.OrgName)
		p.completion = &owned
	}
	s.mu.Lock()
	s.retention = p
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		joined := s.operation == nil && s.retention == p && p.providerRetiredLockedV1()
		if joined {
			s.retention = nil
		}
		s.mu.Unlock()
		if joined {
			p.retireV1()
		}
	}()
	if err := p.phaseV1(p.loadV1); err != nil {
		return true, err
	}
	if p.observation.Outcome != HTMLSendPackageAttemptActiveV1 {
		if p.completion != nil {
			if err := p.completionPhaseV1(p.observeCompletionV1); err != nil {
				return true, err
			}
		}
		return true, p.deliverV1(fn, p.effectVerified && !p.observation.RetentionCompletedAt.IsZero())
	}
	if p.completion != nil {
		if err := p.completionPhaseV1(p.prepareOrAbortV1); err != nil {
			return true, err
		}
		if p.observation.Outcome != HTMLSendPackageAttemptActiveV1 {
			return true, p.deliverV1(fn, !p.observation.RetentionCompletedAt.IsZero())
		}
	}
	for i := 0; i < p.count; i++ {
		if p.members[i].verified {
			continue // An acknowledged same-namespace receipt is durable progress.
		}
		position := int16(i)
		// Each member's start and exact aggregate mirror are acknowledged together
		// before its first provider dispatch. Unknown COMMIT never dispatches.
		if err := p.phaseV1(func(ctx context.Context, w *ApplicationHTMLSendWorkV1) error { return p.startV1(ctx, w, position) }); err != nil {
			return true, err
		}
		if err := p.retainMemberV1(position); err != nil {
			return true, err
		}
	}
	if err := p.phaseV1(p.completeV1); err != nil {
		return true, err
	}
	if p.completion != nil {
		if err := p.completionPhaseV1(p.finalizeSendV1); err != nil {
			return true, err
		}
	}
	return true, p.deliverV1(fn, true)
}

func (p *applicationPackageSendRetentionPlanV1) retireV1() {
	p.closePendingAuditsV1()
	p.pendingAudits = nil
	if p.completionControls != nil {
		p.completionControls.Close()
		p.completionControls = nil
	}
	p.main = documentpackage.MemberV1{}
	p.completion = nil
	p.members = [documentpackage.MaxAnnexesV1 + 1]applicationPackageSendRetentionMemberV1{}
	p.client = nil
	if p.grant != nil {
		p.grant.Close()
		p.grant = nil
	}
}

// Called with the batch mutex held, after the active consumer has ended. A
// cancelled storage method may return before its concrete local I/O joins.
// Keep that actual receipt and this plan registered/funded until both join and
// its last consumer release are proven; context cancellation is not retirement.
func (p *applicationPackageSendRetentionPlanV1) providerRetiredLockedV1() bool {
	if p.provider == nil {
		return true
	}
	p.provider.CloseConsumerV1()
	if !p.provider.RetiredV1() {
		return false
	}
	p.provider = nil
	return true
}

func (p *applicationPackageSendRetentionPlanV1) deliverV1(fn func(HTMLSendPackageSendObservationV1) error, verified bool) error {
	p.batch.mu.Lock()
	live := !p.batch.closed && p.batch.ctx.Err() == nil && p.ctx.Err() == nil
	p.batch.mu.Unlock()
	if !live {
		return ErrHTMLSendPackageRetentionV1
	}
	return fn(HTMLSendPackageSendObservationV1{Attempt: p.observation, RetentionVerified: verified, CompletionVerified: p.effectVerified, Status: p.effectStatus})
}

// Every phase is a new native operation minted inside the same active private
// slot. It has ONE SQL stage: the existing16-stage legacy topology is unchanged.
// Both physical SQL and its actual Work consumer end before the next provider
// call. An unresolved close remains registered/funded in the batch/factory.
func (p *applicationPackageSendRetentionPlanV1) phaseV1(fn func(context.Context, *ApplicationHTMLSendWorkV1) error) (failure error) {
	return p.phasePurposeV1(htmlSendPackageRetentionPurposeV1, fn)
}
func (p *applicationPackageSendRetentionPlanV1) completionPhaseV1(fn func(context.Context, *ApplicationHTMLSendWorkV1) error) error {
	if p == nil || p.completion == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	return p.phasePurposeV1(HTMLSendCompletionV1, fn)
}
func (p *applicationPackageSendRetentionPlanV1) phasePurposeV1(purpose HTMLSendSQLPurposeV1, fn func(context.Context, *ApplicationHTMLSendWorkV1) error) (failure error) {
	if p == nil || p.batch == nil || p.ctx == nil || p.ctx.Err() != nil || fn == nil || !p.batch.registeredV1() {
		return ErrHTMLSendPackageRetentionV1
	}
	ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
	defer cancel()
	op, err := p.batch.factory.NewHTMLSendOperationV1(ctx, p.entry.org, p.entry.document)
	if op == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	p.batch.mu.Lock()
	valid := p.batch.active && !p.batch.closed && p.batch.operation == nil && p.batch.next > 0 && p.batch.entries[p.batch.next-1] == p.entry
	if valid {
		p.batch.operation = op
	}
	p.batch.mu.Unlock()
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(p.ctx), 5*time.Second)
		closeErr := op.CloseV1(cleanup)
		stop()
		p.batch.mu.Lock()
		if closeErr == nil && p.batch.operation == op {
			p.batch.operation = nil
		}
		p.batch.mu.Unlock()
		if closeErr != nil {
			failure = ErrHTMLSendPackageRetentionV1
		}
	}()
	if err != nil || !valid {
		return ErrHTMLSendPackageRetentionV1
	}
	stage, err := op.OpenSQLV1(purpose)
	if err != nil || stage == nil || stage.SessionV1() == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	session := stage.SessionV1()
	if _, err := session.NewAdmissionV1(stage.ContextV1()); err != nil {
		return ErrHTMLSendPackageRetentionV1
	}
	var acknowledged HTMLSendPackageAttemptObservationV1
	err = stage.WithTxV1(func(call context.Context, _ generated.DBTX) error {
		w, e := session.NewHTMLSendWorkV1(call, stage)
		if e != nil {
			return e
		}
		if _, e = w.StateV1(call); e != nil {
			return e
		}
		scope := applicationPackageSendRecoveryWorkScopeV1{batch: p.batch, operation: op, entry: p.entry}
		observation, e := w.inspectDurablePackageSendAttemptV1(call, p.entry.attempt, &scope)
		if e != nil {
			return e
		}
		if p.loaded && !packageRetentionProgressV1(p.observation, observation) && (purpose != HTMLSendCompletionV1 || !packageSendTerminalProgressV1(p.observation, observation)) {
			return ErrHTMLSendPackageRetentionV1
		}
		if p.loaded && (observation.Outcome != HTMLSendPackageAttemptActiveV1 || w.state.BoundedStatus != "sealing") && purpose != HTMLSendCompletionV1 {
			return ErrHTMLSendPackageRetentionV1
		}
		if !p.loaded {
			p.observation = observation
		}
		p.current = observation
		if e = fn(call, w); e != nil {
			return e
		}
		row, e := w.queries.InspectDocumentPackageSendAttemptStateV1(call, generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document})
		if e != nil {
			return e
		}
		acknowledged, e = htmlSendPackageAttemptObservationV1(row, p.entry.attempt, observation.Capture)
		if e != nil || (!packageRetentionProgressV1(observation, acknowledged) && (purpose != HTMLSendCompletionV1 || !packageSendTerminalProgressV1(observation, acknowledged))) {
			return ErrHTMLSendPackageRetentionV1
		}
		return nil
	})
	if err == nil {
		err = session.CommitV1(stage.ContextV1())
	}
	if err == nil && purpose == HTMLSendCompletionV1 {
		err = p.publishPendingAuditsV1()
	}
	err = errors.Join(err, stage.CloseSQLV1())
	if err != nil || session.CommitUnknownV1() || !session.RetiredV1() {
		// Raw SQL/provider errors never escape their paid producer lifetime.
		return ErrHTMLSendPackageRetentionV1
	}
	p.observation = acknowledged
	return nil
}

func packageRetentionProgressV1(before, after HTMLSendPackageAttemptObservationV1) bool {
	if (!before.RetentionStartedAt.IsZero() && !before.RetentionStartedAt.Equal(after.RetentionStartedAt)) || (!before.RetentionCompletedAt.IsZero() && !before.RetentionCompletedAt.Equal(after.RetentionCompletedAt)) || !before.TerminalAt.Equal(after.TerminalAt) {
		return false
	}
	before.RetentionStartedAt, before.RetentionCompletedAt = time.Time{}, time.Time{}
	after.RetentionStartedAt, after.RetentionCompletedAt = time.Time{}, time.Time{}
	return before == after
}

func (p *applicationPackageSendRetentionPlanV1) memberParamsV1() generated.ListDocumentPackageSendRetentionMembersV1Params {
	c := p.observation.Capture
	return generated.ListDocumentPackageSendRetentionMembersV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, PackageID: c.PackageID, CaptureRevision: c.Revision, ExpectedMemberCount: c.MemberCount, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]}
}

func (p *applicationPackageSendRetentionPlanV1) loadV1(ctx context.Context, w *ApplicationHTMLSendWorkV1) error {
	if p.observation.Outcome != HTMLSendPackageAttemptActiveV1 {
		return nil
	}
	if w.state.BoundedStatus != "sealing" {
		return ErrHTMLSendPackageRetentionV1
	}
	namespace, err := p.client.PackageEvidenceNamespaceV1()
	if err != nil || namespace == ([32]byte{}) {
		return ErrHTMLSendPackageRetentionV1
	}
	p.namespace = namespace
	c := p.observation.Capture
	raw, err := w.queries.GetDocumentPackageCapturePayloadV1(ctx, generated.GetDocumentPackageCapturePayloadV1Params{PackageID: c.PackageID, OrgID: c.OrgID, DocumentID: c.DocumentID, Revision: c.Revision, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], ExpectedManifestBytes: c.ManifestBytes})
	if err != nil {
		return err
	}
	capture, err := documentpackage.DecodeCaptureV1(raw, documentpackage.CaptureHeaderV1{Binding: documentpackage.BindingV1{OrgID: c.OrgID, DocumentID: c.DocumentID, PackageID: c.PackageID, Revision: c.Revision}, Guard: documentpackage.CaptureGuardV1{RootUpdatedAt: c.RootUpdatedAt, DraftGeneration: c.DraftGeneration, PreviousRevision: c.PreviousRevision}, ManifestBytes: c.ManifestBytes, MemberCount: c.MemberCount, PDFBytes: c.PDFBytes, PDFPages: c.PDFPages, CanonicalSHA256: hex.EncodeToString(c.CanonicalSHA256[:]), CommitmentSHA256: hex.EncodeToString(c.CommitmentSHA256[:])})
	if err != nil {
		return err
	}
	input := capture.Manifest().Input()
	p.main = input.Main
	rows, err := w.queries.ListDocumentPackageSendRetentionMembersV1(ctx, p.memberParamsV1())
	if err != nil || len(rows) != int(c.MemberCount) {
		return ErrHTMLSendPackageRetentionV1
	}
	for i, row := range rows {
		member := input.Main
		if i > 0 {
			member = input.Annexes[i-1]
		}
		if !p.rowValidV1(row, i, false) || row.MemberDocumentID != member.DocumentID || row.PdfKey != member.PDF.Key || row.PdfVersionID != member.PDF.VersionID || hex.EncodeToString(row.PdfSha256) != member.PDF.SHA256 || row.PdfBytes != member.PDF.Bytes || row.PdfPages != member.PDF.Pages {
			return ErrHTMLSendPackageRetentionV1
		}
		m := &p.members[i]
		m.document, m.key, m.version, m.bytes, m.pages = row.MemberDocumentID, strings.Clone(row.PdfKey), strings.Clone(row.PdfVersionID), row.PdfBytes, row.PdfPages
		copy(m.digest[:], row.PdfSha256)
		m.verified = row.VerifiedAt.Valid
	}
	p.count, p.loaded = len(rows), true
	return nil
}

func (p *applicationPackageSendRetentionPlanV1) rowValidV1(r *generated.ListDocumentPackageSendRetentionMembersV1Row, position int, complete bool) bool {
	c := p.observation.Capture
	if r == nil || r.AttemptID != p.entry.attempt || r.OrgID != p.entry.org || r.DocumentID != p.entry.document || r.PackageID != c.PackageID || r.CaptureRevision != c.Revision || r.MemberCount != c.MemberCount || r.MemberPosition != int16(position) || r.MemberDocumentID == uuid.Nil || len(r.PdfKey) == 0 || len(r.PdfKey) > documentpackage.MaxObjectTextBytesV1 || len(r.PdfVersionID) == 0 || len(r.PdfVersionID) > documentpackage.MaxObjectTextBytesV1 || len(r.PdfSha256) != 32 || r.PdfBytes < 1 || r.PdfBytes > documentpackage.MaxPDFBytesV1 || r.PdfPages < 1 || r.PdfPages > documentpackage.MaxPDFPagesV1 {
		return false
	}
	if !r.StartedAt.Valid {
		return !complete && len(r.ProviderNamespaceSha256) == 0 && !r.VerifiedAt.Valid && !r.ObservedMode.Valid && !r.ObservedRetainUntil.Valid && !r.VerifierProfile.Valid
	}
	if !applicationStampV1(r.StartedAt) || !bytes.Equal(r.ProviderNamespaceSha256, p.namespace[:]) {
		return false
	}
	if !r.VerifiedAt.Valid {
		return !complete && !r.ObservedMode.Valid && !r.ObservedRetainUntil.Valid && !r.VerifierProfile.Valid
	}
	return applicationStampV1(r.VerifiedAt) && r.ObservedMode.Valid && r.ObservedMode.String == "COMPLIANCE" && r.VerifierProfile.Valid && r.VerifierProfile.String == "s3-compliance-digest-v1" && applicationStampV1(r.ObservedRetainUntil) && !r.ObservedRetainUntil.Time.Before(p.observation.RetainUntil)
}

func (p *applicationPackageSendRetentionPlanV1) startV1(ctx context.Context, w *ApplicationHTMLSendWorkV1, position int16) error {
	c := p.observation.Capture
	before, err := w.queries.InspectDocumentPackageSendAttemptStateV1(ctx, generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document})
	if err != nil || before == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	if !before.RetentionStartedAt.Valid {
		if err := ValidateSendExpiryV1(w.state.ExpiresAt, time.Now()); err != nil {
			return ErrHTMLSendPackageRetentionV1
		}
	}
	intent, err := w.queries.MarkDocumentPackageMemberRetentionStartedV1(ctx, generated.MarkDocumentPackageMemberRetentionStartedV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if err != nil {
		// A previously completed aggregate is not per-member proof. Its immutable
		// started pair may still accept explicit member re-verification below.
		row, readErr := w.queries.InspectDocumentPackageSendAttemptStateV1(ctx, generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document})
		if readErr != nil || row == nil || !applicationStampV1(row.RetentionStartedAt) || !applicationStampV1(row.RetentionCompletedAt) || !applicationStampEqualV1(row.RetentionStartedAt, row.IntentRetentionStartedAt) || !applicationStampEqualV1(row.RetentionCompletedAt, row.IntentRetentionCompletedAt) {
			return ErrHTMLSendPackageRetentionV1
		}
	} else {
		if intent == nil || !applicationStampV1(intent.RetentionStartedAt) {
			return ErrHTMLSendPackageRetentionV1
		}
		if _, err = w.queries.SynchronizeDocumentPackageSendRetentionV1(ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]}); err != nil {
			return err
		}
	}
	row, err := w.queries.StartDocumentPackageSendMemberRetentionV1(ctx, generated.StartDocumentPackageSendMemberRetentionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], MemberPosition: position, ProviderNamespaceSha256: p.namespace[:]})
	if err != nil || !p.receiptValidV1(row, position, false) {
		return ErrHTMLSendPackageRetentionV1
	}
	return nil
}

func (p *applicationPackageSendRetentionPlanV1) receiptValidV1(r *generated.DocumentPackageSendMemberRetentionV1, position int16, complete bool) bool {
	if r == nil || r.AttemptID != p.entry.attempt || r.OrgID != p.entry.org || r.DocumentID != p.entry.document || r.MemberPosition != position || !bytes.Equal(r.ProviderNamespaceSha256, p.namespace[:]) || !applicationStampV1(r.StartedAt) {
		return false
	}
	if !r.VerifiedAt.Valid {
		return !complete && !r.ObservedMode.Valid && !r.ObservedRetainUntil.Valid && !r.VerifierProfile.Valid
	}
	return applicationStampV1(r.VerifiedAt) && r.ObservedMode.Valid && r.ObservedMode.String == "COMPLIANCE" && r.VerifierProfile.Valid && r.VerifierProfile.String == "s3-compliance-digest-v1" && applicationStampV1(r.ObservedRetainUntil) && !r.ObservedRetainUntil.Time.Before(p.observation.RetainUntil)
}

func (p *applicationPackageSendRetentionPlanV1) retainMemberV1(position int16) error {
	m := &p.members[position]
	owned, _, err := p.client.RetainPackagePDFLocalOwnedV1(p.ctx, m.key, m.version, m.digest[:], m.bytes, p.observation.RetainUntil, p.coordinator, p.entry.org)
	if owned != nil {
		p.batch.mu.Lock()
		p.provider = owned
		p.batch.mu.Unlock()
		defer func() {
			owned.CloseConsumerV1()
			p.batch.mu.Lock()
			if p.provider == owned && owned.RetiredV1() {
				p.provider = nil
			}
			p.batch.mu.Unlock()
		}()
	}
	if err != nil || owned == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	return owned.WithRetainedV1(func(observedUntil time.Time) error {
		if observedUntil.IsZero() || observedUntil.Before(p.observation.RetainUntil) {
			return ErrHTMLSendPackageRetentionV1
		}
		return p.phaseV1(func(ctx context.Context, w *ApplicationHTMLSendWorkV1) error {
			c := p.observation.Capture
			r, e := w.queries.ConfirmDocumentPackageSendMemberRetentionV1(ctx, generated.ConfirmDocumentPackageSendMemberRetentionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], MemberPosition: position, ProviderNamespaceSha256: p.namespace[:], ObservedRetainUntil: pgtype.Timestamptz{Time: observedUntil.UTC(), Valid: true}})
			if e != nil || !p.receiptValidV1(r, position, true) {
				return ErrHTMLSendPackageRetentionV1
			}
			return nil
		})
	})
}

func (p *applicationPackageSendRetentionPlanV1) completeV1(ctx context.Context, w *ApplicationHTMLSendWorkV1) error {
	rows, err := w.queries.ListDocumentPackageSendRetentionMembersV1(ctx, p.memberParamsV1())
	if err != nil || len(rows) != p.count {
		return ErrHTMLSendPackageRetentionV1
	}
	for i, row := range rows {
		m := &p.members[i]
		if !p.rowValidV1(row, i, true) || row.MemberDocumentID != m.document || row.PdfKey != m.key || row.PdfVersionID != m.version || !bytes.Equal(row.PdfSha256, m.digest[:]) || row.PdfBytes != m.bytes || row.PdfPages != m.pages {
			return ErrHTMLSendPackageRetentionV1
		}
	}
	c := p.observation.Capture
	if !p.observation.RetentionCompletedAt.IsZero() {
		return nil // Existing aggregate plus the complete exact ledger was checked.
	}
	// Another worker can acknowledge completion between our previous phase and
	// this root lock. Read this phase's actual pair, rather than incrementing the
	// attempt counter from stale last-acknowledged progress.
	current, err := w.queries.InspectDocumentPackageSendAttemptStateV1(ctx, generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document})
	if err != nil || current == nil {
		return ErrHTMLSendPackageRetentionV1
	}
	if current.RetentionCompletedAt.Valid {
		if !applicationStampV1(current.RetentionStartedAt) || !applicationStampV1(current.RetentionCompletedAt) || !applicationStampEqualV1(current.RetentionStartedAt, current.IntentRetentionStartedAt) || !applicationStampEqualV1(current.RetentionCompletedAt, current.IntentRetentionCompletedAt) {
			return ErrHTMLSendPackageRetentionV1
		}
		return nil
	}
	if _, err = w.queries.MarkDocumentPackageMemberRetentionCompleteV1(ctx, generated.MarkDocumentPackageMemberRetentionCompleteV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]}); err != nil {
		return err
	}
	a, err := w.queries.SynchronizeDocumentPackageSendRetentionV1(ctx, generated.SynchronizeDocumentPackageSendRetentionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if err != nil || a == nil || !applicationStampV1(a.RetentionStartedAt) || !applicationStampV1(a.RetentionCompletedAt) {
		return ErrHTMLSendPackageRetentionV1
	}
	return nil
}
