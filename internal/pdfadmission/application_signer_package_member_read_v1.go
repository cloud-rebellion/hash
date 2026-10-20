// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
)

type applicationSignerPackageMemberPinV1 struct {
	metadata                                          SignerPackageMemberPDFMetadataV1
	attempt, member                                   uuid.UUID
	key, version                                      string
	digest, namespace                                 [32]byte
	retainUntil, startedAt, verifiedAt, observedUntil time.Time
}

func (s *applicationSignerPackageMemberReadStateV1) finishV1() {
	s.mu.Lock()
	s.active--
	closed := s.closed
	s.mu.Unlock()
	if closed {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
		defer stop()
		_ = s.reconcileV1(cleanup)
	}
}

// This method has no caller SQL/policy/key callback. Both native phases derive
// authority again from the same concrete member input and original token scope.
func (w *ApplicationHTMLSendWorkV1) readSignerPackageMemberPinV1(call context.Context, s *applicationSignerPackageMemberReadStateV1) (pin applicationSignerPackageMemberPinV1, failure error) {
	if w == nil || w.self != w || s == nil || s.self != s {
		return pin, ErrSignerPackageMemberReadV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s.mu.Lock()
	valid := !s.closed && !s.retired && s.active == 1 && s.operation != nil && s.current == w.stage && s.ctx.Err() == nil
	op, scope, expected := s.operation, s.scope, s.expected
	s.mu.Unlock()
	if !valid || !w.valid(call) || w.state == nil || w.stage == nil || w.stage.purpose != HTMLSignerPackageReadV1 || w.stage.operation != op || op.packageMemberRead != s || op.packageReadScope != &s.scope || w.state.ID != scope.document || w.state.OrgID != scope.org {
		return pin, ErrSignerPackageMemberReadV1
	}
	p := s.factory.state
	p.mu.Lock()
	registered := p.signerPackageMemberReads[s.slot] == s && !p.closing
	p.mu.Unlock()
	if !registered {
		return pin, ErrSignerPackageMemberReadV1
	}
	now := time.Now()
	if !applicationStampEqualV1(w.state.SentAt, s.originalSentAt) || !applicationStampEqualV1(w.state.Article13NoticeEpochAt, s.originalNoticeEpoch) || !w.state.Article13NoticeEpochV61Committed || !w.state.HasSupportedArticle13NoticeSchema || !now.Before(s.originalTokenExpiry.Time) || (s.profile == signerPackageActiveProfileV1 && s.originalDocumentExpiry.Valid && !now.Before(s.originalDocumentExpiry.Time)) {
		return pin, ErrSignerReadCredentialV1
	}
	resolved, err := w.resolveSignerPackageCaptureForProfileLockedV1(call, scope, s.profile, s.completed)
	if err != nil {
		return pin, err
	}
	defer resolved.close()
	if !resolved.observation.PackagePresent || resolved.capture == nil {
		return pin, ErrSignerPackageMemberAbsentV1
	}
	c := resolved.observation.Capture
	if c.CanonicalSHA256 != expected.ManifestSHA256 || c.CommitmentSHA256 != expected.LegalCommitmentSHA256 {
		return pin, ErrSignerPackageMemberPreconditionV1
	}
	input := resolved.capture.Manifest().Input()
	if int(expected.Position) >= int(c.MemberCount) {
		return pin, ErrSignerPackageMemberAbsentV1
	}
	if input.Main.PDF.SHA256 != hex.EncodeToString(s.originalRootSHA[:]) {
		return pin, ErrSignerReadCredentialV1
	}
	namespace, err := s.client.PackageEvidenceNamespaceV1()
	if err != nil || namespace != s.namespace {
		return pin, ErrSignerPackageMemberReadV1
	}
	// Canonical capture bounds every variable key/version. Fund all18 possible
	// returned rows, actual wire overlap and typed copies before the SQL query.
	raw := int64(32768) + 18*(64*int64(documentpackage.MaxObjectTextBytesV1)+4096+8*int64(unsafe.Sizeof(generated.ListDocumentPackageSendRetentionMembersV1Row{})))
	wire := int64(18) * (2*int64(documentpackage.MaxObjectTextBytesV1) + 256)
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return pin, errors.Join(ErrSignerPackageMemberReadV1, err)
	}
	defer closeRows()
	rows, err := w.queries.ListDocumentPackageSendRetentionMembersV1(call, generated.ListDocumentPackageSendRetentionMembersV1Params{AttemptID: resolved.attempt.AttemptID, OrgID: c.OrgID, DocumentID: c.DocumentID, PackageID: c.PackageID, CaptureRevision: c.Revision, ExpectedMemberCount: c.MemberCount, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if err != nil {
		return pin, err
	}
	if len(rows) != int(c.MemberCount) {
		return pin, ErrSignerPackageMemberReadV1
	}
	for i, row := range rows {
		member := input.Main
		if i > 0 {
			member = input.Annexes[i-1]
		}
		if !signerPackageMemberReceiptV1(row, resolved.attempt, member, i, namespace) {
			return pin, ErrSignerPackageMemberReadV1
		}
		if i == int(expected.Position) {
			pin = applicationSignerPackageMemberPinV1{metadata: SignerPackageMemberPDFMetadataV1{Observation: resolved.observation, Position: expected.Position, PDFSHA256: strings.Clone(member.PDF.SHA256), PDFBytes: row.PdfBytes, PDFPages: row.PdfPages}, attempt: row.AttemptID, member: row.MemberDocumentID, key: strings.Clone(row.PdfKey), version: strings.Clone(row.PdfVersionID), namespace: namespace, retainUntil: resolved.attempt.RetainUntil.UTC(), startedAt: row.StartedAt.Time.UTC(), verifiedAt: row.VerifiedAt.Time.UTC(), observedUntil: row.ObservedRetainUntil.Time.UTC()}
			copy(pin.digest[:], row.PdfSha256)
		}
	}
	if pin.member == uuid.Nil || !w.valid(call) {
		return applicationSignerPackageMemberPinV1{}, ErrSignerPackageMemberReadV1
	}
	return pin, nil
}

func signerPackageMemberReceiptV1(r *generated.ListDocumentPackageSendRetentionMembersV1Row, a HTMLSendPackageAttemptObservationV1, m documentpackage.MemberV1, position int, namespace [32]byte) bool {
	c := a.Capture
	return r != nil && a.Outcome == HTMLSendPackageAttemptCompletedV1 && r.AttemptID == a.AttemptID && r.OrgID == c.OrgID && r.DocumentID == c.DocumentID && r.PackageID == c.PackageID && r.CaptureRevision == c.Revision && r.MemberCount == c.MemberCount && r.MemberPosition == int16(position) && r.MemberDocumentID == m.DocumentID && r.PdfKey == m.PDF.Key && r.PdfVersionID == m.PDF.VersionID && hex.EncodeToString(r.PdfSha256) == m.PDF.SHA256 && len(r.PdfSha256) == 32 && r.PdfBytes == m.PDF.Bytes && r.PdfPages == m.PDF.Pages && bytes.Equal(r.ProviderNamespaceSha256, namespace[:]) && applicationStampV1(r.StartedAt) && applicationStampV1(r.VerifiedAt) && r.ObservedMode.Valid && r.ObservedMode.String == "COMPLIANCE" && r.VerifierProfile.Valid && r.VerifierProfile.String == "s3-compliance-digest-v1" && applicationStampV1(r.ObservedRetainUntil) && !r.ObservedRetainUntil.Time.Before(a.RetainUntil)
}

func (s *applicationSignerPackageMemberReadStateV1) phaseV1(index int) (pin applicationSignerPackageMemberPinV1, failure error) {
	stage, err := s.operation.OpenSQLV1(HTMLSignerPackageReadV1)
	if err != nil {
		return pin, err
	}
	s.mu.Lock()
	s.current = stage
	s.phase = index
	s.mu.Unlock()
	call, session := stage.ContextV1(), stage.SessionV1()
	var admission *ApplicationAdmissionV1
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(s.ctx), 5*time.Second)
		defer stop()
		failure = errors.Join(failure, stage.closeSQLV1(cleanup))
		if session == nil || !session.RetiredV1() || session.CommitUnknownV1() {
			failure = errors.Join(failure, ErrApplicationSessionUnknownV1)
		}
		s.operation.mu.Lock()
		work := stage.work
		s.operation.mu.Unlock()
		if work != nil {
			work.CloseConsumerV1()
		}
		// Only this finished stage's sources have ended. Retire their exact
		// admission before provider IO or delivery; the original reader and
		// retained PDF body have independent owners and remain charged.
		if admission != nil {
			p := s.factory.state
			p.mu.Lock()
			registration := p.htmlAdmissions[admission]
			p.mu.Unlock()
			pending, err := s.factory.reconcileHTMLAdmissionRegistrationV1(cleanup, admission, registration)
			failure = errors.Join(failure, err)
			if pending != 0 {
				failure = errors.Join(failure, ErrApplicationSessionUnknownV1)
			}
		}
	}()
	if call == nil || session == nil {
		return pin, ErrSignerPackageMemberReadV1
	}
	if admission, err = session.NewAdmissionV1(call); err != nil {
		return pin, err
	}
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		if _, err = w.StateV1(actual); err != nil {
			return err
		}
		pin, err = w.readSignerPackageMemberPinV1(actual, s)
		return err
	})
	if err != nil {
		return pin, err
	}
	if err = session.CommitV1(call); err != nil {
		return pin, err
	}
	return pin, nil
}

func (h *ApplicationSignerPackageMemberReadV1) LoadV1() (failure error) {
	if h == nil || h.state == nil {
		return ErrSignerPackageMemberReadV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.closed || s.retired || s.attempted || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrSignerPackageMemberReadV1
	}
	s.attempted = true
	s.active++
	s.mu.Unlock()
	defer s.finishV1()
	op, err := s.factory.NewHTMLSendOperationV1(s.ctx, s.scope.org, s.scope.document)
	if err != nil {
		return err
	}
	op.packageMemberRead = s
	op.packageReadScope = &s.scope
	s.mu.Lock()
	s.operation = op
	closed := s.closed
	s.mu.Unlock()
	if closed {
		op.EndConsumerV1()
		return ErrSignerPackageMemberReadV1
	}
	initial, err := s.phaseV1(0)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.pin = initial
	s.mu.Unlock()
	// The provider helper owns its sole stream and constructor-bound local IO.
	// Even an error handle remains in this registered owner until real retirement.
	provider, _, err := s.client.ReadPackagePDFLocalOwnedV1(s.ctx, initial.key, initial.version, initial.digest[:], initial.metadata.PDFBytes, s.factory.state.work.coordinator, s.scope.org)
	s.mu.Lock()
	s.provider = provider
	closed = s.closed
	s.mu.Unlock()
	if closed && provider != nil {
		provider.CloseConsumerV1()
	}
	if err != nil {
		return err
	}
	if provider == nil || closed {
		return ErrSignerPackageMemberReadV1
	}
	fresh, err := s.phaseV1(1)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(initial, fresh) {
		return ErrSignerPackageMemberPreconditionV1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ctx.Err() != nil {
		return ErrSignerPackageMemberReadV1
	}
	s.loaded = true
	return nil
}
func (h *ApplicationSignerPackageMemberReadV1) ObservationV1() (SignerPackageMemberPDFMetadataV1, error) {
	if h == nil || h.state == nil {
		return SignerPackageMemberPDFMetadataV1{}, ErrSignerPackageMemberReadV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.retired || !s.loaded || s.ctx.Err() != nil {
		return SignerPackageMemberPDFMetadataV1{}, ErrSignerPackageMemberReadV1
	}
	return s.pin.metadata, nil
}
func (h *ApplicationSignerPackageMemberReadV1) WithPDFV1(fn func(SignerPackageMemberPDFMetadataV1, []byte) error) error {
	if h == nil || h.state == nil || fn == nil {
		return ErrSignerPackageMemberReadV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.closed || s.retired || !s.loaded || s.delivered || s.provider == nil || s.ctx.Err() != nil {
		s.mu.Unlock()
		return ErrSignerPackageMemberReadV1
	}
	s.delivered = true
	s.active++
	metadata, provider := s.pin.metadata, s.provider
	s.mu.Unlock()
	defer s.finishV1()
	return provider.WithPDFV1(func(body []byte) error { return fn(metadata, body) })
}
