// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const SignerPackagePresentationSchemaV1 = "hash-recipient-package-v1"

type SignerPackageMemberPresentationV1 struct {
	Title     string `json:"title"`
	Category  string `json:"category"`
	PDFSHA256 string `json:"pdf_sha256"`
	Bytes     int64  `json:"bytes"`
	Pages     int32  `json:"pages"`
}
type SignerPackagePresentationV1 struct {
	Schema                string                              `json:"schema"`
	Incorporation         documentpackage.IncorporationV1     `json:"incorporation"`
	PackageID             uuid.UUID                           `json:"package_id"`
	Revision              string                              `json:"revision"`
	ManifestSHA256        string                              `json:"manifest_sha256"`
	LegalCommitmentSHA256 string                              `json:"legal_commitment_sha256"`
	Main                  SignerPackageMemberPresentationV1   `json:"main"`
	Annexes               []SignerPackageMemberPresentationV1 `json:"annexes"`
}
type SignerPackageReadObservationV1 struct {
	DocumentID, OrgID, RecipientID uuid.UUID
	SentAt, NoticeEpoch            pgtype.Timestamptz
	PackagePresent                 bool
	Capture                        HTMLSendPackageCaptureMetadataV1
}

// Ordinary copies share the actual JSON consumer and borrow accounting. This
// handle contains no storage locators, SQL capability or signing permission.
type ApplicationSignerPackagePresentationV1 struct {
	state *applicationSignerPackagePresentationStateV1
}
type applicationSignerPackagePresentationStateV1 struct {
	mu          sync.Mutex
	self        *applicationSignerPackagePresentationStateV1
	ctx         context.Context
	body        []byte
	observation SignerPackageReadObservationV1
	close       func()
	borrowers   int
	closed      bool
}

func (h *ApplicationSignerPackagePresentationV1) ObservationV1() (SignerPackageReadObservationV1, error) {
	if h == nil || h.state == nil {
		return SignerPackageReadObservationV1{}, ErrSignerPackageReadV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.ctx == nil || s.ctx.Err() != nil {
		return SignerPackageReadObservationV1{}, ErrSignerPackageReadV1
	}
	return s.observation, nil
}
func (s *applicationSignerPackagePresentationStateV1) releaseLockedV1() func() {
	if !s.closed || s.borrowers != 0 {
		return nil
	}
	close := s.close
	s.close = nil
	s.body = nil
	s.ctx = nil
	s.observation = SignerPackageReadObservationV1{}
	return close
}

// The callback borrows read-only bytes only through its return. The original
// native loan remains live through copied Close calls and the writer's last use.
func (h *ApplicationSignerPackagePresentationV1) WithJSONV1(consume func([]byte) error) error {
	if h == nil || h.state == nil || consume == nil {
		return ErrSignerPackageReadV1
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.closed || s.ctx == nil || s.ctx.Err() != nil || s.close == nil {
		s.mu.Unlock()
		return ErrSignerPackageReadV1
	}
	s.borrowers++
	body := s.body
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.borrowers--
		close := s.releaseLockedV1()
		s.mu.Unlock()
		if close != nil {
			close()
		}
	}()
	return consume(body)
}
func (h *ApplicationSignerPackagePresentationV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close := s.releaseLockedV1()
	s.mu.Unlock()
	if close != nil {
		close()
	}
}
func signerPackageReadBodyCostV1(manifestBytes int32) (int64, int64, error) {
	if manifestBytes < 0 || manifestBytes > documentpackage.MaxManifestBytesV1 {
		return 0, 0, ErrSignerPackageReadV1
	}
	// Canonical decode/validation clones, input+public DTO copies, JSON escaping,
	// encoding scratch and independently retained output coexist before delivery.
	raw := int64(32768) + 32*int64(manifestBytes) + 16*int64(documentpackage.MaxAnnexesV1+1)*int64(unsafe.Sizeof(SignerPackageMemberPresentationV1{}))
	return raw, int64(manifestBytes), nil
}
func signerPackageMemberProjectionV1(m documentpackage.MemberV1) SignerPackageMemberPresentationV1 {
	return SignerPackageMemberPresentationV1{Title: m.Title, Category: m.Category, PDFSHA256: m.PDF.SHA256, Bytes: m.PDF.Bytes, Pages: m.PDF.Pages}
}
func signerPackageCaptureHeaderV1(c HTMLSendPackageCaptureMetadataV1) documentpackage.CaptureHeaderV1 {
	return documentpackage.CaptureHeaderV1{Binding: documentpackage.BindingV1{OrgID: c.OrgID, DocumentID: c.DocumentID, PackageID: c.PackageID, Revision: c.Revision}, Guard: documentpackage.CaptureGuardV1{RootUpdatedAt: c.RootUpdatedAt, DraftGeneration: c.DraftGeneration, PreviousRevision: c.PreviousRevision}, ManifestBytes: c.ManifestBytes, MemberCount: c.MemberCount, PDFBytes: c.PDFBytes, PDFPages: c.PDFPages, CanonicalSHA256: hex.EncodeToString(c.CanonicalSHA256[:]), CommitmentSHA256: hex.EncodeToString(c.CommitmentSHA256[:])}
}
func signerPackageCaptureHeaderMatchesV1(h *generated.GetDocumentPackageCaptureHeaderV1Row, c HTMLSendPackageCaptureMetadataV1) bool {
	return h != nil && h.PackageID == c.PackageID && h.OrgID == c.OrgID && h.DocumentID == c.DocumentID && h.Revision == c.Revision && h.PreviousRevision == c.PreviousRevision && applicationStampV1(h.CapturedRootUpdatedAt) && h.CapturedRootUpdatedAt.Time.Equal(c.RootUpdatedAt) && h.CapturedDraftGeneration == c.DraftGeneration && h.ManifestBytes == c.ManifestBytes && bytes.Equal(h.ManifestSha256, c.CanonicalSHA256[:]) && bytes.Equal(h.LegalCommitmentSha256, c.CommitmentSHA256[:]) && h.MemberCount == c.MemberCount && h.PdfBytes == c.PDFBytes && h.PdfPages == c.PDFPages && h.CreatedBy == c.CreatedBy && applicationStampV1(h.CreatedAt) && h.CreatedAt.Time.Equal(c.CreatedAt)
}

// This one-use read derives all identity from the registered response-reader
// input, then locks fresh root/credential and immutable completed-Send identity.
// No Actor, document/package/revision/key parameter or external DBTX is accepted.
func (w *ApplicationHTMLSendWorkV1) ReadSignerPackagePresentationV1(call context.Context) (out *ApplicationSignerPackagePresentationV1, failure error) {
	if w == nil || w.self != w {
		return nil, ErrSignerPackageReadV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.state == nil || w.stage == nil || w.stage.purpose != HTMLSignerPackageReadV1 || w.stage.operation == nil {
		return nil, ErrSignerPackageReadV1
	}
	op := w.stage.operation
	input := op.packageReadInput
	if input == nil || input.self != input || input.factory != op.factory || input.state == nil || op.packageReadScope != &input.scope || input.scope.org != w.state.OrgID || input.scope.document != w.state.ID || input.scope.recipient == uuid.Nil {
		return nil, ErrSignerPackageReadV1
	}
	input.state.mu.Lock()
	valid := input.bound && !input.readStarted && !input.state.consumerClosed && !input.state.retired && input.state.profile == signerPackageReadInputProfileV1 && input.ctx != nil && input.ctx.Err() == nil
	if valid {
		input.readStarted = true
	}
	input.state.mu.Unlock()
	if !valid {
		return nil, ErrSignerPackageReadV1
	}
	resolved, err := w.resolveSignerPackageCaptureForProfileLockedV1(call, input.scope, input.profile, input.completed)
	if err != nil {
		return nil, err
	}
	state := &applicationSignerPackagePresentationStateV1{ctx: input.ctx, observation: resolved.observation, close: resolved.close}
	state.self = state
	handle := &ApplicationSignerPackagePresentationV1{state: state}
	defer func() {
		if failure != nil {
			handle.CloseConsumerV1()
			out = nil
		}
	}()
	var presentation *SignerPackagePresentationV1
	if resolved.capture != nil {
		c := resolved.observation.Capture
		members := resolved.capture.Manifest().Input()
		presentation = &SignerPackagePresentationV1{Schema: SignerPackagePresentationSchemaV1, Incorporation: documentpackage.IncorporationCopyV1(), PackageID: c.PackageID, Revision: strconv.FormatInt(c.Revision, 10), ManifestSHA256: hex.EncodeToString(c.CanonicalSHA256[:]), LegalCommitmentSHA256: hex.EncodeToString(c.CommitmentSHA256[:]), Main: signerPackageMemberProjectionV1(members.Main), Annexes: make([]SignerPackageMemberPresentationV1, len(members.Annexes))}
		for i, member := range members.Annexes {
			presentation.Annexes[i] = signerPackageMemberProjectionV1(member)
		}
	}
	state.body, err = json.Marshal(struct {
		Package *SignerPackagePresentationV1 `json:"package"`
	}{presentation})
	if err != nil || int64(len(state.body)) > resolved.raw || !w.valid(call) || input.ctx.Err() != nil {
		return nil, ErrSignerPackageReadV1
	}
	return handle, nil
}

// This private result remains funded until its same-method consumer closes it.
// Only native token-bound callers below may supply the already-owned scope.
type applicationSignerPackageResolvedCaptureV1 struct {
	observation SignerPackageReadObservationV1
	attempt     HTMLSendPackageAttemptObservationV1
	capture     *documentpackage.CaptureV1
	close       func()
	raw         int64
}

// Caller holds w.mu and has validated its concrete registered read input.
func (w *ApplicationHTMLSendWorkV1) resolveSignerPackageCaptureLockedV1(call context.Context, scope applicationSignerScopeSnapshotV1) (resolved applicationSignerPackageResolvedCaptureV1, failure error) {
	return w.resolveSignerPackageCaptureForProfileLockedV1(call, scope, signerPackageActiveProfileV1, applicationCompletedPackagePinsV1{})
}

// Both profiles originate only in distinct registered-reader constructors.
// Active policy and its existing query remain unchanged in their branch.
func (w *ApplicationHTMLSendWorkV1) resolveSignerPackageCaptureForProfileLockedV1(call context.Context, scope applicationSignerScopeSnapshotV1, profile applicationSignerPackageProfileV1, completed applicationCompletedPackagePinsV1) (resolved applicationSignerPackageResolvedCaptureV1, failure error) {
	if profile != signerPackageActiveProfileV1 && profile != signerPackageCompletedProfileV1 {
		return resolved, ErrSignerPackageReadV1
	}
	fixed := 8*int64(unsafe.Sizeof(generated.ListCompletedSignerPackageReadBindingV1Row{})) + int64(32768) + 8*int64(unsafe.Sizeof(generated.InspectDocumentPackageSendAttemptStateV1Row{})) + 8*int64(unsafe.Sizeof(generated.GetDocumentPackageCaptureHeaderV1Row{})) + 8*int64(unsafe.Sizeof(generated.DocumentPackageSendCompletionsV1{})) + 8*18*int64(unsafe.Sizeof(generated.ListDocumentPackageSendAttemptSubjectsV1Row{})) + 8*int64(unsafe.Sizeof(applicationSignerPackagePresentationStateV1{}))
	closeHeaders, err := w.actor.acquireOwnedRetainedBodyV1(call, fixed, fixed)
	if err != nil {
		return resolved, errors.Join(ErrSignerPackageReadV1, err)
	}
	w.closes = append(w.closes, closeHeaders)
	credential, err := w.queries.GetSignerRecipientReadHeaderV1(call, generated.GetSignerRecipientReadHeaderV1Params{DocumentID: scope.document, OrgID: scope.org, RecipientID: scope.recipient, TokenHash: scope.hash[:]})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return resolved, errors.Join(ErrSignerReadCredentialV1, err)
		}
		return resolved, err
	}
	if credential == nil || credential.DocumentID != scope.document || credential.OrgID != scope.org || credential.RecipientID != scope.recipient || !bytes.Equal(credential.MagicTokenHash, scope.hash[:]) || !applicationStampV1(credential.MagicTokenExpiresAt) || !time.Now().Before(credential.MagicTokenExpiresAt.Time) || (profile == signerPackageActiveProfileV1 && ((w.state.ExpiresAt.Valid && (!applicationStampV1(w.state.ExpiresAt) || !time.Now().Before(w.state.ExpiresAt.Time))) || (w.state.BoundedStatus != "sent" && w.state.BoundedStatus != "in_progress" && w.state.BoundedStatus != "changes_requested"))) || (profile == signerPackageCompletedProfileV1 && (w.state.BoundedStatus != "completed" || !credential.IsCompletedRecipient)) {
		return resolved, ErrSignerReadCredentialV1
	}
	var subjects [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	subjects[0] = scope.document
	if err = fenceDocumentPackageSubjectsV1(call, w.session, subjects, 1); err != nil {
		return resolved, err
	}
	history, err := w.queries.HasSignerPackageReadHistoryV1(call, generated.HasSignerPackageReadHistoryV1Params{DocumentID: scope.document, OrgID: scope.org})
	if err != nil {
		return resolved, err
	}
	observation := SignerPackageReadObservationV1{DocumentID: scope.document, OrgID: scope.org, RecipientID: scope.recipient, SentAt: w.state.SentAt, NoticeEpoch: w.state.Article13NoticeEpochAt}
	var c HTMLSendPackageCaptureMetadataV1
	if history {
		var id, packageID uuid.UUID
		if profile == signerPackageCompletedProfileV1 {
			bindings, e := w.queries.ListCompletedSignerPackageReadBindingV1(call, generated.ListCompletedSignerPackageReadBindingV1Params{DocumentID: scope.document, OrgID: scope.org, RecipientID: scope.recipient, TokenHash: scope.hash[:], CompletionEffectiveAt: completed.effective, FinalPdfKey: completed.keys[0], FinalPdfVersionID: completed.versions[0], FinalPdfSha256: completed.sums[0][:], AuditCertKey: completed.keys[1], AuditCertVersionID: completed.versions[1], AuditCertSha256: completed.sums[1][:], AuditPayloadKey: completed.keys[2], AuditPayloadVersionID: completed.versions[2], AuditPayloadSha256: completed.sums[2][:], AuditSignatureKey: completed.keys[3], AuditSignatureVersionID: completed.versions[3], AuditSignatureSha256: completed.sums[3][:]})
			if e != nil {
				return resolved, e
			}
			if len(bindings) != 1 || bindings[0] == nil {
				return resolved, ErrSignerPackageReadV1
			}
			id, packageID = bindings[0].AttemptID, bindings[0].PackageID
		} else {
			bindings, e := w.queries.ListSignerPackageReadBindingV1(call, generated.ListSignerPackageReadBindingV1Params{DocumentID: scope.document, OrgID: scope.org, RecipientID: scope.recipient, TokenHash: scope.hash[:]})
			if e != nil {
				return resolved, e
			}
			if len(bindings) != 1 || bindings[0] == nil {
				return resolved, ErrSignerPackageReadV1
			}
			id, packageID = bindings[0].AttemptID, bindings[0].PackageID
		}
		if id == uuid.Nil || packageID == uuid.Nil {
			return resolved, ErrSignerPackageReadV1
		}
		params := generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: id, OrgID: scope.org, DocumentID: scope.document}
		row, e := w.queries.InspectDocumentPackageSendAttemptStateV1(call, params)
		if e != nil {
			return resolved, e
		}
		c, e = htmlSendRecoveryCaptureV1(row, id, scope.org, scope.document)
		if e != nil || c.PackageID != packageID {
			return resolved, ErrSignerPackageReadV1
		}
		rows, e := w.queries.ListDocumentPackageSendAttemptSubjectsV1(call, generated.ListDocumentPackageSendAttemptSubjectsV1Params{AttemptID: id, OrgID: c.OrgID, DocumentID: c.DocumentID, PackageID: c.PackageID, CaptureRevision: c.Revision, MemberCount: c.MemberCount, ManifestSha256: c.CanonicalSHA256[:], LegalCommitmentSha256: c.CommitmentSHA256[:]})
		if e != nil {
			return resolved, e
		}
		subjects, e = htmlSendRecoverySubjectsV1(rows, c)
		if e != nil {
			return resolved, e
		}
		if e = fenceDocumentPackageSubjectsV1(call, w.session, subjects, int(c.MemberCount)); e != nil {
			return resolved, e
		}
		row, e = w.queries.InspectDocumentPackageSendAttemptStateV1(call, params)
		if e != nil {
			return resolved, e
		}
		attempt, e := htmlSendPackageAttemptObservationV1(row, id, c)
		if e != nil || attempt.Outcome != HTMLSendPackageAttemptCompletedV1 || !applicationStampV1(w.state.SentAt) || !attempt.Article13NoticeEpochAt.Equal(w.state.SentAt.Time) || !applicationStampEqualV1(w.state.SentAt, w.state.Article13NoticeEpochAt) || !w.state.Article13NoticeEpochV61Committed {
			return resolved, ErrSignerPackageReadV1
		}
		completed, e := w.queries.InspectDocumentPackageSendCompletionV1(call, generated.InspectDocumentPackageSendCompletionV1Params{AttemptID: id, OrgID: c.OrgID, DocumentID: c.DocumentID, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
		if e != nil {
			return resolved, e
		}
		if completed == nil || completed.Outcome != "sent" || completed.AttemptID != id || completed.OrgID != c.OrgID || completed.DocumentID != c.DocumentID || !applicationStampEqualV1(completed.Article13NoticeEpochAt, w.state.SentAt) || !bytes.Equal(completed.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(completed.LegalCommitmentSha256, c.CommitmentSHA256[:]) {
			return resolved, ErrSignerPackageReadV1
		}
		header, e := w.queries.GetDocumentPackageCaptureHeaderV1(call, generated.GetDocumentPackageCaptureHeaderV1Params{PackageID: c.PackageID, OrgID: c.OrgID, DocumentID: c.DocumentID, Revision: c.Revision})
		if e != nil {
			return resolved, e
		}
		if !signerPackageCaptureHeaderMatchesV1(header, c) {
			return resolved, ErrSignerPackageReadV1
		}
		resolved.attempt = attempt
		observation.PackagePresent, observation.Capture = true, c
	}
	raw, wire, err := signerPackageReadBodyCostV1(c.ManifestBytes)
	if err != nil {
		return resolved, err
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, wire)
	if err != nil {
		return resolved, errors.Join(ErrSignerPackageReadV1, err)
	}
	resolved.observation, resolved.close, resolved.raw = observation, closeBody, raw
	defer func() {
		if failure != nil {
			closeBody()
			resolved = applicationSignerPackageResolvedCaptureV1{}
		}
	}()
	if observation.PackagePresent {
		payload, e := w.queries.GetDocumentPackageCapturePayloadV1(call, generated.GetDocumentPackageCapturePayloadV1Params{PackageID: c.PackageID, OrgID: c.OrgID, DocumentID: c.DocumentID, Revision: c.Revision, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], ExpectedManifestBytes: c.ManifestBytes})
		if e != nil {
			return resolved, e
		}
		resolved.capture, e = documentpackage.DecodeCaptureV1(payload, signerPackageCaptureHeaderV1(c))
		if e != nil {
			return resolved, e
		}
	}
	if !w.valid(call) {
		return resolved, ErrSignerPackageReadV1
	}
	return resolved, nil
}
