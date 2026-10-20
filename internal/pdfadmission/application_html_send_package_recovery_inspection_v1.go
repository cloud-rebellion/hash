// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// InspectDurablePackageSendAttemptV1 reads one exact persisted attempt in a
// fresh native request. The fixed application adapter must authorize the live
// credential before and after this call. IDs are selectors, never capabilities.
// No original session, retry permission or provider/mutation access is inferred.
func (w *ApplicationHTMLSendWorkV1) InspectDurablePackageSendAttemptV1(call context.Context, id uuid.UUID) (out HTMLSendPackageAttemptObservationV1, failure error) {
	return w.inspectDurablePackageSendAttemptV1(call, id, nil)
}

// scope is private process authority minted only by the live registered batch.
// The exported staff primitive always passes nil and retains its actor policy.
func (w *ApplicationHTMLSendWorkV1) inspectDurablePackageSendAttemptV1(call context.Context, id uuid.UUID, scope *applicationPackageSendRecoveryWorkScopeV1) (out HTMLSendPackageAttemptObservationV1, failure error) {
	defer func() {
		if failure != nil {
			out = HTMLSendPackageAttemptObservationV1{}
			failure = errors.Join(ErrHTMLSendPackageInspectionV1, failure)
		}
	}()
	if w == nil || w.self != w || id == uuid.Nil {
		return out, ErrHTMLSendPackageInspectionV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLSendIntentReadV1 && (scope == nil || (w.stage.purpose != htmlSendPackageRetentionPurposeV1 && w.stage.purpose != HTMLSendCompletionV1))) || w.familyRoot != nil || w.state == nil || w.packageRecoveryInspectionAttempted || !w.state.IsPdfSource || w.state.IsEnvelope || w.state.ParentEnvelopeID.Valid {
		return out, ErrHTMLSendPackageInspectionV1
	}
	if scope == nil {
		if w.sourceActor == nil || w.sourceActor.OrgID != w.state.OrgID || (w.sourceActor.Role != "owner" && (w.sourceActor.Role != "sender" || w.state.SenderID != w.sourceActor.ID)) {
			return out, ErrHTMLSendPackageInspectionV1
		}
	} else if !scope.validV1(w) || scope.entry.attempt != id {
		return out, ErrHTMLSendPackageInspectionV1
	}
	w.packageRecoveryInspectionAttempted = true
	// Pay for BOTH scalar snapshots, their digest buffers/terminal text, all18
	// subject rows, private fixed array and the copied owned application result
	// before the first SQL. This loan stays with the Work through response close.
	var subjects [documentpackage.MaxAnnexesV1 + 2]uuid.UUID
	raw := int64(16384) + 16*(int64(unsafe.Sizeof(generated.InspectDocumentPackageSendAttemptStateV1Row{}))+int64(unsafe.Sizeof(HTMLSendPackageAttemptObservationV1{}))+int64(unsafe.Sizeof(subjects))) + 32*(64+9) + 18*8*int64(unsafe.Sizeof(generated.ListDocumentPackageSendAttemptSubjectsV1Row{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 16384+8*raw)
	if err != nil {
		return out, err
	}
	w.closes = append(w.closes, closeBody)
	subjects[0] = w.state.ID
	if err = fenceDocumentPackageSubjectsV1(call, w.session, subjects, 1); err != nil {
		return out, err
	}
	params := generated.InspectDocumentPackageSendAttemptStateV1Params{AttemptID: id, OrgID: w.state.OrgID, DocumentID: w.state.ID}
	row, err := w.queries.InspectDocumentPackageSendAttemptStateV1(call, params)
	if errors.Is(err, pgx.ErrNoRows) {
		if scope != nil {
			return out, ErrHTMLSendPackageInspectionV1
		}
		if !w.valid(call) {
			return out, ErrHTMLSendPackageInspectionV1
		}
		return HTMLSendPackageAttemptObservationV1{AttemptID: id, Outcome: HTMLSendPackageAttemptNotRecordedV1}, nil
	}
	if err != nil {
		return out, err
	}
	if scope != nil && (!applicationStampEqualV1(row.CreatedAt, scope.entry.createdAt) || !scope.validV1(w)) {
		return out, ErrHTMLSendPackageInspectionV1
	}
	capture, err := htmlSendRecoveryCaptureV1(row, id, w.state.OrgID, w.state.ID)
	if err != nil {
		return out, err
	}
	rows, err := w.queries.ListDocumentPackageSendAttemptSubjectsV1(call, generated.ListDocumentPackageSendAttemptSubjectsV1Params{AttemptID: id, OrgID: capture.OrgID, DocumentID: capture.DocumentID, PackageID: capture.PackageID, CaptureRevision: capture.Revision, MemberCount: capture.MemberCount, ManifestSha256: capture.CanonicalSHA256[:], LegalCommitmentSha256: capture.CommitmentSHA256[:]})
	if err != nil {
		return out, err
	}
	subjects, err = htmlSendRecoverySubjectsV1(rows, capture)
	if err != nil {
		return out, err
	}
	if err = fenceDocumentPackageSubjectsV1(call, w.session, subjects, int(capture.MemberCount)); err != nil {
		return out, err
	}
	// A separate fresh statement after the privacy fences sees pending requests
	// and exact attempt/capture/intent state together under the original root lock.
	row, err = w.queries.InspectDocumentPackageSendAttemptStateV1(call, params)
	if err != nil {
		return out, err // post-header absence is inconsistency, never NotRecorded.
	}
	out, err = htmlSendPackageAttemptObservationV1(row, id, capture)
	if err != nil || !w.valid(call) {
		return out, errors.Join(ErrHTMLSendPackageInspectionV1, err)
	}
	return out, nil
}

func htmlSendRecoveryCaptureV1(r *generated.InspectDocumentPackageSendAttemptStateV1Row, id, org, root uuid.UUID) (HTMLSendPackageCaptureMetadataV1, error) {
	c := HTMLSendPackageCaptureMetadataV1{}
	if r == nil || id == uuid.Nil || org == uuid.Nil || root == uuid.Nil || r.AttemptID != id || r.OrgID != org || r.DocumentID != root || r.PackageID == uuid.Nil || r.ActorUserID == uuid.Nil || !r.ExactCapture || r.CaptureRevision <= 0 || r.PreviousRevision < 0 || r.PreviousRevision != r.CaptureRevision-1 || r.CapturedDraftGeneration <= 0 || !applicationStampV1(r.CapturedRootUpdatedAt) || !applicationStampV1(r.CaptureCreatedAt) || r.ManifestBytes < 1 || r.ManifestBytes > documentpackage.MaxManifestBytesV1 || r.MemberCount < 1 || r.MemberCount > documentpackage.MaxAnnexesV1+1 || r.PdfBytes < 1 || r.PdfBytes > documentpackage.MaxPDFBytesV1 || r.PdfPages < 1 || r.PdfPages > documentpackage.MaxPDFPagesV1 || len(r.ManifestSha256) != 32 || len(r.LegalCommitmentSha256) != 32 {
		return c, ErrHTMLSendPackageInspectionV1
	}
	c = HTMLSendPackageCaptureMetadataV1{Present: true, OrgID: org, DocumentID: root, PackageID: r.PackageID, CreatedBy: r.ActorUserID, Revision: r.CaptureRevision, PreviousRevision: r.PreviousRevision, DraftGeneration: r.CapturedDraftGeneration, RootUpdatedAt: r.CapturedRootUpdatedAt.Time.UTC(), CreatedAt: r.CaptureCreatedAt.Time.UTC(), ManifestBytes: r.ManifestBytes, MemberCount: r.MemberCount, PDFBytes: r.PdfBytes, PDFPages: r.PdfPages}
	copy(c.CanonicalSHA256[:], r.ManifestSha256)
	copy(c.CommitmentSHA256[:], r.LegalCommitmentSha256)
	if c.CanonicalSHA256 == ([32]byte{}) || c.CommitmentSHA256 == ([32]byte{}) {
		return HTMLSendPackageCaptureMetadataV1{}, ErrHTMLSendPackageInspectionV1
	}
	return c, nil
}

func htmlSendRecoverySubjectsV1(rows []*generated.ListDocumentPackageSendAttemptSubjectsV1Row, c HTMLSendPackageCaptureMetadataV1) (out [documentpackage.MaxAnnexesV1 + 2]uuid.UUID, err error) {
	if c.MemberCount < 1 || c.MemberCount > documentpackage.MaxAnnexesV1+1 || len(rows) != int(c.MemberCount) {
		return out, ErrHTMLSendPackageInspectionV1
	}
	for i, r := range rows {
		if r == nil || r.MemberPosition != int16(i) || r.MemberDocumentID == uuid.Nil || (i == 0 && r.MemberDocumentID != c.DocumentID) {
			return [documentpackage.MaxAnnexesV1 + 2]uuid.UUID{}, ErrHTMLSendPackageInspectionV1
		}
		for j := 0; j < i; j++ {
			if out[j] == r.MemberDocumentID {
				return [documentpackage.MaxAnnexesV1 + 2]uuid.UUID{}, ErrHTMLSendPackageInspectionV1
			}
		}
		out[i] = r.MemberDocumentID
	}
	return out, nil
}
