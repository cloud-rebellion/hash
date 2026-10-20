// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrPackageSendSelectionRequiredV1 = errors.New("review the saved attachments before sending the complete package")
var ErrPackageSendSelectionChangedV1 = errors.New("the reviewed document or attachment selection changed before Send")

// Fixed observations from the sender's reviewed selection. These identify no
// credential, source, transaction, storage capability or permission to replay.
// The zero value is the ordinary document path, including empty draft headers.
type HTMLSendPackageSelectionV1 struct {
	ExpectedUpdatedAt time.Time
	PackageID         uuid.UUID
	Generation        int64
}

func (v HTMLSendPackageSelectionV1) PresentV1() bool {
	return v.PackageID != uuid.Nil || v.Generation != 0 || !v.ExpectedUpdatedAt.IsZero()
}
func (v HTMLSendPackageSelectionV1) ValidV1() bool {
	return v.PackageID != uuid.Nil && v.Generation > 0 && v.Generation < 9223372036854775807 &&
		!v.ExpectedUpdatedAt.IsZero() && v.ExpectedUpdatedAt.Year() >= 1 && v.ExpectedUpdatedAt.Year() <= 9999 &&
		v.ExpectedUpdatedAt.Equal(v.ExpectedUpdatedAt.Truncate(time.Microsecond))
}

// CheckPackageSendSelectionV1 runs under the original root lock both before
// measurement and in admission. Old clients cannot silently omit saved annexes.
// The original source owner still independently validates every selected pin.
func (w *ApplicationHTMLSendWorkV1) CheckPackageSendSelectionV1(call context.Context, v HTMLSendPackageSelectionV1) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLSendPreparationV1 && w.stage.purpose != HTMLSendAdmissionV1) || w.state == nil || w.sourceActor == nil || w.sourceDocument == nil || w.packageInitialSelectionChecked || w.sourceActor.OrgID != w.state.OrgID || (w.sourceActor.Role != "owner" && (w.sourceActor.Role != "sender" || w.state.SenderID != w.sourceActor.ID)) {
		return ErrHTMLSendWorkV1
	}
	w.packageInitialSelectionChecked = true
	if v.PresentV1() && (!v.ValidV1() || !w.state.IsPdfSource || w.state.IsEnvelope || w.state.ParentEnvelopeID.Valid || !w.sourceDocument.UpdatedAt.Valid || !w.sourceDocument.UpdatedAt.Time.Equal(v.ExpectedUpdatedAt)) {
		return ErrPackageSendSelectionChangedV1
	}
	present, err := w.selectedPackageMembersLockedV1(call)
	if err != nil {
		return err
	}
	if present != v.PresentV1() {
		if present {
			return ErrPackageSendSelectionRequiredV1
		}
		return ErrPackageSendSelectionChangedV1
	}
	return nil
}

// Work mutex is held. This fixed scalar quote covers bind/result/driver and
// bounded EXISTS work before SQL. No source/report/member body is selected.
func (w *ApplicationHTMLSendWorkV1) selectedPackageMembersLockedV1(call context.Context) (bool, error) {
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, 4096, 16384)
	if err != nil {
		return false, err
	}
	w.closes = append(w.closes, closeBody)
	s := w.session.state
	return w.queries.HasDocumentPackageDraftMembersV1(call, generated.HasDocumentPackageDraftMembersV1Params{DocumentID: s.document, OrgID: s.org})
}

// FindPackageSendSelectionAttemptV1 is a fresh authenticated read, never a
// request to create, resume or execute the selected job. A unique persisted
// result prevents a repeated POST from minting another capture/invitation set.
// Caller actor/credential policy must run before AND after this primitive.
func (w *ApplicationHTMLSendWorkV1) FindPackageSendSelectionAttemptV1(call context.Context, v HTMLSendPackageSelectionV1) (HTMLSendPackageAttemptObservationV1, error) {
	if w == nil || w.self != w || !v.ValidV1() {
		return HTMLSendPackageAttemptObservationV1{}, ErrPackageSendSelectionChangedV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.stage == nil || w.stage.purpose != HTMLSendIntentReadV1 || w.state == nil || !w.state.IsPdfSource || w.state.IsEnvelope || w.state.ParentEnvelopeID.Valid || w.sourceActor == nil || w.sourceActor.OrgID != w.state.OrgID || w.packageInitialLookupAttempted ||
		(w.sourceActor.Role != "owner" && (w.sourceActor.Role != "sender" || w.state.SenderID != w.sourceActor.ID)) {
		w.mu.Unlock()
		return HTMLSendPackageAttemptObservationV1{}, ErrHTMLSendPackageInspectionV1
	}
	w.packageInitialLookupAttempted = true
	raw := int64(16384) + 8*int64(unsafe.Sizeof(generated.FindDocumentPackageSendAttemptForSelectionV1Params{}))
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 8*raw)
	if err != nil {
		w.mu.Unlock()
		return HTMLSendPackageAttemptObservationV1{}, err
	}
	w.closes = append(w.closes, closeBody)
	s := w.session.state
	ids, err := w.queries.FindDocumentPackageSendAttemptForSelectionV1(call, generated.FindDocumentPackageSendAttemptForSelectionV1Params{OrgID: s.org, DocumentID: s.document, PackageID: v.PackageID, CapturedDraftGeneration: v.Generation, CapturedRootUpdatedAt: pgtype.Timestamptz{Time: v.ExpectedUpdatedAt, Valid: true}})
	count, id := len(ids), uuid.Nil
	if count == 1 {
		id = ids[0]
	}
	ids = nil
	w.mu.Unlock()
	if err != nil {
		return HTMLSendPackageAttemptObservationV1{}, err
	}
	if count == 0 {
		return HTMLSendPackageAttemptObservationV1{Outcome: HTMLSendPackageAttemptNotRecordedV1}, nil
	}
	if count != 1 || id == uuid.Nil {
		return HTMLSendPackageAttemptObservationV1{}, ErrHTMLSendPackageInspectionV1
	}
	observation, err := w.InspectDurablePackageSendAttemptV1(call, id)
	if err != nil {
		return HTMLSendPackageAttemptObservationV1{}, err
	}
	if observation.Outcome == HTMLSendPackageAttemptNotRecordedV1 || observation.Capture.PackageID != v.PackageID || observation.Capture.DraftGeneration != v.Generation || !observation.Capture.RootUpdatedAt.Equal(v.ExpectedUpdatedAt) {
		return HTMLSendPackageAttemptObservationV1{}, ErrHTMLSendPackageInspectionV1
	}
	return observation, nil
}
