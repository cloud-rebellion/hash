// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "context"

// The reviewed pre-sign contract has no annex/package capture. Reuse the
// original selected-draft scalar gate, then refuse existing frozen captures
// or membership in another selected package. Empty draft headers are neutral.
// This fixed entry is checked before preparation and again at fresh admission;
// ordinary package Send and its purpose guards are unchanged.
func (w *ApplicationHTMLSendWorkV1) CheckPreSignStandaloneV1(call context.Context) error {
	if w == nil || w.self != w {
		return ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage == nil || w.state == nil || w.sourceActor == nil || w.sourceDocument == nil || w.packageInitialSelectionChecked ||
		(w.stage.purpose != HTMLPreSignReadV1 && w.stage.purpose != HTMLPreSignPreparationV1 && w.stage.purpose != HTMLPreSignReservationV1 && w.stage.purpose != HTMLPreSignCommitV1) {
		return ErrHTMLSendWorkV1
	}
	w.packageInitialSelectionChecked = true
	present, err := w.selectedPackageMembersLockedV1(call)
	if err != nil {
		return err
	}
	if present {
		return ErrPackageSendSelectionRequiredV1
	}
	db := &applicationOwnedDBTXV1{session: w.session.state}
	err = db.QueryRow(call, `SELECT EXISTS(SELECT 1 FROM document_package_captures_v1 WHERE org_id=$1 AND document_id=$2)
  OR EXISTS(SELECT 1 FROM document_package_send_attempts_v1 WHERE org_id=$1 AND document_id=$2)
  OR EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE org_id=$1 AND member_document_id=$2)
  OR EXISTS(SELECT 1 FROM document_package_capture_members_v1 WHERE org_id=$1 AND member_document_id=$2)`, w.session.state.org, w.logicalDocumentV1()).Scan(&present)
	if err != nil {
		return err
	}
	if present {
		return ErrPackageSendSelectionRequiredV1
	}
	return nil
}
