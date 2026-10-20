// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
)

// PersistResolvedVariablesV1 is the original non-HTML FreezeDocumentVariables
// CAS at its existing final-authorized policy point. Only this SAME operation's
// completed opaque resolver can supply bytes. The old immutable source remains
// independently retained; the new source is created only from actual RETURNING.
// No reader repair, caller replacement Document or timestamp normalization.
func (w *ApplicationHTMLSendWorkV1) PersistResolvedVariablesV1(call context.Context, h *ApplicationHTMLSendResolutionV1) (*generated.Document, *ApplicationHTMLSendSourceV1, error) {
	if w == nil || w.self != w || h == nil || h.state == nil {
		return nil, nil, ErrHTMLSendWorkV1
	}
	p := h.state
	p.mu.Lock()
	if !p.liveV1() || !p.attempted || p.failure != nil || p.active != 0 || p.work == nil || p.work.stage == nil || w.stage == nil || p.work.stage.operation != w.stage.operation || p.document == nil || p.document.ID != w.logicalDocumentV1() || p.frozen == nil {
		p.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	p.active++
	frozen := p.frozen
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.active--; p.retireV1(); p.mu.Unlock() }()
	w.mu.Lock()
	if !w.valid(call) || w.stage.purpose != HTMLSendAdmissionV1 || w.sourceDocument == nil || w.sourceOwner == nil || w.sourceState == nil || w.priorFrozenSource != nil || w.freezeVariablesAttempted || !w.reviewedOriginalValidated || !w.reviewedCandidateValidated || len(w.sourceDocument.HtmlSourceJson) != 0 || len(w.sourceDocument.HtmlCurrentSourceJson) != 0 || w.sourceDocument.HtmlCurrentMaterializationID.Valid || (w.sourceDocument.ParentEnvelopeID.Valid && w.familyRoot == nil) || (w.sourceDocument.IsEnvelope && !w.familyMembersAttempted) || w.sourceServerVersion <= 0 {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	w.freezeVariablesAttempted = true
	original := w.sourceDocument
	s := w.session.state
	upper, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, frozen)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	wire, err := htmlAuthoringSumV1(int64(len(original.BlocksJson)), int64(len(original.Metadata)), int64(len(original.MetadataRedactionReport)), upper)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	// Positive independent row/result/cache staging before actual SQL expansion.
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(call, signerDocumentRawBytesV1(original), wire)
	if err != nil {
		w.mu.Unlock()
		return nil, nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.FreezeDocumentVariables(call, generated.FreezeDocumentVariablesParams{ID: w.logicalDocumentV1(), OrgID: s.org, VariablesJson: frozen, ExpectedUpdatedAt: original.UpdatedAt})
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	if row == nil || row.ID != w.logicalDocumentV1() || row.OrgID != s.org || row.Status != "draft" || int64(len(row.VariablesJson)) > upper || len(row.VariablesJson) == 0 {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	// The fixed SQL changes ONLY variables and its real database timestamp.
	// Compare every other actual legal/source/pin field without normalizing the
	// old owner's snapshot or accepting a public caller view as source authority.
	before, after := *original, *row
	before.VariablesJson = after.VariablesJson
	before.UpdatedAt = after.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&before, &after) || !bytes.Equal(row.BlocksJson, original.BlocksJson) {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	// This producer measured the row it JUST changed, under the retained actual
	// original parent lock and exact source-derived variable-wire admission.
	measured, err := w.queries.MeasureSignatureFitHTMLPolicyDocumentV1(call, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: w.logicalDocumentV1(), OrgID: s.org})
	if err != nil {
		w.mu.Unlock()
		return nil, nil, err
	}
	if measured == nil || measured.DocumentID != w.logicalDocumentV1() || measured.OrgID != s.org || measured.HtmlOriginWireBytes != 0 || measured.HtmlCurrentWireBytes != 0 || measured.VariablesWireBytes != int64(len(row.VariablesJson)) || measured.VariablesWireBytes > upper || measured.MeasurementServerVersionNum != w.sourceServerVersion {
		w.mu.Unlock()
		return nil, nil, ErrHTMLSendWorkV1
	}
	w.priorFrozenSource = w.sourceState
	w.sourceOwner = nil
	w.sourceState = nil
	w.sourceStarted = false
	w.reviewedOriginalValidated = false
	w.sourceDocument = htmlSendCloneDocumentV1(row)
	w.models.Document = row
	w.models.Current = nil
	w.sourceCurrent = nil
	w.currentRead = false
	w.currentAttempted = false
	w.state.UpdatedAt = row.UpdatedAt
	w.mu.Unlock()
	source, err := w.NewSourceV1(call)
	if err != nil {
		return nil, nil, err
	}
	if err = source.ValidateReviewedV1(); err != nil {
		return nil, nil, err
	}
	if err = source.ValidateResolvedBlocksV1(); err != nil {
		return nil, nil, err
	}
	if err = source.ValidateCurrentV1(); err != nil {
		return nil, nil, err
	}
	return row, source, nil
}
