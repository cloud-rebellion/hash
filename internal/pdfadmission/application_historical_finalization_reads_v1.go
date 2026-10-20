// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"net/netip"
	"unsafe"
)

type applicationHistoricalFinalizationV1 struct {
	signatures, signatureViews                                     []*generated.Signature
	intentView                                                     *generated.DocumentFinalizationIntent
	intent                                                         *generated.DocumentFinalizationIntent
	signatureAttempted, signatureRead, intentAttempted, intentRead bool
	source                                                         *ApplicationHTMLSendSourceV1
	roles, roleViews                                               []string
	rolesAttempted, rolesRead, ready                               bool
	mode                                                           string
	memberViews                                                    []*generated.Document
	claimed                                                        *generated.Document
	beginAttempted, stageAttempted, checkpointAttempted            bool
	publication                                                    *applicationHistoricalPublicationV1
	compatibilityChecked                                           bool
}

func (w *ApplicationHTMLSendWorkV1) historicalFinalizationStateV1(call context.Context) (*applicationHistoricalFinalizationV1, error) {
	if !w.valid(call) || w.stage == nil || (w.stage.purpose != HTMLHistoricalFinalizationClaimV1 && w.stage.purpose != HTMLHistoricalFinalizationStageV1 && w.stage.purpose != HTMLHistoricalFinalizationResumeV1 && w.stage.purpose != HTMLHistoricalFinalizationPublicationV1 && w.stage.purpose != HTMLHistoricalFinalizationSourceV1) || w.sourceDocument == nil || w.models == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if w.finalization != nil {
		return w.finalization, nil
	}
	raw := 2*int64(unsafe.Sizeof(applicationHistoricalFinalizationV1{})) + 8*int64(unsafe.Sizeof(uintptr(0))) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationSignatureReadHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationIntentReadHeaderV1Row{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationSignatureReadHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationIntentReadHeaderV1Params{})) + 2*int64(unsafe.Sizeof(generated.LockHistoricalFinalizationSignatureRowsV1Params{}))
	closeState, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, 0)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeState)
	w.finalization = &applicationHistoricalFinalizationV1{}
	return w.finalization, nil
}
func (w *ApplicationHTMLSendWorkV1) historicalFinalizationUpdatedAtV1() pgtype.Timestamptz {
	if w.sourceDocument != nil {
		return w.sourceDocument.UpdatedAt
	}
	if w.stage != nil && (w.stage.purpose == HTMLHistoricalFinalizationCheckpointV1 || w.stage.purpose == HTMLHistoricalFinalizationResumeV1 || w.stage.purpose == HTMLHistoricalFinalizationPublicationV1 || w.stage.purpose == HTMLHistoricalFinalizationSourceV1 || w.stage.purpose == HTMLHistoricalFinalizationEvidenceV1 || w.stage.purpose == htmlHistoricalFinalizationPublicationPurposeV1) && w.state != nil {
		return w.state.UpdatedAt
	}
	return pgtype.Timestamptz{}
}
func historicalFinalizationSignatureRawV1(row *generated.Signature) (int64, error) {
	if row == nil {
		return 0, ErrHTMLSendWorkV1
	}
	return htmlAuthoringSumV1(int64(len(row.Font)), int64(len(row.TypedName)), int64(len(row.ImageStorageKey)), int64(len(row.ImageSha256)), int64(len(row.ImageVersionID.String)), int64(len(row.SignerUa.String)), int64(len(row.SignatureKind)))
}
func historicalFinalizationCloneSignatureV1(row *generated.Signature) *generated.Signature {
	if row == nil {
		return nil
	}
	copy := *row
	copy.ImageSha256 = bytes.Clone(row.ImageSha256)
	if row.SignerIp != nil {
		ip := *row.SignerIp
		copy.SignerIp = &ip
	}
	return &copy
}

// A real root-scoped scalar header funds native/driver/private rows, sortable
// UUID pins and their DB staging before the actual row lock or body expansion.
// The fresh header and exact returned raw count preserve READ COMMITTED safety.
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalFinalizationSignaturesV1(call context.Context) ([]*generated.Signature, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalFinalizationStateV1(call)
	if err != nil {
		return nil, err
	}
	return w.readFinalizationSignaturesLockedV1(call, state)
}

// Fixed private measured row producer shared with response capacity admission.
// Public historical reads retain their original purpose/reference decisions;
// this helper does not authorize a claim, render or publication.
func (w *ApplicationHTMLSendWorkV1) readFinalizationSignaturesLockedV1(call context.Context, state *applicationHistoricalFinalizationV1) ([]*generated.Signature, error) {
	if !w.valid(call) || state == nil || w.sourceDocument == nil {
		return nil, ErrHTMLSendWorkV1
	}
	if state.signatureRead {
		return state.signatureViews, nil
	}
	if state.signatureAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	state.signatureAttempted = true
	params := generated.GetHistoricalFinalizationSignatureReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org}
	header, err := w.queries.GetHistoricalFinalizationSignatureReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != w.logicalDocumentV1() || header.OrgID != w.session.state.org || header.UpdatedAt != w.sourceDocument.UpdatedAt || header.SignatureCount < 0 || header.RawBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw := header.RawBytes
	per := 5*int64(unsafe.Sizeof(generated.Signature{})) + 8*int64(unsafe.Sizeof((*generated.Signature)(nil))) + 8*int64(unsafe.Sizeof(uuid.UUID{})) + 8*int64(unsafe.Sizeof(uintptr(0))) + 4*int64(unsafe.Sizeof(netip.Addr{}))
	if !htmlInputAddV1(&raw, header.SignatureCount, per) {
		return nil, ErrHTMLSendWorkV1
	}
	closeRows, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeRows)
	count, err := w.queries.LockHistoricalFinalizationSignatureRowsV1(call, generated.LockHistoricalFinalizationSignatureRowsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil {
		return nil, err
	}
	if count != header.SignatureCount {
		return nil, ErrHTMLSendWorkV1
	}
	fresh, err := w.queries.GetHistoricalFinalizationSignatureReadHeaderV1(call, params)
	if err != nil {
		return nil, err
	}
	if fresh == nil || *fresh != *header {
		return nil, ErrHTMLSendWorkV1
	}
	rows, err := w.queries.ListSignaturesByDocument(call, w.logicalDocumentV1())
	if err != nil {
		return nil, err
	}
	if int64(len(rows)) != header.SignatureCount {
		return nil, ErrHTMLSendWorkV1
	}
	actual := int64(0)
	for _, row := range rows {
		if row == nil || row.ID == uuid.Nil || row.DocumentID != w.logicalDocumentV1() {
			return nil, ErrHTMLSendWorkV1
		}
		n, err := historicalFinalizationSignatureRawV1(row)
		if err != nil || !htmlInputAddV1(&actual, n, 1) {
			return nil, ErrHTMLSendWorkV1
		}
	}
	if actual != header.RawBytes {
		return nil, ErrHTMLSendWorkV1
	}
	state.signatures = make([]*generated.Signature, len(rows))
	for i, row := range rows {
		state.signatures[i] = historicalFinalizationCloneSignatureV1(row)
	}
	state.signatureViews = rows
	state.signatureRead = true
	return rows, nil
}
func historicalFinalizationIntentRawV1(row *generated.DocumentFinalizationIntent) (int64, error) {
	if row == nil {
		return 0, ErrHTMLSendWorkV1
	}
	return htmlAuthoringSumV1(int64(len(row.Mode)), int64(len(row.FinalPdfKey)), int64(len(row.FinalPdfSha256)), int64(len(row.FinalPdfVersionID.String)), int64(len(row.AuditCertKey)), int64(len(row.AuditCertSha256)), int64(len(row.AuditCertVersionID.String)), int64(len(row.AuditPayloadKey)), int64(len(row.AuditPayloadSha256)), int64(len(row.AuditPayloadVersionID.String)), int64(len(row.AuditSignatureKey)), int64(len(row.AuditSignatureSha256)), int64(len(row.AuditSignatureVersionID.String)), int64(len(row.LastError.String)), int64(len(row.FitsIndexStorageKey.String)), int64(len(row.FitsIndexVersionID.String)), int64(len(row.FitsIndexSha256)))
}
func historicalFinalizationCloneIntentV1(row *generated.DocumentFinalizationIntent) *generated.DocumentFinalizationIntent {
	if row == nil {
		return nil
	}
	copy := *row
	copy.FinalPdfSha256 = bytes.Clone(row.FinalPdfSha256)
	copy.AuditCertSha256 = bytes.Clone(row.AuditCertSha256)
	copy.AuditPayloadSha256 = bytes.Clone(row.AuditPayloadSha256)
	copy.AuditSignatureSha256 = bytes.Clone(row.AuditSignatureSha256)
	copy.FitsIndexSha256 = bytes.Clone(row.FitsIndexSha256)
	return &copy
}
func (w *ApplicationHTMLSendWorkV1) ReadHistoricalFinalizationIntentV1(call context.Context) (*generated.DocumentFinalizationIntent, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	state, err := w.historicalFinalizationIntentStateV1(call)
	if err != nil {
		return nil, err
	}
	if state.intentRead {
		if state.intent == nil {
			return nil, pgx.ErrNoRows
		}
		return state.intentView, nil
	}
	if state.intentAttempted {
		return nil, ErrHTMLSendWorkV1
	}
	state.intentAttempted = true
	header, err := w.queries.GetHistoricalFinalizationIntentReadHeaderV1(call, generated.GetHistoricalFinalizationIntentReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if err != nil {
		return nil, err
	}
	if header == nil || header.DocumentID != w.logicalDocumentV1() || header.OrgID != w.session.state.org || header.UpdatedAt != w.historicalFinalizationUpdatedAtV1() || header.RawBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	raw := header.RawBytes
	if !htmlInputAddV1(&raw, 1, 5*int64(unsafe.Sizeof(generated.DocumentFinalizationIntent{}))+int64(unsafe.Sizeof(generated.CreateDocumentFinalizationIntentParams{}))+2*int64(unsafe.Sizeof(generated.GetHistoricalFinalizationIntentReadHeaderV1Row{}))) {
		return nil, ErrHTMLSendWorkV1
	}
	closeRow, err := w.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
	if err != nil {
		return nil, err
	}
	w.closes = append(w.closes, closeRow)
	row, err := w.queries.GetDocumentFinalizationIntent(call, generated.GetDocumentFinalizationIntentParams{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org})
	if !header.HasIntent {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrHTMLSendWorkV1
		}
		state.intentRead = true
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	n, err := historicalFinalizationIntentRawV1(row)
	if err != nil || n != header.RawBytes || row.DocumentID != w.logicalDocumentV1() || row.OrgID != w.session.state.org {
		return nil, ErrHTMLSendWorkV1
	}
	state.intent = historicalFinalizationCloneIntentV1(row)
	state.intentView = row
	state.intentRead = true
	return row, nil
}
