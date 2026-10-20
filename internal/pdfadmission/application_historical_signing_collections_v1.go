// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/db/generated"
)

// Only fixed native historical mutation/preparation stages select this suite.
// The caller cannot supply status, session, cost, rows or an alternate DBTX.
// Original Send keeps its independent draft/sealing predicates byte-for-byte.
func (w *ApplicationHTMLSendWorkV1) historicalSigningCollectionsV1() bool {
	// Ordinary durable-output preparation revalidates the same frozen signing
	// page under its genuine finalization Stage callback. Its finalizing root
	// must use the existing historical row/cache/loan suite; the independent
	// Send suite intentionally admits only draft/sealing documents.
	return w.stage != nil && (w.stage.purpose == HTMLBlockSignPreparationV1 || w.stage.purpose == HTMLBlockSignMutationV1 || w.stage.purpose == HTMLHistoricalFinalizationClaimV1 || w.stage.purpose == HTMLHistoricalFinalizationStageV1 || w.stage.purpose == HTMLHistoricalFinalizationResumeV1 || w.stage.purpose == HTMLHistoricalFinalizationPublicationV1 || w.stage.purpose == HTMLHistoricalFinalizationSourceV1 || w.stage.purpose == HTMLAcknowledgementMutationV1 || w.stage.purpose == HTMLSignerFieldsMutationV1 || w.stage.purpose == HTMLReminderManualV1 || w.stage.purpose == HTMLReminderScheduledV1)
}
func (w *ApplicationHTMLSendWorkV1) readCollectionHeaderForPurposeV1(call context.Context) (*generated.GetHTMLSendCollectionReadHeaderV1Row, error) {
	params := generated.GetHTMLSendCollectionReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org}
	if !w.historicalSigningCollectionsV1() {
		return w.queries.GetHTMLSendCollectionReadHeaderV1(call, params)
	}
	row, err := w.queries.GetHistoricalSigningCollectionReadHeaderV1(call, generated.GetHistoricalSigningCollectionReadHeaderV1Params(params))
	if row == nil {
		return nil, err
	}
	copy := generated.GetHTMLSendCollectionReadHeaderV1Row(*row)
	return &copy, err
}
func (w *ApplicationHTMLSendWorkV1) lockCollectionRowsForPurposeV1(call context.Context) (*generated.LockHTMLSendCollectionRowsV1Row, error) {
	params := generated.LockHTMLSendCollectionRowsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org}
	if !w.historicalSigningCollectionsV1() {
		return w.queries.LockHTMLSendCollectionRowsV1(call, params)
	}
	row, err := w.queries.LockHistoricalSigningCollectionRowsV1(call, generated.LockHistoricalSigningCollectionRowsV1Params(params))
	if row == nil {
		return nil, err
	}
	copy := generated.LockHTMLSendCollectionRowsV1Row(*row)
	return &copy, err
}
func (w *ApplicationHTMLSendWorkV1) verifyCollectionHeaderForPurposeV1(call context.Context, h *generated.GetHTMLSendCollectionReadHeaderV1Row) (*generated.VerifyHTMLSendCollectionReadHeaderV1Row, error) {
	params := generated.VerifyHTMLSendCollectionReadHeaderV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org, ExpectedRecipientCount: h.RecipientCount, ExpectedRecipientRawBytes: h.RecipientRawBytes, ExpectedFieldCount: h.FieldCount, ExpectedFieldRawBytes: h.FieldRawBytes, ExpectedFieldOptionsWireBytes: h.FieldOptionsWireBytes, ExpectedBindingCount: h.BindingCount, ExpectedBindingRawBytes: h.BindingRawBytes}
	if !w.historicalSigningCollectionsV1() {
		return w.queries.VerifyHTMLSendCollectionReadHeaderV1(call, params)
	}
	row, err := w.queries.VerifyHistoricalSigningCollectionReadHeaderV1(call, generated.VerifyHistoricalSigningCollectionReadHeaderV1Params(params))
	if row == nil {
		return nil, err
	}
	copy := generated.VerifyHTMLSendCollectionReadHeaderV1Row(*row)
	return &copy, err
}
func (w *ApplicationHTMLSendWorkV1) listCollectionRecipientsForPurposeV1(call context.Context, h *generated.GetHTMLSendCollectionReadHeaderV1Row) ([]*generated.Recipient, error) {
	params := generated.ListHTMLSendRecipientsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org, ExpectedCount: h.RecipientCount, ExpectedRawBytes: h.RecipientRawBytes}
	if !w.historicalSigningCollectionsV1() {
		return w.queries.ListHTMLSendRecipientsV1(call, params)
	}
	return w.queries.ListHistoricalSigningRecipientsV1(call, generated.ListHistoricalSigningRecipientsV1Params(params))
}
func (w *ApplicationHTMLSendWorkV1) listCollectionFieldsForPurposeV1(call context.Context, h *generated.GetHTMLSendCollectionReadHeaderV1Row) ([]*generated.DocumentField, error) {
	params := generated.ListHTMLSendFieldsV1Params{DocumentID: w.logicalDocumentV1(), OrgID: w.session.state.org, ExpectedCount: h.FieldCount, ExpectedRawBytes: h.FieldRawBytes, ExpectedOptionsWireBytes: h.FieldOptionsWireBytes}
	if !w.historicalSigningCollectionsV1() {
		return w.queries.ListHTMLSendFieldsV1(call, params)
	}
	return w.queries.ListHistoricalSigningFieldsV1(call, generated.ListHistoricalSigningFieldsV1Params(params))
}
