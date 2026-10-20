// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
)

// MeasureFreshPolicyV1 derives only the new projection and fields produced by
// THIS writer. Its original source/candidate/collection uses and complete native
// writer loan remain held across every dispatch and returned scalar. Missing
// old rows never cause this method to run, and it does not repair M92 metadata.
func (w *ApplicationHTMLRevisionWriterV1) MeasureFreshPolicyV1(call context.Context) error {
	done, err := w.beginV1(call)
	if err != nil {
		return err
	}
	defer done()
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.validV1(call) || !w.appended || !w.fieldsWritten || w.measured ||
		w.queries == nil || w.original == nil || w.updated == nil || w.row == nil ||
		w.candidate == nil || w.candidate.document == nil {
		return ErrHTMLRevisionWriterV1
	}
	document, org := w.original.ID, w.original.OrgID
	if document == uuid.Nil || org == uuid.Nil || w.updated.ID != document || w.updated.OrgID != org ||
		w.candidate.document.ID != document || w.candidate.document.OrgID != org ||
		w.row.ID == uuid.Nil || w.row.DocumentID != document || w.row.OrgID != org ||
		!w.updated.HtmlCurrentMaterializationID.Valid || uuid.UUID(w.updated.HtmlCurrentMaterializationID.Bytes) != w.row.ID ||
		!w.updated.HtmlCurrentMaterializationSequence.Valid || w.updated.HtmlCurrentMaterializationSequence.Int32 != w.row.Sequence ||
		w.originWireUpper < 1 || w.sourceWireUpper < 1 || w.variablesWireUpper < 1 || w.reportWireUpper < 1 {
		return ErrHTMLRevisionWriterV1
	}
	// Generic designs create no managed fields; the fixed signing-page producer
	// creates the two intended-party fields. Both IDs and models are private
	// results retained from its actual INSERTs, never a list of existing fields.
	if len(w.freshFields) != len(w.freshFieldIDs) || (len(w.freshFields) != 0 && len(w.freshFields) != 2) {
		return ErrHTMLRevisionWriterV1
	}
	var fieldWire [2]int64
	for i, field := range w.freshFields {
		if field == nil || field.ID == uuid.Nil || field.ID != w.freshFieldIDs[i] || field.DocumentID != document ||
			(i == 1 && field.ID == w.freshFieldIDs[0]) || len(field.OptionsJson) > 2048 {
			return ErrHTMLRevisionWriterV1
		}
		fieldWire[i], err = sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, field.OptionsJson)
		if err != nil {
			return err
		}
		// The writer constructor prices two fixed 2048-byte option envelopes.
		if fieldWire[i] < 1 || fieldWire[i] > 2048 {
			return ErrHTMLRevisionWriterV1
		}
	}
	// Validate every retained ID/option bound before the first size-cache write.
	sizes, err := w.queries.MeasureSignatureFitHTMLPolicyDocumentV1(call, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{
		DocumentID: document, OrgID: org,
	})
	if err != nil {
		return err
	}
	if sizes == nil || sizes.DocumentID != document || sizes.OrgID != org || sizes.MeasurementServerVersionNum < 1 ||
		sizes.HtmlOriginWireBytes < 1 || sizes.HtmlOriginWireBytes > w.originWireUpper ||
		sizes.HtmlCurrentWireBytes < 1 || sizes.HtmlCurrentWireBytes > w.sourceWireUpper ||
		sizes.VariablesWireBytes < 1 || sizes.VariablesWireBytes > w.variablesWireUpper {
		return ErrHTMLRevisionWriterV1
	}
	for i, id := range w.freshFieldIDs {
		size, err := w.queries.MeasureSignatureFitHTMLPolicyFieldV1(call, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{
			DocumentID: document, OrgID: org, FieldID: id,
		})
		if err != nil {
			return err
		}
		if size == nil || size.DocumentID != document || size.OrgID != org || size.FieldID != id ||
			size.MeasurementServerVersionNum != sizes.MeasurementServerVersionNum ||
			size.OptionsWireBytes < 1 || size.OptionsWireBytes > fieldWire[i] {
			return ErrHTMLRevisionWriterV1
		}
	}
	// The exact new report is owned by the candidate. Only Project's actual
	// COALESCE(NULL,'{}') case has the literal two-byte bound set by NewWriter.
	report, err := w.queries.MeasureSignerDocumentReportV1(call, generated.MeasureSignerDocumentReportV1Params{
		DocumentID: document, OrgID: org,
	})
	if err != nil {
		return err
	}
	if report == nil || report.DocumentID != document || report.OrgID != org ||
		report.MeasurementServerVersionNum != sizes.MeasurementServerVersionNum ||
		report.ReportWireBytes < 1 || report.ReportWireBytes > w.reportWireUpper || !w.validV1(call) {
		return ErrHTMLRevisionWriterV1
	}
	w.measured = true
	return nil
}
