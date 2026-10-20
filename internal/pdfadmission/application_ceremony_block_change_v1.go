// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sourcejson"
)

// ApplyApprovedBlockChangeV1 is the original first-quoted-occurrence edit,
// derived ONLY from this actual workflow's private locked document and change.
// The fixed engine has already run original actor/state/open-change/auto-apply/
// captured-evidence policy. No caller tree, document, source bytes, edit callback,
// cost, query, result or historical measurement is accepted as native authority.
// PDF/HTML and incomplete marks remain the original no-op. No post-edit grammar
// validator is added: the old path parsed the original canonical tree, replaced
// one text occurrence, then marshaled it without reinterpreting proposed prose.
func (w *ApplicationHTMLCeremonyWorkflowV1) ApplyApprovedBlockChangeV1(call context.Context) error {
	if !w.validCallV1(call) || w.operation.state.workflow != HTMLCeremonyChangeDecisionV1 {
		return ErrHTMLCeremonyWorkflowV1
	}
	if err := w.captureBodyV1(call); err != nil {
		return err
	}
	w.mu.Lock()
	if w.autoApplyAttempted || w.resolveAttempted || w.change == nil || w.snapshot == nil || w.snapshot.document == nil {
		w.mu.Unlock()
		return ErrHTMLCeremonyWorkflowV1
	}
	w.autoApplyAttempted = true
	original, change := w.snapshot.document, w.change
	w.mu.Unlock()
	if change.DocumentID != original.ID || original.Status != "changes_requested" || change.Status != "open" {
		return ErrHTMLCeremonyWorkflowV1
	}
	if original.SourceKind != "blocks" || change.BlockID == "" || change.Quote == "" || change.Proposed == "" {
		return nil
	}
	if len(original.HtmlSourceJson) != 0 || len(original.HtmlCurrentSourceJson) != 0 || original.HtmlCurrentMaterializationID.Valid {
		return ErrHTMLCeremonyWorkflowV1
	}
	// Fund actual private work/decimal bookkeeping before its allocation. The
	// original reader remains borrowed by w through every result/publication.
	headers := 2 * int64(unsafe.Sizeof(applicationBlocksCreationStateV1{}))
	headers += 2 * int64(unsafe.Sizeof(ApplicationBlocksCreationWriterV1{}))
	headers += 2 * int64(unsafe.Sizeof([]func(){}))
	if err := w.retainV1(call, headers, 0); err != nil {
		return err
	}
	q, err := w.queriesV1(call)
	if err != nil {
		return err
	}
	work := &applicationBlocksCreationStateV1{session: w.stage.state.session, reader: w.reader.authoring, queries: q}
	owner := &ApplicationBlocksCreationWriterV1{state: work}
	w.mu.Lock()
	w.closeConsumers = append(w.closeConsumers, owner.CloseConsumerV1)
	w.mu.Unlock()
	// This is the same first-party lexical decoder and decimal magnitude hook
	// already used by native block writers. All increasing decimal loans remain
	// in this original work through actual workflow/physical-backend retirement.
	lexical, err := plainSendBlockLexicalWorkV1(call, original.BlocksJson)
	if err != nil {
		return err
	}
	if err = work.holdV1(call, lexical, 0); err != nil {
		return err
	}
	work.processing = true
	defer func() { work.processing = false }()
	tree, err := blocks.ParseCanonicalTreeForSendV1(original.BlocksJson, blocksCreationDecimalAdmissionV1{state: work, ctx: call})
	if work.admissionFailure != nil {
		return work.admissionFailure
	}
	if err != nil {
		return fmt.Errorf("parse blocks for change: %w", err)
	}
	var target *blocks.Block
	var visit func([]blocks.Block) error
	visit = func(items []blocks.Block) error {
		for i := range items {
			if err := call.Err(); err != nil {
				return err
			}
			if target == nil && items[i].ID == change.BlockID && strings.Contains(items[i].Text, change.Quote) {
				target = &items[i]
			}
			if len(items[i].Content) > 0 {
				if err := visit(items[i].Content); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err = visit(tree.Blocks); err != nil {
		return err
	}
	if target == nil {
		return nil
	}
	// Price the actual replacement backing before strings.Replace allocates it.
	newText, err := htmlAuthoringSumV1(int64(len(target.Text)), int64(len(change.Proposed)))
	if err != nil {
		return err
	}
	if err = work.holdV1(call, newText, 0); err != nil {
		return err
	}
	target.Text = strings.Replace(target.Text, change.Quote, change.Proposed, 1)
	upper, err := blocksCanonicalOutputUpperV1(call, tree)
	if err != nil {
		return err
	}
	if err = work.holdV1(call, upper, upper); err != nil {
		return err
	}
	raw, err := json.Marshal(tree)
	if err != nil {
		return err
	}
	if int64(len(raw)) > upper {
		return ErrHTMLCeremonyWorkflowV1
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(call, raw)
	if err != nil {
		return err
	}
	if err = work.holdV1(call, int64(len(raw)), wire); err != nil {
		return err
	}
	oldWire, err := htmlCeremonyDocumentWireV1(original)
	if err != nil {
		return err
	}
	returnedWire, err := htmlAuthoringSumV1(oldWire, wire)
	if err != nil {
		return err
	}
	if err = w.retainV1(call, signerDocumentRawBytesV1(original), returnedWire); err != nil {
		return err
	}
	row, err := q.ApplyBlocksForChange(call, generated.ApplyBlocksForChangeParams{ID: original.ID, OrgID: original.OrgID, BlocksJson: raw})
	if err != nil {
		return fmt.Errorf("apply approved change: %w", err)
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) || int64(len(row.BlocksJson)) > wire {
		return ErrHTMLCeremonyWorkflowV1
	}
	expected := *original
	expected.BlocksJson, expected.UpdatedAt = row.BlocksJson, row.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return ErrHTMLCeremonyWorkflowV1
	}
	// Retain the actual input and RETURNING model through the same original
	// workflow close. No caller mutation can change its original private source.
	work.blocks, work.doc = raw, row
	// Only this actual new source write may derive fresh source measurements.
	// An earlier missing/stale body cache failed at ReadActorDocumentV1; there
	// is no read-time refresh or repair of old events or historical snapshots.
	policy, err := q.MeasureSignatureFitHTMLPolicyDocumentV1(call, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: row.ID, OrgID: row.OrgID})
	if err != nil {
		return err
	}
	if policy == nil || policy.DocumentID != row.ID || policy.OrgID != row.OrgID || policy.HtmlOriginWireBytes != 0 || policy.HtmlCurrentWireBytes != 0 || policy.VariablesWireBytes != int64(len(original.VariablesJson)) || policy.MeasurementServerVersionNum <= 0 {
		return ErrHTMLCeremonyWorkflowV1
	}
	response, err := q.MeasureNegotiatedBlocksResponseV1(call, generated.MeasureNegotiatedBlocksResponseV1Params{DocumentID: row.ID, OrgID: row.OrgID, ExpectedUpdatedAt: row.UpdatedAt})
	if err != nil {
		return err
	}
	if response == nil || response.DocumentID != row.ID || response.OrgID != row.OrgID || response.BlocksWireBytes < 1 || response.BlocksWireBytes > wire || response.MetadataWireBytes != int64(len(original.Metadata)) || response.MeasurementServerVersionNum != policy.MeasurementServerVersionNum {
		return ErrHTMLCeremonyWorkflowV1
	}
	report, err := q.MeasureSignerDocumentReportV1(call, generated.MeasureSignerDocumentReportV1Params{DocumentID: row.ID, OrgID: row.OrgID})
	if err != nil {
		return err
	}
	if report == nil || report.DocumentID != row.ID || report.OrgID != row.OrgID || report.ReportWireBytes != int64(len(original.MetadataRedactionReport)) || report.MeasurementServerVersionNum != policy.MeasurementServerVersionNum || !w.validCallV1(call) {
		return ErrHTMLCeremonyWorkflowV1
	}
	return nil
}
