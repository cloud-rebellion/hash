// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpurpose"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"math"
	"unsafe"
)

// Parent is already held by THIS native reader/creator. EXISTS is deliberately
// scalar and bounded; it does not collect recipient, field or package bodies.
const documentPurposeTransitionSQLV1 = `SELECT
 EXISTS(SELECT 1 FROM recipients WHERE document_id=$1),
 EXISTS(SELECT 1 FROM document_fields WHERE document_id=$1),
 EXISTS(SELECT 1 FROM document_packages_v1 WHERE document_id=$1 AND org_id=$2),
 EXISTS(SELECT 1 FROM document_attachment_drafts_v1 WHERE member_document_id=$1 AND org_id=$2),
 EXISTS(SELECT 1 FROM documents WHERE parent_envelope_id=$1 AND org_id=$2),
 EXISTS(SELECT 1 FROM documents d WHERE d.id=$1 AND d.org_id=$2 AND (
  COALESCE(d.html_source_json #> '{master,contract_profile}','null'::jsonb)<>'null'::jsonb OR
  COALESCE(d.html_current_source_json #> '{master,contract_profile}','null'::jsonb)<>'null'::jsonb OR
  COALESCE(d.html_source_json->'party_bindings','[]'::jsonb)<>'[]'::jsonb OR
  COALESCE(d.html_current_source_json->'party_bindings','[]'::jsonb)<>'[]'::jsonb OR
  COALESCE(d.html_source_json->'signing_artifact','null'::jsonb)<>'null'::jsonb OR
  COALESCE(d.html_current_source_json->'signing_artifact','null'::jsonb)<>'null'::jsonb))`
const measureDocumentPurposeResponseSQLV1 = `WITH parent AS MATERIALIZED (
 SELECT id,org_id FROM documents WHERE id=$1 AND org_id=$2 AND updated_at=$3
 AND status='draft' AND deleted_at IS NULL FOR UPDATE NOWAIT)
 INSERT INTO html_creation_response_sizes_v1(document_id,org_id,blocks_wire_bytes,metadata_wire_bytes,measurement_server_version_num,measured_at)
 SELECT id,org_id,0,0,current_setting('server_version_num')::integer,clock_timestamp() FROM parent
 ON CONFLICT(document_id) DO UPDATE SET org_id=EXCLUDED.org_id RETURNING *`

type ApplicationDocumentPurposeWriterV1 struct {
	state *applicationBlocksMutationStateV1
}

func (h *ApplicationSessionV1) NewDocumentPurposeWriterV1(ctx context.Context, r *ApplicationHTMLRevisionReaderV1) (*ApplicationDocumentPurposeWriterV1, error) {
	// The private handle exposes purpose only: it never exposes block/PDF edits
	// for the additional HTML source accepted by this constructor.
	w, err := h.newBlocksMutationWriterWithCRMV1(ctx, r, true, true)
	if err != nil {
		return nil, err
	}
	return &ApplicationDocumentPurposeWriterV1{w.state}, nil
}
func (w *ApplicationDocumentPurposeWriterV1) ChangeV1(ctx context.Context, p documentpurpose.Purpose) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || s.attempted {
		return nil, ErrBlocksWriterV1
	}
	s.attempted = true
	if err := validateDocumentBlocksPurposeV1(ctx, s.snapshot.document, p, s.sourceWork); err != nil {
		return nil, err
	}
	row, err := applyDocumentPurposeV1(ctx, &applicationOwnedDBTXV1{session: s.session.state}, s.sourceWork.queries, s.snapshot.document, p, s.sourceWork.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	s.measured = true
	return row, nil
}
func (w *ApplicationDocumentPurposeWriterV1) CloseConsumerV1() {
	if w != nil {
		(&ApplicationBlocksMutationWriterV1{state: w.state}).CloseConsumerV1()
	}
}

// The actual parent/source owner funds lexical maps and both old/new response
// bodies BEFORE parsing or SQL. Loan remains in its registry through final
// response use plus real native client/backend closure.
func applyDocumentPurposeV1(ctx context.Context, db generated.DBTX, q *generated.Queries, old *generated.Document, p documentpurpose.Purpose, hold func(context.Context, int64, int64) error) (*generated.Document, error) {
	if old == nil || old.Status != "draft" || documentpurpose.Validate(p) != nil || hold == nil {
		return nil, documentpurpose.ErrInvalid
	}
	n := int64(len(old.Metadata))
	if n > (math.MaxInt64-(256<<10))/128 {
		return nil, ErrBlocksWriterV1
	}
	if err := hold(ctx, n*128+(256<<10), 0); err != nil {
		return nil, err
	}
	if _, err := documentpurpose.Parse(old.Metadata); err != nil {
		return nil, err
	}
	if p != documentpurpose.Signing {
		if old.IsEnvelope || old.ParentEnvelopeID.Valid {
			return nil, documentpurpose.ErrTransition
		}
		var recipients, fields, packages, annex, children, signingProfile bool
		if err := db.QueryRow(ctx, documentPurposeTransitionSQLV1, old.ID, old.OrgID).Scan(&recipients, &fields, &packages, &annex, &children, &signingProfile); err != nil {
			return nil, err
		}
		if recipients || fields || packages || annex || children || signingProfile {
			return nil, documentpurpose.ErrTransition
		}
	}
	metadata, err := documentpurpose.With(old.Metadata, p)
	if err != nil {
		return nil, err
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, metadata)
	if err != nil {
		return nil, err
	}
	raw, err := htmlAuthoringSumV1(2*signerDocumentRawBytesV1(old), 2*int64(unsafe.Sizeof(generated.Document{})), 2*int64(unsafe.Sizeof(generated.UpdateDocumentMetadataParams{})), 2*int64(unsafe.Sizeof(generated.HtmlCreationResponseSizesV1{})), 2*int64(len(metadata)))
	if err != nil {
		return nil, err
	}
	oldWire, err := htmlAuthoringSumV1(int64(len(old.HtmlSourceJson)), int64(len(old.HtmlCurrentSourceJson)), int64(len(old.BlocksJson)), int64(len(old.VariablesJson)), int64(len(old.MetadataRedactionReport)))
	if err != nil {
		return nil, err
	}
	if err = hold(ctx, raw, 2*(oldWire+wire)); err != nil {
		return nil, err
	}
	row, err := q.UpdateDocumentMetadata(ctx, generated.UpdateDocumentMetadataParams{ID: old.ID, OrgID: old.OrgID, Name: old.Name, ExpiresAt: old.ExpiresAt, Metadata: metadata})
	if err != nil {
		return nil, err
	}
	if row == nil || !applicationStampV1(row.UpdatedAt) || int64(len(row.Metadata)) > wire {
		return nil, ErrBlocksWriterV1
	}
	observed, err := documentpurpose.Parse(row.Metadata)
	if err != nil || observed != p {
		return nil, ErrBlocksWriterV1
	}
	expected := *old
	expected.Metadata = row.Metadata
	expected.UpdatedAt = row.UpdatedAt
	if !htmlSendDocumentExactTupleEqualV1(&expected, row) {
		return nil, ErrBlocksWriterV1
	}
	// PostgreSQL JSONB formatting differs from the private JSON input. Both exact
	// JSONB values must be semantically equal, including every external key.
	same, err := documentpurpose.EqualMetadata(metadata, row.Metadata)
	if err != nil || !same {
		return nil, ErrBlocksWriterV1
	}
	var response generated.HtmlCreationResponseSizesV1
	if err = db.QueryRow(ctx, measureDocumentPurposeResponseSQLV1, row.ID, row.OrgID, row.UpdatedAt).Scan(&response.DocumentID, &response.OrgID, &response.BlocksWireBytes, &response.MetadataWireBytes, &response.MeasurementServerVersionNum, &response.MeasuredAt); err != nil {
		return nil, err
	}
	if response.DocumentID != row.ID || response.OrgID != row.OrgID || response.BlocksWireBytes != int64(len(row.BlocksJson)) || response.MetadataWireBytes != int64(len(row.Metadata)) || response.MeasurementServerVersionNum < 1 {
		return nil, ErrBlocksWriterV1
	}
	return row, nil
}

// Fresh creators preserve historical omission/literal{} and only record an
// explicitly supplied purpose inside their original atomic transaction.
func freshPurposeMetadataV1(ctx context.Context, db generated.DBTX, q *generated.Queries, old *generated.Document, p documentpurpose.Purpose, hold func(context.Context, int64, int64) error) (*generated.Document, error) {
	if p == "" {
		return old, nil
	}
	if old == nil || !bytes.Equal(old.Metadata, []byte("{}")) {
		return nil, ErrBlocksWriterV1
	}
	return applyDocumentPurposeV1(ctx, db, q, old, p, hold)
}

func (w *ApplicationBlocksCreationWriterV1) RecordPurposeV1(ctx context.Context, p documentpurpose.Purpose) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrBlocksWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured {
		return nil, ErrBlocksWriterV1
	}
	if err := validateDocumentBlocksPurposeV1(ctx, s.doc, p, s); err != nil {
		return nil, err
	}
	row, err := freshPurposeMetadataV1(ctx, &applicationOwnedDBTXV1{session: s.session.state}, s.queries, s.doc, p, s.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	return row, nil
}
func (w *ApplicationPlainPDFCreationWriterV1) RecordPurposeV1(ctx context.Context, p documentpurpose.Purpose) (*generated.Document, error) {
	if w == nil || w.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := w.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validV1(ctx) || !s.created || s.measured {
		return nil, ErrPlainPDFWriterV1
	}
	row, err := freshPurposeMetadataV1(ctx, &applicationOwnedDBTXV1{session: s.session.state}, s.queries, s.doc, p, s.holdV1)
	if err != nil {
		return nil, err
	}
	s.doc = htmlRevisionCloneDocumentV1(row)
	return row, nil
}
func (w *ApplicationHTMLCreationWriterV1) RecordPurposeV1(ctx context.Context, p documentpurpose.Purpose) (*generated.Document, error) {
	if w == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.created || w.doc == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	if p == "" {
		return w.doc, nil
	}
	reader, err := w.session.NewHTMLAuthoringReaderV1(ctx)
	if err != nil {
		return nil, err
	}
	w.purposeCloses = append(w.purposeCloses, reader.CloseConsumerV1)
	hold := func(call context.Context, raw, wire int64) error {
		close, err := reader.acquireOwnedRetainedBodyV1(call, raw, wire)
		if err == nil {
			w.purposeCloses = append(w.purposeCloses, close)
		}
		return err
	}
	row, err := freshPurposeMetadataV1(ctx, &applicationOwnedDBTXV1{session: w.session.state}, w.queries, w.doc, p, hold)
	if err != nil {
		return nil, err
	}
	w.doc = row
	return row, nil
}

func requireSigningPurposeV1(ctx context.Context, metadata []byte, hold func(context.Context, int64, int64) error) error {
	// The schema-default legacy value needs no lexical map or extra body grant.
	if len(metadata) == 0 || bytes.Equal(metadata, []byte("{}")) {
		return nil
	}
	n := int64(len(metadata))
	if n > (math.MaxInt64-(32<<10))/128 {
		return ErrBlocksWriterV1
	}
	if err := hold(ctx, n*128+(32<<10), 0); err != nil {
		return err
	}
	return documentpurpose.RequireSigning(metadata)
}

// Fixed caller has already read this SAME actual parent under its native body
// loan. This grants no actor/workflow authority and cannot accept a caller row.
func (r *ApplicationHTMLRevisionReaderV1) RequireSigningPurposeV1(ctx context.Context) error {
	if r == nil || r.self != r {
		return ErrHTMLRevisionReadV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil {
		return ErrHTMLRevisionReadV1
	}
	hold := func(call context.Context, raw, wire int64) error {
		close, err := r.authoring.acquireOwnedRetainedBodyV1(call, raw, wire)
		if err == nil {
			r.closeConsumers = append(r.closeConsumers, close)
		}
		return err
	}
	return requireSigningPurposeV1(ctx, r.snapshot.document.Metadata, hold)
}

func purposeFromMetadataV1(ctx context.Context, metadata []byte, hold func(context.Context, int64, int64) error) (documentpurpose.Purpose, error) {
	if len(metadata) == 0 || bytes.Equal(metadata, []byte("{}")) {
		return documentpurpose.Signing, nil
	}
	n := int64(len(metadata))
	if n > (math.MaxInt64-(32<<10))/128 {
		return "", ErrBlocksWriterV1
	}
	if err := hold(ctx, n*128+(32<<10), 0); err != nil {
		return "", err
	}
	return documentpurpose.Parse(metadata)
}
func validateBlockTreePurposeV1(ctx context.Context, p documentpurpose.Purpose, tree *blocks.Tree) error {
	if p == documentpurpose.Signing {
		return nil
	}
	if documentpurpose.Validate(p) != nil || tree == nil {
		return documentpurpose.ErrInvalid
	}
	var walk func([]blocks.Block) error
	walk = func(items []blocks.Block) error {
		for _, b := range items {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch b.Type {
			case blocks.TypeSignatureField, blocks.TypeInitialField, blocks.TypeTextField, blocks.TypeDateField, blocks.TypeCheckbox:
				return documentpurpose.ErrSigningRequired
			}
			if err := walk(b.Content); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(tree.Blocks)
}
func validateDocumentBlocksPurposeV1(ctx context.Context, doc *generated.Document, p documentpurpose.Purpose, work *applicationBlocksCreationStateV1) error {
	if p == "" || p == documentpurpose.Signing || doc == nil || doc.SourceKind != "blocks" {
		return nil
	}
	raw, err := plainSendBlockLexicalWorkV1(ctx, doc.BlocksJson)
	if err != nil {
		return err
	}
	if err = work.holdV1(ctx, raw, 0); err != nil {
		return err
	}
	work.processing = true
	defer func() { work.processing = false }()
	tree, err := blocks.ParseTreeForAuthoringV1(ctx, doc.BlocksJson, blocksCreationDecimalAdmissionV1{state: work, ctx: ctx})
	if work.admissionFailure != nil {
		return work.admissionFailure
	}
	if err != nil {
		return err
	}
	return validateBlockTreePurposeV1(ctx, p, tree)
}
