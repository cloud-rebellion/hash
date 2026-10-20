// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math/big"
	"strings"
	"sync"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Only exact, newly INSERTed field results can be measured by this native
// producer. There is no field-ID input, old-row refresh or caller transaction.
// Each batch prices its actual typed parameters before copy/INSERT RETURNING;
// one loan covers the original <=1000 layout fields without spending1000 loans.
type ApplicationPlainPDFFieldBatchV1 struct {
	state *applicationPlainPDFFieldBatchStateV1
}
type applicationPlainPDFFieldBatchStateV1 struct {
	mu      sync.Mutex
	session *ApplicationSessionV1
	reader  *ApplicationHTMLAuthoringReaderV1
	queries *generated.Queries
	fields  []generated.CreateDraftFieldParams
	wires   []int64
	next    int
	close   func()
	closed  bool
}

func (h *ApplicationSessionV1) newPlainPDFFieldBatchV1(ctx context.Context, reader *ApplicationHTMLAuthoringReaderV1, fields []generated.CreateDraftFieldParams) (*ApplicationPlainPDFFieldBatchV1, error) {
	if h == nil || h.state == nil || reader == nil || reader.self != reader || reader.session != h || !reader.valid(ctx) || len(fields) < 1 || len(fields) > 1000 {
		return nil, ErrPlainPDFWriterV1
	}
	raw, err := htmlAuthoringSumV1(2*int64(unsafe.Sizeof(applicationPlainPDFFieldBatchStateV1{})), 2*int64(unsafe.Sizeof(ApplicationPlainPDFFieldBatchV1{})), int64(len(fields))*(2*int64(unsafe.Sizeof(generated.CreateDraftFieldParams{}))+16))
	if err != nil {
		return nil, err
	}
	var wire int64
	for _, p := range fields {
		if p.DocumentID != h.state.document || p.OrgID != h.state.org {
			return nil, ErrPlainPDFWriterV1
		}
		for _, n := range []pgtype.Numeric{p.XPct, p.YPct, p.WPct, p.HPct} {
			if !n.Valid || n.NaN || n.InfinityModifier != pgtype.Finite || n.Int == nil || !n.Int.IsInt64() || n.Exp != -4 || n.Int.Sign() < 0 || n.Int.Int64() > 1000000 {
				return nil, ErrPlainPDFWriterV1
			}
		}
		n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.OptionsJson)
		if err != nil {
			return nil, err
		}
		raw, err = htmlAuthoringSumV1(raw, int64(len(p.Type)), int64(len(p.Label.String)), int64(len(p.OptionsJson)))
		if err != nil {
			return nil, err
		}
		wire, err = htmlAuthoringSumV1(wire, n)
		if err != nil {
			return nil, err
		}
	}
	close, err := reader.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return nil, errors.Join(ErrPlainPDFWriterV1, err)
	}
	s := &applicationPlainPDFFieldBatchStateV1{session: h, reader: reader, queries: generated.New(&applicationOwnedDBTXV1{session: h.state}), close: close, fields: make([]generated.CreateDraftFieldParams, len(fields)), wires: make([]int64, len(fields))}
	for i, p := range fields {
		p.Type = strings.Clone(p.Type)
		p.Label.String = strings.Clone(p.Label.String)
		p.OptionsJson = bytes.Clone(p.OptionsJson)
		// pgtype.Numeric contains *big.Int. Detach its finite coefficient rather
		// than letting another mutable parameter overwrite actual persisted input.
		if p.XPct.Int != nil {
			p.XPct.Int = new(big.Int).Set(p.XPct.Int)
		}
		if p.YPct.Int != nil {
			p.YPct.Int = new(big.Int).Set(p.YPct.Int)
		}
		if p.WPct.Int != nil {
			p.WPct.Int = new(big.Int).Set(p.WPct.Int)
		}
		if p.HPct.Int != nil {
			p.HPct.Int = new(big.Int).Set(p.HPct.Int)
		}
		s.fields[i] = p
		s.wires[i], _ = sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.OptionsJson)
	}
	return &ApplicationPlainPDFFieldBatchV1{state: s}, nil
}
func (b *ApplicationPlainPDFFieldBatchV1) CreateNextV1(ctx context.Context) (*generated.DocumentField, error) {
	if b == nil || b.state == nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := b.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.session == nil || s.reader == nil || s.reader.session != s.session || !s.reader.valid(ctx) || s.next >= len(s.fields) {
		return nil, ErrPlainPDFWriterV1
	}
	index := s.next
	p := s.fields[index]
	s.next++
	row, err := s.queries.CreateDraftField(ctx, p)
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID == uuid.Nil || row.DocumentID != p.DocumentID || row.Value.Valid || row.CompletedAt.Valid || int64(len(row.OptionsJson)) > s.wires[index] {
		return nil, ErrPlainPDFWriterV1
	}
	// The ID is acknowledged only by this exact fresh INSERT in this SAME
	// native session. Even an identical pre-existing field cannot enter here.
	m, err := s.queries.MeasureSignatureFitHTMLPolicyFieldV1(ctx, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{DocumentID: p.DocumentID, OrgID: p.OrgID, FieldID: row.ID})
	if err != nil {
		return nil, err
	}
	if m == nil || m.FieldID != row.ID || m.DocumentID != p.DocumentID || m.OrgID != p.OrgID || m.OptionsWireBytes < 1 || m.OptionsWireBytes > s.wires[index] || m.MeasurementServerVersionNum < 1 {
		return nil, ErrPlainPDFWriterV1
	}
	return row, nil
}
func (b *ApplicationPlainPDFFieldBatchV1) CloseConsumerV1() {
	if b == nil || b.state == nil {
		return
	}
	s := b.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.fields = nil
	s.wires = nil
	if s.close != nil {
		s.close()
		s.close = nil
	}
}

// The actual parent/actor/credential/body read must finish before this
// explicit authoring input credit. It grants no authoring authority, nor any
// existing-field measurement. The fixed shared fields engine retains the
// original validation/error order and then supplies one exact normalized row.
func (r *ApplicationHTMLRevisionReaderV1) RetainPlainFieldInputV1(ctx context.Context, options []byte, kind, label string) error {
	if r == nil || r.self != r {
		return ErrPlainPDFWriterV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil {
		return ErrPlainPDFWriterV1
	}
	wire, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, options)
	// Invalid JSON is rejected by the original field validator at its original
	// position. Its raw copy still needs retained credit before that validator.
	if err != nil {
		wire = 0
	}
	raw, err := htmlAuthoringSumV1(int64(len(options)), int64(len(kind)), int64(len(label)), 2*int64(unsafe.Sizeof(generated.CreateDraftFieldParams{})))
	if err != nil {
		return err
	}
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, raw, wire)
	if err != nil {
		return err
	}
	r.closeConsumers = append(r.closeConsumers, close)
	return nil
}
func (r *ApplicationHTMLRevisionReaderV1) NewPlainPDFFieldBatchV1(ctx context.Context, fields []generated.CreateDraftFieldParams) (*ApplicationPlainPDFFieldBatchV1, error) {
	if r == nil || r.self != r {
		return nil, ErrPlainPDFWriterV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil {
		return nil, ErrPlainPDFWriterV1
	}
	return r.session.newPlainPDFFieldBatchV1(ctx, r.authoring, fields)
}

func (r *ApplicationHTMLRevisionReaderV1) ReadPlainFieldRecipientV1(ctx context.Context, id uuid.UUID) (*generated.Recipient, error) {
	if r == nil || r.self != r {
		return nil, ErrPlainPDFWriterV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || !r.bodyComplete || r.snapshot == nil || r.snapshot.document == nil || id == uuid.Nil {
		return nil, ErrPlainPDFWriterV1
	}
	s := r.session.state
	h, err := r.queries.GetPlainFieldRecipientReadHeaderV1(ctx, generated.GetPlainFieldRecipientReadHeaderV1Params{RecipientID: id, DocumentID: s.document, OrgID: s.org})
	if err != nil {
		return nil, err
	}
	if h == nil || h.ID != id || h.DocumentID != s.document || h.RawTextBytes < 0 {
		return nil, ErrPlainPDFWriterV1
	}
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, err
	}
	r.closeConsumers = append(r.closeConsumers, close)
	row, err := r.queries.ReadPlainFieldRecipientV1(ctx, generated.ReadPlainFieldRecipientV1Params{RecipientID: id, DocumentID: s.document, OrgID: s.org, ExpectedRawTextBytes: h.RawTextBytes})
	if err != nil {
		return nil, err
	}
	if row == nil || row.ID != id || row.DocumentID != s.document || int64(len(row.Role)+len(row.Email)+len(row.Name)+len(row.Status)+len(row.DeclinedReason.String)+len(row.Locale)+len(row.MagicTokenHash)) != h.RawTextBytes {
		return nil, ErrPlainPDFWriterV1
	}
	return row, nil
}

// Field authoring preserves its original source/signing-page refusal BEFORE
// Current() reads/expansion. The initial document is the real complete row;
// the immutable current projection is obtained only at that later stage.
func (r *ApplicationHTMLRevisionReaderV1) ReadFieldDocumentWithActorV1(ctx context.Context, user uuid.UUID, preflight func(HTMLRevisionReadAccessV1) error, gate func(HTMLRevisionReadAccessV1, *generated.User) error) (*HTMLRevisionReadModelsV1, error) {
	if gate == nil {
		return nil, ErrPlainPDFWriterV1
	}
	return r.readDocumentBodyModeV1(ctx, user, preflight, gate, false, true)
}
func (r *ApplicationHTMLRevisionReaderV1) ReadFieldCurrentV1(ctx context.Context) (*htmlmaterialization.CurrentReadProjectionV1, error) {
	if r == nil || r.self != r {
		return nil, ErrPlainPDFWriterV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(ctx) || !r.bodyComplete || !r.fieldCurrentDeferred || r.fieldCurrentAttempted || r.snapshot == nil || r.snapshot.document == nil {
		return nil, ErrPlainPDFWriterV1
	}
	r.fieldCurrentAttempted = true
	doc := r.snapshot.document
	if !doc.HtmlCurrentMaterializationID.Valid {
		return nil, nil
	}
	h, err := r.queries.GetSignerCurrentMaterializationHeaderV1(ctx, generated.GetSignerCurrentMaterializationHeaderV1Params{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, err
	}
	if h == nil || h.MaterializationID != uuid.UUID(doc.HtmlCurrentMaterializationID.Bytes) || h.DocumentID != doc.ID || h.OrgID != doc.OrgID || h.ServerVersionNum < 1 || h.MeasurementServerVersionNum != h.ServerVersionNum || h.RawTextBytes < 0 || h.SourceWireBytes < 1 || (h.ReportWireUpperBound != 0 && h.ReportWireUpperBound != 65536) {
		return nil, ErrPlainPDFWriterV1
	}
	wire, err := htmlAuthoringSumV1(h.SourceWireBytes, h.ReportWireUpperBound)
	if err != nil {
		return nil, err
	}
	close, err := r.authoring.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, wire)
	if err != nil {
		return nil, err
	}
	r.closeConsumers = append(r.closeConsumers, close)
	m, err := r.queries.ReadSignerCurrentMaterializationV1(ctx, generated.ReadSignerCurrentMaterializationV1Params{DocumentID: doc.ID, OrgID: doc.OrgID, ExpectedMaterializationID: h.MaterializationID, ExpectedSourceWireBytes: h.SourceWireBytes, ExpectedRawTextBytes: h.RawTextBytes, ExpectedReportWireUpperBound: h.ReportWireUpperBound})
	if err != nil {
		return nil, err
	}
	if m == nil || m.ID != h.MaterializationID || m.DocumentID != doc.ID || m.OrgID != doc.OrgID || int64(len(m.SourceJson)) != h.SourceWireBytes || int64(len(m.MetadataRedactionReport)) > h.ReportWireUpperBound || signerMaterializationRawBytesV1(m) != h.RawTextBytes {
		return nil, ErrPlainPDFWriterV1
	}
	row := &htmlmaterialization.CurrentReadProjectionV1{ID: m.ID, DocumentID: m.DocumentID, OrgID: m.OrgID, Sequence: m.Sequence, PageCount: m.PageCount, PdfKey: m.PdfKey, PdfVersionID: m.PdfVersionID, PdfSha256: m.PdfSha256, SourceCommitment: m.SourceCommitment, OriginCommitment: m.OriginCommitment, SourceJson: m.SourceJson, MetadataRedactionReport: m.MetadataRedactionReport}
	r.snapshot.current = htmlRevisionCloneCurrentV1(row)
	r.models.Current = row
	return row, nil
}
