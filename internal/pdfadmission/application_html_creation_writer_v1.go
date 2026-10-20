// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/htmlmaterialization"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/sourcejson"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

var ErrHTMLCreationWriterV1 = errors.New("pdfadmission: owned HTML creation writer unavailable")

// These are ACTUAL retained bytes from the private approved producer. They
// are not a size declaration, authority or a receipt for an existing DB row.
type HTMLCreationInputsV1 struct {
	StoredMaster, StoredDefaults       []byte
	CanonicalMaster, CanonicalDefaults []byte
	Variables, Sections                []byte
}
type HTMLCreationResourcesV1 struct {
	InputRawBytes, InputWireBytes, SourceWireUpperBound, WorkingBytes, DBStagingBytes int64
}

const htmlCreationSourceEnvelopeWireV1 int64 = 16384
const htmlCreationOtherWorkV1 int64 = 32 << 20

// Input strings and nested assets are counted without materializing output.
// New emits only the validated canonical master/defaults, exact values/sections,
// UUID/digest/time strings, at most2 party bindings and fixed integer geometry.
// The16384 allowance bounds that typed envelope, not unrestricted RawMessage.
// No input is normalized, hashed or rewritten by this preflight.
func HTMLCreationResourcesForV1(ctx context.Context, in HTMLCreationInputsV1) (HTMLCreationResourcesV1, error) {
	var r HTMLCreationResourcesV1
	var bounds [6]int64
	raws := [][]byte{in.StoredMaster, in.StoredDefaults, in.CanonicalMaster, in.CanonicalDefaults, in.Variables, in.Sections}
	for i, raw := range raws {
		n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
		if err != nil {
			return r, ErrHTMLCreationWriterV1
		}
		bounds[i] = n
		if int64(len(raw)) > math.MaxInt64-r.InputRawBytes {
			return HTMLCreationResourcesV1{}, ErrHTMLCreationWriterV1
		}
		r.InputRawBytes += int64(len(raw))
		if n > math.MaxInt64-r.InputWireBytes {
			return HTMLCreationResourcesV1{}, ErrHTMLCreationWriterV1
		}
		r.InputWireBytes += n
	}
	r.SourceWireUpperBound = htmlCreationSourceEnvelopeWireV1
	for _, n := range bounds[2:] {
		if n > math.MaxInt64-r.SourceWireUpperBound {
			return HTMLCreationResourcesV1{}, ErrHTMLCreationWriterV1
		}
		r.SourceWireUpperBound += n
	}
	return htmlCreationFixedResourcesV1(r.InputRawBytes, r.InputWireBytes, r.SourceWireUpperBound)
}

type ApplicationHTMLCreationWriterV1 struct {
	mu                                              sync.Mutex
	session                                         *ApplicationSessionV1
	queries                                         *generated.Queries
	org, document                                   uuid.UUID
	inputs                                          HTMLCreationInputsV1
	resources                                       HTMLCreationResourcesV1
	doc                                             *generated.Document
	source                                          []byte
	created, sourceWritten, originWritten, measured bool
	reportWireUpperBound                            int64
	closeConsumer                                   func()
}

// NewHTMLCreationWriterV1 can only start inside THIS native owned session's
// tracked callback, after its one admission registry exists. It acquires actual
// fixed coordinator costs before copy, fresh INSERT, template reread or body SQL.
// No external pgx transaction, caller grant, reported byte total or retired flag.
func (h *ApplicationSessionV1) NewHTMLCreationWriterV1(ctx context.Context, in HTMLCreationInputsV1) (*ApplicationHTMLCreationWriterV1, error) {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return nil, ErrHTMLCreationWriterV1
	}
	r, err := HTMLCreationResourcesForV1(ctx, in)
	if err != nil {
		return nil, err
	}
	s := h.state
	p := s.factory
	if p == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	// Same lock order as factory snapshots: factory -> session -> admission ->
	// fixed coordinator. Hold factory through this finite nonblocking admit,
	// so shutdown cannot miss an installed loan or remove an empty registry.
	p.mu.Lock()
	s.mu.Lock()
	a := s.admission
	if p.closing || p.work == nil || p.work.coordinator == nil || p.htmlAdmissions == nil ||
		s.observer || s.closed || s.unknown || s.ended || s.retired || s.creating || s.sqlActive || s.htmlWriterStarted || s.tx == nil || s.conn == nil ||
		!s.dialed || s.fence == nil || !applicationIdentityValidV1(s.fence.identity) ||
		a == nil || !a.valid() || a.fence != s.fence || a.cleanupDone != s.fence.clientDone ||
		!s.callbackActive || ctx.Value(applicationSessionCallbackKeyV1{}) != s ||
		(p.htmlAdmissions[a] == nil && len(p.htmlAdmissions) >= applicationSessionMaxWorkV1) {
		s.mu.Unlock()
		p.mu.Unlock()
		return nil, ErrHTMLCreationWriterV1
	}
	// A nonzero private registration object identifies this actual install.
	// Its identity is ONLY a cleanup-race guard, not a generation/retirement/
	// credential/row/replay proof. Retain even admitted cancellation/refusal.
	p.htmlAdmissions[a] = &applicationHTMLAdmissionRegistrationV1{admission: a}
	closeConsumer, err := a.admit(ctx, ApplicationBudgetV1{
		Phase: "locked-html-fresh-creation", OrgID: s.org, DocumentID: s.document,
		HTMLInputRawBytes: r.InputRawBytes, HTMLInputWireBytes: r.InputWireBytes, HTMLSourceWireBytes: r.SourceWireUpperBound,
		WorkingBytes: r.WorkingBytes, DBStagingBytes: r.DBStagingBytes,
	})
	if err == nil {
		s.htmlWriterStarted = true
	}
	s.mu.Unlock()
	p.mu.Unlock()
	if err != nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w := &ApplicationHTMLCreationWriterV1{session: h, org: s.org, document: s.document, resources: r, closeConsumer: closeConsumer}
	w.inputs = HTMLCreationInputsV1{
		StoredMaster: bytes.Clone(in.StoredMaster), StoredDefaults: bytes.Clone(in.StoredDefaults),
		CanonicalMaster: bytes.Clone(in.CanonicalMaster), CanonicalDefaults: bytes.Clone(in.CanonicalDefaults),
		Variables: bytes.Clone(in.Variables), Sections: bytes.Clone(in.Sections),
	}
	w.queries = generated.New(&applicationOwnedDBTXV1{session: s})
	if ctx.Err() != nil {
		closeConsumer()
		return nil, applicationErrorV1(ctx, nil)
	}
	return w, nil
}
func (w *ApplicationHTMLCreationWriterV1) valid(ctx context.Context) bool {
	if w == nil || w.session == nil || w.session.state == nil || w.queries == nil || w.closeConsumer == nil || !applicationContextV1(ctx) {
		return false
	}
	s := w.session.state
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.closed && !s.unknown && !s.ended && !s.retired && s.callbackActive && !s.sqlActive &&
		s.org == w.org && s.document == w.document && ctx.Value(applicationSessionCallbackKeyV1{}) == s
}

// CreatePDFDocument owns the real fresh INSERT with explicit scope ID. Caller
// cannot replace the target with an existing row: SQL INSERT and the PK enforce
// birth. This binds only native work/provenance scope; the unchanged application
// retains original actor, approved template, quota, CRM and final audit authority.
func (w *ApplicationHTMLCreationWriterV1) CreatePDFDocument(ctx context.Context, p generated.CreatePDFDocumentParams) (*generated.Document, error) {
	if w == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.created || p.OrgID != w.org || p.SenderID == uuid.Nil || !p.TemplateID.Valid || uuid.UUID(p.TemplateID.Bytes) == uuid.Nil ||
		!p.PdfStorageKey.Valid || len(p.PdfStorageKey.String) < 1 || len(p.PdfStorageKey.String) > 1024 ||
		!p.PdfStorageVersionID.Valid || len(p.PdfStorageVersionID.String) < 1 || len(p.PdfStorageVersionID.String) > 1024 ||
		len(p.PdfSha256) != 32 || len(p.Name) < 1 || len(p.Name) > 800 || !p.EvidenceVersionPinsRequired ||
		(p.ExpiresAt.Valid && p.ExpiresAt.InfinityModifier != pgtype.Finite) {
		return nil, ErrHTMLCreationWriterV1
	}
	doc, err := w.queries.CreateFreshHTMLPDFDocumentV1(ctx, generated.CreateFreshHTMLPDFDocumentV1Params{
		ID: w.document, OrgID: p.OrgID, TemplateID: p.TemplateID, Name: p.Name,
		PdfStorageKey: p.PdfStorageKey, PdfSha256: p.PdfSha256, PdfStorageVersionID: p.PdfStorageVersionID,
		EvidenceVersionPinsRequired: p.EvidenceVersionPinsRequired, SenderID: p.SenderID, ExpiresAt: p.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	if doc == nil || doc.ID != w.document || doc.OrgID != w.org || doc.Status != "draft" || doc.SourceKind != "pdf" ||
		len(doc.HtmlSourceJson) != 0 || len(doc.HtmlCurrentSourceJson) != 0 || !bytes.Equal(doc.VariablesJson, []byte("{}")) || !bytes.Equal(doc.MetadataRedactionReport, []byte("{}")) {
		return nil, ErrHTMLCreationWriterV1
	}
	w.doc = doc
	w.created = true
	// The actual fresh INSERT owns the schema default {} report (wire2).
	w.reportWireUpperBound = 2
	return doc, nil
}
func (w *ApplicationHTMLCreationWriterV1) FreezeVariablesV1(ctx context.Context, expected pgtype.Timestamptz) (*generated.Document, error) {
	if w == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.created || w.sourceWritten {
		return nil, ErrHTMLCreationWriterV1
	}
	doc, err := w.queries.FreezeDocumentVariables(ctx, generated.FreezeDocumentVariablesParams{
		ID: w.document, OrgID: w.org, VariablesJson: w.inputs.Variables, ExpectedUpdatedAt: expected,
	})
	if err != nil {
		return nil, err
	}
	w.doc = doc
	return doc, nil
}

// SetSourceAndOriginV1 executes only the first-set source and existing unchanged
// RegisterOrigin producer on this native newly inserted row. It cannot load or
// opportunistically measure an old unbounded document.
func (w *ApplicationHTMLCreationWriterV1) SetSourceAndOriginV1(ctx context.Context, raw []byte, expected pgtype.Timestamptz, pages int32, actor uuid.UUID) (*generated.Document, error) {
	if w == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.created || w.sourceWritten || w.doc == nil {
		return nil, ErrHTMLCreationWriterV1
	}
	n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
	if err != nil || n > w.resources.SourceWireUpperBound || int64(len(raw)) > w.resources.SourceWireUpperBound {
		return nil, ErrHTMLCreationWriterV1
	}
	candidate := *w.doc
	candidate.HtmlSourceJson = raw
	if err := htmlsource.Validate(&candidate, false); err != nil {
		return nil, err
	}
	w.source = bytes.Clone(raw)
	doc, err := w.queries.SetDocumentHTMLSource(ctx, generated.SetDocumentHTMLSourceParams{
		ID: w.document, OrgID: w.org, HtmlSourceJson: w.source, ExpectedUpdatedAt: expected,
	})
	if err != nil {
		return nil, err
	}
	w.sourceWritten = true
	w.doc = doc
	doc, _, err = htmlmaterialization.RegisterOrigin(ctx, w.queries, doc, pages, actor)
	if err != nil {
		return nil, err
	}
	w.doc = doc
	w.originWritten = true
	return doc, nil
}

// Metadata report is fixed internal worker output, not contract prose. Bound
// its actual retained raw and JSONB output before dispatch; the fresh32MiB
// other-work allowance covers this supported1MiB report and small new rows.
func (w *ApplicationHTMLCreationWriterV1) UpdateMetadataRedactionReport(ctx context.Context, p generated.UpdateMetadataRedactionReportParams) error {
	if w == nil {
		return ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.created || w.sourceWritten || p.ID != w.document || len(p.MetadataRedactionReport) > 1<<20 {
		return ErrHTMLCreationWriterV1
	}
	n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, p.MetadataRedactionReport)
	if err != nil || n > 1<<20 {
		return ErrHTMLCreationWriterV1
	}
	if err := w.queries.UpdateMetadataRedactionReport(ctx, p); err != nil {
		return err
	}
	// Only acknowledged worker output replaces the default bound. This is
	// retained under the original creator loan, never an old-row refresh.
	w.reportWireUpperBound = n
	return nil
}

// Fresh signing fields are created by the existing typed two-party helper in
// this same fixed application callback. They cannot be concurrent old rows:
// the native newly INSERTed parent is not visible outside this transaction.
// Existing HTML design, review, parties, current source and history are preserved.
func (w *ApplicationHTMLCreationWriterV1) MeasureFreshPolicyV1(ctx context.Context) error {
	if w == nil {
		return ErrHTMLCreationWriterV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || !w.originWritten || w.measured {
		return ErrHTMLCreationWriterV1
	}
	sizes, err := w.queries.MeasureSignatureFitHTMLPolicyDocumentV1(ctx, generated.MeasureSignatureFitHTMLPolicyDocumentV1Params{DocumentID: w.document, OrgID: w.org})
	if err != nil {
		return err
	}
	vars, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, w.inputs.Variables)
	if err != nil || sizes == nil || sizes.DocumentID != w.document || sizes.OrgID != w.org ||
		sizes.HtmlOriginWireBytes < 1 || sizes.HtmlOriginWireBytes > w.resources.SourceWireUpperBound ||
		sizes.HtmlCurrentWireBytes < 1 || sizes.HtmlCurrentWireBytes > w.resources.SourceWireUpperBound ||
		sizes.VariablesWireBytes < 1 || sizes.VariablesWireBytes > vars {
		return ErrHTMLCreationWriterV1
	}
	fields, err := w.queries.ListFieldsByDocument(ctx, w.document)
	if err != nil {
		return err
	}
	if len(fields) != 0 && len(fields) != 2 {
		return ErrHTMLCreationWriterV1
	}
	for _, field := range fields {
		if field == nil || field.DocumentID != w.document || len(field.OptionsJson) > 2048 {
			return ErrHTMLCreationWriterV1
		}
		n, err := sourcejson.PostgreSQLJSONBWireUpperBoundV1(ctx, field.OptionsJson)
		if err != nil {
			return err
		}
		size, err := w.queries.MeasureSignatureFitHTMLPolicyFieldV1(ctx, generated.MeasureSignatureFitHTMLPolicyFieldV1Params{
			DocumentID: w.document, OrgID: w.org, FieldID: field.ID,
		})
		if err != nil {
			return err
		}
		if size == nil || size.DocumentID != w.document || size.OrgID != w.org || size.FieldID != field.ID || size.OptionsWireBytes < 1 || size.OptionsWireBytes > n {
			return ErrHTMLCreationWriterV1
		}
	}
	// The native fresh PDF INSERT owns NULL blocks and literal {} metadata.
	// Measure only this new row under its retained actual creation work loan.
	responseSize, err := w.queries.MeasureHTMLCreationResponseV1(ctx, generated.MeasureHTMLCreationResponseV1Params{DocumentID: w.document, OrgID: w.org})
	if err != nil {
		return err
	}
	if responseSize == nil || responseSize.DocumentID != w.document || responseSize.OrgID != w.org || responseSize.BlocksWireBytes != 0 || responseSize.MetadataWireBytes != 2 {
		return ErrHTMLCreationWriterV1
	}
	reportSize, err := w.queries.MeasureSignerDocumentReportV1(ctx, generated.MeasureSignerDocumentReportV1Params{DocumentID: w.document, OrgID: w.org})
	if err != nil {
		return err
	}
	if reportSize == nil || reportSize.DocumentID != w.document || reportSize.OrgID != w.org || w.reportWireUpperBound < 1 || reportSize.ReportWireBytes < 1 || reportSize.ReportWireBytes > w.reportWireUpperBound {
		return ErrHTMLCreationWriterV1
	}
	w.measured = true
	return nil
}

// CloseConsumerV1 ends only the actual application consumer. It does NOT release
// the coordinator, authorize retirement or settle commit uncertainty. Keep it
// through response generation; the factory's retained registry and genuine
// original-client/backend fence alone reconcile the native loan.
func (w *ApplicationHTMLCreationWriterV1) CloseConsumerV1() {
	if w != nil && w.closeConsumer != nil {
		w.closeConsumer()
	}
}

func htmlCreationFixedResourcesV1(raw, input, source int64) (HTMLCreationResourcesV1, error) {
	if raw < 1 || input < 1 || source < htmlCreationSourceEnvelopeWireV1 || source > (math.MaxInt64-input-htmlCreationOtherWorkV1)/2 {
		return HTMLCreationResourcesV1{}, workguard.ErrUnavailableV1
	}
	bodies := input + 2*source
	if bodies > (math.MaxInt64-htmlCreationOtherWorkV1)/16 {
		return HTMLCreationResourcesV1{}, workguard.ErrUnavailableV1
	}
	db := 16*bodies + htmlCreationOtherWorkV1
	if raw > (math.MaxInt64-db)/8 {
		return HTMLCreationResourcesV1{}, workguard.ErrUnavailableV1
	}
	return HTMLCreationResourcesV1{InputRawBytes: raw, InputWireBytes: input, SourceWireUpperBound: source, WorkingBytes: 8*raw + db, DBStagingBytes: db}, nil
}
