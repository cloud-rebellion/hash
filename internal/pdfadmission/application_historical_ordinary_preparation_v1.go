// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var ErrOrdinaryFinalizationPreparationV1 = errors.New("pdfadmission: ordinary finalization preparation unavailable")

// The native session intentionally hides raw database messages, which can
// contain document data. Keep that contract and expose only a fixed operation
// label, SQLSTATE and bounded schema identifiers to operational diagnostics.
func ordinaryPreparationFailureV1(phase string, err error) error {
	if err == nil {
		return nil
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		bounded := func(s string) string {
			if len(s) > 63 {
				return s[:63]
			}
			return s
		}
		return fmt.Errorf("ordinary preparation %s (SQLSTATE %s table=%s constraint=%s): %w", phase, bounded(pg.Code), bounded(pg.TableName), bounded(pg.ConstraintName), err)
	}
	return fmt.Errorf("ordinary preparation %s: %w", phase, err)
}

const ordinaryRenderHTMLV1 = "render_html"

const ordinaryProviderBudgetV1 = 60 * time.Second

var ordinaryOutputKindsV1 = [4]string{"final_pdf", "certificate_pdf", "certificate_payload", "certificate_signature"}

// Only genuine native captures or bounded reads under the current original
// finalization lock construct these owners. Public hashes, rows and callbacks
// cannot create or adopt preparation authority.
type ApplicationHistoricalOrdinaryPreparationV1 struct {
	mu          sync.Mutex
	self        *ApplicationHistoricalOrdinaryPreparationV1
	closed      bool
	grant       *workguard.GrantV1
	factory     *ApplicationSessionFactoryV1
	coordinator *workguard.CoordinatorV1
	ctx         context.Context
	header      generated.GetOrdinaryFinalizationPreparationHeaderV1Row
	outputs     [4]*generated.ListOrdinaryFinalizationOutputHeadersV1Row
}
type ApplicationHistoricalOrdinaryBodyV1 struct {
	mu                        sync.Mutex
	self                      *ApplicationHistoricalOrdinaryBodyV1
	closed                    bool
	grant                     *workguard.GrantV1
	preparation               *ApplicationHistoricalOrdinaryPreparationV1
	kind, key, media, version string
	sum                       [32]byte
	raw                       []byte
}
type ApplicationHistoricalOrdinaryRenderedV1 struct {
	mu     sync.Mutex
	closed bool
	self   *ApplicationHistoricalOrdinaryRenderedV1
	source *ApplicationHistoricalOrdinaryBodyV1
	local  *render.HTMLLocalPDFV1
}

func ordinaryOutputIndexV1(kind string) int {
	for i, k := range ordinaryOutputKindsV1 {
		if kind == k {
			return i
		}
	}
	return -1
}
func ordinaryOutputLimitV1(kind string) int64 {
	switch kind {
	case "final_pdf", "certificate_pdf":
		return 60 << 20
	case "certificate_payload":
		return 4 << 20
	case "certificate_signature":
		return 256
	case ordinaryRenderHTMLV1:
		return render.MaxHTMLMultipartBytes
	}
	return 0
}
func ordinaryOutputIdentityV1(org, document uuid.UUID, kind string, sum [32]byte) (string, string) {
	prefix, suffix, media := "", ".txt", ""
	switch kind {
	case "final_pdf":
		prefix, suffix, media = "final-", ".pdf", "application/pdf"
	case "certificate_pdf":
		prefix, suffix, media = "audit-", ".pdf", "application/pdf"
	case "certificate_payload":
		prefix, media = "audit-payload-", "text/html; charset=utf-8"
	case "certificate_signature":
		prefix, media = "audit-signature-", "text/plain; charset=utf-8"
	default:
		return "", ""
	}
	return path.Join("org", org.String(), "documents", document.String(), prefix+hex.EncodeToString(sum[:])+suffix), media
}
func (w *ApplicationHTMLSendWorkV1) ordinaryContextV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1) (*generated.Document, *workguard.CoordinatorV1, error) {
	if w == nil || w.self != w || ref == nil {
		return nil, nil, ErrOrdinaryFinalizationPreparationV1
	}
	if err := w.ValidateHistoricalFinalizationStageReferenceV1(call, ref); err != nil {
		return nil, nil, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(call) || w.stage.purpose != HTMLHistoricalFinalizationStageV1 || w.sourceDocument == nil || w.familyRoot != nil || w.sourceDocument.Status != "finalizing" {
		return nil, nil, ErrOrdinaryFinalizationPreparationV1
	}
	p := w.stage.operation.factory.state
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closing || p.work == nil || p.work.coordinator == nil {
		return nil, nil, ErrOrdinaryFinalizationPreparationV1
	}
	return w.sourceDocument, p.work.coordinator, nil
}
func (w *ApplicationHTMLSendWorkV1) ordinaryFundV1(call context.Context, n int64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ordinaryFundLockedV1(call, n)
}
func (w *ApplicationHTMLSendWorkV1) ordinaryFundLockedV1(call context.Context, n int64) error {
	if !w.valid(call) || n < 0 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	parent, db := int64(65536), int64(65536)
	if !htmlInputAddV1(&parent, n, 8) || !htmlInputAddV1(&db, n, 4) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	factory := w.stage.operation.factory.state
	factory.mu.Lock()
	if factory.closing || factory.work == nil {
		factory.mu.Unlock()
		return ErrOrdinaryFinalizationPreparationV1
	}
	coord := factory.work.coordinator
	factory.mu.Unlock()
	grant, err := coord.TryAcquireV1(w.stage.operation.original, w.session.state.org, workguard.VectorV1{ParentBytes: parent, DBStagingBytes: db})
	if err != nil {
		return err
	}
	w.closes = append(w.closes, grant.Close)
	return nil
}

// An admitted native callback retains its actual Work/reader aliases through
// SQL and argument consumption even if a copied Close races the producer.
func (w *ApplicationHTMLSendWorkV1) borrowOrdinaryWorkV1(call context.Context) (func(), error) {
	if w == nil || w.self != w {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	w.mu.Lock()
	if !w.valid(call) || w.resourcesClosed {
		w.mu.Unlock()
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	w.sourceBorrowers++
	w.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			w.sourceBorrowers--
			closes, actor := w.retireSourcesLockedV1()
			w.mu.Unlock()
			htmlSendCloseSourceResourcesV1(closes, actor)
			w.releaseFamilyRootIfRetiredV1()
		})
	}, nil
}

func ordinaryHeaderMatchesDocumentV1(h *generated.GetOrdinaryFinalizationPreparationHeaderV1Row, d *generated.Document) bool {
	return h != nil && d != nil && participantReportSchemaKnownV1(h.ReportSchema) && h.ReportSchema == d.ParticipantReportSchema && h.DocumentID == d.ID && h.OrgID == d.OrgID && (h.Mode == "signature") == d.RequiresSignature && historicalFinalizationTimestampEqualV1(h.CompletionEffectiveAt, d.CompletionEffectiveAt) && historicalFinalizationTimestampEqualV1(h.Cutoff, d.UpdatedAt) && historicalFinalizationTimestampEqualV1(h.RetainUntil, d.FinalizationRetainUntil) && len(h.FinalPdfSha256) == 32
}
func (w *ApplicationHTMLSendWorkV1) captureOrdinaryOutputV1(call context.Context, d *generated.Document, kind string, raw []byte) error {
	if len(raw) == 0 || int64(len(raw)) > ordinaryOutputLimitV1(kind) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	sum := sha256.Sum256(raw)
	key, media := ordinaryOutputIdentityV1(d.OrgID, d.ID, kind, sum)
	if key == "" {
		return ErrOrdinaryFinalizationPreparationV1
	}
	if err := w.ordinaryFundV1(call, int64(len(raw))); err != nil {
		return err
	}
	n, err := w.queries.CaptureOrdinaryFinalizationOutputV1(call, generated.CaptureOrdinaryFinalizationOutputV1Params{DocumentID: d.ID, OrgID: d.OrgID, Kind: kind, StorageKey: key, ContentType: media, Payload: raw})
	if err != nil {
		return ordinaryPreparationFailureV1("capture output body", err)
	}
	if n < 0 || n > 1 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	rows, err := w.queries.ListOrdinaryFinalizationOutputHeadersV1(call, generated.ListOrdinaryFinalizationOutputHeadersV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return ordinaryPreparationFailureV1("read captured output metadata", err)
	}
	if len(rows) > 4 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	for _, r := range rows {
		if r != nil && r.Kind == kind && r.StorageKey == key && r.ContentType == media && r.Bytes == int64(len(raw)) && bytes.Equal(r.Sha256, sum[:]) {
			return nil
		}
	}
	return ErrOrdinaryFinalizationPreparationV1
}

// The original acknowledgement SDK bytes are captured while their actual
// callback is still live. Other final producers obey the same native proof.
func (w *ApplicationHTMLSendWorkV1) CaptureHistoricalOrdinaryFinalPDFV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, f *ApplicationHistoricalFinalizationPDFV1) error {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return err
	}
	defer releaseWork()
	d, _, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return err
	}
	if f == nil || f.self != f || !f.lockV1() {
		return ErrOrdinaryFinalizationPreparationV1
	}
	defer f.unlockV1()
	if f.closeRequested.Load() || f.grant == nil || !f.hashAttempted || f.hashFailure != nil || f.factory != w.stage.operation.factory || f.org != d.OrgID || f.document != d.ID || f.source == nil || f.source.document == nil || f.source.document.UpdatedAt != d.UpdatedAt {
		return ErrOrdinaryFinalizationPreparationV1
	}
	if err = w.ordinaryFundV1(call, 32); err != nil {
		return err
	}
	mode := "acknowledgement"
	if d.RequiresSignature {
		mode = "signature"
	}
	_, err = w.queries.CaptureOrdinaryFinalizationPreparationV1(call, generated.CaptureOrdinaryFinalizationPreparationV1Params{DocumentID: d.ID, OrgID: d.OrgID, Mode: mode, FinalPdfSha256: f.sum[:], CompletionEffectiveAt: d.CompletionEffectiveAt, Cutoff: d.UpdatedAt})
	if err != nil {
		return ordinaryPreparationFailureV1("capture final PDF header", err)
	}
	h, err := w.queries.GetOrdinaryFinalizationPreparationHeaderV1(call, generated.GetOrdinaryFinalizationPreparationHeaderV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return ordinaryPreparationFailureV1("read captured final PDF header", err)
	}
	if !ordinaryHeaderMatchesDocumentV1(h, d) || !bytes.Equal(h.FinalPdfSha256, f.sum[:]) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	return f.withBodyLockedV1(func(raw []byte) error { return w.captureOrdinaryOutputV1(call, d, "final_pdf", raw) })
}

func (w *ApplicationHTMLSendWorkV1) FreezeHistoricalOrdinaryCertificateV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, c *ApplicationHistoricalAuditCertificateV1) error {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return err
	}
	defer releaseWork()
	d, _, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return err
	}
	if c == nil || c.self != c || !c.lockV1() {
		return ErrOrdinaryFinalizationPreparationV1
	}
	defer c.unlockV1()
	if c.closeRequested.Load() || c.grant == nil || c.stored || c.html == nil || c.factory != w.stage.operation.factory || c.org != d.OrgID || c.document != d.ID || c.report.schema != d.ParticipantReportSchema || !historicalFinalizationTimestampEqualV1(c.report.cutoff, d.UpdatedAt) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	h, err := w.queries.GetOrdinaryFinalizationPreparationHeaderV1(call, generated.GetOrdinaryFinalizationPreparationHeaderV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return err
	}
	if !ordinaryHeaderMatchesDocumentV1(h, d) || !bytes.Equal(h.FinalPdfSha256, c.finalPDFSHA[:]) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	if err = w.ordinaryFundV1(call, int64(len(c.html.html)+len(c.payload)+len(c.signature))); err != nil {
		return err
	}
	html := []byte(c.html.html)
	defer clear(html)
	htmlsum := sha256.Sum256(html)
	if h.CertificateInputFrozen {
		if !bytes.Equal(h.CertificateRenderSha256, htmlsum[:]) || !bytes.Equal(h.ReportSha256, c.report.sha[:]) || h.HistoryRows.Int64 != c.report.rows {
			return ErrOrdinaryFinalizationPreparationV1
		}
	} else {
		n, e := w.queries.FreezeOrdinaryFinalizationCertificateInputV1(call, generated.FreezeOrdinaryFinalizationCertificateInputV1Params{ReportSchema: c.report.schema, DocumentID: d.ID, OrgID: d.OrgID, RenderHtml: html, ReportCutoff: c.report.cutoff, HistoryRows: c.report.rows, ReportSha256: c.report.sha[:]})
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrOrdinaryFinalizationPreparationV1
		}
	}
	payload, sig := []byte(c.payload), []byte(c.signature)
	defer clear(payload)
	defer clear(sig)
	if err = w.captureOrdinaryOutputV1(call, d, "certificate_payload", payload); err != nil {
		return err
	}
	return w.captureOrdinaryOutputV1(call, d, "certificate_signature", sig)
}

func (w *ApplicationHTMLSendWorkV1) ReadHistoricalOrdinaryPreparationV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1) (*ApplicationHistoricalOrdinaryPreparationV1, error) {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return nil, err
	}
	defer releaseWork()
	d, coord, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return nil, err
	}
	// Four fixed bounded key/version columns, digests and header controls. No
	// variable body or render HTML is selected until a separate measured read.
	grant, err := coord.TryAcquireV1(w.stage.operation.original, d.OrgID, workguard.VectorV1{ParentBytes: 128 << 10, DBStagingBytes: 32 << 10})
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			grant.Close()
		}
	}()
	h, err := w.queries.GetOrdinaryFinalizationPreparationHeaderV1(call, generated.GetOrdinaryFinalizationPreparationHeaderV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return nil, err
	}
	if !ordinaryHeaderMatchesDocumentV1(h, d) || h.PublishedAt.Valid || h.BodiesRetiredAt.Valid {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	rows, err := w.queries.ListOrdinaryFinalizationOutputHeadersV1(call, generated.ListOrdinaryFinalizationOutputHeadersV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return nil, err
	}
	if len(rows) < 1 || len(rows) > 4 {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	serialization, err := ref.ownerV1(w.stage.operation.factory)
	if err != nil {
		return nil, err
	}
	serialization.mu.Lock()
	providerParent := serialization.providerContext
	live := !serialization.closed && serialization.acquired && serialization.stagePrepared && applicationContextV1(providerParent)
	serialization.mu.Unlock()
	if !live {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	// The metadata SQL operation is about to retire. Its cancellation child is
	// not the lifetime of later provider work; the original serialization owner
	// remains live across those independent short phases and cancels all IO on
	// its own Close. Each actual provider attempt gets a further finite child.
	o := &ApplicationHistoricalOrdinaryPreparationV1{grant: grant, factory: w.stage.operation.factory, coordinator: coord, ctx: providerParent, header: *h}
	o.header.FinalPdfSha256 = bytes.Clone(h.FinalPdfSha256)
	o.header.CertificateRenderSha256 = bytes.Clone(h.CertificateRenderSha256)
	o.header.ReportSha256 = bytes.Clone(h.ReportSha256)
	for _, r := range rows {
		if r == nil {
			return nil, ErrOrdinaryFinalizationPreparationV1
		}
		i := ordinaryOutputIndexV1(r.Kind)
		if i < 0 || o.outputs[i] != nil || r.DocumentID != d.ID || r.OrgID != d.OrgID || r.Bytes < 1 || r.Bytes > ordinaryOutputLimitV1(r.Kind) || len(r.Sha256) != 32 || len(r.StorageKey) > 1024 || len(r.VersionID.String) > 1024 {
			return nil, ErrOrdinaryFinalizationPreparationV1
		}
		var sum [32]byte
		copy(sum[:], r.Sha256)
		key, media := ordinaryOutputIdentityV1(d.OrgID, d.ID, r.Kind, sum)
		if key != r.StorageKey || media != r.ContentType {
			return nil, ErrOrdinaryFinalizationPreparationV1
		}
		copy := *r
		copy.Sha256 = bytes.Clone(r.Sha256)
		copy.StorageKey = strings.Clone(r.StorageKey)
		copy.VersionID.String = strings.Clone(r.VersionID.String)
		o.outputs[i] = &copy
	}
	o.self = o
	keep = true
	return o, nil
}
func (p *ApplicationHistoricalOrdinaryPreparationV1) CloseConsumerV1() {
	if p == nil || p.self != p {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		p.grant.Close()
		p.grant = nil
		p.outputs = [4]*generated.ListOrdinaryFinalizationOutputHeadersV1Row{}
		p.header = generated.GetOrdinaryFinalizationPreparationHeaderV1Row{}
	}
}
func (p *ApplicationHistoricalOrdinaryPreparationV1) HasCertificateInputV1() bool {
	if p == nil || p.self != p {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.header.CertificateInputFrozen
}
func (p *ApplicationHistoricalOrdinaryPreparationV1) HasCertificatePDFV1() bool {
	if p == nil || p.self != p {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.outputs[1] != nil
}
func (p *ApplicationHistoricalOrdinaryPreparationV1) bodyAllowedV1(kind string) bool {
	if kind == ordinaryRenderHTMLV1 {
		return p.header.CertificateInputFrozen && p.header.RenderHtmlBytes > 0
	}
	i := ordinaryOutputIndexV1(kind)
	if i < 0 || !p.header.CertificateInputFrozen {
		return false
	}
	for _, r := range p.outputs {
		if r == nil {
			return false
		}
	}
	return true
}

func (w *ApplicationHTMLSendWorkV1) ReadHistoricalOrdinaryBodyV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, p *ApplicationHistoricalOrdinaryPreparationV1, kind string) (*ApplicationHistoricalOrdinaryBodyV1, error) {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return nil, err
	}
	defer releaseWork()
	d, coord, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return nil, err
	}
	if p == nil || p.self != p {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.factory != w.stage.operation.factory || !ordinaryHeaderMatchesDocumentV1(&p.header, d) || !p.bodyAllowedV1(kind) {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	n := p.header.RenderHtmlBytes
	digest := p.header.CertificateRenderSha256
	key, media, version := "", "text/html; charset=utf-8", ""
	if kind != ordinaryRenderHTMLV1 {
		r := p.outputs[ordinaryOutputIndexV1(kind)]
		n, digest, key, media, version = r.Bytes, r.Sha256, r.StorageKey, r.ContentType, r.VersionID.String
	}
	if n < 1 || n > ordinaryOutputLimitV1(kind) || len(digest) != 32 {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	parent := int64(65536)
	if !htmlInputAddV1(&parent, n, 12) {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	grant, err := coord.TryAcquireV1(w.stage.operation.original, d.OrgID, workguard.VectorV1{ParentBytes: parent, DBStagingBytes: n*4 + 65536})
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			grant.Close()
		}
	}()
	var raw []byte
	if kind == ordinaryRenderHTMLV1 {
		raw, err = w.queries.ReadOrdinaryFinalizationRenderHTMLV1(call, generated.ReadOrdinaryFinalizationRenderHTMLV1Params{DocumentID: d.ID, OrgID: d.OrgID, ExpectedBytes: n, ExpectedSha256: digest})
	} else {
		raw, err = w.queries.ReadOrdinaryFinalizationOutputBodyV1(call, generated.ReadOrdinaryFinalizationOutputBodyV1Params{DocumentID: d.ID, OrgID: d.OrgID, Kind: kind, ExpectedBytes: n, ExpectedSha256: digest})
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if int64(len(raw)) != n || !bytes.Equal(sum[:], digest) {
		clear(raw)
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	b := &ApplicationHistoricalOrdinaryBodyV1{grant: grant, preparation: p, kind: kind, key: key, media: media, version: version, sum: sum, raw: raw}
	b.self = b
	keep = true
	return b, nil
}
func (b *ApplicationHistoricalOrdinaryBodyV1) CloseConsumerV1() {
	if b == nil || b.self != b {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		clear(b.raw)
		b.raw = nil
		b.grant.Close()
		b.grant = nil
	}
}
func (b *ApplicationHistoricalOrdinaryBodyV1) StoreV1(client *storage.Client) (*storage.EvidenceLocalPutV1, error) {
	if b == nil || b.self != b || client == nil {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.preparation
	if b.closed || b.grant == nil || p == nil || p.self != p || b.kind == ordinaryRenderHTMLV1 {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !applicationContextV1(p.ctx) {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	// The local method returns only after its actual IO joins or this finite
	// child expires. Cancel after that synchronous return; any late IO and
	// result/error aliases retain their independent native grants until joined
	// and consumed. Context cancellation itself releases no ownership credit.
	providerContext, stop := context.WithTimeout(p.ctx, ordinaryProviderBudgetV1)
	defer stop()
	if b.version != "" {
		return client.PutEvidenceVersionedLocalPinnedOwnedV1(providerContext, b.key, b.version, b.media, b.raw, p.header.RetainUntil.Time, p.coordinator, p.header.OrgID)
	}
	return client.PutEvidenceVersionedLocalOwnedV1(providerContext, b.key, b.media, b.raw, p.header.RetainUntil.Time, p.coordinator, p.header.OrgID)
}
func (b *ApplicationHistoricalOrdinaryBodyV1) RenderCertificateV1(renderer *render.Gotenberg) (*ApplicationHistoricalOrdinaryRenderedV1, error) {
	if b == nil || b.self != b || renderer == nil {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.preparation
	if b.closed || b.kind != ordinaryRenderHTMLV1 || p == nil || p.self != p {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || !applicationContextV1(p.ctx) {
		return nil, ErrOrdinaryFinalizationPreparationV1
	}
	providerContext, stop := context.WithTimeout(p.ctx, ordinaryProviderBudgetV1)
	defer stop()
	local, err := renderer.HTMLToPDFLocalOwnedV1(providerContext, string(b.raw), render.PDFOptions{}, p.coordinator, p.header.OrgID)
	r := &ApplicationHistoricalOrdinaryRenderedV1{source: b, local: local}
	r.self = r
	return r, err
}
func (r *ApplicationHistoricalOrdinaryRenderedV1) CloseConsumerV1() {
	if r == nil || r.self != r {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		if r.local != nil {
			r.local.CloseConsumerV1()
			r.local = nil
		}
	}
}

func (w *ApplicationHTMLSendWorkV1) CaptureHistoricalOrdinaryCertificatePDFV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, r *ApplicationHistoricalOrdinaryRenderedV1) error {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return err
	}
	defer releaseWork()
	d, _, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return err
	}
	if r == nil || r.self != r {
		return ErrOrdinaryFinalizationPreparationV1
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.source == nil || r.local == nil {
		return ErrOrdinaryFinalizationPreparationV1
	}
	b := r.source
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.preparation
	p.mu.Lock()
	defer p.mu.Unlock()
	if b.closed || p.closed || p.factory != w.stage.operation.factory || !ordinaryHeaderMatchesDocumentV1(&p.header, d) || b.kind != ordinaryRenderHTMLV1 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	return r.local.WithPDFV1(func(raw []byte) error { return w.captureOrdinaryOutputV1(call, d, "certificate_pdf", raw) })
}

func (w *ApplicationHTMLSendWorkV1) CheckpointHistoricalOrdinaryOutputV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, b *ApplicationHistoricalOrdinaryBodyV1, put *storage.EvidenceLocalPutV1) error {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return err
	}
	defer releaseWork()
	d, _, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return err
	}
	if b == nil || b.self != b || put == nil {
		return ErrOrdinaryFinalizationPreparationV1
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	p := b.preparation
	p.mu.Lock()
	defer p.mu.Unlock()
	if b.closed || p.closed || p.factory != w.stage.operation.factory || !ordinaryHeaderMatchesDocumentV1(&p.header, d) || ordinaryOutputIndexV1(b.kind) < 0 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	if err = w.ordinaryFundV1(call, 4096); err != nil {
		return err
	}
	return put.WithObservationV1(func(stored storage.StoredObject, succeeded bool) error {
		if stored.SHA256 != b.sum || strings.TrimSpace(stored.VersionID) == "" || (b.version != "" && stored.VersionID != b.version) {
			return ErrOrdinaryFinalizationPreparationV1
		}
		if b.version == "" {
			_, e := w.queries.PinOrdinaryFinalizationOutputVersionV1(call, generated.PinOrdinaryFinalizationOutputVersionV1Params{DocumentID: d.ID, OrgID: d.OrgID, Kind: b.kind, ExpectedSha256: b.sum[:], VersionID: stored.VersionID})
			if e != nil {
				return e
			}
		}
		rows, e := w.queries.ListOrdinaryFinalizationOutputHeadersV1(call, generated.ListOrdinaryFinalizationOutputHeadersV1Params{DocumentID: d.ID, OrgID: d.OrgID})
		if e != nil {
			return e
		}
		matched := false
		for _, r := range rows {
			if r != nil && r.Kind == b.kind && bytes.Equal(r.Sha256, b.sum[:]) && r.VersionID.Valid && r.VersionID.String == stored.VersionID {
				matched = true
			}
		}
		if !matched {
			return ErrOrdinaryFinalizationPreparationV1
		}
		if succeeded {
			_, e = w.queries.VerifyOrdinaryFinalizationOutputVersionV1(call, generated.VerifyOrdinaryFinalizationOutputVersionV1Params{DocumentID: d.ID, OrgID: d.OrgID, Kind: b.kind, ExpectedSha256: b.sum[:], VersionID: stored.VersionID})
			return e
		}
		return nil
	})
}

// The recovered final hash is usable for claims only from the original locked
// final PDF capture. It is never an exported arbitrary hash setter.
func (s *ApplicationHistoricalCertificateSnapshotV1) PrepareOrdinaryClaimsV1(source *ApplicationHistoricalFinalizationSourceEvidenceV1, p *ApplicationHistoricalOrdinaryPreparationV1) error {
	if s == nil || s.self != s || p == nil || p.self != p || source == nil {
		return ErrOrdinaryFinalizationPreparationV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return ErrOrdinaryFinalizationPreparationV1
	}
	if !s.lockV1() {
		return ErrOrdinaryFinalizationPreparationV1
	}
	defer s.unlockV1()
	if !source.lockV1() {
		return ErrOrdinaryFinalizationPreparationV1
	}
	defer source.unlockV1()
	if s.closeRequested.Load() || s.grant == nil || s.claimAttempted || !source.validV1() || !source.sourceChecked || source.document == nil || p.factory != s.factory || source.work.stage.operation.factory != s.factory || p.header.OrgID != s.org || p.header.DocumentID != s.document || p.header.ReportSchema != s.reportSchema || source.document.UpdatedAt != s.updated || !ordinaryHeaderMatchesDocumentV1(&p.header, source.document) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	return s.prepareClaimsFromFinalSHA256V1(source, p.header.FinalPdfSha256)
}

func (w *ApplicationHTMLSendWorkV1) StageHistoricalOrdinaryPreparationV1(call context.Context, ref *ApplicationHistoricalFinalizationStageReferenceV1, p *ApplicationHistoricalOrdinaryPreparationV1) error {
	releaseWork, err := w.borrowOrdinaryWorkV1(call)
	if err != nil {
		return err
	}
	defer releaseWork()
	d, _, err := w.ordinaryContextV1(call, ref)
	if err != nil {
		return err
	}
	if p == nil || p.self != p {
		return ErrOrdinaryFinalizationPreparationV1
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.factory != w.stage.operation.factory || !ordinaryHeaderMatchesDocumentV1(&p.header, d) || !p.header.CertificateInputFrozen || !p.header.HistoryRows.Valid || len(p.header.ReportSha256) != 32 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	for _, o := range p.outputs {
		if o == nil || !o.VersionID.Valid || strings.TrimSpace(o.VersionID.String) == "" || !o.VerifiedAt.Valid {
			return ErrOrdinaryFinalizationPreparationV1
		}
	}
	if err = w.ordinaryFundV1(call, 16384); err != nil {
		return err
	}
	o := p.outputs
	params := generated.CreateDocumentFinalizationIntentParams{DocumentID: d.ID, OrgID: d.OrgID, Mode: p.header.Mode, CompletionEffectiveAt: p.header.CompletionEffectiveAt, RetainUntil: p.header.RetainUntil,
		FinalPdfKey: o[0].StorageKey, FinalPdfSha256: o[0].Sha256, FinalPdfVersionID: o[0].VersionID,
		AuditCertKey: o[1].StorageKey, AuditCertSha256: o[1].Sha256, AuditCertVersionID: o[1].VersionID,
		AuditPayloadKey: o[2].StorageKey, AuditPayloadSha256: o[2].Sha256, AuditPayloadVersionID: o[2].VersionID,
		AuditSignatureKey: o[3].StorageKey, AuditSignatureSha256: o[3].Sha256, AuditSignatureVersionID: o[3].VersionID}
	existing, getErr := w.ReadHistoricalFinalizationIntentV1(call)
	if getErr == nil {
		if !historicalFinalizationIntentMatchesV1(existing, params) {
			return ErrOrdinaryFinalizationPreparationV1
		}
	} else {
		if !errors.Is(getErr, pgx.ErrNoRows) {
			return getErr
		}
		if _, err = w.CreateHistoricalFinalizationIntentV1(call, params); err != nil {
			return err
		}
	}
	receipt := generated.InsertParticipantReportReceiptV1Params{ReportSchema: p.header.ReportSchema, DocumentID: d.ID, OrgID: d.OrgID, CompletionEffectiveAt: p.header.CompletionEffectiveAt, Cutoff: p.header.ReportCutoff, HistoryRows: p.header.HistoryRows.Int64, ReportSha256: p.header.ReportSha256, FinalPdfSha256: o[0].Sha256, AuditCertSha256: o[1].Sha256, AuditPayloadSha256: o[2].Sha256, AuditSignatureSha256: o[3].Sha256}
	if _, err = w.queries.InsertParticipantReportReceiptV1(call, receipt); err != nil {
		return err
	}
	match, err := w.queries.ParticipantReportReceiptMatchesV1(call, generated.ParticipantReportReceiptMatchesV1Params{ReportSchema: receipt.ReportSchema, DocumentID: receipt.DocumentID, OrgID: receipt.OrgID, CompletionEffectiveAt: receipt.CompletionEffectiveAt, Cutoff: receipt.Cutoff, HistoryRows: receipt.HistoryRows, ReportSha256: receipt.ReportSha256, FinalPdfSha256: receipt.FinalPdfSha256, AuditCertSha256: receipt.AuditCertSha256, AuditPayloadSha256: receipt.AuditPayloadSha256, AuditSignatureSha256: receipt.AuditSignatureSha256})
	if err != nil {
		return err
	}
	if !match {
		return ErrOrdinaryFinalizationPreparationV1
	}
	n, err := w.queries.MarkOrdinaryFinalizationPreparationStagedV1(call, generated.MarkOrdinaryFinalizationPreparationStagedV1Params{DocumentID: d.ID, OrgID: d.OrgID})
	if err != nil {
		return err
	}
	if n != 1 && !p.header.StagedAt.Valid {
		return ErrOrdinaryFinalizationPreparationV1
	}
	return nil
}

// Called only by the actual publication owner after all completion effects and
// audit producers are bound, before M46 intent deletion in that SAME tx. Exact
// retained S3 versions become the byte recovery owner; SQL keeps scalar proof.
func (w *ApplicationHTMLSendWorkV1) retirePublishedOrdinaryBodiesLockedV1(call context.Context) error {
	state, p, err := w.historicalPublicationV1(call)
	if err != nil {
		return err
	}
	if p.deleted || !p.tokensInvalidated || len(p.payloads) != len(p.children)+1 {
		return ErrOrdinaryFinalizationPreparationV1
	}
	for _, event := range p.payloads {
		if event.owner == nil {
			return ErrOrdinaryFinalizationPreparationV1
		}
	}
	if err = w.ordinaryFundLockedV1(call, 16384); err != nil {
		return err
	}
	h, err := w.queries.GetOrdinaryFinalizationPreparationHeaderV1(call, generated.GetOrdinaryFinalizationPreparationHeaderV1Params{DocumentID: state.intent.DocumentID, OrgID: state.intent.OrgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if h == nil || !h.StagedAt.Valid || h.CompletionEffectiveAt != state.intent.CompletionEffectiveAt || !bytes.Equal(h.FinalPdfSha256, state.intent.FinalPdfSha256) {
		return ErrOrdinaryFinalizationPreparationV1
	}
	n, err := w.queries.MarkOrdinaryFinalizationPreparationPublishedV1(call, generated.MarkOrdinaryFinalizationPreparationPublishedV1Params{DocumentID: h.DocumentID, OrgID: h.OrgID})
	if err != nil {
		return err
	}
	if n != 1 && !h.PublishedAt.Valid {
		return ErrOrdinaryFinalizationPreparationV1
	}
	n, err = w.queries.RetirePublishedOrdinaryFinalizationRenderHTMLV1(call, generated.RetirePublishedOrdinaryFinalizationRenderHTMLV1Params{DocumentID: h.DocumentID, OrgID: h.OrgID})
	if err != nil {
		return err
	}
	if n != 1 && !h.BodiesRetiredAt.Valid {
		return ErrOrdinaryFinalizationPreparationV1
	}
	n, err = w.queries.RetirePublishedOrdinaryFinalizationBodiesV1(call, generated.RetirePublishedOrdinaryFinalizationBodiesV1Params{DocumentID: h.DocumentID, OrgID: h.OrgID})
	if err != nil {
		return err
	}
	if n != 4 && !h.BodiesRetiredAt.Valid {
		return ErrOrdinaryFinalizationPreparationV1
	}
	return nil
}
