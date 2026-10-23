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
	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"math/big"
	"path"
	"strings"
	"sync"
	"time"
	"unsafe"
)

// This private capture is produced only while the actual signer reader owns
// its original scoped SQL row and body loan, BEFORE any mutable callback. It
// preserves the original pre-lock signature source; a later row is not adopted
// as the original contract. It is data, never signing/credential authority.
type applicationBlockSigningReadSnapshotV1 struct {
	org, document, recipient uuid.UUID
	isEnvelope               bool
	sourceKind               string
	pdfKey, pdfVersion       pgtype.Text
	pdfSHA                   []byte
	versionPinsRequired      bool
	role                     string
	blocks, variables        []byte
}

func (r *ApplicationSignerReaderV1) captureBlockSigningSourceV1(call context.Context, m *ApplicationSignerReadModelsV1) error {
	// Caller holds r.mu inside the genuine WithModelsV1 transaction.
	if r.mode != SignerReadActiveV1 || m == nil || m.Document == nil || (m.Document.SourceKind != "blocks" && m.Document.SourceKind != "pdf") {
		return nil
	}
	if r.blockSigningSnapshot != nil || m.Recipient == nil || m.Document.ID != r.scope.document || m.Document.OrgID != r.scope.org || m.Recipient.ID != r.scope.recipient || m.Recipient.DocumentID != r.scope.document {
		return ErrSignerReadV1
	}
	d, rec := m.Document, m.Recipient
	raw, err := htmlAuthoringSumV1(int64(len(d.BlocksJson)), int64(len(d.VariablesJson)), int64(len(rec.Role)), int64(len(d.SourceKind)), int64(len(d.PdfStorageKey.String)), int64(len(d.PdfStorageVersionID.String)), int64(len(d.PdfSha256)))
	if err != nil {
		return err
	}
	closeCopy, err := r.session.acquireHTMLAuthoringV1(call, "locked-signer-read-body", raw, raw)
	if err != nil {
		return err
	}
	r.appendConsumerV1(closeCopy)
	r.blockSigningSnapshot = &applicationBlockSigningReadSnapshotV1{org: r.scope.org, document: r.scope.document, recipient: r.scope.recipient, isEnvelope: d.IsEnvelope, sourceKind: strings.Clone(d.SourceKind), pdfKey: pgtype.Text{String: strings.Clone(d.PdfStorageKey.String), Valid: d.PdfStorageKey.Valid}, pdfVersion: pgtype.Text{String: strings.Clone(d.PdfStorageVersionID.String), Valid: d.PdfStorageVersionID.Valid}, pdfSHA: bytes.Clone(d.PdfSha256), versionPinsRequired: d.EvidenceVersionPinsRequired, role: strings.Clone(rec.Role), blocks: bytes.Clone(d.BlocksJson), variables: bytes.Clone(d.VariablesJson)}
	return nil
}
func (r *ApplicationSignerReaderV1) retireBlockSigningReadConsumersV1() []func() {
	// Caller holds r.mu. Closing a shell or SQL cannot release an actual ongoing
	// immutable signing-source operation and its escaped prepared signature view.
	if !r.consumerClosed || r.blockSigningBorrowers != 0 || r.packageMemberBorrowers != 0 || r.presignBorrowers != 0 {
		return nil
	}
	consumers := r.consumers
	r.consumers = nil
	r.models = nil
	r.blockSigningSnapshot = nil
	return consumers
}

var ErrBlockSignatureRequestV1 = errors.New("pdfadmission: owned blocks signature unavailable")

// Copies share this one immutable request/source owner. The native Reader is
// the ONLY original document producer. Typed request values are priced before
// copy/render; their strings and UUIDs never authenticate a recipient.
type ApplicationBlockSignatureRequestV1 struct {
	state *applicationBlockSignatureRequestV1
}
type applicationBlockSignatureRequestV1 struct {
	mu                              sync.Mutex
	self                            *applicationBlockSignatureRequestV1
	reader                          *ApplicationSignerReaderV1
	snapshot                        *applicationBlockSigningReadSnapshotV1
	pdfTargets                      *historicalPDFSignatureTargetsV1
	ctx                             context.Context
	cancel                          context.CancelFunc
	coordinator                     *workguard.CoordinatorV1
	grant                           *workguard.GrantV1
	typedName, font, ip, userAgent  string
	tree                            *blocks.Tree
	values                          map[string]string
	fieldID, imageKey, imageVersion string
	storeAttempted, stored          bool
	span                            []byte
	digest                          [sha256.Size]byte
	base, decimalPeak               int64
	prepared, closed                bool
}

func (f *ApplicationSessionFactoryV1) NewBlockSignatureRequestV1(ctx context.Context, r *ApplicationSignerReaderV1, typedName, font, ip, userAgent string) (*ApplicationBlockSignatureRequestV1, error) {
	if f == nil || f.state == nil || r == nil || r.self != r || !applicationContextV1(ctx) || render.ValidateSignatureName(typedName) != nil || !render.IsValidFont(font) {
		return nil, ErrBlockSignatureRequestV1
	}
	if deadline, ok := ctx.Deadline(); !ok || !deadline.After(time.Now()) {
		return nil, ErrBlockSignatureRequestV1
	}
	r.mu.Lock()
	if r.factory != f || r.consumerClosed || r.released || r.creating || !r.read || r.mode != SignerReadActiveV1 || r.blockSigningSnapshot == nil || r.session == nil || r.admission == nil {
		r.mu.Unlock()
		return nil, ErrBlockSignatureRequestV1
	}
	snapshot := r.blockSigningSnapshot
	if snapshot.org != r.scope.org || snapshot.document != r.scope.document || snapshot.recipient != r.scope.recipient {
		r.mu.Unlock()
		return nil, ErrBlockSignatureRequestV1
	}
	p := f.state
	p.mu.Lock()
	_, registered := p.signerReaders[r]
	available := registered && !p.closing && p.work != nil && p.work.coordinator != nil
	var coordinator *workguard.CoordinatorV1
	if available {
		coordinator = p.work.coordinator
	}
	p.mu.Unlock()
	if !available {
		r.mu.Unlock()
		return nil, ErrBlockSignatureRequestV1
	}
	base, variables := int64(0), int64(0)
	var err error
	if snapshot.sourceKind == "blocks" {
		base, err = plainSendBlockLexicalWorkV1(ctx, snapshot.blocks)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		variables, err = plainSendBlockLexicalWorkV1(ctx, snapshot.variables)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
	}
	for _, part := range [][2]int64{{variables, 4}, {int64(len(typedName) + len(font) + len(ip) + len(userAgent)), 8}, {render.MaxArchivedSignatureSpanBytes, 8}, {1, 2*int64(unsafe.Sizeof(applicationBlockSignatureRequestV1{})) + 8*int64(unsafe.Sizeof(big.Rat{})) + 16*int64(unsafe.Sizeof(uintptr(0)))}} {
		if !htmlInputAddV1(&base, part[0], part[1]) {
			r.mu.Unlock()
			return nil, ErrBlockSignatureRequestV1
		}
	}
	// Pure CPU/result credit has no SQL/provider vector. The still-retained
	// genuine reader/body borrower remains independently charged after SQL ends.
	grant, err := coordinator.TryAcquireV1(ctx, snapshot.org, workguard.VectorV1{ParentBytes: base})
	if err != nil {
		r.mu.Unlock()
		return nil, errors.Join(ErrBlockSignatureRequestV1, err)
	}
	r.blockSigningBorrowers++
	child, cancel := context.WithCancel(ctx)
	owner := &applicationBlockSignatureRequestV1{reader: r, snapshot: snapshot, ctx: child, cancel: cancel, coordinator: coordinator, grant: grant, typedName: strings.Clone(typedName), font: strings.Clone(font), ip: strings.Clone(ip), userAgent: strings.Clone(userAgent), base: base}
	owner.self = owner
	r.mu.Unlock()
	return &ApplicationBlockSignatureRequestV1{state: owner}, nil
}

type blockSignatureDecimalAdmissionV1 struct {
	owner *applicationBlockSignatureRequestV1
}

func (a blockSignatureDecimalAdmissionV1) BeforeDecimalV1(value string) error {
	s := a.owner
	if s == nil || s.self != s || s.closed || s.grant == nil || s.ctx.Err() != nil {
		return ErrBlockSignatureRequestV1
	}
	bound, err := blocks.DecimalLogicalBoundForSendV1(value)
	if err != nil {
		return err
	}
	bits := int64(0)
	for _, n := range []int64{bound.MantissaBits, bound.PowerFiveBits, bound.NumeratorBits, bound.DenominatorBits} {
		if !htmlInputAddV1(&bits, n, 1) {
			return ErrBlockSignatureRequestV1
		}
	}
	words := bits / 64
	if bits%64 != 0 {
		words++
	}
	peak := int64(0)
	if !htmlInputAddV1(&peak, words, 64*8) || !htmlInputAddV1(&peak, bound.SourceBytes, 8) || !htmlInputAddV1(&peak, 1, 32*int64(unsafe.Sizeof(big.Int{}))+8*int64(unsafe.Sizeof(big.Rat{}))) {
		return ErrBlockSignatureRequestV1
	}
	if peak > s.decimalPeak {
		if err = s.grant.TryGrowParentV1(s.ctx, peak-s.decimalPeak); err != nil {
			return errors.Join(ErrBlockSignatureRequestV1, err)
		}
		s.decimalPeak = peak
	}
	return nil
}
func (h *ApplicationBlockSignatureRequestV1) PrepareStandaloneV1() error {
	if h == nil || h.state == nil {
		return ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.prepared || s.snapshot == nil || s.snapshot.isEnvelope || s.snapshot.sourceKind != "blocks" || s.ctx.Err() != nil {
		return ErrBlockSignatureRequestV1
	}
	admission := blockSignatureDecimalAdmissionV1{s}
	tree, err := blocks.ParseCanonicalTreeForSendV1(s.snapshot.blocks, admission)
	if err != nil {
		return fmt.Errorf("find signature field: parse block tree: %w", err)
	}
	values, err := blocks.ValidateResolvedVariableValuesForSendV1(tree, s.snapshot.variables, admission)
	if err != nil {
		return fmt.Errorf("find signature field: validate frozen variables: %w", err)
	}
	fieldID, err := blocks.SignatureFieldIDForVariablesForSigningV1(tree, s.snapshot.role, values, admission)
	if err != nil {
		return fmt.Errorf("find signature field: %w", err)
	}
	if fieldID == "" {
		return fmt.Errorf("no signature field assigned to role %q", s.snapshot.role)
	}
	span, err := render.RenderSignatureSpan(s.typedName, s.font)
	if err != nil {
		return fmt.Errorf("prepare signature: %w", err)
	}
	s.tree, s.values, s.fieldID = tree, values, fieldID
	s.span = []byte(span)
	s.digest = sha256.Sum256(s.span)
	s.prepared = true
	return nil
}
func (h *ApplicationBlockSignatureRequestV1) CloseConsumerV1() {
	if h == nil || h.state == nil {
		return
	}
	s := h.state
	s.mu.Lock()
	if s.self != s || s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.cancel()
	r, g := s.reader, s.grant
	s.reader = nil
	s.snapshot = nil
	s.pdfTargets = nil
	s.tree = nil
	s.values = nil
	s.fieldID = ""
	s.imageKey = ""
	s.imageVersion = ""
	clear(s.span)
	s.span = nil
	s.typedName = ""
	s.font = ""
	s.ip = ""
	s.userAgent = ""
	s.grant = nil
	s.mu.Unlock()
	if g != nil {
		g.Close()
	}
	if r != nil {
		r.mu.Lock()
		r.blockSigningBorrowers--
		consumers := r.retireBlockSigningReadConsumersV1()
		r.mu.Unlock()
		for _, close := range consumers {
			close()
		}
	}
}

var _ blocks.ConditionalSendAdmissionV1 = blockSignatureDecimalAdmissionV1{}

// This method reads only the same actual root's pre-registered native members.
// It never calls the configured shared service or adopts a caller child slice.
func (h *ApplicationBlockSignatureRequestV1) PrepareEnvelopeV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if h == nil || h.state == nil || w == nil || w.self != w {
		return ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || s.prepared || s.snapshot == nil || !s.snapshot.isEnvelope || s.snapshot.sourceKind != "blocks" || s.ctx.Err() != nil {
		return ErrBlockSignatureRequestV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.familyRoot == nil && w.stage != nil && w.stage.purpose == HTMLBlockSignPreparationV1 && w.sourceDocument != nil && w.sourceDocument.IsEnvelope && w.familyMembersAttempted && w.sourceDocument.ID == s.snapshot.document && w.sourceDocument.OrgID == s.snapshot.org && w.stage.operation.factory == s.reader.factory
	members := w.familyMembers
	w.mu.Unlock()
	if !valid {
		return ErrBlockSignatureRequestV1
	}
	if len(members) == 0 {
		return errors.New("find signature field: envelope has no children")
	}
	for i, m := range members {
		if m == nil {
			return fmt.Errorf("find signature field: child %d is nil", i+1)
		}
		if _, err := m.ReadModelsV1(call); err != nil {
			return err
		}
		m.mu.Lock()
		d := m.sourceDocument
		m.mu.Unlock()
		if d == nil {
			return fmt.Errorf("find signature field: child %d is nil", i+1)
		}
		if d.SourceKind != "blocks" {
			return fmt.Errorf("find signature field: child %s is not a blocks document", d.ID)
		}
		source, err := m.NewSourceV1(call)
		if err != nil {
			return err
		}
		field, err := source.SignatureFieldForSigningV1(s.snapshot.role)
		if err != nil {
			return fmt.Errorf("find signature field: child %s: %w", d.ID, err)
		}
		if field == "" {
			continue
		}
		extra := int64(0)
		if !htmlInputAddV1(&extra, int64(len(field))+37, 8) {
			return ErrBlockSignatureRequestV1
		}
		if err = s.grant.TryGrowParentV1(s.ctx, extra); err != nil {
			return errors.Join(ErrBlockSignatureRequestV1, err)
		}
		s.fieldID = d.ID.String() + ":" + strings.Clone(field)
		span, err := render.RenderSignatureSpan(s.typedName, s.font)
		if err != nil {
			return err
		}
		s.span = []byte(span)
		s.digest = sha256.Sum256(s.span)
		s.prepared = true
		return nil
	}
	return fmt.Errorf("no envelope signature field assigned to role %q", s.snapshot.role)
}

type BlockSignaturePreparedViewV1 struct {
	FieldBlockID, TypedName, Font, IP, UserAgent, ImageKey, ImageVersion string
	SHA256                                                               [sha256.Size]byte
}

func (h *ApplicationBlockSignatureRequestV1) PreparedViewV1() (BlockSignaturePreparedViewV1, error) {
	if h == nil || h.state == nil {
		return BlockSignaturePreparedViewV1{}, ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || !s.prepared || s.snapshot == nil {
		return BlockSignaturePreparedViewV1{}, ErrBlockSignatureRequestV1
	}
	return BlockSignaturePreparedViewV1{s.fieldID, s.typedName, s.font, s.ip, s.userAgent, s.imageKey, s.imageVersion, s.digest}, nil
}
func (h *ApplicationBlockSignatureRequestV1) StoreEvidenceV1(call context.Context, w *ApplicationHTMLSendWorkV1, client *storage.Client) error {
	if h == nil || h.state == nil || w == nil || w.self != w || client == nil {
		return ErrBlockSignatureRequestV1
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.self != s || s.closed || !s.prepared || s.storeAttempted || s.snapshot == nil || s.ctx.Err() != nil {
		return ErrBlockSignatureRequestV1
	}
	w.mu.Lock()
	valid := w.valid(call) && w.stage != nil && w.stage.purpose == HTMLBlockSignMutationV1 && w.blockSignature != nil && w.blockSignature.request == s && w.blockSignature.field != nil && w.sourceDocument != nil && w.sourceDocument.ID == s.snapshot.document && w.sourceDocument.OrgID == s.snapshot.org && w.stage.operation.factory == s.reader.factory
	var sent time.Time
	if valid && w.sourceDocument.SentAt.Valid {
		sent = w.sourceDocument.SentAt.Time
	}
	w.mu.Unlock()
	if !valid || sent.IsZero() {
		return errors.New("store signature span: authoritative sent timestamp is unavailable")
	}
	limits, err := client.SendEvidenceLimitsV1()
	if err != nil {
		return err
	}
	w.mu.Lock()
	closeVersion, err := w.actor.acquireOwnedRetainedBodyV1(call, limits.VersionIDBytes, limits.VersionIDBytes)
	if err == nil {
		w.closes = append(w.closes, closeVersion)
	}
	w.mu.Unlock()
	if err != nil {
		return err
	}
	scratch := int64(0)
	for _, part := range [][2]int64{{limits.ObjectBytes + 1, 4}, {limits.MetadataBytes, 4}, {limits.HeaderBytes, 4}, {limits.VersionIDBytes, 2}} {
		if !htmlInputAddV1(&scratch, part[0], part[1]) {
			return ErrBlockSignatureRequestV1
		}
	}
	g, err := s.coordinator.TryAcquireV1(s.ctx, s.snapshot.org, workguard.VectorV1{ParentBytes: scratch, ProviderStreams: 1})
	if err != nil {
		return errors.Join(ErrBlockSignatureRequestV1, err)
	}
	defer g.Close()
	s.storeAttempted = true
	key := path.Join("org", s.snapshot.org.String(), "documents", s.snapshot.document.String(), "signatures", s.snapshot.recipient.String()+"-"+hex.EncodeToString(s.digest[:])+".html")
	stored, err := client.PutBlockSignatureEvidenceV1(s.ctx, key, s.span, storage.EvidenceRetentionDeadline(sent, article13.RetentionYearsV1))
	retained := int64(0)
	for _, part := range [][2]int64{{limits.MetadataBytes, 4}, {limits.HeaderBytes, 4}, {int64(len(key)), 2}, {int64(len(stored.VersionID)), 2}} {
		if !htmlInputAddV1(&retained, part[0], part[1]) {
			return ErrBlockSignatureRequestV1
		}
	}
	if err != nil {
		if !htmlInputAddV1(&retained, int64(len(err.Error())), 4) {
			return ErrBlockSignatureRequestV1
		}
	}
	if failure := s.grant.TryGrowParentV1(s.ctx, retained); failure != nil {
		return errors.Join(ErrBlockSignatureRequestV1, failure)
	}
	if err != nil {
		return fmt.Errorf("store signature span: %w", err)
	}
	if stored.SHA256 != s.digest || strings.TrimSpace(stored.VersionID) == "" {
		return errors.New("store signature span: storage digest mismatch")
	}
	s.imageKey = key
	s.imageVersion = strings.Clone(stored.VersionID)
	s.stored = true
	return nil
}
