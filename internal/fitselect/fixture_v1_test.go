// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package fitselect

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

type objectBlobV1 struct {
	pin manualfit.ObjectPinV1
	raw []byte
}
type objectStoreV1 struct {
	mu           sync.Mutex
	blobs        map[string]objectBlobV1
	retained     []manualfit.ObjectPinV1
	until        []time.Time
	failAt       int
	beforeRetain func(int)
}

func blobIDV1(k, v string) string { return k + "\x00" + v }
func testSHA(b []byte) string     { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func (s *objectStoreV1) GetVerifiedVersionBounded(ctx context.Context, key, version string, digest []byte, limit int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, ok := s.blobs[blobIDV1(key, version)]
	if !ok || b.pin.Bytes != limit || b.pin.SHA256 != hex.EncodeToString(digest) {
		return nil, errors.New("PRIVATE_STORAGE_DETAIL")
	}
	return bytes.Clone(b.raw), nil
}
func (s *objectStoreV1) RetainEvidenceVersion(ctx context.Context, key, version string, digest []byte, until time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	b, ok := s.blobs[blobIDV1(key, version)]
	if !ok || b.pin.SHA256 != hex.EncodeToString(digest) {
		return errors.New("bad pin")
	}
	n := len(s.retained) + 1
	if s.beforeRetain != nil {
		s.beforeRetain(n)
	}
	s.retained = append(s.retained, b.pin)
	s.until = append(s.until, until)
	if s.failAt == n {
		return errors.New("PRIVATE_RETENTION_FAILURE")
	}
	return nil
}

// This is an INTEGRITY-ONLY fixture. It retains genuine current-generated PDF/font/
// DOM measurement bytes and rewrites metadata bindings to a synthetic valid
// application authority. It does not claim a genuine source-bound renderer
// invocation, isolated PDF admission, or glyph paint. Root-owned acceptance
// must generate packages directly from real AuthorityV1.Pages().
type selectionReportV1 struct {
	Schema           int               `json:"schema"`
	Policy           string            `json:"policy"`
	Plan             signaturefit.Plan `json:"plan"`
	InputSHA256      string            `json:"inputSha256"`
	RecipeSHA256     string            `json:"recipeSha256"`
	HTMLSHA256       string            `json:"htmlSha256"`
	FontFile         string            `json:"fontFile"`
	FontSHA256       string            `json:"fontSha256"`
	PDFSHA256        string            `json:"pdfSha256"`
	PDFBytes         int               `json:"pdfBytes"`
	FragmentPage     int               `json:"fragmentPage"`
	SnapshotSHA256   string            `json:"snapshotSha256"`
	ChromiumProduct  string            `json:"chromiumProduct"`
	ChromiumRevision string            `json:"chromiumRevision"`
	ChromiumProtocol string            `json:"chromiumProtocol"`
	Measurement      json.RawMessage   `json:"measurement"`
}

func selectionFixtureV1(t *testing.T, file string) (*manualfit.ManifestV1, manualfit.ObjectPinV1, *objectStoreV1) {
	t.Helper()
	raw, err := os.ReadFile("../signaturefit/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var parts [5][]byte
	offset := 60
	for i := range parts {
		n := int(binary.BigEndian.Uint32(raw[8+i*4:]))
		parts[i] = bytes.Clone(raw[offset : offset+n])
		offset += n
	}
	var report selectionReportV1
	if json.Unmarshal(parts[0], &report) != nil {
		t.Fatal("archive fixture report")
	}
	// Name and archived span are already independently bounded by V1 authority.
	span := []byte(`<span class="hash-signature" data-font="` + report.Plan.Font + `">` + html.EscapeString(report.Plan.Text) + `</span>`)
	org := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	doc := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	rec := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	first := uuid.MustParse(report.Plan.Targets[0].ID)
	second := uuid.MustParse(report.Plan.Targets[1].ID)
	source := manualfit.SourceTupleV1{Key: "opaque/source.pdf", VersionID: " original+/version= ", SHA256: report.Plan.SourceSHA256, Bytes: 100}
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{0, 0, 1000, 600}
	}
	g := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes, Pages: []sanitize.PDFManualPage{page}}
	geometryRaw, _ := json.Marshal(g.Pages)
	g.GeometrySHA256 = testSHA(geometryRaw)
	in := manualfit.AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: time.Date(2026, 10, 11, 12, 0, 0, 123456000, time.UTC), Source: source,
		TypedName: report.Plan.Text, Font: report.Plan.Font, SpanSHA256: testSHA(span), ExpectedTargetIDs: []uuid.UUID{first, second}, Targets: []manualfit.TargetV1{
			{ID: first, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "5.0000", W: "90.0000", H: "35.0000"},
			{ID: second, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "50.0000", W: "80.0000", H: "45.0000"},
		}}
	authority, err := manualfit.BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
	}
	plan := authority.Pages()[0]
	oldInput := report.InputSHA256
	report.Plan = plan.Plan
	report.InputSHA256 = plan.InputSHA256
	parts[2] = bytes.ReplaceAll(parts[2], []byte(oldInput), []byte(plan.InputSHA256))
	report.HTMLSHA256 = testSHA(parts[2])
	report.Measurement = bytes.ReplaceAll(report.Measurement, []byte(oldInput), []byte(plan.InputSHA256))
	parts[0], err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes := make([]byte, 60)
	copy(packageBytes, []byte("HSHFIT01"))
	for i, part := range parts {
		binary.BigEndian.PutUint32(packageBytes[8+i*4:], uint32(len(part)))
		packageBytes = append(packageBytes, part...)
	}
	reportSHA := sha256.Sum256(parts[0])
	copy(packageBytes[28:60], reportSHA[:])
	decoded, err := signaturefit.Decode(packageBytes, plan.Plan)
	if err != nil {
		t.Fatalf("integrity-only rebound fixture: %v", err)
	}
	d := decoded.Digests()
	op := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	prefix := manualfit.ObjectPrefixV1(op, org, doc)
	spanPin := manualfit.ObjectPinV1{Key: prefix + "span.html", VersionID: " span+/opaque=version ", SHA256: in.SpanSHA256, Bytes: int64(len(span)), ContentType: "text/html"}
	pagePin := manualfit.ObjectPinV1{Key: prefix + "page-1.fit", VersionID: " page+/opaque=version ", SHA256: d.PackageSHA256, Bytes: int64(len(packageBytes)), ContentType: signaturefit.MediaType}
	artifact := manualfit.PageArtifactV1{Page: 1, InputSHA256: plan.InputSHA256, Package: pagePin, PDFSHA256: d.PDFSHA256, ReportSHA256: d.ReportSHA256, HTMLSHA256: d.HTMLSHA256, FontSHA256: d.FontSHA256, SnapshotSHA256: d.SnapshotSHA256}
	m, err := manualfit.NewManifestV1(op, authority, spanPin, []manualfit.PageArtifactV1{artifact})
	if err != nil {
		t.Fatal(err)
	}
	manifestPin := manualfit.ObjectPinV1{Key: m.ManifestKey(), VersionID: " manifest+/opaque=version ", SHA256: m.SHA256(), Bytes: int64(len(m.CanonicalJSON())), ContentType: "application/json"}
	store := &objectStoreV1{blobs: map[string]objectBlobV1{}}
	for _, b := range []objectBlobV1{{spanPin, span}, {pagePin, packageBytes}, {manifestPin, m.CanonicalJSON()}} {
		store.blobs[blobIDV1(b.pin.Key, b.pin.VersionID)] = b
	}
	return m, manifestPin, store
}

type memoryStoreV1 struct {
	mu       sync.Mutex
	state    LockedStateV1
	row      *generated.SignatureFitSelection
	sessions int
	commits  int
	// Commit can have happened even when its response is lost.
	failCommitAt     int
	rollbackCommitAt int
	selectErr        bool
	failBeginAt      int
	lockHook         func(int, *LockedStateV1)
	lockCalls        int
	beginHook        func(int, *memoryStoreV1)
}
type memoryTxV1 struct {
	s       *memoryStoreV1
	state   LockedStateV1
	row     *generated.SignatureFitSelection
	done    bool
	session int
}

func cloneStateV1(s LockedStateV1) LockedStateV1 {
	raw, _ := json.Marshal(s)
	var copy LockedStateV1
	_ = json.Unmarshal(raw, &copy)
	return copy
}
func (s *memoryStoreV1) Begin(ctx context.Context) (TransactionV1, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.sessions++
	n := s.sessions
	if s.failBeginAt == n {
		s.mu.Unlock()
		return nil, errors.New("fresh SQL unavailable")
	}
	if s.beginHook != nil {
		s.beginHook(n, s)
	}
	return &memoryTxV1{s: s, state: cloneStateV1(s.state), row: cloneSelection(s.row), session: n}, nil
}
func (t *memoryTxV1) Lock(ctx context.Context, b manualfit.BindingV1) (LockedStateV1, error) {
	if err := ctx.Err(); err != nil {
		return LockedStateV1{}, err
	}
	t.s.lockCalls++
	if t.s.lockHook != nil {
		t.s.lockHook(t.s.lockCalls, &t.state)
	}
	if t.state.Preparation == nil || t.state.Preparation.ID != b.OperationID {
		return LockedStateV1{}, pgx.ErrNoRows
	}
	return cloneStateV1(t.state), nil
}
func (t *memoryTxV1) FindSelection(ctx context.Context, b manualfit.BindingV1) (*generated.SignatureFitSelection, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if t.row == nil {
		return nil, pgx.ErrNoRows
	}
	return cloneSelection(t.row), nil
}
func (t *memoryTxV1) MarkAttempt(ctx context.Context, r RequestV1) (*generated.SignatureFitPreparation, error) {
	if t.row != nil && t.row.PreparationID == r.Binding.OperationID {
		return nil, pgx.ErrNoRows
	}
	t.state.Preparation.SelectionCommitAttemptedAt = timestamp(time.Now())
	return t.state.Preparation, nil
}
func (t *memoryTxV1) Select(ctx context.Context, r RequestV1, id uuid.UUID) (*generated.SignatureFitSelection, error) {
	if t.s.selectErr {
		return nil, errors.New("selection SQL refused")
	}
	if t.row != nil {
		return nil, errors.New("duplicate selection")
	}
	p := t.state.Preparation
	var span, manifest *generated.SignatureFitObject
	for _, o := range t.state.Objects {
		if o.Kind == "span" {
			span = o
		}
		if o.Kind == "manifest" {
			manifest = o
		}
	}
	t.row = &generated.SignatureFitSelection{ID: id, PreparationID: p.ID, OrgID: p.OrgID, DocumentID: p.DocumentID, RecipientID: p.RecipientID, CeremonyEpoch: p.CeremonyEpoch, AuthoritySha256: bytes.Clone(p.AuthoritySha256), SourceStorageKey: p.SourceStorageKey, SourceVersionID: p.SourceVersionID, SourceSha256: bytes.Clone(p.SourceSha256), SourceBytes: p.SourceBytes, GeometrySha256: bytes.Clone(p.GeometrySha256), SpanStorageKey: span.StorageKey, SpanVersionID: span.VersionID.String, SpanSha256: bytes.Clone(span.Sha256), SpanBytes: span.Bytes, ManifestStorageKey: manifest.StorageKey, ManifestVersionID: manifest.VersionID.String, ManifestSha256: bytes.Clone(manifest.Sha256), ManifestBytes: manifest.Bytes, RetainUntil: timestamp(retentionFloor(p.CeremonyEpoch.Time))}
	return cloneSelection(t.row), nil
}
func (t *memoryTxV1) MarkNotCommitted(ctx context.Context, r RequestV1) (*generated.SignatureFitPreparation, error) {
	t.state.Preparation.SelectionNotCommittedAt = timestamp(time.Now())
	return t.state.Preparation, nil
}
func (t *memoryTxV1) MarkRetentionStarted(ctx context.Context, row *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error) {
	t.row.RetentionStartedAt = timestamp(time.Now())
	return cloneSelection(t.row), nil
}
func (t *memoryTxV1) MarkRetentionComplete(ctx context.Context, row *generated.SignatureFitSelection) (*generated.SignatureFitSelection, error) {
	if !t.row.RetentionStartedAt.Valid {
		return nil, errors.New("no checkpoint")
	}
	t.row.RetentionCompletedAt = timestamp(time.Now())
	return cloneSelection(t.row), nil
}
func (t *memoryTxV1) Commit(ctx context.Context) error {
	if t.done {
		return pgx.ErrTxClosed
	}
	t.done = true
	t.s.commits++
	n := t.s.commits
	if t.s.rollbackCommitAt != n {
		t.s.state = cloneStateV1(t.state)
		t.s.row = cloneSelection(t.row)
	}
	t.s.mu.Unlock()
	if t.s.failCommitAt == n || t.s.rollbackCommitAt == n {
		return errors.New("COMMIT response lost PRIVATE_SQL")
	}
	return nil
}
func (t *memoryTxV1) Rollback(ctx context.Context) error {
	if t.done {
		return pgx.ErrTxClosed
	}
	t.done = true
	t.s.mu.Unlock()
	return nil
}
func setupSelectionV1(t *testing.T) (*ServiceV1, RequestV1, *memoryStoreV1, *objectStoreV1) {
	t.Helper()
	m, pin, objects := selectionFixtureV1(t, "v1-case-1.fit")
	in := m.Authority().Input()
	b := m.Binding()
	owner := uuid.New()
	d := &generated.Document{ID: in.DocumentID, OrgID: in.OrgID, SourceKind: "pdf", Status: "sent", RequiresSignature: true, PdfStorageKey: pgtype.Text{String: in.Source.Key, Valid: true}, PdfStorageVersionID: pgtype.Text{String: in.Source.VersionID, Valid: true}, PdfSha256: mustDigestV1(in.Source.SHA256), Article13NoticeEpochAt: timestamp(in.CeremonyEpoch), Article13NoticeEpochV61Committed: true, SignatureFitReservedBytes: m.AggregateBytes()}
	rec := &generated.Recipient{ID: in.RecipientID, DocumentID: in.DocumentID, Status: "sent", Role: "signer"}
	p := &generated.SignatureFitPreparation{ID: b.OperationID, OrgID: b.OrgID, DocumentID: b.DocumentID, RecipientID: b.RecipientID, CeremonyEpoch: timestamp(b.CeremonyEpoch), AuthoritySha256: mustDigestV1(b.AuthoritySHA256), SourceStorageKey: in.Source.Key, SourceVersionID: in.Source.VersionID, SourceSha256: mustDigestV1(in.Source.SHA256), SourceBytes: in.Source.Bytes, GeometrySha256: mustDigestV1(m.Authority().Geometry().GeometrySHA256), SpanSha256: mustDigestV1(in.SpanSHA256), ReservedBytes: m.AggregateBytes(), ExpectedObjects: int32(len(m.Pages()) + 2), OwnerID: owner, Status: "prepared", LeaseUntil: timestamp(time.Now().Add(time.Hour))}
	state := LockedStateV1{Document: d, Recipient: rec, Preparation: p}
	for _, target := range in.Targets {
		f := &generated.DocumentField{ID: target.ID, DocumentID: d.ID, RecipientID: pgtype.UUID{Bytes: rec.ID, Valid: true}, Type: "signature", Page: int32(target.Page), Required: target.Required}
		_ = f.XPct.Scan(target.X)
		_ = f.YPct.Scan(target.Y)
		_ = f.WPct.Scan(target.W)
		_ = f.HPct.Scan(target.H)
		state.AllFields = append(state.AllFields, f)
	}
	pins := []manualfit.ObjectPinV1{m.Span(), m.Pages()[0].Package, pin}
	kinds := []string{"span", "page", "manifest"}
	for i, pin := range pins {
		page := int32(0)
		if kinds[i] == "page" {
			page = 1
		}
		o := &generated.SignatureFitObject{PreparationID: b.OperationID, Kind: kinds[i], Page: page, StorageKey: pin.Key, Sha256: mustDigestV1(pin.SHA256), Bytes: pin.Bytes, ContentType: pin.ContentType, UploadAttemptedAt: timestamp(time.Now()), UploadOwnerID: pgtype.UUID{Bytes: owner, Valid: true}, VersionID: pgtype.Text{String: pin.VersionID, Valid: true}, ReadbackVerifiedAt: timestamp(time.Now())}
		state.Objects = append(state.Objects, o)
		state.Inventory = append(state.Inventory, &generated.ListSignatureFitInventoryRow{PreparationID: b.OperationID, RecipientID: b.RecipientID, CeremonyEpoch: timestamp(b.CeremonyEpoch), Status: "prepared", OwnerID: owner, LeaseUntil: p.LeaseUntil, ExpectedObjects: p.ExpectedObjects, ReservedBytes: p.ReservedBytes, Kind: pgtype.Text{String: o.Kind, Valid: true}, Page: pgtype.Int4{Int32: o.Page, Valid: true}, StorageKey: pgtype.Text{String: o.StorageKey, Valid: true}, Sha256: bytes.Clone(o.Sha256), Bytes: pgtype.Int8{Int64: o.Bytes, Valid: true}, ContentType: pgtype.Text{String: o.ContentType, Valid: true}, UploadAttemptedAt: o.UploadAttemptedAt, UploadOwnerID: o.UploadOwnerID, VersionID: o.VersionID, ReadbackVerifiedAt: o.ReadbackVerifiedAt})
	}
	store := &memoryStoreV1{state: state}
	service := &ServiceV1{Store: store, Reader: objects, Retainer: objects, Admit: testAdmissionV1}
	return service, RequestV1{b, owner, pin}, store, objects
}
func mustDigestV1(s string) []byte { b, _ := hex.DecodeString(s); return b }
func testEntriesV1(state LockedStateV1) []ArchiveEntryLimitV1 {
	return []ArchiveEntryLimitV1{{manualfit.SourceArchiveNameV1(state.Document.ID), state.Preparation.SourceBytes}, {"final-pdf.pdf", 1000000}, {"audit-cert.pdf", 1000000}, {"audit-cert-payload.txt", 100000}, {"audit-cert-signature.txt", 64}, {"signature-fit-index.json", 100000}, {"events.json", 100}, {"versions.json", 100}, {"manifest.json", 100}, {"manifest-public-key.pem", 100}, {"certificate-public-key.pem", 100}}
}
func testAdmissionV1(ctx context.Context, state LockedStateV1) (AdmissionV1, error) {
	b, e := AdmitArchiveBudgetV1(state, testEntriesV1(state))
	if e != nil {
		return AdmissionV1{}, e
	}
	return AuthorizeV1(b, retentionFloor(state.Preparation.CeremonyEpoch.Time))
}
