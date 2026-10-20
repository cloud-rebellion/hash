// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

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
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
)

type fittedFinalizeBlobTestV1 struct {
	pin manualfit.ObjectPinV1
	raw []byte
}
type fittedFinalizeStoreTestV1 struct {
	blobs         map[string]fittedFinalizeBlobTestV1
	reads         []manualfit.ObjectPinV1
	retained      []manualfit.ObjectPinV1
	deadlines     []time.Time
	failRetention int
	readHook      func(manualfit.ObjectPinV1) error
	retainHook    func(manualfit.ObjectPinV1) error
}

func fittedFinalizeBlobIDTestV1(k, v string) string { return k + string(rune(0)) + v }
func (s *fittedFinalizeStoreTestV1) GetVerifiedVersionBounded(ctx context.Context, k, v string, digest []byte, max int64) ([]byte, error) {
	b, ok := s.blobs[fittedFinalizeBlobIDTestV1(k, v)]
	if !ok {
		return nil, errors.New("private provider missing object")
	}
	if (max != b.pin.Bytes && !(b.pin.ContentType == "text/html" && max == int64(render.MaxArchivedSignatureSpanBytes))) || hex.EncodeToString(digest) != b.pin.SHA256 {
		return nil, errors.New("unbound size or digest")
	}
	s.reads = append(s.reads, b.pin)
	if s.readHook != nil {
		if err := s.readHook(b.pin); err != nil {
			return nil, err
		}
	}
	return bytes.Clone(b.raw), nil
}
func (s *fittedFinalizeStoreTestV1) RetainEvidenceVersion(ctx context.Context, k, v string, digest []byte, until time.Time) error {
	b, ok := s.blobs[fittedFinalizeBlobIDTestV1(k, v)]
	if !ok || hex.EncodeToString(digest) != b.pin.SHA256 {
		return errors.New("unbound retention")
	}
	s.retained = append(s.retained, b.pin)
	s.deadlines = append(s.deadlines, until)
	if s.retainHook != nil {
		if err := s.retainHook(b.pin); err != nil {
			return err
		}
	}
	if len(s.retained) == s.failRetention {
		return errors.New("private provider irreversible retention failure")
	}
	return nil
}

type fittedFinalizeQueriesTestV1 struct {
	signatures  []*generated.Signature
	recipients  []*generated.Recipient
	fields      []*generated.DocumentField
	companions  []*generated.SignatureFitCompanion
	selected    *generated.SignatureFitSelection
	preparation *generated.SignatureFitPreparation
	objects     []*generated.SignatureFitObject
	intent      *generated.DocumentFinalizationIntent
	fitReads    int
}

func (q *fittedFinalizeQueriesTestV1) ListSignaturesByDocument(context.Context, uuid.UUID) ([]*generated.Signature, error) {
	return q.signatures, nil
}
func (q *fittedFinalizeQueriesTestV1) ListRecipientsByDocument(context.Context, uuid.UUID) ([]*generated.Recipient, error) {
	return q.recipients, nil
}
func (q *fittedFinalizeQueriesTestV1) ListFieldsByDocument(context.Context, uuid.UUID) ([]*generated.DocumentField, error) {
	return q.fields, nil
}
func (q *fittedFinalizeQueriesTestV1) ListDocumentSignatureFitCompanions(context.Context, generated.ListDocumentSignatureFitCompanionsParams) ([]*generated.SignatureFitCompanion, error) {
	q.fitReads++
	return q.companions, nil
}
func (q *fittedFinalizeQueriesTestV1) GetSignatureFitSelection(ctx context.Context, p generated.GetSignatureFitSelectionParams) (*generated.SignatureFitSelection, error) {
	q.fitReads++
	if q.selected != nil && (p.DocumentID != q.selected.DocumentID || p.OrgID != q.selected.OrgID || p.RecipientID != q.selected.RecipientID || !p.CeremonyEpoch.Time.Equal(q.selected.CeremonyEpoch.Time)) {
		return nil, errors.New("incorrect selection lookup")
	}
	return q.selected, nil
}
func (q *fittedFinalizeQueriesTestV1) GetSignatureFitPreparation(ctx context.Context, p generated.GetSignatureFitPreparationParams) (*generated.SignatureFitPreparation, error) {
	q.fitReads++
	if q.preparation != nil && (p.ID != q.preparation.ID || p.OrgID != q.preparation.OrgID) {
		return nil, errors.New("incorrect preparation lookup")
	}
	return q.preparation, nil
}
func (q *fittedFinalizeQueriesTestV1) ListSignatureFitObjects(context.Context, generated.ListSignatureFitObjectsParams) ([]*generated.SignatureFitObject, error) {
	q.fitReads++
	return q.objects, nil
}
func (q *fittedFinalizeQueriesTestV1) GetDocumentFinalizationIntent(context.Context, generated.GetDocumentFinalizationIntentParams) (*generated.DocumentFinalizationIntent, error) {
	return q.intent, nil
}

type fittedFinalizeReportTestV1 struct {
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

// Integrity-only fixture: genuine current-generated PDF/font/DOM observations are rebound to
// synthetic application metadata. This is not a genuine renderer invocation,
// PDF structural admission, visual proof, or activation acceptance.
func fittedFinalizeFixtureTestV1(t *testing.T) (*generated.Document, *fittedFinalizeQueriesTestV1, *fittedFinalizeStoreTestV1) {
	t.Helper()
	return fittedFinalizeFixtureWithPagesTestV1(t, 2)
}
func fittedFinalizeFixtureWithPagesTestV1(t *testing.T, pageCount int) (*generated.Document, *fittedFinalizeQueriesTestV1, *fittedFinalizeStoreTestV1) {
	t.Helper()
	raw, err := os.ReadFile("../signaturefit/testdata/v1-case-1.fit")
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
	var report fittedFinalizeReportTestV1
	if json.Unmarshal(parts[0], &report) != nil {
		t.Fatal("fixture report")
	}
	org, doc, rec, op := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	first, second := uuid.MustParse(report.Plan.Targets[0].ID), uuid.MustParse(report.Plan.Targets[1].ID)
	sourceBytes := []byte("exact synthetic source for archive-binding unit tests")
	source := manualfit.SourceTupleV1{Key: "org/" + org.String() + "/documents/" + doc.String() + "/source.pdf", VersionID: " original+/opaque=version ", SHA256: fittedSHA256V1(sourceBytes), Bytes: int64(len(sourceBytes))}
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{0, 0, 1000, 600}
	}
	geometry := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes, Pages: make([]sanitize.PDFManualPage, pageCount)}
	for i := range geometry.Pages {
		geometry.Pages[i] = page
	}
	pagesJSON, _ := json.Marshal(geometry.Pages)
	geometry.GeometrySHA256 = fittedSHA256V1(pagesJSON)
	epoch := time.Date(2026, 10, 11, 12, 0, 0, 123456000, time.UTC)
	span := []byte("<span class=\"hash-signature\" data-font=\"" + report.Plan.Font + "\">" + html.EscapeString(report.Plan.Text) + "</span>")
	authority, err := manualfit.BuildAuthorityV1(manualfit.AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: epoch, Source: source, TypedName: report.Plan.Text, Font: report.Plan.Font, SpanSHA256: fittedSHA256V1(span), ExpectedTargetIDs: []uuid.UUID{first, second}, Targets: []manualfit.TargetV1{{ID: first, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "5.0000", W: "90.0000", H: "35.0000"}, {ID: second, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "50.0000", W: "80.0000", H: "45.0000"}}}, geometry)
	if err != nil {
		t.Fatal(err)
	}
	plan := authority.Pages()[0]
	replacements := [][2]string{{report.InputSHA256, plan.InputSHA256}, {report.Plan.SourceSHA256, source.SHA256}, {report.Plan.GeometrySHA256, geometry.GeometrySHA256}}
	for _, r := range replacements {
		parts[2] = bytes.ReplaceAll(parts[2], []byte(r[0]), []byte(r[1]))
		report.Measurement = bytes.ReplaceAll(report.Measurement, []byte(r[0]), []byte(r[1]))
	}
	report.Plan = plan.Plan
	report.InputSHA256 = plan.InputSHA256
	report.HTMLSHA256 = fittedSHA256V1(parts[2])
	parts[0], err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	packaged := make([]byte, 60)
	copy(packaged, []byte("HSHFIT01"))
	for i, p := range parts {
		binary.BigEndian.PutUint32(packaged[8+i*4:], uint32(len(p)))
		packaged = append(packaged, p...)
	}
	sum := sha256.Sum256(parts[0])
	copy(packaged[28:60], sum[:])
	decoded, err := signaturefit.Decode(packaged, plan.Plan)
	if err != nil {
		t.Fatalf("integrity-only rebound package: %v", err)
	}
	digests := decoded.Digests()
	prefix := manualfit.ObjectPrefixV1(op, org, doc)
	spanPin := manualfit.ObjectPinV1{Key: prefix + "span.html", VersionID: " span+/opaque=version ", SHA256: fittedSHA256V1(span), Bytes: int64(len(span)), ContentType: "text/html"}
	pagePin := manualfit.ObjectPinV1{Key: prefix + "page-1.fit", VersionID: " page+/opaque=version ", SHA256: digests.PackageSHA256, Bytes: int64(len(packaged)), ContentType: signaturefit.MediaType}
	manifest, err := manualfit.NewManifestV1(op, authority, spanPin, []manualfit.PageArtifactV1{{Page: 1, InputSHA256: plan.InputSHA256, Package: pagePin, PDFSHA256: digests.PDFSHA256, ReportSHA256: digests.ReportSHA256, HTMLSHA256: digests.HTMLSHA256, FontSHA256: digests.FontSHA256, SnapshotSHA256: digests.SnapshotSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	manifestPin := manualfit.ObjectPinV1{Key: manifest.ManifestKey(), VersionID: " manifest+/opaque=version ", SHA256: manifest.SHA256(), Bytes: int64(len(manifest.CanonicalJSON())), ContentType: "application/json"}
	store := &fittedFinalizeStoreTestV1{blobs: map[string]fittedFinalizeBlobTestV1{}}
	sourcePin := manualfit.ObjectPinV1{Key: source.Key, VersionID: source.VersionID, SHA256: source.SHA256, Bytes: source.Bytes, ContentType: "application/pdf"}
	for _, b := range []fittedFinalizeBlobTestV1{{sourcePin, sourceBytes}, {spanPin, span}, {pagePin, packaged}, {manifestPin, manifest.CanonicalJSON()}} {
		store.blobs[fittedFinalizeBlobIDTestV1(b.pin.Key, b.pin.VersionID)] = b
	}
	timestamp := func(t time.Time) pgtype.Timestamptz { return pgtype.Timestamptz{Time: t, Valid: true} }
	effective := epoch.Add(2 * time.Hour)
	floor := storage.EvidenceRetentionDeadline(epoch, article13.RetentionYearsV1)
	document := &generated.Document{ID: doc, OrgID: org, Status: "finalizing", SourceKind: "pdf", RequiresSignature: true, SentAt: timestamp(epoch), Article13NoticeEpochAt: timestamp(epoch), Article13NoticeEpochV61Committed: true, CompletionEffectiveAtBound: true, CompletionEffectiveAt: timestamp(effective), FinalizationRetainUntil: timestamp(storage.EvidenceRetentionDeadline(effective, article13.RetentionYearsV1)), PdfStorageKey: pgtype.Text{String: source.Key, Valid: true}, PdfStorageVersionID: pgtype.Text{String: source.VersionID, Valid: true}, PdfSha256: fittedHexTestV1(source.SHA256), EvidenceVersionPinsRequired: true, SignatureFitReservedBytes: manifest.AggregateBytes()}
	signature := &generated.Signature{ID: uuid.New(), DocumentID: doc, RecipientID: rec, FieldID: first, Font: "redacted mutable font", TypedName: "redacted mutable name", ImageStorageKey: spanPin.Key, ImageSha256: fittedHexTestV1(spanPin.SHA256), ImageVersionID: pgtype.Text{String: spanPin.VersionID, Valid: true}, ImageVersionPinRequired: true, SignatureKind: manualfit.AuthoritySchemaV1, SignedAt: timestamp(epoch.Add(time.Hour))}
	q := &fittedFinalizeQueriesTestV1{signatures: []*generated.Signature{signature}, recipients: []*generated.Recipient{{ID: rec, DocumentID: doc, Role: "signer", Status: "signed"}}, companions: []*generated.SignatureFitCompanion{{SignatureID: signature.ID, OrgID: org, DocumentID: doc, RecipientID: rec, FieldID: first, SelectionID: uuid.New(), SpanSha256: fittedHexTestV1(spanPin.SHA256)}}}
	for _, target := range authority.Input().Targets {
		q.fields = append(q.fields, &generated.DocumentField{ID: target.ID, DocumentID: doc, RecipientID: pgtype.UUID{Bytes: rec, Valid: true}, Type: "signature", Page: int32(target.Page), Required: true, XPct: fittedNumericTestV1(t, target.X), YPct: fittedNumericTestV1(t, target.Y), WPct: fittedNumericTestV1(t, target.W), HPct: fittedNumericTestV1(t, target.H)})
	}
	q.selected = &generated.SignatureFitSelection{ID: q.companions[0].SelectionID, PreparationID: op, OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: timestamp(epoch), AuthoritySha256: fittedHexTestV1(authority.SHA256()), SourceStorageKey: source.Key, SourceVersionID: source.VersionID, SourceSha256: fittedHexTestV1(source.SHA256), SourceBytes: source.Bytes, GeometrySha256: fittedHexTestV1(geometry.GeometrySHA256), SpanStorageKey: spanPin.Key, SpanVersionID: spanPin.VersionID, SpanSha256: fittedHexTestV1(spanPin.SHA256), SpanBytes: spanPin.Bytes, ManifestStorageKey: manifestPin.Key, ManifestVersionID: manifestPin.VersionID, ManifestSha256: fittedHexTestV1(manifestPin.SHA256), ManifestBytes: manifestPin.Bytes, RetainUntil: timestamp(floor), RetentionStartedAt: timestamp(epoch.Add(time.Minute)), RetentionCompletedAt: timestamp(epoch.Add(2 * time.Minute))}
	q.preparation = &generated.SignatureFitPreparation{ID: op, OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: timestamp(epoch), AuthoritySha256: bytes.Clone(q.selected.AuthoritySha256), SourceStorageKey: source.Key, SourceVersionID: source.VersionID, SourceSha256: bytes.Clone(q.selected.SourceSha256), SourceBytes: source.Bytes, GeometrySha256: bytes.Clone(q.selected.GeometrySha256), SpanSha256: bytes.Clone(q.selected.SpanSha256), Status: "prepared", ReservedBytes: manifest.AggregateBytes(), ExpectedObjects: 3}
	for i, pin := range []manualfit.ObjectPinV1{spanPin, pagePin, manifestPin} {
		kind, pageNumber := "span", int32(0)
		if i == 1 {
			kind, pageNumber = "page", 1
		} else if i == 2 {
			kind = "manifest"
		}
		q.objects = append(q.objects, &generated.SignatureFitObject{PreparationID: op, Kind: kind, Page: pageNumber, StorageKey: pin.Key, Sha256: fittedHexTestV1(pin.SHA256), Bytes: pin.Bytes, ContentType: pin.ContentType, VersionID: pgtype.Text{String: pin.VersionID, Valid: true}, UploadOwnerID: pgtype.UUID{Bytes: uuid.New(), Valid: true}, UploadAttemptedAt: timestamp(epoch.Add(time.Second)), ReadbackVerifiedAt: timestamp(epoch.Add(2 * time.Second))})
	}
	_, intent, _ := finalizationFixture(t)
	intent.DocumentID = doc
	intent.OrgID = org
	intent.CompletionEffectiveAt = document.CompletionEffectiveAt
	intent.RetainUntil = document.FinalizationRetainUntil
	intent.RetentionStartedAt = timestamp(effective.Add(time.Minute))
	q.intent = intent
	return document, q, store
}
func fittedHexTestV1(s string) []byte { v, _ := hex.DecodeString(s); return v }
func fittedNumericTestV1(t *testing.T, s string) pgtype.Numeric {
	t.Helper()
	var n pgtype.Numeric
	if err := n.Scan(s); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestFittedFinalizationExactArchivedOriginalsV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries()) != 1 || len(snapshot.Geometry().Pages) != 2 || snapshot.Entries()[0].OriginalName() == q.signatures[0].TypedName || snapshot.Entries()[0].Font() == q.signatures[0].Font || snapshot.RetainUntil().Equal(snapshot.Entries()[0].RetentionFloor()) {
		t.Fatal("lost original archive or full-source/final target commitments")
	}
	entry := snapshot.Entries()[0]
	span := entry.SpanBytes()
	span[0] = '!'
	if bytes.Equal(span, entry.SpanBytes()) {
		t.Fatal("span accessor aliases original")
	}
	geometry := snapshot.Geometry()
	geometry.Pages[1].UserUnit = 2
	if snapshot.Geometry().Pages[1].UserUnit != 1 {
		t.Fatal("geometry accessor aliases source")
	}
	entries := snapshot.Entries()
	entries[0] = nil
	if snapshot.Entries()[0] == nil {
		t.Fatal("entries accessor aliases selection")
	}
	for _, pin := range store.reads {
		if strings.TrimSpace(pin.VersionID) == pin.VersionID {
			t.Fatal("fixture requires preserving opaque version whitespace")
		}
	}
	layers, err := fittedOrderedLayersV1(context.Background(), snapshot)
	if err != nil || len(layers) != 1 || layers[0].Kind != sanitize.PDFManualLayerSignatureV1 || layers[0].Identity != "signature:"+entry.SignatureID().String() {
		t.Fatalf("archived ordered layers: %v", err)
	}
}
func TestFittedFinalizationRebindRefusalsV1(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*generated.Document, *fittedFinalizeQueriesTestV1, *fittedFinalizeStoreTestV1)
	}{
		{"companion selection", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.companions[0].SelectionID = uuid.New()
		}},
		{"second target moved", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.fields[1].XPct = fittedNumericTestV1(t, "6.0000")
		}},
		{"target omitted", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.fields = q.fields[:1]
		}},
		{"source version", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			d.PdfStorageVersionID.String = "new source version"
		}},
		{"unknown upload", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.objects[1].VersionID.Valid = false
		}},
		{"readback missing", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.objects[1].ReadbackVerifiedAt.Valid = false
		}},
		{"wrong media", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.objects[1].ContentType = "application/pdf"
		}},
		{"cleaned selected object", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.objects[1].CleanupCompletedAt = q.objects[1].ReadbackVerifiedAt
		}},
		{"selection retention incomplete", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.selected.RetentionCompletedAt.Valid = false
		}},
		{"preparation incomplete", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.preparation.Status = "staging"
		}},
		{"reserved ceiling", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			q.preparation.ReservedBytes--
		}},
		{"fit subtotal", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			d.SignatureFitReservedBytes--
		}},
		{"archive tamper", func(d *generated.Document, q *fittedFinalizeQueriesTestV1, s *fittedFinalizeStoreTestV1) {
			id := fittedFinalizeBlobIDTestV1(q.selected.ManifestStorageKey, q.selected.ManifestVersionID)
			b := s.blobs[id]
			b.raw[0] = '!'
			s.blobs[id] = b
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc, q, store := fittedFinalizeFixtureTestV1(t)
			tc.mutate(doc, q, store)
			if _, err := LoadFittedFinalizationV1(context.Background(), q, store, doc); !errors.Is(err, ErrFittedFinalizationV1) {
				t.Fatalf("accepted changed archive authority: %v", err)
			}
			if len(store.retained) != 0 {
				t.Fatal("loader had irreversible effects")
			}
		})
	}
}
func TestFittedFinalizationLegacyCapabilityCompatibilityV1(t *testing.T) {
	q := &fittedFinalizeQueriesTestV1{signatures: []*generated.Signature{{SignatureKind: "manual"}}}
	doc := &generated.Document{ID: uuid.New(), OrgID: uuid.New()}
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, nil, doc)
	if err != nil || snapshot != nil || q.fitReads != 0 {
		t.Fatalf("legacy path demanded fitted capabilities: %v", err)
	}
}
func TestFittedFinalizationDurableBaseRefusesRegenerationV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	valueField := &generated.DocumentField{ID: uuid.New(), DocumentID: doc.ID, RecipientID: q.fields[0].RecipientID, Type: "text", Page: 2, XPct: fittedNumericTestV1(t, "5.0000"), YPct: fittedNumericTestV1(t, "5.0000"), WPct: fittedNumericTestV1(t, "50.0000"), HPct: fittedNumericTestV1(t, "10.0000"), Value: pgtype.Text{String: "frozen approved value", Valid: true}}
	q.fields = append(q.fields, valueField)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ComposeFittedPDFV1(context.Background(), store, snapshot); !errors.Is(err, ErrFittedBaseDurabilityRequiredV1) {
		t.Fatal("unstaged base did not fail before worker dispatch")
	}
	baseBytes := []byte("durably staged synthetic base fixture")
	base := FittedBasePagePinV1{Page: 2, Object: manualfit.ObjectPinV1{Key: "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/finalization/base/" + uuid.New().String() + "/page-2.pdf", VersionID: " base+/opaque=version ", SHA256: fittedSHA256V1(baseBytes), Bytes: int64(len(baseBytes)), ContentType: "application/pdf"}, SourceSHA256: snapshot.Source().SHA256, GeometrySHA256: snapshot.Geometry().GeometrySHA256, FieldSnapshotSHA256: snapshot.FieldSnapshotSHA256()}
	store.blobs[fittedFinalizeBlobIDTestV1(base.Object.Key, base.Object.VersionID)] = fittedFinalizeBlobTestV1{base.Object, baseBytes}
	if _, err = LoadFittedBasePagesV1(context.Background(), store, snapshot, nil); !errors.Is(err, ErrFittedBaseDurabilityRequiredV1) {
		t.Fatal("missing required base accepted")
	}
	wrong := base
	wrong.FieldSnapshotSHA256 = strings.Repeat("a", 64)
	if _, err = LoadFittedBasePagesV1(context.Background(), store, snapshot, []FittedBasePagePinV1{wrong}); err == nil {
		t.Fatal("unrelated field snapshot accepted")
	}
	loaded, err := LoadFittedBasePagesV1(context.Background(), store, snapshot, []FittedBasePagePinV1{base})
	if err != nil {
		t.Fatal(err)
	}
	layers, err := fittedOrderedLayersV1(context.Background(), loaded)
	if err != nil || len(layers) != 2 || layers[1].Page != 2 || layers[1].Kind != sanitize.PDFManualLayerBaseV1 {
		t.Fatalf("missing durable page layer: %v", err)
	}
	mutated := loaded.BasePages()
	mutated[0].Object.VersionID = "shadow"
	if loaded.BasePages()[0].Object.VersionID != base.Object.VersionID {
		t.Fatal("base accessor aliases descriptor")
	}
	id := fittedFinalizeBlobIDTestV1(base.Object.Key, base.Object.VersionID)
	b := store.blobs[id]
	b.raw[0] = '!'
	store.blobs[id] = b
	if _, err = ComposeFittedPDFV1(context.Background(), store, loaded); err == nil {
		t.Fatal("changed exact base accepted")
	}
}
func TestFittedFinalizationRetentionUsesCommittedFinalTargetV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	q.intent.RetentionStartedAt.Valid = false
	if err = RetainFittedFinalizationV1(context.Background(), q, store, store, doc, snapshot); err == nil || len(store.retained) != 0 {
		t.Fatal("retained before durable checkpoint")
	}
	q.intent.RetentionStartedAt = pgtype.Timestamptz{Time: doc.CompletionEffectiveAt.Time.Add(time.Minute), Valid: true}
	store.failRetention = 3
	if err = RetainFittedFinalizationV1(context.Background(), q, store, store, doc, snapshot); !errors.Is(err, ErrFittedFinalizationV1) || len(store.retained) != 3 || strings.Contains(err.Error(), "private provider") {
		t.Fatalf("partial retention: %v", err)
	}
	store.failRetention = 0
	if err = RetainFittedFinalizationV1(context.Background(), q, store, store, doc, snapshot); err != nil {
		t.Fatal(err)
	}
	last := store.retained[len(store.retained)-4:]
	if last[0].Key != snapshot.Source().Key || last[1].Key != snapshot.Entries()[0].Manifest().Span().Key || last[2].ContentType != signaturefit.MediaType || last[3] != snapshot.Entries()[0].ManifestObject() {
		t.Fatal("did not extend complete source/span/page/manifest set")
	}
	for _, until := range store.deadlines {
		if !until.Equal(snapshot.RetainUntil()) || until.Equal(snapshot.Entries()[0].RetentionFloor()) {
			t.Fatal("used initial stage floor instead of committed completion target")
		}
	}
}
func TestFittedFinalizationCancellationOwnershipV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	private := errors.New("private custom cancellation owner")
	ctx, cancel := context.WithCancelCause(context.Background())
	store.readHook = func(manualfit.ObjectPinV1) error { cancel(private); return nil }
	_, err := LoadFittedFinalizationV1(ctx, q, store, doc)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
		t.Fatalf("lost cancellation owner or leaked cause: %v", err)
	}
	doc, q, store = fittedFinalizeFixtureTestV1(t)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancelCause(context.Background())
	store.retainHook = func(manualfit.ObjectPinV1) error { cancel(private); return nil }
	err = RetainFittedFinalizationV1(ctx, q, store, store, doc, snapshot)
	if !errors.Is(err, private) || !errors.Is(err, context.Canceled) || len(store.retained) != 1 || strings.Contains(err.Error(), private.Error()) {
		t.Fatalf("post-effect cancellation lost ownership: %v", err)
	}
}
func TestFittedFieldSnapshotFrozenValuesV1(t *testing.T) {
	doc, q, _ := fittedFinalizeFixtureTestV1(t)
	a, pages, err := fittedFieldSnapshotV1(doc.ID, q.fields, q.signatures)
	if err != nil || len(pages) != 0 {
		t.Fatal(err)
	}
	fields := append([]*generated.DocumentField(nil), q.fields...)
	fields[0], fields[1] = fields[1], fields[0]
	b, _, err := fittedFieldSnapshotV1(doc.ID, fields, q.signatures)
	if err != nil || a != b {
		t.Fatal("field row order changed canonical basis")
	}
	q.fields[0].XPct = fittedNumericTestV1(t, "5.0001")
	c, _, err := fittedFieldSnapshotV1(doc.ID, q.fields, q.signatures)
	if err != nil || a == c {
		t.Fatal("exact decimal change omitted")
	}
}

func TestFittedFinalizationCanceledBeforeAdmissionV1(t *testing.T) {
	private := errors.New("private before-admission cause")
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			doc, q, store := fittedFinalizeFixtureTestV1(t)
			var ctx context.Context
			var cleanup context.CancelFunc
			var sentinel error
			if deadline {
				ctx, cleanup = context.WithDeadlineCause(context.Background(), time.Now().Add(-time.Second), private)
				sentinel = context.DeadlineExceeded
			} else {
				c, cancel := context.WithCancelCause(context.Background())
				cancel(private)
				ctx = c
				cleanup = func() { cancel(nil) }
				sentinel = context.Canceled
			}
			defer cleanup()
			_, err := LoadFittedFinalizationV1(ctx, q, store, doc)
			if !errors.Is(err, sentinel) || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) || q.fitReads != 0 || len(store.reads) != 0 {
				t.Fatalf("before-admission cancellation ownership: %v", err)
			}
		})
	}
}
func TestFittedBareSpanRetentionRefusesBeforeAnyEffectV1(t *testing.T) {
	doc, q, _ := fittedFinalizeFixtureTestV1(t)
	legacy := *q.signatures[0]
	legacy.SignatureKind = "manual"
	legacy.ID = uuid.New()
	store := &finalizationStorageStub{objects: map[string][]byte{}}
	err := retainPinnedSignatureEvidence(context.Background(), store, doc.ID, []*generated.Signature{&legacy, q.signatures[0]}, doc.FinalizationRetainUntil.Time)
	if !errors.Is(err, ErrFittedCompositionRequiredV1) || len(store.retained) != 0 {
		t.Fatalf("bare-span fitted guard allowed an effect: %v", err)
	}
}

// These counters observe the actual archive decode and PDF-copy boundaries;
// they do not replace the production admission or construct an alternate loop.
type fittedLayerStatsTestV1 struct {
	fittedArchivedLayerAccessV1
	manifests, byteCounts, copies int
	cancelAt                      int
	cancel                        context.CancelCauseFunc
	cause                         error
}

func (s *fittedLayerStatsTestV1) Manifest(entry *FittedSignatureFinalizationV1) *manualfit.ManifestV1 {
	s.manifests++
	if s.cancel != nil && s.manifests == s.cancelAt {
		s.cancel(s.cause)
	}
	return s.fittedArchivedLayerAccessV1.Manifest(entry)
}
func (s *fittedLayerStatsTestV1) PDFByteCount(entry *FittedSignatureFinalizationV1, page int) (int, error) {
	s.byteCounts++
	return s.fittedArchivedLayerAccessV1.PDFByteCount(entry, page)
}
func (s *fittedLayerStatsTestV1) PDFBytes(entry *FittedSignatureFinalizationV1, page int) ([]byte, error) {
	s.copies++
	return s.fittedArchivedLayerAccessV1.PDFBytes(entry, page)
}

func fittedSparseLayerSnapshotTestV1(t *testing.T) *FittedFinalizationV1 {
	t.Helper()
	doc, q, store := fittedFinalizeFixtureWithPagesTestV1(t, 500)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	original := snapshot.entries[0]
	snapshot.entries = make([]*FittedSignatureFinalizationV1, 100)
	// Synthetic private resource fixture, not application signing acceptance:
	// share one fully decoded archive to avoid 100 copies of font/PDF storage.
	// Distinct ordered IDs exercise every real layer while 499 pages stay empty.
	for i := range snapshot.entries {
		entry := *original
		entry.signatureID = uuid.MustParse("11111111-1111-4111-8111-111111111111")
		entry.signatureID[15] = byte(i + 1)
		snapshot.entries[i] = &entry
	}
	return snapshot
}
func TestFittedLayersSparse500Pages100PartiesLinearArchiveWorkV1(t *testing.T) {
	snapshot := fittedSparseLayerSnapshotTestV1(t)
	stats := &fittedLayerStatsTestV1{}
	layers, err := fittedOrderedLayersWithAccessV1(context.Background(), snapshot, stats)
	if err != nil {
		t.Fatal(err)
	}
	if stats.manifests != 100 || stats.byteCounts != 100 || stats.copies != 100 || len(layers) != 100 {
		t.Fatalf("sparse composition amplified archive work: decodes=%d sizes=%d copies=%d layers=%d", stats.manifests, stats.byteCounts, stats.copies, len(layers))
	}
	for i, l := range layers {
		if l.Page != 1 || l.Order != i+1 || l.Kind != sanitize.PDFManualLayerSignatureV1 || l.Identity != "signature:"+snapshot.entries[i].SignatureID().String() {
			t.Fatal("occupied-page indexing changed canonical composition order")
		}
	}
}
func TestFittedLayersCancellationStopsArchiveWorkV1(t *testing.T) {
	snapshot := fittedSparseLayerSnapshotTestV1(t)
	private := errors.New("private layer cancellation owner")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(private)
	stats := &fittedLayerStatsTestV1{}
	_, err := fittedOrderedLayersWithAccessV1(ctx, snapshot, stats)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) || stats.manifests != 0 || stats.copies != 0 {
		t.Fatalf("canceled admission performed archive work or lost owner: %v", err)
	}
	ctx, cancel = context.WithCancelCause(context.Background())
	defer cancel(nil)
	stats = &fittedLayerStatsTestV1{cancelAt: 4, cancel: cancel, cause: private}
	_, err = fittedOrderedLayersWithAccessV1(ctx, snapshot, stats)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) || stats.manifests != 4 || stats.byteCounts != 3 || stats.copies != 0 {
		t.Fatalf("CPU admission continued after cancellation: decodes=%d sizes=%d copies=%d error=%v", stats.manifests, stats.byteCounts, stats.copies, err)
	}
}
func TestFittedLayersExactProcessingAdmissionBeforePDFCopiesV1(t *testing.T) {
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	n, err := snapshot.entries[0].retained.PDFByteCount(1)
	if err != nil {
		t.Fatal(err)
	}
	// Source plus PDF exactly consumes50MiB; the mandatory JSON descriptor
	// makes this inadmissible. No section may be copied before that refusal.
	snapshot.source.Bytes = int64(sanitize.MaxPDFBytes - n)
	stats := &fittedLayerStatsTestV1{}
	_, err = fittedOrderedLayersWithAccessV1(context.Background(), snapshot, stats)
	if !errors.Is(err, sanitize.ErrPDFTooLarge) || stats.manifests != 1 || stats.byteCounts != 1 || stats.copies != 0 {
		t.Fatalf("processing admission copied before exact frame gate: copies=%d error=%v", stats.copies, err)
	}
}
func TestFittedPinsShareFrozenOpaqueVersionPolicyV1(t *testing.T) {
	raw := []byte("positive exact-version fixture")
	pin := manualfit.ObjectPinV1{Key: "org/source.pdf", SHA256: fittedSHA256V1(raw), Bytes: int64(len(raw)), ContentType: "application/pdf"}
	rejected := []string{"", " ", "null", " null ", "hash:unversioned-development", " hash:unversioned-development ", "version\n", "version\x00", "version\x7f", string([]byte{0xff}), strings.Repeat("v", 1025)}
	for _, version := range rejected {
		pin.VersionID = version
		store := &fittedFinalizeStoreTestV1{blobs: map[string]fittedFinalizeBlobTestV1{fittedFinalizeBlobIDTestV1(pin.Key, version): {pin, raw}}}
		if validFittedPinV1(pin, 1000) {
			t.Fatal("accepted non-positive opaque version")
		}
		if _, err := readFittedPinV1(context.Background(), store, pin, 1000); err == nil || len(store.reads) != 0 {
			t.Fatal("delegated invalid version refusal to provider")
		}
	}
	for _, version := range []string{"v1", " original+/opaque=version ", "雲/版本="} {
		pin.VersionID = version
		store := &fittedFinalizeStoreTestV1{blobs: map[string]fittedFinalizeBlobTestV1{fittedFinalizeBlobIDTestV1(pin.Key, version): {pin, raw}}}
		body, err := readFittedPinV1(context.Background(), store, pin, 1000)
		if err != nil || !bytes.Equal(body, raw) || len(store.reads) != 1 || store.reads[0].VersionID != version {
			t.Fatalf("changed accepted opaque version: %v", err)
		}
	}
}

func fittedMixedLegacyFixtureTestV1(t *testing.T, kind string) (*generated.Document, *fittedFinalizeQueriesTestV1, *fittedFinalizeStoreTestV1, *generated.Signature, []byte) {
	t.Helper()
	doc, q, store := fittedFinalizeFixtureTestV1(t)
	rec, fieldID, id := uuid.New(), uuid.New(), uuid.New()
	name := "Original\u00a0Legacy Name"
	raw := []byte("<SPAN data-font='Caveat' class='hash-signature'>Original&nbsp;Legacy Name</SPAN>")
	pin := manualfit.ObjectPinV1{Key: "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/signatures/" + rec.String() + ".html", VersionID: " legacy+/opaque=version ", SHA256: fittedSHA256V1(raw), Bytes: int64(len(raw)), ContentType: "text/html"}
	signature := &generated.Signature{ID: id, DocumentID: doc.ID, RecipientID: rec, FieldID: fieldID, SignatureKind: kind, SignedAt: pgtype.Timestamptz{Time: doc.Article13NoticeEpochAt.Time.Add(30 * time.Minute), Valid: true}, ImageStorageKey: pin.Key, ImageVersionID: pgtype.Text{String: pin.VersionID, Valid: true}, ImageVersionPinRequired: true, ImageSha256: fittedHexTestV1(pin.SHA256), TypedName: name, Font: "historical unknown font"}
	if kind == "delegated_grant_v1" {
		signature.PresignExecutionID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
	}
	q.signatures = append(q.signatures, signature)
	q.recipients = append(q.recipients, &generated.Recipient{ID: rec, DocumentID: doc.ID, Role: "approver", Status: "signed"})
	q.fields = append(q.fields, &generated.DocumentField{ID: fieldID, DocumentID: doc.ID, RecipientID: pgtype.UUID{Bytes: rec, Valid: true}, Type: "signature", Required: true, Page: 2, XPct: fittedNumericTestV1(t, "5.0000"), YPct: fittedNumericTestV1(t, "5.0000"), WPct: fittedNumericTestV1(t, "80.0000"), HPct: fittedNumericTestV1(t, "20.0000")})
	store.blobs[fittedFinalizeBlobIDTestV1(pin.Key, pin.VersionID)] = fittedFinalizeBlobTestV1{pin, raw}
	return doc, q, store, signature, raw
}
func fittedMixedLegacyBaseTestV1(t *testing.T, store *fittedFinalizeStoreTestV1, snapshot *FittedFinalizationV1) *FittedFinalizationV1 {
	t.Helper()
	raw := []byte("synthetic already-staged legacy base for integrity/retention tests")
	descriptor := FittedBasePagePinV1{Page: 2, SourceSHA256: snapshot.Source().SHA256, GeometrySHA256: snapshot.Geometry().GeometrySHA256, FieldSnapshotSHA256: snapshot.FieldSnapshotSHA256(), Object: manualfit.ObjectPinV1{Key: "org/" + snapshot.OrgID().String() + "/documents/" + snapshot.DocumentID().String() + "/finalization/base/" + uuid.New().String() + "/page-2.pdf", VersionID: " legacy-base+/opaque=version ", SHA256: fittedSHA256V1(raw), Bytes: int64(len(raw)), ContentType: "application/pdf"}}
	store.blobs[fittedFinalizeBlobIDTestV1(descriptor.Object.Key, descriptor.Object.VersionID)] = fittedFinalizeBlobTestV1{descriptor.Object, raw}
	loaded, err := LoadFittedBasePagesV1(context.Background(), store, snapshot, []FittedBasePagePinV1{descriptor})
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}
func TestFittedSnapshotLegacyOriginalsFrozenBeforePrivacyProjectionV1(t *testing.T) {
	for _, kind := range []string{"manual", "delegated_grant_v1"} {
		t.Run(kind, func(t *testing.T) {
			doc, q, store, legacy, raw := fittedMixedLegacyFixtureTestV1(t, kind)
			originalName, originalFont := legacy.TypedName, legacy.Font
			// Simulate a privacy projection changing only row metadata during the
			// provider wait. Captured original names/fonts must remain byte-exact.
			store.readHook = func(pin manualfit.ObjectPinV1) error {
				if pin.Key == legacy.ImageStorageKey {
					legacy.TypedName = "redacted"
					legacy.Font = "redacted"
				}
				return nil
			}
			snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
			if err != nil {
				t.Fatal(err)
			}
			entries := snapshot.LegacySignatures()
			if len(entries) != 1 {
				t.Fatal("legacy descriptor missing")
			}
			entry := entries[0]
			if entry.Kind != kind || entry.DocumentID != doc.ID || entry.SignatureID != legacy.ID || entry.RecipientID != legacy.RecipientID || entry.FieldID != legacy.FieldID || entry.OriginalName != originalName || entry.Font != originalFont || entry.Object.Bytes != int64(len(raw)) || entry.Object.VersionID != legacy.ImageVersionID.String || entry.SpanSHA256 != fittedSHA256V1(raw) {
				t.Fatal("lost original legacy identity, font fallback metadata, or exact bytes")
			}
			bytesFromSnapshot, err := snapshot.LegacySpanBytes(legacy.ID)
			if err != nil || !bytes.Equal(bytesFromSnapshot, raw) {
				t.Fatal("legacy span was regenerated")
			}
			entries[0].OriginalName = "changed"
			bytesFromSnapshot[0] = '!'
			if snapshot.LegacySignatures()[0].OriginalName != originalName {
				t.Fatal("legacy descriptor accessor aliases capture")
			}
			again, _ := snapshot.LegacySpanBytes(legacy.ID)
			if !bytes.Equal(again, raw) {
				t.Fatal("legacy raw accessor aliases capture")
			}
			basis := snapshot.FieldSnapshotBytes()
			if fittedSHA256V1(basis) != snapshot.FieldSnapshotSHA256() || !bytes.Contains(basis, []byte(originalFont)) || !bytes.Contains(basis, []byte("legacy+/opaque=version")) {
				t.Fatal("canonical basis does not bind frozen legacy descriptor")
			}
			basis[0] = '!'
			if fittedSHA256V1(snapshot.FieldSnapshotBytes()) != snapshot.FieldSnapshotSHA256() {
				t.Fatal("canonical basis accessor aliases capture")
			}
			if pages := snapshot.RequiredBasePages(); len(pages) != 1 || pages[0] != 2 {
				t.Fatal("legacy signature did not require exact durable base page")
			}
			if _, err = ComposeFittedPDFV1(context.Background(), store, snapshot); !errors.Is(err, ErrFittedBaseDurabilityRequiredV1) {
				t.Fatal("legacy overlay silently fell back to renderer")
			}
		})
	}
}
func TestFittedLegacyRawRetainedAtFinalTargetAndTamperRefusedV1(t *testing.T) {
	doc, q, store, legacy, _ := fittedMixedLegacyFixtureTestV1(t, "delegated_grant_v1")
	snapshot, err := LoadFittedFinalizationV1(context.Background(), q, store, doc)
	if err != nil {
		t.Fatal(err)
	}
	snapshot = fittedMixedLegacyBaseTestV1(t, store, snapshot)
	if err = RetainFittedFinalizationV1(context.Background(), q, store, store, doc, snapshot); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, pin := range store.retained {
		if pin.Key == legacy.ImageStorageKey && pin.VersionID == legacy.ImageVersionID.String {
			found = true
			if !store.deadlines[i].Equal(snapshot.RetainUntil()) {
				t.Fatal("legacy adoption uses wrong retention target")
			}
		}
	}
	if !found {
		t.Fatal("legacy raw original not retained with fitted set")
	}
	id := fittedFinalizeBlobIDTestV1(legacy.ImageStorageKey, legacy.ImageVersionID.String)
	blob := store.blobs[id]
	blob.raw[0] = '!'
	store.blobs[id] = blob
	if _, err = verifyFittedLegacySpansV1(context.Background(), store, snapshot); err == nil {
		t.Fatal("changed exact legacy original accepted")
	}
	before := len(store.retained)
	if err = RetainFittedFinalizationV1(context.Background(), q, store, store, doc, snapshot); err == nil || len(store.retained) != before {
		t.Fatal("tampered legacy set extended any new retention")
	}
}
func TestFittedLegacyCaptureRefusesRedactedRowsAndInvalidBindingsV1(t *testing.T) {
	for _, reason := range []string{"redacted_name", "span_tamper", "null_version", "wrong_kind", "wrong_document"} {
		t.Run(reason, func(t *testing.T) {
			doc, q, store, legacy, _ := fittedMixedLegacyFixtureTestV1(t, "manual")
			switch reason {
			case "redacted_name":
				legacy.TypedName = "redacted"
			case "span_tamper":
				id := fittedFinalizeBlobIDTestV1(legacy.ImageStorageKey, legacy.ImageVersionID.String)
				b := store.blobs[id]
				b.raw[0] = '!'
				store.blobs[id] = b
			case "null_version":
				legacy.ImageVersionID.String = "null"
			case "wrong_kind":
				legacy.SignatureKind = "qualified"
			case "wrong_document":
				legacy.DocumentID = uuid.New()
			}
			if _, err := LoadFittedFinalizationV1(context.Background(), q, store, doc); !errors.Is(err, ErrFittedFinalizationV1) {
				t.Fatalf("accepted altered legacy capture: %v", err)
			}
		})
	}
}
