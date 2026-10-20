// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package testfitarchive is imported ONLY by tests. Its rebound current-generated
// PDF/font/DOM bytes and synthetic source/finalization provide integrity-only
// fixtures, never runtime authorization, genuine renderer, SQL, S3/WORM,
// isolated PDF/glyph, delegated grant or legal-effect proof.
package testfitarchive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

type Blob struct {
	Pin manualfit.ObjectPinV1
	Raw []byte
}
type Store struct {
	Blobs map[string]Blob
	Reads []manualfit.ObjectPinV1
}

func Identity(key, version string) string { return key + "\x00" + version }
func SHA(raw []byte) string               { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (s *Store) Put(pin manualfit.ObjectPinV1, raw []byte) {
	s.Blobs[Identity(pin.Key, pin.VersionID)] = Blob{Pin: pin, Raw: bytes.Clone(raw)}
}
func (s *Store) GetVerifiedVersionBounded(ctx context.Context, key, version string, digest []byte, maximum int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	blob, ok := s.Blobs[Identity(key, version)]
	if !ok || blob.Pin.SHA256 != hex.EncodeToString(digest) || int64(len(blob.Raw)) > maximum || SHA(blob.Raw) != blob.Pin.SHA256 {
		return nil, errors.New("synthetic exact object unavailable")
	}
	s.Reads = append(s.Reads, blob.Pin)
	return bytes.Clone(blob.Raw), nil
}
func (s *Store) GetVerifiedVersion(ctx context.Context, key, version string, digest []byte) ([]byte, error) {
	blob, ok := s.Blobs[Identity(key, version)]
	if !ok {
		return nil, errors.New("synthetic exact object missing")
	}
	return s.GetVerifiedVersionBounded(ctx, key, version, digest, blob.Pin.Bytes)
}
func (s *Store) ResolveVerifiedLegacy(context.Context, string, []byte) ([]byte, storage.StoredObject, error) {
	return nil, storage.StoredObject{}, errors.New("fixture forbids latest/legacy resolution")
}

type Fixture struct {
	Input    manualfit.FitsIndexInputV1
	Store    *Store
	Index    *manualfit.SignedFitsIndexV1
	IndexPin manualfit.ObjectPinV1
	Signer   *sign.CertSigner
}
type reportV1 struct {
	Schema           int               "json:\"schema\""
	Policy           string            "json:\"policy\""
	Plan             signaturefit.Plan "json:\"plan\""
	InputSHA256      string            "json:\"inputSha256\""
	RecipeSHA256     string            "json:\"recipeSha256\""
	HTMLSHA256       string            "json:\"htmlSha256\""
	FontFile         string            "json:\"fontFile\""
	FontSHA256       string            "json:\"fontSha256\""
	PDFSHA256        string            "json:\"pdfSha256\""
	PDFBytes         int               "json:\"pdfBytes\""
	FragmentPage     int               "json:\"fragmentPage\""
	SnapshotSHA256   string            "json:\"snapshotSha256\""
	ChromiumProduct  string            "json:\"chromiumProduct\""
	ChromiumRevision string            "json:\"chromiumRevision\""
	ChromiumProtocol string            "json:\"chromiumProtocol\""
	Measurement      json.RawMessage   "json:\"measurement\""
}
type layerV1 struct {
	Page     int    "json:\"page\""
	Order    int    "json:\"order\""
	Kind     string "json:\"kind\""
	Identity string "json:\"identity\""
	Bytes    int    "json:\"bytes\""
	SHA256   string "json:\"sha256\""
}
type batchV1 struct {
	SchemaVersion  int       "json:\"schema_version\""
	SourceSHA256   string    "json:\"source_sha256\""
	SourceBytes    int64     "json:\"source_bytes\""
	GeometrySHA256 string    "json:\"geometry_sha256\""
	Pages          int       "json:\"pages\""
	Layers         []layerV1 "json:\"layers\""
}
type fieldV1 struct {
	ID             uuid.UUID
	RecipientID    uuid.UUID
	RecipientValid bool
	Type           string
	Page           int32
	Required       bool
	X, Y, W, H     string
	ValueValid     bool
	Value          string
}
type legacyV1 struct {
	DocumentID, ID, RecipientID, FieldID uuid.UUID
	Kind                                 string
	SignedAt                             time.Time
	Object                               manualfit.ObjectPinV1
	Name, Font, SpanSHA256               string
}
type basisV1 struct {
	Schema     string
	DocumentID uuid.UUID
	Fields     []fieldV1
	Legacy     []legacyV1
}

func New(t *testing.T, file string) *Fixture {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("fixture path")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "../signaturefit/testdata", file))
	if err != nil {
		t.Fatal(err)
	}
	var parts [5][]byte
	offset := 60
	for j := range parts {
		n := int(binary.BigEndian.Uint32(raw[8+j*4:]))
		parts[j] = bytes.Clone(raw[offset : offset+n])
		offset += n
	}
	var report reportV1
	if json.Unmarshal(parts[0], &report) != nil {
		t.Fatal("current-generated fixture report")
	}
	org := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	doc := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	rec := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	op := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	source := []byte("%PDF-1.4\nSYNTHETIC source integrity bytes\n%%EOF")
	span := []byte("<span class=\"hash-signature\" data-font=\"" + report.Plan.Font + "\">" + html.EscapeString(report.Plan.Text) + "</span>")
	page := sanitize.PDFManualPage{UserUnit: 1}
	for j := range page.Boxes {
		page.Boxes[j] = [4]float64{0, 0, 1000, 600}
	}
	pagesRaw, _ := json.Marshal([]sanitize.PDFManualPage{page})
	geometry := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: SHA(source), SourceBytes: int64(len(source)), GeometrySHA256: SHA(pagesRaw), Pages: []sanitize.PDFManualPage{page}}
	first := uuid.MustParse(report.Plan.Targets[0].ID)
	second := uuid.MustParse(report.Plan.Targets[1].ID)
	epoch := time.Date(2026, 10, 11, 12, 0, 0, 123456000, time.UTC)
	sourceTuple := manualfit.SourceTupleV1{Key: "opaque/source.pdf", VersionID: " original+/version= ", SHA256: SHA(source), Bytes: int64(len(source))}
	authorityInput := manualfit.AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: epoch, Source: sourceTuple, TypedName: report.Plan.Text, Font: report.Plan.Font, SpanSHA256: SHA(span), ExpectedTargetIDs: []uuid.UUID{first, second}, Targets: []manualfit.TargetV1{
		{ID: first, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "5.0000", W: "90.0000", H: "35.0000"},
		{ID: second, OrgID: org, DocumentID: doc, RecipientID: rec, Page: 1, Required: true, X: "5.0000", Y: "50.0000", W: "80.0000", H: "45.0000"},
	}}
	authority, err := manualfit.BuildAuthorityV1(authorityInput, geometry)
	if err != nil {
		t.Fatal(err)
	}
	plan := authority.Pages()[0]
	oldInput := report.InputSHA256
	report.Plan = plan.Plan
	report.InputSHA256 = plan.InputSHA256
	parts[2] = bytes.ReplaceAll(parts[2], []byte(oldInput), []byte(plan.InputSHA256))
	report.HTMLSHA256 = SHA(parts[2])
	report.Measurement = bytes.ReplaceAll(report.Measurement, []byte(oldInput), []byte(plan.InputSHA256))
	parts[0], err = json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	packageBytes := make([]byte, 60)
	copy(packageBytes, "HSHFIT01")
	for j, part := range parts {
		binary.BigEndian.PutUint32(packageBytes[8+j*4:], uint32(len(part)))
		packageBytes = append(packageBytes, part...)
	}
	reportSHA := sha256.Sum256(parts[0])
	copy(packageBytes[28:60], reportSHA[:])
	decoded, err := signaturefit.Decode(packageBytes, plan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	digests := decoded.Digests()
	prefix := manualfit.ObjectPrefixV1(op, org, doc)
	spanPin := manualfit.ObjectPinV1{Key: prefix + "span.html", VersionID: " span+/opaque=version ", SHA256: SHA(span), Bytes: int64(len(span)), ContentType: "text/html"}
	pagePin := manualfit.ObjectPinV1{Key: prefix + "page-1.fit", VersionID: " page+/opaque=version ", SHA256: digests.PackageSHA256, Bytes: int64(len(packageBytes)), ContentType: signaturefit.MediaType}
	manifest, err := manualfit.NewManifestV1(op, authority, spanPin, []manualfit.PageArtifactV1{{Page: 1, InputSHA256: plan.InputSHA256, Package: pagePin, PDFSHA256: digests.PDFSHA256, ReportSHA256: digests.ReportSHA256, HTMLSHA256: digests.HTMLSHA256, FontSHA256: digests.FontSHA256, SnapshotSHA256: digests.SnapshotSHA256}})
	if err != nil {
		t.Fatal(err)
	}
	manifestPin := manualfit.ObjectPinV1{Key: manifest.ManifestKey(), VersionID: " manifest+/opaque=version ", SHA256: manifest.SHA256(), Bytes: int64(len(manifest.CanonicalJSON())), ContentType: "application/json"}
	final := decoded.PDF()
	finalPin := manualfit.ObjectPinV1{Key: "org/" + org.String() + "/documents/" + doc.String() + "/final-" + SHA(final) + ".pdf", VersionID: " final+/version= ", SHA256: SHA(final), Bytes: int64(len(final)), ContentType: "application/pdf"}
	signature := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	metadata, _ := json.Marshal(batchV1{SchemaVersion: 1, SourceSHA256: SHA(source), SourceBytes: int64(len(source)), GeometrySHA256: geometry.GeometrySHA256, Pages: 1, Layers: []layerV1{{Page: 1, Order: 1, Kind: "retained_signature_v1", Identity: "signature:" + signature.String(), Bytes: len(final), SHA256: SHA(final)}}})
	processing := sha256.New()
	_, _ = processing.Write(metadata)
	_, _ = processing.Write(source)
	_, _ = processing.Write(final)
	completion := epoch.Add(2 * time.Second)
	fields := make([]fieldV1, 0, len(authorityInput.Targets))
	for _, target := range authorityInput.Targets {
		fields = append(fields, fieldV1{ID: target.ID, RecipientID: target.RecipientID, RecipientValid: true, Type: "signature", Page: int32(target.Page), Required: target.Required, X: target.X, Y: target.Y, W: target.W, H: target.H})
	}
	sort.Slice(fields, func(i, j int) bool { return bytes.Compare(fields[i].ID[:], fields[j].ID[:]) < 0 })
	basisRaw, err := json.Marshal(basisV1{Schema: "hash-manual-finalization-field-basis-v1", DocumentID: doc, Fields: fields, Legacy: []legacyV1{}})
	if err != nil {
		t.Fatal(err)
	}

	input := manualfit.FitsIndexInputV1{Binding: manualfit.FitsIndexBindingV1{OrgID: org, DocumentID: doc, CeremonyEpoch: epoch, CompletionEffectiveAt: completion, RetainUntil: manualfit.RetentionFloorV1(completion), FinalPDF: finalPin}, OriginalDocumentName: "Original Åsa & Company document", Documents: []manualfit.FitsIndexDocumentV1{{DocumentID: doc, Position: 0, CeremonyEpoch: epoch, Source: sourceTuple, Geometry: geometry, FieldSnapshotSHA256: SHA(basisRaw), FieldSnapshotJSON: basisRaw, Composition: sanitize.PDFManualLayersManifest{SchemaVersion: 1, Policy: "hash-pdf-manual-ordered-layers-v1", SourceSHA256: SHA(source), SourceBytes: int64(len(source)), GeometrySHA256: geometry.GeometrySHA256, Pages: 1, Layers: 1, DescriptorSHA256: SHA(metadata), OriginalContentSHA256: strings.Repeat("a", 64), OrderedPaintingSHA256: strings.Repeat("b", 64), ProcessingSHA256: hex.EncodeToString(processing.Sum(nil)), ProcessingBytes: int64(len(metadata) + len(source) + len(final)), OutputSHA256: SHA(final), OutputBytes: int64(len(final))}}}, Entries: []manualfit.FitsIndexEntryV1{{SignatureID: signature, SelectionID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), RecipientID: rec, FieldID: first, SignedAt: epoch.Add(time.Second), RetentionFloor: manualfit.RetentionFloorV1(epoch), ManifestObject: manifestPin, Manifest: manifest}}}
	store := &Store{Blobs: map[string]Blob{}}
	store.Put(spanPin, span)
	store.Put(pagePin, packageBytes)
	store.Put(manifestPin, manifest.CanonicalJSON())
	store.Put(finalPin, final)
	store.Put(manualfit.ObjectPinV1{Key: sourceTuple.Key, VersionID: sourceTuple.VersionID, SHA256: sourceTuple.SHA256, Bytes: sourceTuple.Bytes, ContentType: "application/pdf"}, source)
	index, err := manualfit.BuildFitsIndexV1(context.Background(), store, input)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(signer.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := manualfit.NewSignedFitsIndexV1(index, public, signer.SignFitsIndexV1)
	if err != nil {
		t.Fatal(err)
	}
	indexPin := manualfit.ObjectPinV1{Key: manualfit.IndexStorageKeyV1(org, doc, uuid.MustParse("77777777-7777-4777-8777-777777777777")), VersionID: " index+/version= ", SHA256: signed.SHA256(), Bytes: int64(len(signed.Bytes())), ContentType: "application/json"}
	store.Put(indexPin, signed.Bytes())
	return &Fixture{Input: input, Store: store, Index: signed, IndexPin: indexPin, Signer: signer}
}
