// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

// This fixture exercises archive INTEGRITY ONLY. The source/final bytes and
// completion are synthetic, and retained historical PDF/font/DOM bytes are
// rebound to synthetic authority. Genuine source-bound renderer/paint and
// committed SQL/provider acceptance remain separate root-owned checks.
func fitsIndexIntegrityFixtureV1(t *testing.T, file string) (FitsIndexInputV1, *fitStoreTestV1) {
	t.Helper()
	old, _, store := retainedFixtureTestV1(t, file)
	source := []byte("%PDF-1.4\nsynthetic source integrity bytes; not structural admission\n%%EOF")
	input := old.Authority().Input()
	input.Source.SHA256 = authoritySHA256V1(source)
	input.Source.Bytes = int64(len(source))
	geometry := old.Authority().Geometry()
	geometry.SourceSHA256 = input.Source.SHA256
	geometry.SourceBytes = input.Source.Bytes
	authority, err := BuildAuthorityV1(input, geometry)
	if err != nil {
		t.Fatal(err)
	}
	oldPage := old.Pages()[0]
	oldBlob := store.blobs[blobIDTestV1(oldPage.Package.Key, oldPage.Package.VersionID)]
	var parts [5][]byte
	offset := 60
	for j := range parts {
		n := int(binary.BigEndian.Uint32(oldBlob.raw[8+j*4:]))
		parts[j] = bytes.Clone(oldBlob.raw[offset : offset+n])
		offset += n
	}
	var report fitReportTestV1
	if json.Unmarshal(parts[0], &report) != nil {
		t.Fatal("fixture report")
	}
	plan := authority.Pages()[0]
	oldInput := report.InputSHA256
	report.Plan = plan.Plan
	report.InputSHA256 = plan.InputSHA256
	parts[2] = bytes.ReplaceAll(parts[2], []byte(oldInput), []byte(plan.InputSHA256))
	report.HTMLSHA256 = authoritySHA256V1(parts[2])
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
	pkg, err := signaturefit.Decode(packageBytes, plan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	digest := pkg.Digests()
	pagePin := oldPage.Package
	pagePin.SHA256 = digest.PackageSHA256
	pagePin.Bytes = int64(len(packageBytes))
	artifact := PageArtifactV1{Page: 1, InputSHA256: plan.InputSHA256, Package: pagePin, PDFSHA256: digest.PDFSHA256, ReportSHA256: digest.ReportSHA256, HTMLSHA256: digest.HTMLSHA256, FontSHA256: digest.FontSHA256, SnapshotSHA256: digest.SnapshotSHA256}
	manifest, err := NewManifestV1(old.Binding().OperationID, authority, old.Span(), []PageArtifactV1{artifact})
	if err != nil {
		t.Fatal(err)
	}
	manifestPin := ObjectPinV1{Key: manifest.ManifestKey(), VersionID: "index-fixture manifest+/= version", SHA256: manifest.SHA256(), Bytes: int64(len(manifest.CanonicalJSON())), ContentType: "application/json"}
	store.blobs = map[string]fitBlobTestV1{
		blobIDTestV1(pagePin.Key, pagePin.VersionID):         {pin: pagePin, raw: packageBytes},
		blobIDTestV1(manifestPin.Key, manifestPin.VersionID): {pin: manifestPin, raw: manifest.CanonicalJSON()},
		blobIDTestV1(old.Span().Key, old.Span().VersionID):   store.blobs[blobIDTestV1(old.Span().Key, old.Span().VersionID)],
	}
	sourcePin := ObjectPinV1{Key: input.Source.Key, VersionID: input.Source.VersionID, SHA256: input.Source.SHA256, Bytes: input.Source.Bytes, ContentType: "application/pdf"}
	store.blobs[blobIDTestV1(sourcePin.Key, sourcePin.VersionID)] = fitBlobTestV1{pin: sourcePin, raw: source}
	final := pkg.PDF()
	finalPin := ObjectPinV1{Key: "org/" + input.OrgID.String() + "/documents/" + input.DocumentID.String() + "/final-" + authoritySHA256V1(final) + ".pdf", VersionID: "final exact+/= version", SHA256: authoritySHA256V1(final), Bytes: int64(len(final)), ContentType: "application/pdf"}
	store.blobs[blobIDTestV1(finalPin.Key, finalPin.VersionID)] = fitBlobTestV1{pin: finalPin, raw: final}
	signatureID := uuid.MustParse("55555555-5555-4555-8555-555555555555")
	descriptors := []archivedLayerDescriptorV1{{Page: 1, Order: 1, Kind: "retained_signature_v1", Identity: "signature:" + signatureID.String(), Bytes: len(final), SHA256: authoritySHA256V1(final)}}
	metadata, err := json.Marshal(archivedLayerBatchV1{SchemaVersion: 1, SourceSHA256: input.Source.SHA256, SourceBytes: input.Source.Bytes, GeometrySHA256: geometry.GeometrySHA256, Pages: 1, Layers: descriptors})
	if err != nil {
		t.Fatal(err)
	}
	processing := sha256.New()
	_, _ = processing.Write(metadata)
	_, _ = processing.Write(source)
	_, _ = processing.Write(final)
	completion := input.CeremonyEpoch.Add(2 * time.Second)
	witness := sanitize.PDFManualLayersManifest{SchemaVersion: 1, Policy: "hash-pdf-manual-ordered-layers-v1", SourceSHA256: input.Source.SHA256, SourceBytes: input.Source.Bytes, GeometrySHA256: geometry.GeometrySHA256, Pages: 1, Layers: 1, DescriptorSHA256: authoritySHA256V1(metadata), OriginalContentSHA256: strings.Repeat("a", 64), OrderedPaintingSHA256: strings.Repeat("b", 64), ProcessingSHA256: hex.EncodeToString(processing.Sum(nil)), ProcessingBytes: int64(len(metadata) + len(source) + len(final)), OutputSHA256: finalPin.SHA256, OutputBytes: finalPin.Bytes}
	fields := make([]indexFieldBasisV1, 0, len(input.Targets))
	for _, target := range input.Targets {
		fields = append(fields, indexFieldBasisV1{ID: target.ID, RecipientID: target.RecipientID, RecipientValid: true, Type: "signature", Page: int32(target.Page), Required: target.Required, X: target.X, Y: target.Y, W: target.W, H: target.H})
	}
	sort.Slice(fields, func(i, j int) bool { return bytes.Compare(fields[i].ID[:], fields[j].ID[:]) < 0 })
	basisRaw, err := json.Marshal(indexFieldBasisDocumentV1{Schema: "hash-manual-finalization-field-basis-v1", DocumentID: input.DocumentID, Fields: fields, Legacy: []indexLegacyBasisV1{}})
	if err != nil {
		t.Fatal(err)
	}

	return FitsIndexInputV1{Binding: FitsIndexBindingV1{OrgID: input.OrgID, DocumentID: input.DocumentID, CeremonyEpoch: input.CeremonyEpoch, CompletionEffectiveAt: completion, RetainUntil: RetentionFloorV1(completion), FinalPDF: finalPin}, OriginalDocumentName: "Original Åsa & Company document",
		Documents: []FitsIndexDocumentV1{{DocumentID: input.DocumentID, Position: 0, CeremonyEpoch: input.CeremonyEpoch, Source: input.Source, Geometry: geometry, FieldSnapshotSHA256: authoritySHA256V1(basisRaw), FieldSnapshotJSON: basisRaw, Composition: witness}},
		Entries:   []FitsIndexEntryV1{{SignatureID: signatureID, SelectionID: uuid.MustParse("66666666-6666-4666-8666-666666666666"), RecipientID: input.RecipientID, FieldID: input.Targets[0].ID, SignedAt: input.CeremonyEpoch.Add(time.Second), RetentionFloor: RetentionFloorV1(input.CeremonyEpoch), ManifestObject: manifestPin, Manifest: manifest}}}, store
}
func signedIndexTestV1(t *testing.T, index *FitsIndexV1) (*SignedFitsIndexV1, ed25519.PublicKey) {
	t.Helper()
	pub, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := NewSignedFitsIndexV1(index, pub, func(raw []byte) string {
		sum := sha256.Sum256(append([]byte(FitsIndexSignaturePrefixV1), raw...))
		return base64.StdEncoding.EncodeToString(ed25519.Sign(private, sum[:]))
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed, pub
}
func TestFitsIndexV1FrozenIntegrityRecoveryAllFonts(t *testing.T) {
	for _, file := range []string{"v1-case-1.fit", "v1-case-3.fit", "v1-case-5.fit", "v1-case-7.fit", "v1-case-9.fit"} {
		t.Run(file, func(t *testing.T) {
			input, store := fitsIndexIntegrityFixtureV1(t, file)
			index, err := BuildFitsIndexV1(context.Background(), store, input)
			if err != nil {
				t.Fatal(err)
			}
			signed, pub := signedIndexTestV1(t, index)
			pin := ObjectPinV1{Key: IndexStorageKeyV1(input.Binding.OrgID, input.Binding.DocumentID, uuid.MustParse("77777777-7777-4777-8777-777777777777")), VersionID: "signed index+/= exact", SHA256: signed.SHA256(), Bytes: int64(len(signed.Bytes())), ContentType: "application/json"}
			store.blobs[blobIDTestV1(pin.Key, pin.VersionID)] = fitBlobTestV1{pin: pin, raw: signed.Bytes()}
			t.Chdir(t.TempDir())
			recovered, err := ReadFitsArchiveSnapshotV1(context.Background(), store, pin, input.Binding, pub)
			if err != nil {
				t.Fatal(err)
			}
			if recovered.Index().Index().OriginalDocumentName() != input.OriginalDocumentName || len(recovered.Objects()) != 6 || len(store.retained) != 0 {
				t.Fatal("original frozen inventory or scope changed")
			}
			original := recovered.Index().Bytes()
			original[0] = 'x'
			if recovered.Index().Bytes()[0] != '{' {
				t.Fatal("signed bytes aliased")
			}
			for _, read := range store.reads {
				if read.VersionID == "" {
					t.Fatal("latest object read")
				}
			}
		})
	}
}
func TestFitsIndexV1RefusesChangedObjectsWitnessAndRecoveryBinding(t *testing.T) {
	for _, name := range []string{"missing-source", "replaced-source-version", "source-byte-tamper", "processing-witness", "descriptor-witness", "original-manifest-byte-tamper", "private-error", "cancel-cause"} {
		t.Run(name, func(t *testing.T) {
			input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			cause := errors.New("PRIVATE_INDEX_CONTEXT")
			source := input.Documents[0].Source
			switch name {
			case "missing-source":
				delete(store.blobs, blobIDTestV1(source.Key, source.VersionID))
			case "replaced-source-version":
				b := store.blobs[blobIDTestV1(source.Key, source.VersionID)]
				delete(store.blobs, blobIDTestV1(source.Key, source.VersionID))
				b.pin.VersionID = "new latest"
				store.blobs[blobIDTestV1(b.pin.Key, b.pin.VersionID)] = b
			case "source-byte-tamper":
				b := store.blobs[blobIDTestV1(source.Key, source.VersionID)]
				b.raw[10] ^= 1
				store.blobs[blobIDTestV1(source.Key, source.VersionID)] = b
			case "processing-witness":
				input.Documents[0].Composition.ProcessingSHA256 = strings.Repeat("d", 64)
			case "descriptor-witness":
				input.Documents[0].Composition.DescriptorSHA256 = strings.Repeat("d", 64)
			case "original-manifest-byte-tamper":
				pin := input.Entries[0].ManifestObject
				b := store.blobs[blobIDTestV1(pin.Key, pin.VersionID)]
				b.raw[len(b.raw)-1] = 'x'
				store.blobs[blobIDTestV1(pin.Key, pin.VersionID)] = b
			case "private-error":
				store.readHook = func(int, ObjectPinV1, []byte) ([]byte, error) { return nil, errors.New("PRIVATE_STORAGE_DETAIL") }
			case "cancel-cause":
				store.readHook = func(_ int, _ ObjectPinV1, raw []byte) ([]byte, error) { cancel(cause); return raw, nil }
			}
			_, err := BuildFitsIndexV1(ctx, store, input)
			if err == nil || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("accepted change or leaked private failure: %v", err)
			}
			if name == "cancel-cause" && (!errors.Is(err, context.Canceled) || !errors.Is(err, cause)) {
				t.Fatal("context cause lost")
			}
		})
	}
	input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
	index, err := BuildFitsIndexV1(context.Background(), store, input)
	if err != nil {
		t.Fatal(err)
	}
	signed, pub := signedIndexTestV1(t, index)
	for _, edit := range []func(*FitsIndexBindingV1){func(b *FitsIndexBindingV1) { b.DocumentID = uuid.New() }, func(b *FitsIndexBindingV1) { b.CeremonyEpoch = b.CeremonyEpoch.Add(time.Nanosecond) }, func(b *FitsIndexBindingV1) { b.CompletionEffectiveAt = b.CompletionEffectiveAt.Add(time.Nanosecond) }, func(b *FitsIndexBindingV1) { b.RetainUntil = b.RetainUntil.Add(time.Second) }, func(b *FitsIndexBindingV1) { b.FinalPDF.VersionID = "other exact version" }} {
		binding := input.Binding
		edit(&binding)
		if _, err := DecodeSignedFitsIndexV1(signed.Bytes(), binding, pub); err == nil {
			t.Fatal("changed external completion/final binding accepted")
		}
	}
	raw := signed.Bytes()
	raw = bytes.Replace(raw, []byte(FitsIndexSignatureDomainV1), []byte("hash:audit-cert:v1"), 1)
	if _, err := DecodeSignedFitsIndexV1(raw, input.Binding, pub); err == nil {
		t.Fatal("cross-domain signature accepted")
	}
	raw = append(signed.Bytes(), ' ')
	if _, err := DecodeSignedFitsIndexV1(raw, input.Binding, pub); err == nil {
		t.Fatal("noncanonical signed wrapper accepted")
	}
}
func TestSchema4ArchiveLimitsMatchActualStoreZIP(t *testing.T) {
	files := []ArchiveSizeV1{{Name: "versions.json", Bytes: 2}, {Name: "events.json", Bytes: 2}, {Name: "audit-cert-signature.txt", Bytes: 88}}
	expected, err := StoreZIPSizeV1(files)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, entry := range files {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: entry.Name, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write(bytes.Repeat([]byte{'x'}, int(entry.Bytes))); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(out.Len()) != expected {
		t.Fatalf("Store ZIP reservation %d actual %d", expected, out.Len())
	}
	for _, bad := range []string{"../page.fit", "page.fit", "fit-00000000-0000-0000-0000-000000000000-page-1.fit", "fit-55555555-5555-4555-8555-555555555555-page-01.fit", "source-55555555-5555-4555-8555-555555555555.pdf/extra"} {
		if _, err := ArchiveEntryLimitV1(bad); err == nil {
			t.Fatal("unsafe member obtains package cap")
		}
	}
	if _, err := StoreZIPSizeV1([]ArchiveSizeV1{{Name: "events.json", Bytes: MaxEventsJSONBytesV1 + 1}}); err == nil {
		t.Fatal("per-file cap absent")
	}
	if _, err := StoreZIPSizeV1([]ArchiveSizeV1{{Name: "events.json", Bytes: 1}, {Name: "events.json", Bytes: 1}}); err == nil {
		t.Fatal("duplicate cap absent")
	}
}

func addLegacyIntegrityV1(t *testing.T, input *FitsIndexInputV1, store *fitStoreTestV1, kind string) {
	t.Helper()
	doc := &input.Documents[0]
	source := store.blobs[blobIDTestV1(doc.Source.Key, doc.Source.VersionID)].raw
	final := store.blobs[blobIDTestV1(input.Binding.FinalPDF.Key, input.Binding.FinalPDF.VersionID)].raw
	basePin := ObjectPinV1{Key: "org/" + input.Binding.OrgID.String() + "/documents/" + doc.DocumentID.String() + "/finalization/base/88888888-8888-4888-8888-888888888888/page-1.pdf", VersionID: "base exact+/=", SHA256: authoritySHA256V1(final), Bytes: int64(len(final)), ContentType: "application/pdf"}
	store.blobs[blobIDTestV1(basePin.Key, basePin.VersionID)] = fitBlobTestV1{pin: basePin, raw: bytes.Clone(final)}
	doc.BasePages = []FitsIndexBasePageV1{{Page: 1, Object: basePin, SourceSHA256: doc.Source.SHA256, GeometrySHA256: doc.Geometry.GeometrySHA256, FieldSnapshotSHA256: doc.FieldSnapshotSHA256}}
	name := strings.Repeat("Å", 198) + " &"
	span := []byte("<SPAN data-font='Caveat' class='hash-signature'>" + html.EscapeString(name) + "</SPAN>")
	pin := ObjectPinV1{Key: "opaque/legacy-original.html", VersionID: "old exact+/=", SHA256: authoritySHA256V1(span), Bytes: int64(len(span)), ContentType: "text/html"}
	store.blobs[blobIDTestV1(pin.Key, pin.VersionID)] = fitBlobTestV1{pin: pin, raw: span}
	input.LegacySignatures = []FitsIndexLegacySignatureV1{{DocumentID: doc.DocumentID, SignatureID: uuid.MustParse("99999999-9999-4999-8999-999999999999"), RecipientID: uuid.MustParse("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"), FieldID: uuid.MustParse("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"), Kind: kind, SignedAt: doc.CeremonyEpoch.Add(time.Second), Object: pin, OriginalName: name, Font: "historical-unknown-font", SpanSHA256: pin.SHA256}}
	var basis indexFieldBasisDocumentV1
	if json.Unmarshal(doc.FieldSnapshotJSON, &basis) != nil {
		t.Fatal("frozen basis fixture")
	}
	old := input.LegacySignatures[0]
	basis.Fields = append(basis.Fields, indexFieldBasisV1{ID: old.FieldID, RecipientID: old.RecipientID, RecipientValid: true, Type: "signature", Page: 1, Required: true, X: "10.0000", Y: "10.0000", W: "20.0000", H: "20.0000"})
	sort.Slice(basis.Fields, func(i, j int) bool { return bytes.Compare(basis.Fields[i].ID[:], basis.Fields[j].ID[:]) < 0 })
	basis.Legacy = []indexLegacyBasisV1{{DocumentID: old.DocumentID, ID: old.SignatureID, RecipientID: old.RecipientID, FieldID: old.FieldID, Kind: old.Kind, SignedAt: old.SignedAt, Object: old.Object, Name: old.OriginalName, Font: old.Font, SpanSHA256: old.SpanSHA256}}
	basisJSON, err := json.Marshal(basis)
	doc.FieldSnapshotJSON = basisJSON
	if err != nil {
		t.Fatal(err)
	}
	doc.FieldSnapshotSHA256 = authoritySHA256V1(doc.FieldSnapshotJSON)
	doc.BasePages[0].FieldSnapshotSHA256 = doc.FieldSnapshotSHA256

	layers := []archivedLayerDescriptorV1{{Page: 1, Order: 1, Kind: "base_text_v1", Identity: "base-page-1", Bytes: len(final), SHA256: authoritySHA256V1(final)}, {Page: 1, Order: 2, Kind: "retained_signature_v1", Identity: "signature:" + input.Entries[0].SignatureID.String(), Bytes: len(final), SHA256: authoritySHA256V1(final)}}
	metadata, err := json.Marshal(archivedLayerBatchV1{SchemaVersion: 1, SourceSHA256: doc.Source.SHA256, SourceBytes: doc.Source.Bytes, GeometrySHA256: doc.Geometry.GeometrySHA256, Pages: 1, Layers: layers})
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, _ = hash.Write(metadata)
	_, _ = hash.Write(source)
	_, _ = hash.Write(final)
	_, _ = hash.Write(final)
	doc.Composition.Layers = 2
	doc.Composition.DescriptorSHA256 = authoritySHA256V1(metadata)
	doc.Composition.ProcessingBytes = int64(len(metadata) + len(source) + 2*len(final))
	doc.Composition.ProcessingSHA256 = hex.EncodeToString(hash.Sum(nil))
}
func TestFitsIndexV1PreservesLegacyAdoptionBytesAndFallback(t *testing.T) {
	for _, kind := range []string{"manual", "delegated_grant_v1"} {
		t.Run(kind, func(t *testing.T) {
			input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
			addLegacyIntegrityV1(t, &input, store, kind)
			index, err := BuildFitsIndexV1(context.Background(), store, input)
			if err != nil {
				t.Fatal(err)
			}
			signed, pub := signedIndexTestV1(t, index)
			pin := ObjectPinV1{Key: IndexStorageKeyV1(input.Binding.OrgID, input.Binding.DocumentID, uuid.MustParse("77777777-7777-4777-8777-777777777777")), VersionID: "legacy index version", SHA256: signed.SHA256(), Bytes: int64(len(signed.Bytes())), ContentType: "application/json"}
			store.blobs[blobIDTestV1(pin.Key, pin.VersionID)] = fitBlobTestV1{pin: pin, raw: signed.Bytes()}
			snapshot, err := ReadFitsArchiveSnapshotV1(context.Background(), store, pin, input.Binding, pub)
			if err != nil {
				t.Fatal(err)
			}
			name := LegacySpanArchiveNameV1(input.LegacySignatures[0].SignatureID)
			reader, err := snapshot.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := io.ReadAll(reader)
			if err != nil {
				t.Fatal(err)
			}
			original := store.blobs[blobIDTestV1(input.LegacySignatures[0].Object.Key, input.LegacySignatures[0].Object.VersionID)].raw
			if !bytes.Equal(raw, original) || index.wire.LegacySignatures[0].OriginalName != input.LegacySignatures[0].OriginalName || index.wire.LegacySignatures[0].Font != input.LegacySignatures[0].Font {
				t.Fatal("original bytes/name projection lost")
			}
			input.LegacySignatures[0].OriginalName = "[erased]"
			if _, err := BuildFitsIndexV1(context.Background(), store, input); err == nil {
				t.Fatal("mutable name projection replaced old adoption")
			}
		})
	}
}

func TestFitsIndexV1OriginalFieldBasisRejectsStaleTargetsAndProjection(t *testing.T) {
	for _, name := range []string{"literal-tamper", "changed-target", "missing-target", "extra-required-target", "ordinary-base-omitted", "legacy-name-projection"} {
		t.Run(name, func(t *testing.T) {
			input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
			if name == "legacy-name-projection" {
				addLegacyIntegrityV1(t, &input, store, "manual")
			}
			doc := &input.Documents[0]
			var basis indexFieldBasisDocumentV1
			if json.Unmarshal(doc.FieldSnapshotJSON, &basis) != nil {
				t.Fatal("basis fixture")
			}
			switch name {
			case "literal-tamper":
				doc.FieldSnapshotJSON[10] ^= 1
			case "changed-target":
				basis.Fields[0].X = "6.0000"
			case "missing-target":
				basis.Fields = basis.Fields[1:]
			case "extra-required-target":
				field := basis.Fields[0]
				field.ID = uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd")
				basis.Fields = append(basis.Fields, field)
				sort.Slice(basis.Fields, func(i, j int) bool { return bytes.Compare(basis.Fields[i].ID[:], basis.Fields[j].ID[:]) < 0 })
			case "ordinary-base-omitted":
				basis.Fields = append(basis.Fields, indexFieldBasisV1{ID: uuid.MustParse("dddddddd-dddd-4ddd-8ddd-dddddddddddd"), Type: "text", Page: 1, X: "10.0000", Y: "10.0000", W: "20.0000", H: "20.0000", ValueValid: true, Value: "original ordinary text"})
				sort.Slice(basis.Fields, func(i, j int) bool { return bytes.Compare(basis.Fields[i].ID[:], basis.Fields[j].ID[:]) < 0 })
			case "legacy-name-projection":
				basis.Legacy[0].Name = "[erased]"
			}
			if name != "literal-tamper" {
				raw, err := json.Marshal(basis)
				if err != nil {
					t.Fatal(err)
				}
				doc.FieldSnapshotJSON = raw
				doc.FieldSnapshotSHA256 = authoritySHA256V1(raw)
				for j := range doc.BasePages {
					doc.BasePages[j].FieldSnapshotSHA256 = doc.FieldSnapshotSHA256
				}
			}
			if _, err := BuildFitsIndexV1(context.Background(), store, input); err == nil {
				t.Fatal("stale or projected original field authority accepted")
			}
			if len(store.reads) != 0 {
				t.Fatal("incoherent field basis reached storage")
			}
		})
	}
	input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
	index, err := BuildFitsIndexV1(context.Background(), store, input)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(input.Documents[0].FieldSnapshotJSON)
	input.Documents[0].FieldSnapshotJSON[0] = 'x'
	raw, err := index.OriginalFieldSnapshotJSONV1(input.Binding.DocumentID)
	if err != nil || !bytes.Equal(raw, original) {
		t.Fatal("input field bytes alias signed recovery authority")
	}
	raw[0] = 'x'
	again, err := index.OriginalFieldSnapshotJSONV1(input.Binding.DocumentID)
	if err != nil || again[0] != '{' {
		t.Fatal("field accessor exposes retained alias")
	}
}

func TestFitsIndexV1FieldBasisCapBeforeExactReads(t *testing.T) {
	input, store := fitsIndexIntegrityFixtureV1(t, "v1-case-1.fit")
	input.Documents[0].FieldSnapshotJSON = bytes.Repeat([]byte{' '}, MaxAuthorityBytesV1+1)
	if _, err := BuildFitsIndexV1(context.Background(), store, input); err == nil || len(store.reads) != 0 {
		t.Fatal("oversized field basis reached storage")
	}
}
