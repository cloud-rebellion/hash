// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strconv"
	"time"
)

type ArchiveObjectV1 struct {
	Name   string
	Object ObjectPinV1
}
type archiveBlobV1 struct {
	object ArchiveObjectV1
	raw    []byte
}
type FitsArchiveSnapshotV1 struct {
	signed *SignedFitsIndexV1
	blobs  []archiveBlobV1
}
type archivedLayerDescriptorV1 struct {
	Page     int    "json:\"page\""
	Order    int    "json:\"order\""
	Kind     string "json:\"kind\""
	Identity string "json:\"identity\""
	Bytes    int    "json:\"bytes\""
	SHA256   string "json:\"sha256\""
}
type archivedLayerBatchV1 struct {
	SchemaVersion  int                         "json:\"schema_version\""
	SourceSHA256   string                      "json:\"source_sha256\""
	SourceBytes    int64                       "json:\"source_bytes\""
	GeometrySHA256 string                      "json:\"geometry_sha256\""
	Pages          int                         "json:\"pages\""
	Layers         []archivedLayerDescriptorV1 "json:\"layers\""
}

// BuildFitsIndexV1 derives sizes and processing commitments from bounded exact
// object versions. A caller-declared witness is never sufficient admission.
// There is no renderer or current font lookup in this constructor or reader.
func BuildFitsIndexV1(ctx context.Context, reader BoundedReaderV1, input FitsIndexInputV1) (*FitsIndexV1, error) {
	if len(input.OriginalDocumentName) > 65536 {
		return nil, ErrFitsIndexV1
	}
	if ctx == nil || reader == nil || len(input.Documents) < 1 || len(input.Documents) > MaxFitsIndexDocumentsV1 || len(input.Entries) < 1 || len(input.Entries) > MaxFitsIndexSignaturesV1 || len(input.LegacySignatures) > MaxFitsIndexSignaturesV1-len(input.Entries) {
		return nil, ErrFitsIndexV1
	}
	input.Documents = append([]FitsIndexDocumentV1(nil), input.Documents...)
	input.Entries = append([]FitsIndexEntryV1(nil), input.Entries...)
	input.LegacySignatures = append([]FitsIndexLegacySignatureV1(nil), input.LegacySignatures...)
	for j := range input.Documents {
		d := &input.Documents[j]
		if ctx.Err() != nil {
			return nil, indexContextFailureV1(ctx, ctx.Err())
		}
		if len(d.FieldSnapshotJSON) < 1 || len(d.FieldSnapshotJSON) > MaxAuthorityBytesV1 {
			return nil, ErrFitsIndexV1
		}
		d.Geometry.Pages = append(d.Geometry.Pages[:0:0], d.Geometry.Pages...)
		d.BasePages = append([]FitsIndexBasePageV1(nil), d.BasePages...)
		d.FieldSnapshotJSON = bytes.Clone(d.FieldSnapshotJSON)
		sort.Slice(d.BasePages, func(a, b int) bool { return d.BasePages[a].Page < d.BasePages[b].Page })
	}
	sortIndexInputsV1(&input)
	epoch, e1 := canonicalIndexTimeV1(input.Binding.CeremonyEpoch)
	completed, e2 := canonicalIndexTimeV1(input.Binding.CompletionEffectiveAt)
	until, e3 := canonicalIndexTimeV1(input.Binding.RetainUntil)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, ErrFitsIndexV1
	}
	wire := indexPayloadWireV1{Schema: FitsIndexSchemaV1, OrgID: input.Binding.OrgID, DocumentID: input.Binding.DocumentID, OriginalDocumentName: input.OriginalDocumentName, CeremonyEpoch: epoch, CompletionEffectiveAt: completed, RetainUntil: until, FinalPDF: input.Binding.FinalPDF, Documents: make([]indexDocumentWireV1, 0, len(input.Documents)), Entries: make([]indexEntryWireV1, 0, len(input.Entries)), LegacySignatures: make([]indexLegacyWireV1, 0, len(input.LegacySignatures))}
	var metadataBytes int64
	for _, d := range input.Documents {
		at, err := canonicalIndexTimeV1(d.CeremonyEpoch)
		if err != nil {
			return nil, ErrFitsIndexV1
		}
		group := indexDocumentWireV1{DocumentID: d.DocumentID, Position: d.Position, CeremonyEpoch: at, Source: d.Source, Geometry: geometryWireV1(d.Geometry), FieldSnapshotSHA256: d.FieldSnapshotSHA256, FieldSnapshotJSON: d.FieldSnapshotJSON, BasePages: make([]indexBaseWireV1, 0, len(d.BasePages)), Composition: compositionWireV1(d.Composition)}
		for _, base := range d.BasePages {
			group.BasePages = append(group.BasePages, indexBaseWireV1{Page: base.Page, Object: base.Object, SourceSHA256: base.SourceSHA256, GeometrySHA256: base.GeometrySHA256, FieldSnapshotSHA256: base.FieldSnapshotSHA256})
		}
		raw, err := json.Marshal(group)
		if err != nil || int64(len(raw)) > MaxFitsIndexBytesV1-metadataBytes {
			return nil, ErrFitsIndexV1
		}
		metadataBytes += int64(len(raw))
		wire.Documents = append(wire.Documents, group)
	}
	for _, entry := range input.Entries {
		if entry.Manifest == nil {
			return nil, ErrFitsIndexV1
		}
		raw := entry.Manifest.CanonicalJSON()
		if int64(len(raw)) > MaxFitsIndexBytesV1-metadataBytes {
			return nil, ErrFitsIndexV1
		}
		metadataBytes += int64(len(raw))
		at, e1 := canonicalIndexTimeV1(entry.SignedAt)
		floor, e2 := canonicalIndexTimeV1(entry.RetentionFloor)
		if e1 != nil || e2 != nil {
			return nil, ErrFitsIndexV1
		}
		item := indexEntryWireV1{SignatureID: entry.SignatureID, SelectionID: entry.SelectionID, RecipientID: entry.RecipientID, FieldID: entry.FieldID, SignedAt: at, RetentionFloor: floor, ManifestObject: entry.ManifestObject, Manifest: raw, PDFSections: make([]indexPageSectionWireV1, 0, len(entry.Manifest.Pages()))}
		// Temporary placeholders are never emitted: actual frozen-decoded section
		// lengths replace them below before canonical index construction/signing.
		for _, page := range entry.Manifest.Pages() {
			item.PDFSections = append(item.PDFSections, indexPageSectionWireV1{Page: page.Page, PDFBytes: 1})
		}
		wire.Entries = append(wire.Entries, item)
	}
	for _, entry := range input.LegacySignatures {
		at, err := canonicalIndexTimeV1(entry.SignedAt)
		if err != nil {
			return nil, ErrFitsIndexV1
		}
		wire.LegacySignatures = append(wire.LegacySignatures, indexLegacyWireV1{DocumentID: entry.DocumentID, SignatureID: entry.SignatureID, RecipientID: entry.RecipientID, FieldID: entry.FieldID, Kind: entry.Kind, SignedAt: at, Object: entry.Object, OriginalName: entry.OriginalName, Font: entry.Font, SpanSHA256: entry.SpanSHA256})
	}

	if validateFitsIndexPayloadV1(&wire) != nil {
		return nil, ErrFitsIndexV1
	}
	blobs, err := resolveFitsIndexObjectsV1(ctx, reader, &wire, true)
	if err != nil {
		return nil, err
	}
	for _, blob := range blobs {
		clear(blob.raw)
	}
	if validateFitsIndexPayloadV1(&wire) != nil {
		return nil, ErrFitsIndexV1
	}
	if ctx.Err() != nil {
		return nil, indexContextFailureV1(ctx, ctx.Err())
	}
	raw, err := json.Marshal(wire)
	if err != nil || int64(len(raw)) > MaxFitsIndexBytesV1 {
		return nil, ErrFitsIndexV1
	}
	return decodeFitsIndexPayloadV1(raw, input.Binding)
}

// ReadFitsArchiveSnapshotV1 reads an ALREADY committed index pin. Expected
// completion/final identity comes from the actual completed root, while every
// source, base layer and original name comes from the signed frozen index.
func ReadFitsArchiveSnapshotV1(ctx context.Context, reader BoundedReaderV1, indexPin ObjectPinV1, expected FitsIndexBindingV1, trustedPublicKey ed25519.PublicKey) (*FitsArchiveSnapshotV1, error) {
	if ctx == nil || reader == nil || !validIndexObjectV1(indexPin, expected) {
		return nil, ErrFitsIndexV1
	}
	raw, err := readArchiveExactV1(ctx, reader, indexPin)
	if err != nil {
		return nil, err
	}
	signed, err := DecodeSignedFitsIndexV1(raw, expected, trustedPublicKey)
	if err != nil {
		clear(raw)
		return nil, err
	}
	blobs, err := resolveFitsIndexObjectsV1(ctx, reader, &signed.index.wire, false)
	if err != nil {
		clear(raw)
		return nil, err
	}
	blobs = append(blobs, archiveBlobV1{object: ArchiveObjectV1{Name: "signature-fit-index.json", Object: indexPin}, raw: raw})
	sizes := make([]ArchiveSizeV1, 0, len(blobs))
	for _, blob := range blobs {
		sizes = append(sizes, ArchiveSizeV1{Name: blob.object.Name, Bytes: int64(len(blob.raw))})
	}
	if _, err := StoreZIPSizeV1(sizes); err != nil {
		for _, blob := range blobs {
			clear(blob.raw)
		}
		return nil, ErrFitsIndexV1
	}
	sort.Slice(blobs, func(a, b int) bool { return blobs[a].object.Name < blobs[b].object.Name })
	if ctx.Err() != nil {
		for _, blob := range blobs {
			clear(blob.raw)
		}
		return nil, indexContextFailureV1(ctx, ctx.Err())
	}
	return &FitsArchiveSnapshotV1{signed: signed, blobs: blobs}, nil
}
func (s *FitsArchiveSnapshotV1) Index() *SignedFitsIndexV1 {
	if s == nil {
		return nil
	}
	v, _ := DecodeSignedFitsIndexV1(s.signed.raw, s.signed.index.binding, s.signed.key)
	return v
}
func (s *FitsArchiveSnapshotV1) Objects() []ArchiveObjectV1 {
	if s == nil {
		return nil
	}
	out := make([]ArchiveObjectV1, len(s.blobs))
	for j, b := range s.blobs {
		out[j] = b.object
	}
	return out
}

// Open yields a reader, never a mutable alias to retained archive bytes.
func (s *FitsArchiveSnapshotV1) Open(name string) (io.Reader, error) {
	if s == nil {
		return nil, ErrFitsIndexV1
	}
	for _, b := range s.blobs {
		if b.object.Name == name {
			return bytes.NewReader(b.raw), nil
		}
	}
	return nil, ErrFitsIndexV1
}

func readArchiveExactV1(ctx context.Context, reader BoundedReaderV1, pin ObjectPinV1) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, indexContextFailureV1(ctx, err)
	}
	digest, err := hex.DecodeString(pin.SHA256)
	if err != nil || len(digest) != sha256.Size || pin.Bytes < 1 {
		return nil, ErrFitsIndexV1
	}
	raw, err := reader.GetVerifiedVersionBounded(ctx, pin.Key, pin.VersionID, digest, pin.Bytes)
	if err != nil {
		clear(raw)
		if ctx.Err() != nil {
			return nil, indexContextFailureV1(ctx, ctx.Err())
		}
		return nil, ErrFitsIndexV1
	}
	if ctx.Err() != nil {
		clear(raw)
		return nil, indexContextFailureV1(ctx, ctx.Err())
	}
	if int64(len(raw)) != pin.Bytes || authoritySHA256V1(raw) != pin.SHA256 {
		clear(raw)
		return nil, ErrFitsIndexV1
	}
	return raw, nil
}
func manifestFromIndexEntryV1(entry indexEntryWireV1) (*ManifestV1, error) {
	var wire manifestWireV1
	if closedCanonicalV1(entry.Manifest, &wire) != nil {
		return nil, ErrFitsIndexV1
	}
	epoch, err := indexTimeV1(wire.CeremonyEpoch)
	if err != nil {
		return nil, err
	}
	return DecodeManifestV1(entry.Manifest, BindingV1{OperationID: wire.OperationID, OrgID: wire.OrgID, DocumentID: wire.DocumentID, RecipientID: wire.RecipientID, CeremonyEpoch: epoch, AuthoritySHA256: wire.AuthoritySHA256})
}

// resolveFitsIndexObjectsV1 owns every read byte and derives the literal V1
// source+metadata+ordered layer processing hash. mutateSections is construction
// only; historical verification compares every existing signed section length.
func resolveFitsIndexObjectsV1(ctx context.Context, reader BoundedReaderV1, wire *indexPayloadWireV1, mutateSections bool) (result []archiveBlobV1, returnedError error) {
	success := false
	defer func() {
		if !success {
			for _, blob := range result {
				clear(blob.raw)
			}
			result = nil
		}
	}()
	names := map[string]bool{}
	var archiveBytes int64
	add := func(name string, pin ObjectPinV1, raw []byte) error {
		limit, err := ArchiveEntryLimitV1(name)
		if err != nil || names[name] || len(result) >= MaxArchiveEntriesV1 || pin.Bytes > limit || int64(len(raw)) != pin.Bytes || authoritySHA256V1(raw) != pin.SHA256 || pin.Bytes > MaxArchiveBytesV1-archiveBytes {
			return ErrFitsIndexV1
		}
		names[name] = true
		archiveBytes += pin.Bytes
		result = append(result, archiveBlobV1{object: ArchiveObjectV1{Name: name, Object: pin}, raw: raw})
		return nil
	}
	// Budget every declared artifact before initiating potentially large reads.
	plan := []ArchiveSizeV1{{Name: "final-pdf.pdf", Bytes: wire.FinalPDF.Bytes}}
	for _, d := range wire.Documents {
		plan = append(plan, ArchiveSizeV1{Name: SourceArchiveNameV1(d.DocumentID), Bytes: d.Source.Bytes})
		for _, base := range d.BasePages {
			plan = append(plan, ArchiveSizeV1{Name: BaseArchiveNameV1(d.DocumentID, base.Page), Bytes: base.Object.Bytes})
		}
	}
	for _, entry := range wire.Entries {
		m, err := manifestFromIndexEntryV1(entry)
		if err != nil {
			return nil, err
		}
		plan = append(plan, ArchiveSizeV1{Name: ManifestArchiveNameV1(entry.SignatureID), Bytes: entry.ManifestObject.Bytes}, ArchiveSizeV1{Name: SpanArchiveNameV1(entry.SignatureID), Bytes: m.Span().Bytes})
		for _, page := range m.Pages() {
			plan = append(plan, ArchiveSizeV1{Name: PageArchiveNameV1(entry.SignatureID, page.Page), Bytes: page.Package.Bytes})
		}
	}
	for _, entry := range wire.LegacySignatures {
		plan = append(plan, ArchiveSizeV1{Name: LegacySpanArchiveNameV1(entry.SignatureID), Bytes: entry.Object.Bytes})
	}
	if _, err := StoreZIPSizeV1(plan); err != nil {
		return nil, ErrFitsIndexV1
	}
	for _, entry := range wire.LegacySignatures {
		raw, err := readArchiveExactV1(ctx, reader, entry.Object)
		if err != nil {
			return nil, err
		}
		font := entry.Font
		switch font {
		case "Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple":
		default:
			font = "Caveat"
		}
		if !validArchivedSpanV1(raw, entry.OriginalName, font) {
			clear(raw)
			return nil, ErrFitsIndexV1
		}
		if err := add(LegacySpanArchiveNameV1(entry.SignatureID), entry.Object, raw); err != nil {
			clear(raw)
			return nil, err
		}
	}

	final, err := readArchiveExactV1(ctx, reader, wire.FinalPDF)
	if err != nil {
		return nil, err
	}
	if err := add("final-pdf.pdf", wire.FinalPDF, final); err != nil {
		clear(final)
		return nil, err
	}
	type entryPDFsV1 struct {
		entry    int
		retained *RetainedV1
		bytes    int
		sha256   string
	}
	occupied := map[string]map[int][]entryPDFsV1{}

	for entryNo := range wire.Entries {
		entry := &wire.Entries[entryNo]
		manifest, err := manifestFromIndexEntryV1(*entry)
		if err != nil {
			return nil, err
		}
		kept, err := VerifyRetainedV1(ctx, reader, entry.ManifestObject, manifest.Binding())
		if err != nil {
			return nil, safeIndexReadErrorV1(ctx, err)
		}
		if !bytes.Equal(kept.Manifest().CanonicalJSON(), entry.Manifest) {
			return nil, ErrFitsIndexV1
		}
		if err := add(ManifestArchiveNameV1(entry.SignatureID), entry.ManifestObject, bytes.Clone(entry.Manifest)); err != nil {
			return nil, err
		}
		span := kept.SpanBytes()
		if err := add(SpanArchiveNameV1(entry.SignatureID), manifest.Span(), span); err != nil {
			clear(span)
			return nil, err
		}
		pages := manifest.Pages()
		for pageNo, page := range pages {
			raw, err := kept.PackageBytes(page.Page)
			if err != nil {
				return nil, err
			}
			if err := add(PageArchiveNameV1(entry.SignatureID, page.Page), page.Package, raw); err != nil {
				clear(raw)
				return nil, err
			}
			actualBytes, err := kept.PDFByteCount(page.Page)
			if err != nil {
				return nil, err
			}
			if mutateSections {
				entry.PDFSections[pageNo].PDFBytes = int64(actualBytes)
			} else if entry.PDFSections[pageNo].PDFBytes != int64(actualBytes) {
				return nil, ErrFitsIndexV1
			}
		}
		docKey := manifest.Binding().DocumentID.String()
		if occupied[docKey] == nil {
			occupied[docKey] = map[int][]entryPDFsV1{}
		}
		for _, page := range pages {
			count, err := kept.PDFByteCount(page.Page)
			if err != nil {
				return nil, err
			}
			occupied[docKey][page.Page] = append(occupied[docKey][page.Page], entryPDFsV1{entry: entryNo, retained: kept, bytes: count, sha256: page.PDFSHA256})
		}
	}
	// Admit the exact descriptor and all groups before any source/base read or
	// copied PDF section. Signed declared processing values are only compared
	// after the actual frozen section lengths have established this whole gate.
	type orderedLayerV1 struct {
		base *indexBaseWireV1
		fit  *entryPDFsV1
		page int
	}
	type documentPlanV1 struct {
		document   indexDocumentWireV1
		metadata   []byte
		layers     []orderedLayerV1
		processing int64
	}
	groups := make([]documentPlanV1, 0, len(wire.Documents))
	var overallProcessing int64
	for _, d := range wire.Documents {
		bases := map[int]int{}
		for j, base := range d.BasePages {
			bases[base.Page] = j
		}
		descriptors := make([]archivedLayerDescriptorV1, 0, d.Composition.Layers)
		layers := make([]orderedLayerV1, 0, d.Composition.Layers)
		processing := d.Source.Bytes
		for page := 1; page <= len(d.Geometry.Pages); page++ {
			order := 0
			if baseNo, ok := bases[page]; ok {
				base := &d.BasePages[baseNo]
				order++
				if base.Object.Bytes > MaxProcessingBytesV1-processing {
					return nil, ErrFitsIndexV1
				}
				processing += base.Object.Bytes
				descriptors = append(descriptors, archivedLayerDescriptorV1{Page: page, Order: order, Kind: "base_text_v1", Identity: "base-page-" + strconv.Itoa(page), Bytes: int(base.Object.Bytes), SHA256: base.Object.SHA256})
				layers = append(layers, orderedLayerV1{base: base, page: page})
			}
			fits := occupied[d.DocumentID.String()][page]
			for j := range fits {
				fit := &fits[j]
				entry := wire.Entries[fit.entry]
				order++
				if int64(fit.bytes) > MaxProcessingBytesV1-processing {
					return nil, ErrFitsIndexV1
				}
				processing += int64(fit.bytes)
				descriptors = append(descriptors, archivedLayerDescriptorV1{Page: page, Order: order, Kind: "retained_signature_v1", Identity: "signature:" + entry.SignatureID.String(), Bytes: fit.bytes, SHA256: fit.sha256})
				layers = append(layers, orderedLayerV1{fit: fit, page: page})
			}
		}
		if ctx.Err() != nil {
			return nil, indexContextFailureV1(ctx, ctx.Err())
		}
		metadata, err := json.Marshal(archivedLayerBatchV1{SchemaVersion: 1, SourceSHA256: d.Source.SHA256, SourceBytes: d.Source.Bytes, GeometrySHA256: d.Geometry.GeometrySHA256, Pages: len(d.Geometry.Pages), Layers: descriptors})
		if err != nil || int64(len(metadata)) > MaxProcessingBytesV1-processing {
			return nil, ErrFitsIndexV1
		}
		processing += int64(len(metadata))
		if processing > MaxProcessingBytesV1-overallProcessing || len(descriptors) != d.Composition.Layers || authoritySHA256V1(metadata) != d.Composition.DescriptorSHA256 || processing != d.Composition.ProcessingBytes {
			return nil, ErrFitsIndexV1
		}
		overallProcessing += processing
		groups = append(groups, documentPlanV1{document: d, metadata: metadata, layers: layers, processing: processing})
	}
	for _, group := range groups {
		d := group.document
		sourcePin := ObjectPinV1{Key: d.Source.Key, VersionID: d.Source.VersionID, SHA256: d.Source.SHA256, Bytes: d.Source.Bytes, ContentType: "application/pdf"}
		source, err := readArchiveExactV1(ctx, reader, sourcePin)
		if err != nil {
			return nil, err
		}
		if err := add(SourceArchiveNameV1(d.DocumentID), sourcePin, source); err != nil {
			clear(source)
			return nil, err
		}
		hash := sha256.New()
		_, _ = hash.Write(group.metadata)
		_, _ = hash.Write(source)
		for _, layer := range group.layers {
			if ctx.Err() != nil {
				return nil, indexContextFailureV1(ctx, ctx.Err())
			}
			if layer.base != nil {
				base := layer.base
				raw, err := readArchiveExactV1(ctx, reader, base.Object)
				if err != nil {
					return nil, err
				}
				if err := add(BaseArchiveNameV1(d.DocumentID, base.Page), base.Object, raw); err != nil {
					clear(raw)
					return nil, err
				}
				_, _ = hash.Write(raw)
			} else {
				pdf, err := layer.fit.retained.PDFBytes(layer.page)
				if err != nil {
					return nil, err
				}
				if len(pdf) != layer.fit.bytes || authoritySHA256V1(pdf) != layer.fit.sha256 {
					clear(pdf)
					return nil, ErrFitsIndexV1
				}
				_, _ = hash.Write(pdf)
				clear(pdf)
			}
		}
		if hex.EncodeToString(hash.Sum(nil)) != d.Composition.ProcessingSHA256 {
			return nil, ErrFitsIndexV1
		}
	}

	success = true
	return result, nil
}

type fitsIndexContextErrorV1 struct {
	kind  error
	cause error
}

func (e fitsIndexContextErrorV1) Error() string {
	return ErrFitsIndexV1.Error() + ": " + e.kind.Error()
}
func (e fitsIndexContextErrorV1) Unwrap() []error { return []error{ErrFitsIndexV1, e.kind, e.cause} }
func indexContextFailureV1(ctx context.Context, kind error) error {
	cause := context.Cause(ctx)
	if cause == nil {
		cause = kind
	}
	return fitsIndexContextErrorV1{kind: kind, cause: cause}
}
func safeIndexReadErrorV1(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return indexContextFailureV1(ctx, ctx.Err())
	}
	if errors.Is(err, context.Canceled) {
		return fitsIndexContextErrorV1{kind: context.Canceled, cause: err}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fitsIndexContextErrorV1{kind: context.DeadlineExceeded, cause: err}
	}
	return ErrFitsIndexV1
}

// RetentionFloorV1 exposes the same whole-second V1 legal-evidence calculation
// to finalization/index adapters without importing current renderer code.
func RetentionFloorV1(epoch time.Time) time.Time { return retentionTargetV1(epoch) }
