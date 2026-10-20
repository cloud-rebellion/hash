// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/google/uuid"
)

const FitsIndexSchemaV1 = "hash-manual-fit-index-v1"
const FitsIndexSignatureDomainV1 = "hash:manual-fit-index:v1"
const FitsIndexSignaturePrefixV1 = "hash:manual-fit-index:v1:"

var ErrFitsIndexV1 = errors.New("manualfit: invalid signed fitted evidence index V1")

// CommittedFitsIndexV1 is read from the immutable completed document/intent by
// the application callback. Required without a complete exact pin fails closed;
// exporters must never reconstruct a missing index from current signature rows.
type CommittedFitsIndexV1 struct {
	Required bool
	Object   ObjectPinV1
}

type FitsIndexBindingV1 struct {
	OrgID                 uuid.UUID
	DocumentID            uuid.UUID
	CeremonyEpoch         time.Time
	CompletionEffectiveAt time.Time
	RetainUntil           time.Time
	FinalPDF              ObjectPinV1
}
type FitsIndexBasePageV1 struct {
	Page                int
	Object              ObjectPinV1
	SourceSHA256        string
	GeometrySHA256      string
	FieldSnapshotSHA256 string
}
type FitsIndexDocumentV1 struct {
	DocumentID          uuid.UUID
	Position            int
	CeremonyEpoch       time.Time
	Source              SourceTupleV1
	Geometry            sanitize.PDFManualGeometry
	FieldSnapshotSHA256 string
	FieldSnapshotJSON   json.RawMessage
	BasePages           []FitsIndexBasePageV1
	Composition         sanitize.PDFManualLayersManifest
}
type FitsIndexEntryV1 struct {
	SignatureID    uuid.UUID
	SelectionID    uuid.UUID
	RecipientID    uuid.UUID
	FieldID        uuid.UUID
	SignedAt       time.Time
	RetentionFloor time.Time
	ManifestObject ObjectPinV1
	Manifest       *ManifestV1
}

// FitsIndexLegacySignatureV1 preserves exact old adoption bytes. A delegated
// descriptor is an archive integrity claim, not proof of grant authorization,
// execution-chain validity, provider trust or qualified legal effect.
type FitsIndexLegacySignatureV1 struct {
	DocumentID   uuid.UUID
	SignatureID  uuid.UUID
	RecipientID  uuid.UUID
	FieldID      uuid.UUID
	Kind         string
	SignedAt     time.Time
	Object       ObjectPinV1
	OriginalName string
	Font         string
	SpanSHA256   string
}
type indexLegacyWireV1 struct {
	DocumentID   uuid.UUID   "json:\"document_id\""
	SignatureID  uuid.UUID   "json:\"signature_id\""
	RecipientID  uuid.UUID   "json:\"recipient_id\""
	FieldID      uuid.UUID   "json:\"field_id\""
	Kind         string      "json:\"kind\""
	SignedAt     string      "json:\"signed_at\""
	Object       ObjectPinV1 "json:\"object\""
	OriginalName string      "json:\"original_name\""
	Font         string      "json:\"font\""
	SpanSHA256   string      "json:\"span_sha256\""
}
type FitsIndexInputV1 struct {
	Binding              FitsIndexBindingV1
	OriginalDocumentName string
	Documents            []FitsIndexDocumentV1
	Entries              []FitsIndexEntryV1
	LegacySignatures     []FitsIndexLegacySignatureV1
}

type indexBaseWireV1 struct {
	Page                int         "json:\"page\""
	Object              ObjectPinV1 "json:\"object\""
	SourceSHA256        string      "json:\"source_sha256\""
	GeometrySHA256      string      "json:\"geometry_sha256\""
	FieldSnapshotSHA256 string      "json:\"field_snapshot_sha256\""
}

// Literal V1 geometry and composition wire types avoid dependence on future
// worker/renderer models when decoding historical signed index bytes.
type indexPageWireV1 struct {
	Boxes    [5][4]float64 "json:\"boxes\""
	Rotation int           "json:\"rotation\""
	UserUnit float64       "json:\"user_unit\""
}
type indexGeometryWireV1 struct {
	SchemaVersion  int               "json:\"schema_version\""
	SourceSHA256   string            "json:\"source_sha256\""
	SourceBytes    int64             "json:\"source_bytes\""
	GeometrySHA256 string            "json:\"geometry_sha256\""
	Pages          []indexPageWireV1 "json:\"pages\""
}
type indexCompositionWireV1 struct {
	SchemaVersion         int    "json:\"schema_version\""
	Policy                string "json:\"policy\""
	SourceSHA256          string "json:\"source_sha256\""
	SourceBytes           int64  "json:\"source_bytes\""
	DescriptorSHA256      string "json:\"descriptor_sha256\""
	GeometrySHA256        string "json:\"geometry_sha256\""
	Pages                 int    "json:\"pages\""
	Layers                int    "json:\"layers\""
	OriginalContentSHA256 string "json:\"original_content_sha256\""
	OrderedPaintingSHA256 string "json:\"ordered_painting_sha256\""
	ProcessingSHA256      string "json:\"processing_sha256\""
	ProcessingBytes       int64  "json:\"processing_bytes\""
	OutputSHA256          string "json:\"output_sha256\""
	OutputBytes           int64  "json:\"output_bytes\""
}
type indexDocumentWireV1 struct {
	DocumentID          uuid.UUID              "json:\"document_id\""
	Position            int                    "json:\"position\""
	CeremonyEpoch       string                 "json:\"ceremony_epoch\""
	Source              SourceTupleV1          "json:\"source\""
	Geometry            indexGeometryWireV1    "json:\"geometry\""
	FieldSnapshotSHA256 string                 "json:\"field_snapshot_sha256\""
	FieldSnapshotJSON   json.RawMessage        "json:\"field_snapshot_json\""
	BasePages           []indexBaseWireV1      "json:\"base_pages\""
	Composition         indexCompositionWireV1 "json:\"composition\""
}
type indexPageSectionWireV1 struct {
	Page     int   "json:\"page\""
	PDFBytes int64 "json:\"pdf_bytes\""
}
type indexEntryWireV1 struct {
	SignatureID    uuid.UUID                "json:\"signature_id\""
	SelectionID    uuid.UUID                "json:\"selection_id\""
	RecipientID    uuid.UUID                "json:\"recipient_id\""
	FieldID        uuid.UUID                "json:\"field_id\""
	SignedAt       string                   "json:\"signed_at\""
	RetentionFloor string                   "json:\"retention_floor\""
	ManifestObject ObjectPinV1              "json:\"manifest_object\""
	Manifest       json.RawMessage          "json:\"manifest\""
	PDFSections    []indexPageSectionWireV1 "json:\"pdf_sections\""
}
type indexPayloadWireV1 struct {
	Schema                string                "json:\"schema\""
	OrgID                 uuid.UUID             "json:\"org_id\""
	DocumentID            uuid.UUID             "json:\"document_id\""
	OriginalDocumentName  string                "json:\"original_document_name\""
	CeremonyEpoch         string                "json:\"ceremony_epoch\""
	CompletionEffectiveAt string                "json:\"completion_effective_at\""
	RetainUntil           string                "json:\"retain_until\""
	FinalPDF              ObjectPinV1           "json:\"final_pdf\""
	Documents             []indexDocumentWireV1 "json:\"documents\""
	Entries               []indexEntryWireV1    "json:\"entries\""
	LegacySignatures      []indexLegacyWireV1   "json:\"legacy_signatures\""
}
type signedIndexWireV1 struct {
	Schema           string          "json:\"schema\""
	Domain           string          "json:\"signature_domain\""
	SigningKeySHA256 string          "json:\"signing_key_sha256\""
	PublicKeyB64     string          "json:\"public_key_b64\""
	Payload          json.RawMessage "json:\"payload\""
	SignatureB64     string          "json:\"signature_b64\""
}

// FitsIndexV1 is immutable canonical payload material. Production constructs it
// with BuildFitsIndexV1, which re-reads the exact source/layer/package versions
// and derives the worker processing witness from actual bytes before signing.
type FitsIndexV1 struct {
	wire    indexPayloadWireV1
	raw     []byte
	binding FitsIndexBindingV1
}
type SignedFitsIndexV1 struct {
	index *FitsIndexV1
	raw   []byte
	key   ed25519.PublicKey
}

func NewSignedFitsIndexV1(index *FitsIndexV1, publicKey ed25519.PublicKey, sign func([]byte) string) (*SignedFitsIndexV1, error) {
	if index == nil || len(publicKey) != ed25519.PublicKeySize || sign == nil {
		return nil, ErrFitsIndexV1
	}
	payload := index.CanonicalJSON()
	signature := sign(bytes.Clone(payload))
	wire := signedIndexWireV1{Schema: FitsIndexSchemaV1, Domain: FitsIndexSignatureDomainV1, SigningKeySHA256: authoritySHA256V1(publicKey), PublicKeyB64: base64.StdEncoding.EncodeToString(publicKey), Payload: payload, SignatureB64: signature}
	raw, err := json.Marshal(wire)
	if err != nil || int64(len(raw)) > MaxFitsIndexBytesV1 {
		return nil, ErrFitsIndexV1
	}
	return DecodeSignedFitsIndexV1(raw, index.Binding(), publicKey)
}
func DecodeSignedFitsIndexV1(raw []byte, expected FitsIndexBindingV1, trustedPublicKey ed25519.PublicKey) (*SignedFitsIndexV1, error) {
	if len(raw) == 0 || int64(len(raw)) > MaxFitsIndexBytesV1 || len(trustedPublicKey) != ed25519.PublicKeySize {
		return nil, ErrFitsIndexV1
	}
	var wire signedIndexWireV1
	if closedCanonicalV1(raw, &wire) != nil || wire.Schema != FitsIndexSchemaV1 || wire.Domain != FitsIndexSignatureDomainV1 {
		return nil, ErrFitsIndexV1
	}
	key, err := base64.StdEncoding.Strict().DecodeString(wire.PublicKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != wire.PublicKeyB64 || !bytes.Equal(key, trustedPublicKey) || authoritySHA256V1(key) != wire.SigningKeySHA256 {
		return nil, ErrFitsIndexV1
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(wire.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != wire.SignatureB64 {
		return nil, ErrFitsIndexV1
	}
	message := sha256.Sum256(append([]byte(FitsIndexSignaturePrefixV1), wire.Payload...))
	if !ed25519.Verify(key, message[:], signature) {
		return nil, ErrFitsIndexV1
	}
	index, err := decodeFitsIndexPayloadV1(wire.Payload, expected)
	if err != nil {
		return nil, err
	}
	return &SignedFitsIndexV1{index: index, raw: bytes.Clone(raw), key: bytes.Clone(key)}, nil
}
func (i *FitsIndexV1) CanonicalJSON() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.raw)
}
func (i *FitsIndexV1) SHA256() string {
	if i == nil {
		return ""
	}
	return authoritySHA256V1(i.raw)
}
func (i *FitsIndexV1) Binding() FitsIndexBindingV1 {
	if i == nil {
		return FitsIndexBindingV1{}
	}
	return i.binding
}
func (i *FitsIndexV1) OriginalDocumentName() string {
	if i == nil {
		return ""
	}
	return i.wire.OriginalDocumentName
}
func (i *SignedFitsIndexV1) Bytes() []byte {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.raw)
}
func (i *SignedFitsIndexV1) SHA256() string {
	if i == nil {
		return ""
	}
	return authoritySHA256V1(i.raw)
}
func (i *SignedFitsIndexV1) Index() *FitsIndexV1 {
	if i == nil {
		return nil
	}
	v, _ := decodeFitsIndexPayloadV1(i.index.raw, i.index.binding)
	return v
}
func (i *SignedFitsIndexV1) PublicKey() ed25519.PublicKey {
	if i == nil {
		return nil
	}
	return bytes.Clone(i.key)
}
func (i *SignedFitsIndexV1) SigningKeySHA256() string {
	if i == nil {
		return ""
	}
	return authoritySHA256V1(i.key)
}

// ObjectPinSHA256V1 is the certificate's non-circular exact index object claim.
// It hashes opaque provider identity byte-for-byte, not merely object content.
func ObjectPinSHA256V1(pin ObjectPinV1) (string, error) {
	if !validObjectPinV1(pin, MaxFitsIndexBytesV1) || pin.ContentType != "application/json" {
		return "", ErrFitsIndexV1
	}
	raw, err := json.Marshal(pin)
	if err != nil {
		return "", ErrFitsIndexV1
	}
	return authoritySHA256V1(raw), nil
}
func IndexStorageKeyV1(orgID, documentID, operationID uuid.UUID) string {
	return "org/" + orgID.String() + "/documents/" + documentID.String() + "/finalization/index/" + operationID.String() + "/signature-fit-index.json"
}
func validIndexObjectV1(pin ObjectPinV1, b FitsIndexBindingV1) bool {
	if !validObjectPinV1(pin, MaxFitsIndexBytesV1) || pin.ContentType != "application/json" {
		return false
	}
	parts := strings.Split(pin.Key, "/")
	return len(parts) == 8 && parts[0] == "org" && parts[1] == b.OrgID.String() && parts[2] == "documents" && parts[3] == b.DocumentID.String() && parts[4] == "finalization" && parts[5] == "index" && archiveUUIDV1(parts[6]) && parts[7] == "signature-fit-index.json"
}
func canonicalIndexTimeV1(t time.Time) (string, error) {
	if t.IsZero() || t.Year() < 1 || t.Year() > 9999 {
		return "", ErrFitsIndexV1
	}
	return t.UTC().Round(0).Format(time.RFC3339Nano), nil
}
func indexTimeV1(raw string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil || t.IsZero() || t.UTC().Format(time.RFC3339Nano) != raw {
		return time.Time{}, ErrFitsIndexV1
	}
	return t.UTC(), nil
}
func retentionTargetV1(t time.Time) time.Time {
	target := t.UTC().AddDate(7, 0, 0)
	rounded := target.Truncate(time.Second)
	if !target.Equal(rounded) {
		rounded = rounded.Add(time.Second)
	}
	return rounded
}
func fitsBindingEqualV1(a, b FitsIndexBindingV1) bool {
	return a.OrgID == b.OrgID && a.DocumentID == b.DocumentID && a.CeremonyEpoch.Equal(b.CeremonyEpoch) && a.CompletionEffectiveAt.Equal(b.CompletionEffectiveAt) && a.RetainUntil.Equal(b.RetainUntil) && a.FinalPDF == b.FinalPDF
}
func geometryWireV1(g sanitize.PDFManualGeometry) indexGeometryWireV1 {
	v := indexGeometryWireV1{SchemaVersion: g.SchemaVersion, SourceSHA256: g.SourceSHA256, SourceBytes: g.SourceBytes, GeometrySHA256: g.GeometrySHA256, Pages: make([]indexPageWireV1, len(g.Pages))}
	for j, p := range g.Pages {
		v.Pages[j] = indexPageWireV1{Boxes: p.Boxes, Rotation: p.Rotation, UserUnit: p.UserUnit}
	}
	return v
}
func geometryFromWireV1(g indexGeometryWireV1) sanitize.PDFManualGeometry {
	v := sanitize.PDFManualGeometry{SchemaVersion: g.SchemaVersion, SourceSHA256: g.SourceSHA256, SourceBytes: g.SourceBytes, GeometrySHA256: g.GeometrySHA256, Pages: make([]sanitize.PDFManualPage, len(g.Pages))}
	for j, p := range g.Pages {
		v.Pages[j] = sanitize.PDFManualPage{Boxes: p.Boxes, Rotation: p.Rotation, UserUnit: p.UserUnit}
	}
	return v
}
func compositionWireV1(c sanitize.PDFManualLayersManifest) indexCompositionWireV1 {
	return indexCompositionWireV1{SchemaVersion: c.SchemaVersion, Policy: c.Policy, SourceSHA256: c.SourceSHA256, SourceBytes: c.SourceBytes, DescriptorSHA256: c.DescriptorSHA256, GeometrySHA256: c.GeometrySHA256, Pages: c.Pages, Layers: c.Layers, OriginalContentSHA256: c.OriginalContentSHA256, OrderedPaintingSHA256: c.OrderedPaintingSHA256, ProcessingSHA256: c.ProcessingSHA256, ProcessingBytes: c.ProcessingBytes, OutputSHA256: c.OutputSHA256, OutputBytes: c.OutputBytes}
}

func decodeFitsIndexPayloadV1(raw []byte, expected FitsIndexBindingV1) (*FitsIndexV1, error) {
	var wire indexPayloadWireV1
	if len(raw) == 0 || int64(len(raw)) > MaxFitsIndexBytesV1 || closedCanonicalV1(raw, &wire) != nil || validateFitsIndexPayloadV1(&wire) != nil {
		return nil, ErrFitsIndexV1
	}
	epoch, _ := indexTimeV1(wire.CeremonyEpoch)
	completed, _ := indexTimeV1(wire.CompletionEffectiveAt)
	until, _ := indexTimeV1(wire.RetainUntil)
	actual := FitsIndexBindingV1{OrgID: wire.OrgID, DocumentID: wire.DocumentID, CeremonyEpoch: epoch, CompletionEffectiveAt: completed, RetainUntil: until, FinalPDF: wire.FinalPDF}
	if !fitsBindingEqualV1(actual, expected) {
		return nil, ErrFitsIndexV1
	}
	return &FitsIndexV1{wire: wire, raw: bytes.Clone(raw), binding: actual}, nil
}
func validateFitsIndexPayloadV1(w *indexPayloadWireV1) error {
	epoch, e1 := indexTimeV1(w.CeremonyEpoch)
	completed, e2 := indexTimeV1(w.CompletionEffectiveAt)
	until, e3 := indexTimeV1(w.RetainUntil)
	if w.Schema != FitsIndexSchemaV1 || w.OrgID == uuid.Nil || w.DocumentID == uuid.Nil || e1 != nil || e2 != nil || e3 != nil || !completed.After(epoch) || !until.Equal(retentionTargetV1(completed)) || !utf8.ValidString(w.OriginalDocumentName) || strings.TrimSpace(w.OriginalDocumentName) == "" || len(w.OriginalDocumentName) > 65536 || !validObjectPinV1(w.FinalPDF, MaxFinalPDFBytesV1) || w.FinalPDF.ContentType != "application/pdf" {
		return ErrFitsIndexV1
	}
	finalKey := "org/" + w.OrgID.String() + "/documents/" + w.DocumentID.String() + "/final-" + w.FinalPDF.SHA256 + ".pdf"
	if w.FinalPDF.Key != finalKey || len(w.Documents) < 1 || len(w.Documents) > MaxFitsIndexDocumentsV1 || len(w.Entries) < 1 || len(w.Entries) > MaxFitsIndexSignaturesV1 || len(w.LegacySignatures) > MaxFitsIndexSignaturesV1-len(w.Entries) || w.LegacySignatures == nil {
		return ErrFitsIndexV1
	}
	documents := make(map[uuid.UUID]indexDocumentWireV1, len(w.Documents))
	var processing int64
	for j, d := range w.Documents {
		docEpoch, err := indexTimeV1(d.CeremonyEpoch)
		if err != nil || docEpoch.After(completed) || d.DocumentID == uuid.Nil || !authorityObjectTextV1(d.Source.Key) || !validObjectVersionV1(d.Source.VersionID) || !authorityDigestV1(d.Source.SHA256) || d.Source.Bytes < 1 || d.Source.Bytes > MaxArchiveSourcePDFBytesV1 || !authorityDigestV1(d.FieldSnapshotSHA256) {
			return ErrFitsIndexV1
		}
		if _, duplicate := documents[d.DocumentID]; duplicate {
			return ErrFitsIndexV1
		}
		documents[d.DocumentID] = d
		if len(w.Documents) == 1 {
			if d.Position != 0 || d.DocumentID != w.DocumentID {
				return ErrFitsIndexV1
			}
		} else if d.Position != j+1 {
			return ErrFitsIndexV1
		}
		g := d.Geometry
		if g.SchemaVersion != 1 || g.SourceSHA256 != d.Source.SHA256 || g.SourceBytes != d.Source.Bytes || len(g.Pages) < 1 || len(g.Pages) > 500 {
			return ErrFitsIndexV1
		}
		geometryRaw, err := json.Marshal(g.Pages)
		if err != nil || authoritySHA256V1(geometryRaw) != g.GeometrySHA256 {
			return ErrFitsIndexV1
		}
		for _, page := range geometryFromWireV1(g).Pages {
			if _, _, err := page.ViewportPoints(); err != nil {
				return ErrFitsIndexV1
			}
		}
		previous := 0
		operation := ""
		for _, base := range d.BasePages {
			if base.Page <= previous || base.Page > len(g.Pages) || base.SourceSHA256 != d.Source.SHA256 || base.GeometrySHA256 != g.GeometrySHA256 || base.FieldSnapshotSHA256 != d.FieldSnapshotSHA256 || !validObjectPinV1(base.Object, MaxArchiveBasePDFBytesV1) || base.Object.ContentType != "application/pdf" {
				return ErrFitsIndexV1
			}
			parts := strings.Split(base.Object.Key, "/")
			if len(parts) != 8 || parts[0] != "org" || parts[1] != w.OrgID.String() || parts[2] != "documents" || parts[3] != d.DocumentID.String() || parts[4] != "finalization" || parts[5] != "base" || !archiveUUIDV1(parts[6]) || parts[7] != "page-"+strconv.Itoa(base.Page)+".pdf" || (operation != "" && operation != parts[6]) {
				return ErrFitsIndexV1
			}
			operation = parts[6]
			previous = base.Page
		}
		c := d.Composition
		if c.SchemaVersion != 1 || c.Policy != "hash-pdf-manual-ordered-layers-v1" || c.SourceSHA256 != d.Source.SHA256 || c.SourceBytes != d.Source.Bytes || c.GeometrySHA256 != g.GeometrySHA256 || c.Pages != len(g.Pages) || c.Layers < 1 || c.Layers > 1500 || c.ProcessingBytes < d.Source.Bytes || c.ProcessingBytes > MaxProcessingBytesV1 || c.OutputBytes < 1 || c.OutputBytes > MaxFinalPDFBytesV1 {
			return ErrFitsIndexV1
		}
		for _, digest := range []string{c.DescriptorSHA256, c.OriginalContentSHA256, c.OrderedPaintingSHA256, c.ProcessingSHA256, c.OutputSHA256} {
			if !authorityDigestV1(digest) {
				return ErrFitsIndexV1
			}
		}
		if c.ProcessingBytes > MaxProcessingBytesV1-processing {
			return ErrFitsIndexV1
		}
		processing += c.ProcessingBytes
	}
	signatures := map[uuid.UUID]bool{}
	selections := map[uuid.UUID]bool{}
	recipients := map[string]bool{}
	layers := map[uuid.UUID]int{}
	fieldFits := map[uuid.UUID][]indexFieldFitV1{}
	fieldLegacy := map[uuid.UUID][]indexLegacyWireV1{}
	for j, e := range w.Entries {
		at, err := indexTimeV1(e.SignedAt)
		floor, fer := indexTimeV1(e.RetentionFloor)
		if err != nil || fer != nil || e.SignatureID == uuid.Nil || e.SelectionID == uuid.Nil || e.RecipientID == uuid.Nil || e.FieldID == uuid.Nil || signatures[e.SignatureID] || selections[e.SelectionID] || at.After(completed) {
			return ErrFitsIndexV1
		}
		signatures[e.SignatureID] = true
		selections[e.SelectionID] = true
		if j > 0 {
			prior := w.Entries[j-1]
			priorAt, _ := indexTimeV1(prior.SignedAt)
			if at.Before(priorAt) || (at.Equal(priorAt) && bytes.Compare(e.SignatureID[:], prior.SignatureID[:]) <= 0) {
				return ErrFitsIndexV1
			}
		}
		if !validObjectPinV1(e.ManifestObject, MaxManifestBytesV1) || e.ManifestObject.ContentType != "application/json" || e.ManifestObject.Bytes != int64(len(e.Manifest)) || e.ManifestObject.SHA256 != authoritySHA256V1(e.Manifest) {
			return ErrFitsIndexV1
		}
		var m manifestWireV1
		if closedCanonicalV1(e.Manifest, &m) != nil {
			return ErrFitsIndexV1
		}
		mepoch, err := indexTimeV1(m.CeremonyEpoch)
		if err != nil {
			return ErrFitsIndexV1
		}
		binding := BindingV1{OperationID: m.OperationID, OrgID: m.OrgID, DocumentID: m.DocumentID, RecipientID: m.RecipientID, CeremonyEpoch: mepoch, AuthoritySHA256: m.AuthoritySHA256}
		manifest, err := DecodeManifestV1(e.Manifest, binding)
		d, ok := documents[binding.DocumentID]
		if err != nil {
			return ErrFitsIndexV1
		}
		authority := manifest.Authority()
		authorityInput := authority.Input()
		if err != nil || !ok || binding.OrgID != w.OrgID || binding.RecipientID != e.RecipientID || binding.CeremonyEpoch.UTC().Format(time.RFC3339Nano) != d.CeremonyEpoch || e.ManifestObject.Key != manifest.ManifestKey() || at.Before(mepoch) || !floor.Equal(retentionTargetV1(mepoch)) || floor.After(until) || authorityInput.Source != d.Source {
			return ErrFitsIndexV1
		}
		ga, _ := json.Marshal(geometryWireV1(authority.Geometry()))
		gb, _ := json.Marshal(d.Geometry)
		if !bytes.Equal(ga, gb) {
			return ErrFitsIndexV1
		}
		recipientKey := binding.DocumentID.String() + "/" + e.RecipientID.String()
		if recipients[recipientKey] {
			return ErrFitsIndexV1
		}
		recipients[recipientKey] = true
		fieldFound := false
		for _, target := range authorityInput.Targets {
			if target.ID == e.FieldID {
				fieldFound = true
			}
		}
		if !fieldFound {
			return ErrFitsIndexV1
		}
		pages := manifest.Pages()
		if len(e.PDFSections) != len(pages) {
			return ErrFitsIndexV1
		}
		for p, page := range pages {
			section := e.PDFSections[p]
			if section.Page != page.Page || section.PDFBytes < 1 || section.PDFBytes > 8<<20 {
				return ErrFitsIndexV1
			}
		}
		layers[binding.DocumentID] += len(pages)
		fieldFits[binding.DocumentID] = append(fieldFits[binding.DocumentID], indexFieldFitV1{RecipientID: e.RecipientID, Targets: authorityInput.Targets})
	}
	for j, entry := range w.LegacySignatures {
		at, err := indexTimeV1(entry.SignedAt)
		doc, ok := documents[entry.DocumentID]
		epoch, epochErr := indexTimeV1(doc.CeremonyEpoch)
		if err != nil || epochErr != nil || !ok || entry.SignatureID == uuid.Nil || entry.RecipientID == uuid.Nil || entry.FieldID == uuid.Nil || signatures[entry.SignatureID] || at.Before(epoch) || at.After(completed) || (entry.Kind != "manual" && entry.Kind != "delegated_grant_v1") || !validObjectPinV1(entry.Object, MaxLegacySignatureSpanBytesV1) || entry.Object.ContentType != "text/html" || entry.SpanSHA256 != entry.Object.SHA256 || !utf8.ValidString(entry.OriginalName) || strings.TrimSpace(entry.OriginalName) == "" || len(entry.OriginalName) > 800 || utf8.RuneCountInString(entry.OriginalName) > 200 || !utf8.ValidString(entry.Font) || len(entry.Font) > 128 || len(doc.BasePages) < 1 {
			return ErrFitsIndexV1
		}
		if j > 0 {
			prior := w.LegacySignatures[j-1]
			priorAt, _ := indexTimeV1(prior.SignedAt)
			if at.Before(priorAt) || (at.Equal(priorAt) && bytes.Compare(entry.SignatureID[:], prior.SignatureID[:]) <= 0) {
				return ErrFitsIndexV1
			}
		}
		recipientKey := entry.DocumentID.String() + "/" + entry.RecipientID.String()
		if recipients[recipientKey] {
			return ErrFitsIndexV1
		}
		recipients[recipientKey] = true
		signatures[entry.SignatureID] = true
		fieldLegacy[entry.DocumentID] = append(fieldLegacy[entry.DocumentID], entry)
	}

	for _, d := range w.Documents {
		if validateIndexFieldBasisV1(d, fieldFits[d.DocumentID], fieldLegacy[d.DocumentID]) != nil {
			return ErrFitsIndexV1
		}
		if d.Composition.Layers != layers[d.DocumentID]+len(d.BasePages) {
			return ErrFitsIndexV1
		}
	}
	if len(w.Documents) == 1 {
		d := w.Documents[0]
		if d.Composition.OutputSHA256 != w.FinalPDF.SHA256 || d.Composition.OutputBytes != w.FinalPDF.Bytes {
			return ErrFitsIndexV1
		}
	}
	return nil
}
func sortIndexInputsV1(in *FitsIndexInputV1) {
	sort.Slice(in.Documents, func(i, j int) bool {
		if in.Documents[i].Position != in.Documents[j].Position {
			return in.Documents[i].Position < in.Documents[j].Position
		}
		return bytes.Compare(in.Documents[i].DocumentID[:], in.Documents[j].DocumentID[:]) < 0
	})
	sort.Slice(in.LegacySignatures, func(i, j int) bool {
		a, b := in.LegacySignatures[i], in.LegacySignatures[j]
		if !a.SignedAt.Equal(b.SignedAt) {
			return a.SignedAt.Before(b.SignedAt)
		}
		return bytes.Compare(a.SignatureID[:], b.SignatureID[:]) < 0
	})
	sort.Slice(in.Entries, func(i, j int) bool {
		a, b := in.Entries[i], in.Entries[j]
		if !a.SignedAt.Equal(b.SignedAt) {
			return a.SignedAt.Before(b.SignedAt)
		}
		return bytes.Compare(a.SignatureID[:], b.SignatureID[:]) < 0
	})
}

// ArchiveObjects lists every declared exact fitted artifact with safe fixed ZIP
// names. It is metadata only; ReadFitsArchiveSnapshotV1 proves actual bytes.
func (i *FitsIndexV1) ArchiveObjects() ([]ArchiveObjectV1, error) {
	if i == nil {
		return nil, ErrFitsIndexV1
	}
	out := []ArchiveObjectV1{{Name: "final-pdf.pdf", Object: i.wire.FinalPDF}}
	for _, doc := range i.wire.Documents {
		out = append(out, ArchiveObjectV1{Name: SourceArchiveNameV1(doc.DocumentID), Object: ObjectPinV1{Key: doc.Source.Key, VersionID: doc.Source.VersionID, SHA256: doc.Source.SHA256, Bytes: doc.Source.Bytes, ContentType: "application/pdf"}})
		for _, base := range doc.BasePages {
			out = append(out, ArchiveObjectV1{Name: BaseArchiveNameV1(doc.DocumentID, base.Page), Object: base.Object})
		}
	}
	for _, entry := range i.wire.Entries {
		manifest, err := manifestFromIndexEntryV1(entry)
		if err != nil {
			return nil, err
		}
		out = append(out, ArchiveObjectV1{Name: ManifestArchiveNameV1(entry.SignatureID), Object: entry.ManifestObject}, ArchiveObjectV1{Name: SpanArchiveNameV1(entry.SignatureID), Object: manifest.Span()})
		for _, page := range manifest.Pages() {
			out = append(out, ArchiveObjectV1{Name: PageArchiveNameV1(entry.SignatureID, page.Page), Object: page.Package})
		}
	}
	for _, entry := range i.wire.LegacySignatures {
		out = append(out, ArchiveObjectV1{Name: LegacySpanArchiveNameV1(entry.SignatureID), Object: entry.Object})
	}
	return out, nil
}
