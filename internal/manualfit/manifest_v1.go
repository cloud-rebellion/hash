// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

const (
	ManifestSchemaV1         = "hash-manual-signature-fit-manifest-v1"
	MaxManifestBytesV1       = 2 << 20
	MaxEvidenceBytesV1 int64 = 160 << 20
	// Archived inert span objects have a dedicated 1 MiB format allowance.
	MaxSpanBytesV1 int64 = 1 << 20
)

var ErrManifestV1 = errors.New("manualfit: invalid V1 retained fit manifest")

// ObjectPinV1 is an exact encrypted object version, never a latest-version hint.
// Provider VersionID is opaque and preserved byte-for-byte.
type ObjectPinV1 struct {
	Key         string `json:"key"`
	VersionID   string `json:"version_id"`
	SHA256      string `json:"sha256"`
	Bytes       int64  `json:"bytes"`
	ContentType string `json:"content_type"`
}
type BindingV1 struct {
	OperationID     uuid.UUID
	OrgID           uuid.UUID
	DocumentID      uuid.UUID
	RecipientID     uuid.UUID
	CeremonyEpoch   time.Time
	AuthoritySHA256 string
}
type PageArtifactV1 struct {
	Page           int         `json:"page"`
	InputSHA256    string      `json:"input_sha256"`
	Package        ObjectPinV1 `json:"package"`
	PDFSHA256      string      `json:"pdf_sha256"`
	ReportSHA256   string      `json:"report_sha256"`
	HTMLSHA256     string      `json:"html_sha256"`
	FontSHA256     string      `json:"font_sha256"`
	SnapshotSHA256 string      `json:"snapshot_sha256"`
}
type manifestWireV1 struct {
	Schema          string           `json:"schema"`
	OperationID     uuid.UUID        `json:"operation_id"`
	OrgID           uuid.UUID        `json:"org_id"`
	DocumentID      uuid.UUID        `json:"document_id"`
	RecipientID     uuid.UUID        `json:"recipient_id"`
	CeremonyEpoch   string           `json:"ceremony_epoch"`
	AuthoritySHA256 string           `json:"authority_sha256"`
	RecipeSHA256    string           `json:"recipe_sha256"`
	Authority       json.RawMessage  `json:"authority"`
	Span            ObjectPinV1      `json:"span"`
	Pages           []PageArtifactV1 `json:"pages"`
}

// ManifestV1 describes one chosen all-page package set. It is integrity data,
// not authorization, an Object Lock receipt, or isolated PDF/paint admission.
// Activation still needs the complete SQL/sign/composition/evidence saga.
type ManifestV1 struct {
	binding   BindingV1
	authority *AuthorityV1
	span      ObjectPinV1
	pages     []PageArtifactV1
	canonical []byte
	sha256    string
	aggregate int64
}

// ObjectPrefixV1 gives an operation-owned namespace. Individual object names
// are fixed by this archive version and cannot reference another operation.
func ObjectPrefixV1(operationID, orgID, documentID uuid.UUID) string {
	if operationID == uuid.Nil || orgID == uuid.Nil || documentID == uuid.Nil {
		return ""
	}
	return "org/" + orgID.String() + "/documents/" + documentID.String() + "/signatures/fit/" + operationID.String() + "/"
}

func NewManifestV1(operationID uuid.UUID, authority *AuthorityV1, span ObjectPinV1, pages []PageArtifactV1) (*ManifestV1, error) {
	if authority == nil || len(pages) == 0 || len(pages) > 500 {
		return nil, ErrManifestV1
	}
	archived, err := DecodeAuthorityV1(authority.CanonicalJSON())
	if err != nil || archived.SHA256() != authority.SHA256() {
		return nil, ErrManifestV1
	}
	in := archived.Input()
	b := BindingV1{operationID, in.OrgID, in.DocumentID, in.RecipientID, in.CeremonyEpoch, archived.SHA256()}
	copied := append([]PageArtifactV1(nil), pages...)
	sort.Slice(copied, func(i, j int) bool { return copied[i].Page < copied[j].Page })
	if validateManifestPartsV1(b, archived, span, copied) != nil {
		return nil, ErrManifestV1
	}
	wire := manifestWireV1{ManifestSchemaV1, b.OperationID, b.OrgID, b.DocumentID, b.RecipientID, b.CeremonyEpoch.UTC().Format(time.RFC3339Nano),
		b.AuthoritySHA256, signaturefit.RecipeSHA256V1, archived.CanonicalJSON(), span, copied}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) == 0 || len(raw) > MaxManifestBytesV1 {
		return nil, ErrManifestV1
	}
	aggregate, err := aggregateBytesV1(int64(len(raw)), span, copied)
	if err != nil {
		return nil, ErrManifestV1
	}
	return &ManifestV1{b, archived, span, copied, raw, authoritySHA256V1(raw), aggregate}, nil
}

func DecodeManifestV1(raw []byte, expected BindingV1) (*ManifestV1, error) {
	var wire manifestWireV1
	if len(raw) == 0 || len(raw) > MaxManifestBytesV1 || closedCanonicalV1(raw, &wire) != nil || wire.Schema != ManifestSchemaV1 || wire.RecipeSHA256 != signaturefit.RecipeSHA256V1 || !validBindingV1(expected) {
		return nil, ErrManifestV1
	}
	authority, err := DecodeAuthorityV1(wire.Authority)
	if err != nil {
		return nil, ErrManifestV1
	}
	epoch, err := time.Parse(time.RFC3339Nano, wire.CeremonyEpoch)
	if err != nil || epoch.UTC().Format(time.RFC3339Nano) != wire.CeremonyEpoch {
		return nil, ErrManifestV1
	}
	actual := BindingV1{wire.OperationID, wire.OrgID, wire.DocumentID, wire.RecipientID, epoch.UTC(), wire.AuthoritySHA256}
	if !bindingEqualV1(actual, expected) || validateManifestPartsV1(actual, authority, wire.Span, wire.Pages) != nil {
		return nil, ErrManifestV1
	}
	aggregate, err := aggregateBytesV1(int64(len(raw)), wire.Span, wire.Pages)
	if err != nil {
		return nil, ErrManifestV1
	}
	return &ManifestV1{actual, authority, wire.Span, append([]PageArtifactV1(nil), wire.Pages...), bytes.Clone(raw), authoritySHA256V1(raw), aggregate}, nil
}

func validBindingV1(b BindingV1) bool {
	return b.OperationID != uuid.Nil && b.OrgID != uuid.Nil && b.DocumentID != uuid.Nil && b.RecipientID != uuid.Nil &&
		!b.CeremonyEpoch.IsZero() && b.CeremonyEpoch.Year() >= 1 && b.CeremonyEpoch.Year() <= 9999 && authorityDigestV1(b.AuthoritySHA256)
}
func bindingEqualV1(a, b BindingV1) bool {
	return validBindingV1(a) && validBindingV1(b) && a.OperationID == b.OperationID && a.OrgID == b.OrgID && a.DocumentID == b.DocumentID && a.RecipientID == b.RecipientID &&
		a.CeremonyEpoch.Equal(b.CeremonyEpoch) && a.AuthoritySHA256 == b.AuthoritySHA256
}
func validObjectPinV1(p ObjectPinV1, max int64) bool {
	return authorityObjectTextV1(p.Key) && p.Key == strings.TrimSpace(p.Key) && validObjectVersionV1(p.VersionID) &&
		authorityDigestV1(p.SHA256) && p.Bytes > 0 && p.Bytes <= max
}
func validateManifestPartsV1(b BindingV1, a *AuthorityV1, span ObjectPinV1, pages []PageArtifactV1) error {
	if !validBindingV1(b) || a == nil || a.SHA256() != b.AuthoritySHA256 {
		return ErrManifestV1
	}
	in := a.Input()
	if in.OrgID != b.OrgID || in.DocumentID != b.DocumentID || in.RecipientID != b.RecipientID || !in.CeremonyEpoch.Equal(b.CeremonyEpoch) {
		return ErrManifestV1
	}
	prefix := ObjectPrefixV1(b.OperationID, b.OrgID, b.DocumentID)
	if !validObjectPinV1(span, MaxSpanBytesV1) || span.Key != prefix+"span.html" || span.ContentType != "text/html" || span.SHA256 != in.SpanSHA256 {
		return ErrManifestV1
	}
	plans := a.Pages()
	if len(pages) != len(plans) || len(pages) == 0 || len(pages) > 500 {
		return ErrManifestV1
	}
	font := a.FontInfo()
	for i, p := range pages {
		if p.Page != plans[i].Plan.Page || p.InputSHA256 != plans[i].InputSHA256 || !validObjectPinV1(p.Package, int64(signaturefit.MaxPackageBytes)) ||
			p.Package.Key != prefix+"page-"+strconv.Itoa(p.Page)+".fit" || p.Package.ContentType != signaturefit.MediaType ||
			!authorityDigestV1(p.PDFSHA256) || !authorityDigestV1(p.ReportSHA256) || !authorityDigestV1(p.HTMLSHA256) || p.FontSHA256 != font.SHA256 || !authorityDigestV1(p.SnapshotSHA256) {
			return ErrManifestV1
		}
	}
	return nil
}
func aggregateBytesV1(manifestBytes int64, span ObjectPinV1, pages []PageArtifactV1) (int64, error) {
	if manifestBytes <= 0 || manifestBytes > MaxManifestBytesV1 || span.Bytes <= 0 || span.Bytes > MaxEvidenceBytesV1-manifestBytes {
		return 0, ErrManifestV1
	}
	total := manifestBytes + span.Bytes
	for _, p := range pages {
		if p.Package.Bytes <= 0 || p.Package.Bytes > MaxEvidenceBytesV1-total {
			return 0, ErrManifestV1
		}
		total += p.Package.Bytes
	}
	return total, nil
}
func (m *ManifestV1) Binding() BindingV1 {
	if m == nil {
		return BindingV1{}
	}
	return m.binding
}
func (m *ManifestV1) Span() ObjectPinV1 {
	if m == nil {
		return ObjectPinV1{}
	}
	return m.span
}
func (m *ManifestV1) Pages() []PageArtifactV1 {
	if m == nil {
		return nil
	}
	return append([]PageArtifactV1(nil), m.pages...)
}
func (m *ManifestV1) Authority() *AuthorityV1 {
	if m == nil {
		return nil
	}
	a, _ := DecodeAuthorityV1(m.authority.CanonicalJSON())
	return a
}
func (m *ManifestV1) CanonicalJSON() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.canonical)
}
func (m *ManifestV1) SHA256() string {
	if m == nil {
		return ""
	}
	return m.sha256
}

// AggregateBytes counts this set, including its manifest and original span.
// The caller must also reserve/enforce the shared whole-document evidence budget
// across other recipients, selected sets and unpublished preparation inventory.
func (m *ManifestV1) AggregateBytes() int64 {
	if m == nil {
		return 0
	}
	return m.aggregate
}
func (m *ManifestV1) ManifestKey() string {
	if m == nil {
		return ""
	}
	return ObjectPrefixV1(m.binding.OperationID, m.binding.OrgID, m.binding.DocumentID) + "manifest.json"
}
