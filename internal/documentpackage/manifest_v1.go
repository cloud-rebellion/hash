// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package documentpackage defines immutable commitments to the reviewed main
// document and its ordered contractual annexes. These values prove metadata
// integrity, not authorization, actual object contents, retention, malware
// clearance, recipient presentation, consent or signature authority. Application
// adapters must establish those properties before using a manifest for signing.
// Signed outputs and reports generated later belong in a separate delivery
// manifest; including them here would create circular or retroactive claims.
package documentpackage

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ManifestSchemaV1     = "hash-legal-package-manifest-v1"
	CommitmentDomainV1   = "hash:legal-package-manifest:v1\x00"
	SourcePDFImportV1    = "pdf-import"
	SourceHTMLOriginV1   = "html-origin"
	SourceHTMLRevisionV1 = "html-materialization"

	MaxAnnexesV1         = 16
	MaxManifestBytesV1   = 64 << 10
	MaxTitleBytesV1      = 512
	MaxCategoryBytesV1   = 128
	MaxObjectTextBytesV1 = 1024
	// These are aggregate reviewed-PDF input limits, not per-annex allowances
	// or a reservation for composition, evidence, source data or final output.
	MaxPDFBytesV1 int64 = 50 << 20
	MaxPDFPagesV1 int32 = 500
)

var ErrManifestV1 = errors.New("documentpackage: invalid V1 legal package manifest")

// BindingV1 identifies a particular frozen business revision. The owner supplies
// the actual identities; construction never invents a package ID or revision.
type BindingV1 struct {
	OrgID, DocumentID, PackageID uuid.UUID
	Revision                     int64
}

// PDFPinV1 refers to one exact reviewed PDF object. VersionID is opaque and
// accepted provider bytes are preserved, including surrounding whitespace.
type PDFPinV1 struct {
	Key       string `json:"key"`
	VersionID string `json:"version_id"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	Pages     int32  `json:"pages"`
}

type MaterializationPinV1 struct {
	ID       uuid.UUID `json:"id"`
	Sequence int32     `json:"sequence"`
}

// SourcePinV1 distinguishes a cleaned imported PDF from Hash HTML sources.
// Imported PDFs have no HTML commitments: their PDFPin is their source tuple.
// HTML commitments come from validated htmlsource.Commitment, not the distinct
// content/materialization digest. An unchanged legacy HTML origin legitimately
// has no materialization row. Its origin and current commitments must be equal.
type SourcePinV1 struct {
	Kind                   string                `json:"kind"`
	CommitmentSHA256       string                `json:"commitment_sha256"`
	OriginCommitmentSHA256 string                `json:"origin_commitment_sha256"`
	Materialization        *MaterializationPinV1 `json:"materialization"`
}

// Category is an optional, open-ended business label, never a format or policy.
type MemberV1 struct {
	DocumentID uuid.UUID   `json:"document_id"`
	Title      string      `json:"title"`
	Category   string      `json:"category"`
	PDF        PDFPinV1    `json:"pdf"`
	Source     SourcePinV1 `json:"source"`
}

type InputV1 struct {
	Binding BindingV1
	Main    MemberV1
	Annexes []MemberV1
}

// ExpectedV1 must come from the owner's locked freeze/presentation state, not
// an untrusted digest supplied alongside the manifest being decoded.
type ExpectedV1 struct {
	Binding          BindingV1
	CommitmentSHA256 string
}

type bindingWireV1 struct {
	OrgID      uuid.UUID `json:"org_id"`
	DocumentID uuid.UUID `json:"document_id"`
	PackageID  uuid.UUID `json:"package_id"`
	// A decimal string preserves the full positive PostgreSQL bigint range in
	// browser consumers without floating-point truncation.
	Revision string `json:"revision"`
}

type manifestWireV1 struct {
	Schema  string        `json:"schema"`
	Binding bindingWireV1 `json:"binding"`
	Main    MemberV1      `json:"main"`
	Annexes []MemberV1    `json:"annexes"`
}

// ManifestV1 is immutable. Annex order is contractual and is never sorted.
// Its legal commitment differs deliberately from the hash of the stored object.
type ManifestV1 struct {
	input                 InputV1
	canonical             []byte
	commitment, objectSHA string
	pdfBytes              int64
	pdfPages              int32
}

func NewManifestV1(in InputV1) (*ManifestV1, error) {
	if !validBindingV1(in.Binding) || in.Main.DocumentID != in.Binding.DocumentID || len(in.Annexes) > MaxAnnexesV1 {
		return nil, ErrManifestV1
	}
	in = cloneInputV1(in)
	ids := make(map[uuid.UUID]bool, len(in.Annexes)+1)
	objects := make(map[[2]string]bool, len(in.Annexes)+1)
	var pdfBytes int64
	var pdfPages int32
	check := func(member MemberV1) bool {
		if !validMemberV1(member, in.Binding.OrgID) || ids[member.DocumentID] || objects[[2]string{member.PDF.Key, member.PDF.VersionID}] ||
			member.PDF.Bytes > MaxPDFBytesV1-pdfBytes || member.PDF.Pages > MaxPDFPagesV1-pdfPages {
			return false
		}
		ids[member.DocumentID] = true
		objects[[2]string{member.PDF.Key, member.PDF.VersionID}] = true
		pdfBytes += member.PDF.Bytes
		pdfPages += member.PDF.Pages
		return true
	}
	if !check(in.Main) {
		return nil, ErrManifestV1
	}
	for _, member := range in.Annexes {
		if !check(member) {
			return nil, ErrManifestV1
		}
	}
	// Copy validated strings into bounded backing stores; short caller substrings
	// must not retain arbitrarily large source allocations in a frozen manifest.
	owned := in
	owned.Main = ownStringsV1(owned.Main)
	for i := range owned.Annexes {
		owned.Annexes[i] = ownStringsV1(owned.Annexes[i])
	}
	// Even a main-only package encodes annexes as [], never null or omission.
	wire := manifestWireV1{ManifestSchemaV1, bindingWireV1{in.Binding.OrgID, in.Binding.DocumentID, in.Binding.PackageID, strconv.FormatInt(in.Binding.Revision, 10)}, owned.Main, owned.Annexes}
	raw, err := json.Marshal(wire)
	if err != nil || len(raw) == 0 || len(raw) > MaxManifestBytesV1 {
		return nil, ErrManifestV1
	}
	objectSHA := sha256.Sum256(raw)
	return &ManifestV1{owned, raw, commitmentV1(raw), hex.EncodeToString(objectSHA[:]), pdfBytes, pdfPages}, nil
}

// DecodeManifestV1 accepts exact canonical bytes, as retained in an immutable
// object or bytea. PostgreSQL jsonb output is not this byte representation.
// Binding and the expected legal commitment are both mandatory. A matching
// commitment does not excuse malformed, ambiguous or noncanonical metadata.
func DecodeManifestV1(raw []byte, expected ExpectedV1) (*ManifestV1, error) {
	if len(raw) == 0 || len(raw) > MaxManifestBytesV1 {
		return nil, ErrManifestV1
	}
	// Own one bounded snapshot for every hash, parser and comparison pass.
	raw = bytes.Clone(raw)
	if !utf8.Valid(raw) ||
		!validBindingV1(expected.Binding) || !validDigestV1(expected.CommitmentSHA256) ||
		subtle.ConstantTimeCompare([]byte(commitmentV1(raw)), []byte(expected.CommitmentSHA256)) != 1 {
		return nil, ErrManifestV1
	}
	// Bound nesting, members, keys and token count before typed slice/pointer
	// allocation, and reject duplicate decoded keys before they can overwrite.
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 2048
	if closedTokensV1(d, 0, &budget) != nil {
		return nil, ErrManifestV1
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrManifestV1
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var wire manifestWireV1
	if d.Decode(&wire) != nil || wire.Schema != ManifestSchemaV1 {
		return nil, ErrManifestV1
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrManifestV1
	}
	revision, err := strconv.ParseInt(wire.Binding.Revision, 10, 64)
	if err != nil || strconv.FormatInt(revision, 10) != wire.Binding.Revision {
		return nil, ErrManifestV1
	}
	binding := BindingV1{wire.Binding.OrgID, wire.Binding.DocumentID, wire.Binding.PackageID, revision}
	if binding != expected.Binding {
		return nil, ErrManifestV1
	}
	manifest, err := NewManifestV1(InputV1{binding, wire.Main, wire.Annexes})
	if err != nil || !bytes.Equal(manifest.canonical, raw) ||
		subtle.ConstantTimeCompare([]byte(manifest.commitment), []byte(expected.CommitmentSHA256)) != 1 {
		return nil, ErrManifestV1
	}
	return manifest, nil
}

func validBindingV1(b BindingV1) bool {
	return b.OrgID != uuid.Nil && b.DocumentID != uuid.Nil && b.PackageID != uuid.Nil && b.Revision > 0
}

func validDigestV1(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	nonzero := false
	for _, c := range []byte(value) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		if c != '0' {
			nonzero = true
		}
	}
	return nonzero
}

func validOpaqueV1(value string) bool {
	if len(value) == 0 || len(value) > MaxObjectTextBytesV1 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validVersionV1(value string) bool {
	if !validOpaqueV1(value) {
		return false
	}
	switch strings.TrimSpace(value) {
	case "null", "hash:unversioned-development":
		return false
	default:
		return true
	}
}

func validLabelV1(value string, max int, optional bool) bool {
	if optional && value == "" {
		return true
	}
	if len(value) == 0 || len(value) > max || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) || c == '\u2028' || c == '\u2029' {
			return false
		}
	}
	return true
}

func validMemberV1(member MemberV1, orgID uuid.UUID) bool {
	pdf, source := member.PDF, member.Source
	if member.DocumentID == uuid.Nil || !validLabelV1(member.Title, MaxTitleBytesV1, false) || !validLabelV1(member.Category, MaxCategoryBytesV1, true) ||
		!validOpaqueV1(pdf.Key) || strings.TrimSpace(pdf.Key) != pdf.Key || !validVersionV1(pdf.VersionID) || !validDigestV1(pdf.SHA256) ||
		pdf.Bytes <= 0 || pdf.Bytes > MaxPDFBytesV1 || pdf.Pages <= 0 || pdf.Pages > MaxPDFPagesV1 {
		return false
	}
	prefix := "org/" + orgID.String() + "/"
	if !strings.HasPrefix(pdf.Key, prefix) || len(pdf.Key) == len(prefix) || strings.Contains(pdf.Key, "\\") {
		return false
	}
	for _, part := range strings.Split(pdf.Key, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	switch source.Kind {
	case SourcePDFImportV1:
		return source.CommitmentSHA256 == "" && source.OriginCommitmentSHA256 == "" && source.Materialization == nil
	case SourceHTMLOriginV1:
		return validDigestV1(source.CommitmentSHA256) && source.CommitmentSHA256 == source.OriginCommitmentSHA256 && source.Materialization == nil
	case SourceHTMLRevisionV1:
		return validDigestV1(source.CommitmentSHA256) && validDigestV1(source.OriginCommitmentSHA256) &&
			source.Materialization != nil && source.Materialization.ID != uuid.Nil && source.Materialization.Sequence > 0 &&
			(source.Materialization.Sequence != 1 || source.CommitmentSHA256 == source.OriginCommitmentSHA256)
	default:
		return false
	}
}

func commitmentV1(raw []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(CommitmentDomainV1))
	_, _ = h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

func nextTokenV1(d *json.Decoder, budget *int) (json.Token, error) {
	*budget = *budget - 1
	if *budget < 0 {
		return nil, ErrManifestV1
	}
	return d.Token()
}

func closedTokensV1(d *json.Decoder, depth int, budget *int) error {
	if depth > 8 {
		return ErrManifestV1
	}
	token, err := nextTokenV1(d, budget)
	if err != nil {
		return ErrManifestV1
	}
	switch token {
	case json.Delim('{'):
		seen := make(map[string]bool)
		for d.More() {
			key, err := nextTokenV1(d, budget)
			name, ok := key.(string)
			if err != nil || !ok || len(name) > 64 || len(seen) >= 16 || seen[name] {
				return ErrManifestV1
			}
			seen[name] = true
			if closedTokensV1(d, depth+1, budget) != nil {
				return ErrManifestV1
			}
		}
		if token, err = nextTokenV1(d, budget); err != nil || token != json.Delim('}') {
			return ErrManifestV1
		}
	case json.Delim('['):
		members := 0
		for d.More() {
			if members >= MaxAnnexesV1 {
				return ErrManifestV1
			}
			members++
			if closedTokensV1(d, depth+1, budget) != nil {
				return ErrManifestV1
			}
		}
		if token, err = nextTokenV1(d, budget); err != nil || token != json.Delim(']') {
			return ErrManifestV1
		}
	case json.Delim('}'), json.Delim(']'):
		return ErrManifestV1
	}
	return nil
}

// ownStringsV1 is used only after scalar validation has bounded all strings.
func ownStringsV1(member MemberV1) MemberV1 {
	member.Title = strings.Clone(member.Title)
	member.Category = strings.Clone(member.Category)
	member.PDF.Key = strings.Clone(member.PDF.Key)
	member.PDF.VersionID = strings.Clone(member.PDF.VersionID)
	member.PDF.SHA256 = strings.Clone(member.PDF.SHA256)
	member.Source.Kind = strings.Clone(member.Source.Kind)
	member.Source.CommitmentSHA256 = strings.Clone(member.Source.CommitmentSHA256)
	member.Source.OriginCommitmentSHA256 = strings.Clone(member.Source.OriginCommitmentSHA256)
	return member
}

func cloneMemberV1(member MemberV1) MemberV1 {
	if member.Source.Materialization != nil {
		copy := *member.Source.Materialization
		member.Source.Materialization = &copy
	}
	return member
}

func cloneInputV1(in InputV1) InputV1 {
	out := InputV1{Binding: in.Binding, Main: cloneMemberV1(in.Main), Annexes: make([]MemberV1, len(in.Annexes))}
	for i, member := range in.Annexes {
		out.Annexes[i] = cloneMemberV1(member)
	}
	return out
}

func (m *ManifestV1) Input() InputV1 {
	if m == nil {
		return InputV1{}
	}
	return cloneInputV1(m.input)
}

func (m *ManifestV1) Binding() BindingV1 {
	if m == nil {
		return BindingV1{}
	}
	return m.input.Binding
}

func (m *ManifestV1) Main() MemberV1 {
	if m == nil {
		return MemberV1{}
	}
	return cloneMemberV1(m.input.Main)
}

func (m *ManifestV1) Annexes() []MemberV1 {
	if m == nil {
		return nil
	}
	return cloneInputV1(m.input).Annexes
}

func (m *ManifestV1) CanonicalJSON() []byte {
	if m == nil {
		return nil
	}
	return bytes.Clone(m.canonical)
}

func (m *ManifestV1) CommitmentSHA256() string {
	if m == nil {
		return ""
	}
	return m.commitment
}

// CanonicalSHA256 is the plain stored-object hash, not the legal commitment.
func (m *ManifestV1) CanonicalSHA256() string {
	if m == nil {
		return ""
	}
	return m.objectSHA
}

func (m *ManifestV1) AggregatePDFBytes() int64 {
	if m == nil {
		return 0
	}
	return m.pdfBytes
}

func (m *ManifestV1) AggregatePDFPages() int32 {
	if m == nil {
		return 0
	}
	return m.pdfPages
}
