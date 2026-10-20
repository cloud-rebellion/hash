// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package signaturefit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
)

// Request is the closed V1 preparation request. FontBytes is permitted only
// when it is the exact selected V1 font; no filenames, URLs or arbitrary assets
// are admitted. Returned buffers are newly allocated by the JSON decoder.
type Request struct {
	Schema    int    `json:"schema"`
	Plan      Plan   `json:"plan"`
	FontBytes []byte `json:"fontBytes"`
}

func DecodeRequest(raw []byte) (Request, error) {
	var r Request
	if len(raw) == 0 || len(raw) > MaxRequestBytes || decodeCanonicalV1(raw, &r) != nil || r.Schema != 1 || ValidatePlan(r.Plan) != nil || len(r.FontBytes) == 0 || len(r.FontBytes) > maxFontBytes {
		return Request{}, ErrInvalid
	}
	f, ok := Font(r.Plan.Font)
	if !ok || sha(r.FontBytes) != f.SHA256 {
		return Request{}, ErrInvalid
	}
	return r, nil
}

// Digests are computed from exact retained bytes, except InputSHA256 and the
// literal frozen recipe identity. They are integrity commitments, not a renderer
// authenticity proof or an independent proof of printed PDF content.
type Digests struct {
	PackageSHA256, ReportSHA256, PDFSHA256, HTMLSHA256, FontSHA256, SnapshotSHA256 string
	InputSHA256, RecipeSHA256                                                      string
}

type Package struct {
	raw     []byte
	parts   [5][]byte
	plan    Plan
	digests Digests
}

func (p *Package) Bytes() []byte { return bytes.Clone(p.raw) }
func (p *Package) PDF() []byte   { return bytes.Clone(p.parts[1]) }

// PDFByteCount permits aggregate admission before copying a decoded section.
func (p *Package) PDFByteCount() int {
	if p == nil {
		return 0
	}
	return len(p.parts[1])
}
func (p *Package) Report() []byte       { return bytes.Clone(p.parts[0]) }
func (p *Package) HTML() []byte         { return bytes.Clone(p.parts[2]) }
func (p *Package) FontBytes() []byte    { return bytes.Clone(p.parts[3]) }
func (p *Package) Snapshot() []byte     { return bytes.Clone(p.parts[4]) }
func (p *Package) Plan() Plan           { return clonePlan(p.plan) }
func (p *Package) Digests() Digests     { return p.digests }
func (p *Package) SHA256() string       { return p.digests.PackageSHA256 }
func (p *Package) ReportSHA256() string { return p.digests.ReportSHA256 }
func (p *Package) PDFSHA256() string    { return p.digests.PDFSHA256 }
func (p *Package) InputSHA256() string  { return p.digests.InputSHA256 }
func (p *Package) RecipeSHA256() string { return p.digests.RecipeSHA256 }

type reportV1 struct {
	Schema           int           `json:"schema"`
	Policy           string        `json:"policy"`
	Plan             Plan          `json:"plan"`
	InputSHA256      string        `json:"inputSha256"`
	RecipeSHA256     string        `json:"recipeSha256"`
	HTMLSHA256       string        `json:"htmlSha256"`
	FontFile         string        `json:"fontFile"`
	FontSHA256       string        `json:"fontSha256"`
	PDFSHA256        string        `json:"pdfSha256"`
	PDFBytes         int           `json:"pdfBytes"`
	FragmentPage     int           `json:"fragmentPage"`
	SnapshotSHA256   string        `json:"snapshotSha256"`
	ChromiumProduct  string        `json:"chromiumProduct"`
	ChromiumRevision string        `json:"chromiumRevision"`
	ChromiumProtocol string        `json:"chromiumProtocol"`
	Measurement      measurementV1 `json:"measurement"`
}

func decodeCanonicalV1(raw []byte, dst any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	if jsonTokenV1(d, 0) != nil {
		return ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return ErrInvalid
	}
	canonical, err := json.Marshal(dst)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ErrInvalid
	}
	return nil
}

// Decode dispatches the exact archive version. A future recipe must add a new
// reader instead of changing decodeV1 or relying on a current renderer helper.
// expected must be independently derived from application authority, never the
// package's own claims. All targets and their exact decimal representation bind.
func Decode(raw []byte, expected Plan) (*Package, error) {
	if ValidatePlan(expected) != nil || len(raw) < packageHeader || len(raw) > MaxPackageBytes {
		return nil, ErrInvalid
	}
	switch string(raw[:8]) {
	case "HSHFIT01":
		return decodeV1(raw, clonePlan(expected))
	default:
		return nil, ErrInvalid
	}
}

func decodeV1(raw []byte, expected Plan) (*Package, error) {
	limits := [5]int{maxReportBytes, maxPDFBytes, maxHTMLBytes, maxFontBytes, maxSnapshotBytes}
	var parts [5][]byte
	offset := packageHeader
	for i, limit := range limits {
		n := uint64(binary.BigEndian.Uint32(raw[8+i*4:]))
		if n == 0 || n > uint64(limit) || n > uint64(len(raw)-offset) {
			return nil, ErrInvalid
		}
		parts[i] = raw[offset : offset+int(n)]
		offset += int(n)
	}
	if offset != len(raw) {
		return nil, ErrInvalid
	}
	sum := sha256.Sum256(parts[0])
	if !bytes.Equal(sum[:], raw[28:60]) {
		return nil, ErrInvalid
	}
	var r reportV1
	if decodeCanonicalV1(parts[0], &r) != nil {
		return nil, ErrInvalid
	}
	f, ok := Font(expected.Font)
	inputSHA := inputSHAUncheckedV1(expected)
	if !ok || r.Schema != 1 || r.Policy != Policy || ValidatePlan(r.Plan) != nil || inputSHAUncheckedV1(r.Plan) != inputSHA || r.InputSHA256 != inputSHA || r.RecipeSHA256 != RecipeSHA256V1 || r.HTMLSHA256 != sha(parts[2]) || r.FontFile != f.File || r.FontSHA256 != f.SHA256 || r.FontSHA256 != sha(parts[3]) || r.PDFSHA256 != sha(parts[1]) || r.PDFBytes != len(parts[1]) || r.FragmentPage != 1 || !digestV1(r.SnapshotSHA256) || len(r.ChromiumProduct) == 0 || len(r.ChromiumProduct) > 256 || len(r.ChromiumRevision) == 0 || len(r.ChromiumRevision) > 256 || len(r.ChromiumProtocol) == 0 || len(r.ChromiumProtocol) > 32 || !bytes.HasPrefix(parts[1], []byte("%PDF-")) || !validSealedMeasurementV1(&r.Plan, &r.Measurement) {
		return nil, ErrInvalid
	}
	html, err := sealHTMLV1(r.Plan, parts[3])
	if err != nil || !bytes.Equal(html, parts[2]) {
		return nil, ErrInvalid
	}
	// V1 retained the snapshot as opaque JSON plus its exact hash. Preserve this
	// historical contract; {} is valid integrity-only fixture data. No observation
	// semantics, PDF page structure, font embedding or paint proof is inferred.
	if r.SnapshotSHA256 != sha(parts[4]) || !json.Valid(parts[4]) {
		return nil, ErrInvalid
	}
	owned := bytes.Clone(raw)
	var ownedParts [5][]byte
	offset = packageHeader
	for i, part := range parts {
		ownedParts[i] = owned[offset : offset+len(part)]
		offset += len(part)
	}
	return &Package{raw: owned, parts: ownedParts, plan: clonePlan(r.Plan), digests: Digests{
		PackageSHA256: sha(owned), ReportSHA256: sha(parts[0]), PDFSHA256: r.PDFSHA256, HTMLSHA256: r.HTMLSHA256, FontSHA256: r.FontSHA256, SnapshotSHA256: r.SnapshotSHA256, InputSHA256: r.InputSHA256, RecipeSHA256: r.RecipeSHA256,
	}}, nil
}
