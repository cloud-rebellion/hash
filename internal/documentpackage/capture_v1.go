// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package documentpackage

import (
	"crypto/subtle"
	"errors"
	"time"
)

var ErrCaptureV1 = errors.New("documentpackage: invalid V1 stored draft capture")

// CaptureGuardV1 comes from the owner's locked, tenant-scoped root and package.
// It describes draft persistence, not a Send freeze, authorization or consent.
// PreviousRevision is the retained append head; the owner chooses the next
// positive business revision. Exhaustion at MaxInt64 requires a new workflow.
type CaptureGuardV1 struct {
	RootUpdatedAt    time.Time
	DraftGeneration  int64
	PreviousRevision int64
}

// CaptureHeaderV1 must come from a trusted fixed-scalar native lookup before
// allocating payload/member storage. Never trust a header beside an upload.
type CaptureHeaderV1 struct {
	Binding          BindingV1
	Guard            CaptureGuardV1
	ManifestBytes    int32
	MemberCount      int16
	PDFBytes         int64
	PDFPages         int32
	CanonicalSHA256  string
	CommitmentSHA256 string
}

// CaptureV1 owns an immutable canonical manifest and its persistence header.
// Storage/source verification, resource admission and native ownership are
// deliberately outside this integrity value. Returned manifests are immutable.
type CaptureV1 struct {
	manifest *ManifestV1
	header   CaptureHeaderV1
}

func validCaptureHeaderV1(h CaptureHeaderV1) bool {
	t := h.Guard.RootUpdatedAt.UTC()
	return validBindingV1(h.Binding) && !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 && t.Nanosecond()%1000 == 0 &&
		h.Guard.DraftGeneration > 0 && h.Guard.PreviousRevision >= 0 && h.Guard.PreviousRevision < h.Binding.Revision &&
		h.ManifestBytes > 0 && h.ManifestBytes <= MaxManifestBytesV1 && h.MemberCount >= 1 && h.MemberCount <= MaxAnnexesV1+1 &&
		h.PDFBytes > 0 && h.PDFBytes <= MaxPDFBytesV1 && h.PDFPages > 0 && h.PDFPages <= MaxPDFPagesV1 &&
		validDigestV1(h.CanonicalSHA256) && validDigestV1(h.CommitmentSHA256)
}

// NewCaptureV1 derives bytes, both hashes and aggregate declarations from one
// validated manifest. Callers cannot supply a second, contradictory inventory.
func NewCaptureV1(m *ManifestV1, g CaptureGuardV1) (*CaptureV1, error) {
	if m == nil {
		return nil, ErrCaptureV1
	}
	h := CaptureHeaderV1{Binding: m.Binding(), Guard: g, ManifestBytes: int32(len(m.canonical)), MemberCount: int16(len(m.input.Annexes) + 1),
		PDFBytes: m.pdfBytes, PDFPages: m.pdfPages, CanonicalSHA256: m.CanonicalSHA256(), CommitmentSHA256: m.CommitmentSHA256()}
	return DecodeCaptureV1(m.CanonicalJSON(), h)
}

// DecodeCaptureV1 checks the exact historical binding and both distinct hashes.
// It never substitutes today's editable draft state for the captured identity.
// Canonical Go decoding is mandatory even when SQL semantic/hash checks pass.
func DecodeCaptureV1(raw []byte, h CaptureHeaderV1) (*CaptureV1, error) {
	if !validCaptureHeaderV1(h) || len(raw) != int(h.ManifestBytes) {
		return nil, ErrCaptureV1
	}
	m, err := DecodeManifestV1(raw, ExpectedV1{Binding: h.Binding, CommitmentSHA256: h.CommitmentSHA256})
	if err != nil || subtle.ConstantTimeCompare([]byte(m.CanonicalSHA256()), []byte(h.CanonicalSHA256)) != 1 ||
		len(m.input.Annexes)+1 != int(h.MemberCount) || m.pdfBytes != h.PDFBytes || m.pdfPages != h.PDFPages {
		return nil, ErrCaptureV1
	}
	h.Guard.RootUpdatedAt = h.Guard.RootUpdatedAt.UTC()
	// Own bounded hash backing stores instead of retaining caller substrings.
	h.CanonicalSHA256, h.CommitmentSHA256 = m.CanonicalSHA256(), m.CommitmentSHA256()
	return &CaptureV1{manifest: m, header: h}, nil
}

func (c *CaptureV1) Header() CaptureHeaderV1 { return c.header }
func (c *CaptureV1) Manifest() *ManifestV1   { return c.manifest }
