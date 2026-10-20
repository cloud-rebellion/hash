// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/signaturefit"
	"golang.org/x/net/html"
)

var ErrRetainedV1 = errors.New("manualfit: exact retained V1 fit verification unavailable")

// BoundedReaderV1 must enforce the maximum while streaming the exact VersionID.
// Checking a returned buffer is a second defense, not an allocation substitute.
type BoundedReaderV1 interface {
	GetVerifiedVersionBounded(context.Context, string, string, []byte, int64) ([]byte, error)
}
type RetainerV1 interface {
	RetainEvidenceVersion(context.Context, string, string, []byte, time.Time) error
}

// RetainedV1 can only be obtained by complete exact-version byte verification.
// It does not assert Object Lock, renderer authenticity, PDF structure or paint.
type RetainedV1 struct {
	manifest    *ManifestV1
	manifestPin ObjectPinV1
	span        []byte
	packages    []*signaturefit.Package
}

func VerifyRetainedV1(ctx context.Context, reader BoundedReaderV1, manifestPin ObjectPinV1, binding BindingV1) (*RetainedV1, error) {
	if ctx == nil || reader == nil || !validBindingV1(binding) || !validObjectPinV1(manifestPin, MaxManifestBytesV1) ||
		manifestPin.Key != ObjectPrefixV1(binding.OperationID, binding.OrgID, binding.DocumentID)+"manifest.json" || manifestPin.ContentType != "application/json" {
		return nil, ErrRetainedV1
	}
	raw, err := readObjectV1(ctx, reader, manifestPin, MaxManifestBytesV1)
	if err != nil {
		return nil, err
	}
	m, err := DecodeManifestV1(raw, binding)
	if err != nil {
		return nil, ErrRetainedV1
	}
	span, err := readObjectV1(ctx, reader, m.Span(), MaxSpanBytesV1)
	if err != nil {
		return nil, err
	}
	in := m.authority.Input()
	if !validArchivedSpanV1(span, in.TypedName, in.Font) {
		return nil, ErrRetainedV1
	}
	artifacts, plans := m.Pages(), m.authority.Pages()
	packages := make([]*signaturefit.Package, 0, len(artifacts))
	for i, p := range artifacts {
		raw, err := readObjectV1(ctx, reader, p.Package, int64(signaturefit.MaxPackageBytes))
		if err != nil {
			return nil, err
		}
		decoded, err := signaturefit.Decode(raw, plans[i].Plan)
		if err != nil {
			return nil, ErrRetainedV1
		}
		d := decoded.Digests()
		if d.PackageSHA256 != p.Package.SHA256 || d.InputSHA256 != p.InputSHA256 || d.PDFSHA256 != p.PDFSHA256 ||
			d.ReportSHA256 != p.ReportSHA256 || d.HTMLSHA256 != p.HTMLSHA256 || d.FontSHA256 != p.FontSHA256 || d.SnapshotSHA256 != p.SnapshotSHA256 ||
			d.RecipeSHA256 != signaturefit.RecipeSHA256V1 {
			return nil, ErrRetainedV1
		}
		packages = append(packages, decoded)
	}
	if err := ctx.Err(); err != nil {
		return nil, safeRetainedErrorV1(ctx, err)
	}
	return &RetainedV1{m, manifestPin, bytes.Clone(span), packages}, nil
}
func readObjectV1(ctx context.Context, reader BoundedReaderV1, pin ObjectPinV1, max int64) ([]byte, error) {
	if !validObjectPinV1(pin, max) {
		return nil, ErrRetainedV1
	}
	if err := ctx.Err(); err != nil {
		return nil, safeRetainedErrorV1(ctx, err)
	}
	digest, err := hex.DecodeString(pin.SHA256)
	if err != nil {
		return nil, ErrRetainedV1
	}
	// Even a very small declared object never receives the entire format cap.
	raw, err := reader.GetVerifiedVersionBounded(ctx, pin.Key, pin.VersionID, digest, pin.Bytes)
	if err != nil {
		return nil, safeRetainedErrorV1(ctx, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, safeRetainedErrorV1(ctx, err)
	}
	if int64(len(raw)) != pin.Bytes || authoritySHA256V1(raw) != pin.SHA256 {
		return nil, ErrRetainedV1
	}
	return bytes.Clone(raw), nil
}
func safeRetainedErrorV1(ctx context.Context, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrRetainedV1, ctx.Err())
	}
	if errors.Is(cause, context.Canceled) {
		return errors.Join(ErrRetainedV1, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return errors.Join(ErrRetainedV1, context.DeadlineExceeded)
	}
	return ErrRetainedV1
}

// RetainVerifiedV1 requires the caller's durable selection and exact deadline
// checkpoint BEFORE invocation. It never rewrites or regenerates an object.
// Partial retention is irreversible: failure leaves the chosen set retryable,
// and the caller must never compensate it. Every successful call verifies the
// complete set before retention and again afterwards using bounded exact reads.
func RetainVerifiedV1(ctx context.Context, reader BoundedReaderV1, retainer RetainerV1, manifestPin ObjectPinV1, binding BindingV1, until time.Time) (*RetainedV1, error) {
	if ctx == nil || retainer == nil || until.IsZero() || until.Location() != time.UTC || until.Year() < 1 || until.Year() > 9999 || until.Nanosecond() != 0 || !until.After(binding.CeremonyEpoch) {
		return nil, ErrRetainedV1
	}
	verified, err := VerifyRetainedV1(ctx, reader, manifestPin, binding)
	if err != nil {
		return nil, err
	}
	pins := []ObjectPinV1{verified.manifest.Span()}
	for _, p := range verified.manifest.Pages() {
		pins = append(pins, p.Package)
	}
	pins = append(pins, manifestPin)
	// The second complete verification owns its own buffers. Retain only immutable
	// pins from the first read while applying the irreversible storage operations.
	verified.packages = nil
	verified.span = nil
	for _, pin := range pins {
		if err := ctx.Err(); err != nil {
			return nil, safeRetainedErrorV1(ctx, err)
		}
		digest, _ := hex.DecodeString(pin.SHA256)
		if err := retainer.RetainEvidenceVersion(ctx, pin.Key, pin.VersionID, digest, until); err != nil {
			return nil, safeRetainedErrorV1(ctx, err)
		}
	}
	return VerifyRetainedV1(ctx, reader, manifestPin, binding)
}
func (r *RetainedV1) Manifest() *ManifestV1 {
	if r == nil {
		return nil
	}
	m, _ := DecodeManifestV1(r.manifest.CanonicalJSON(), r.manifest.Binding())
	return m
}
func (r *RetainedV1) ManifestObject() ObjectPinV1 {
	if r == nil {
		return ObjectPinV1{}
	}
	return r.manifestPin
}
func (r *RetainedV1) SpanBytes() []byte {
	if r == nil {
		return nil
	}
	return bytes.Clone(r.span)
}
func (r *RetainedV1) PackageBytes(page int) ([]byte, error) {
	if r == nil {
		return nil, ErrRetainedV1
	}
	for i, p := range r.manifest.Pages() {
		if p.Page == page {
			return r.packages[i].Bytes(), nil
		}
	}
	return nil, ErrRetainedV1
}
func (r *RetainedV1) PDFBytes(page int) ([]byte, error) {
	if r == nil {
		return nil, ErrRetainedV1
	}
	for i, p := range r.manifest.Pages() {
		if p.Page == page {
			return r.packages[i].PDF(), nil
		}
	}
	return nil, ErrRetainedV1
}

// PDFByteCount admits the exact frozen section without allocating a PDF copy
// or redecoding the complete manifest for each source page.
func (r *RetainedV1) PDFByteCount(page int) (int, error) {
	if r == nil || r.manifest == nil || len(r.packages) != len(r.manifest.pages) {
		return 0, ErrRetainedV1
	}
	for i, artifact := range r.manifest.pages {
		if artifact.Page == page {
			n := r.packages[i].PDFByteCount()
			if n < 1 {
				return 0, ErrRetainedV1
			}
			return n, nil
		}
	}
	return 0, ErrRetainedV1
}

var manualFitSpanOpeningV1 = regexp.MustCompile(`^<(?i:span)[ \t\r\n]+(?i:class|data-font)[ \t\r\n]*=[ \t\r\n]*(?:"[^"<>\x00]*"|'[^'<>\x00]*')[ \t\r\n]+(?i:class|data-font)[ \t\r\n]*=[ \t\r\n]*(?:"[^"<>\x00]*"|'[^'<>\x00]*')[ \t\r\n]*>$`)

// The historical inert span grammar is frozen here. Names/fonts come from the
// archived authority, never mutable/anonymized rows or a current span generator.
func validArchivedSpanV1(raw []byte, name, font string) bool {
	if len(raw) == 0 || int64(len(raw)) > MaxSpanBytesV1 || !utf8.Valid(raw) {
		return false
	}
	if _, ok := signaturefit.Font(font); !ok {
		return false
	}
	z := html.NewTokenizer(bytes.NewReader(raw))
	if z.Next() != html.StartTagToken || !manualFitSpanOpeningV1.Match(z.Raw()) {
		return false
	}
	opening := z.Token()
	if opening.Data != "span" || len(opening.Attr) != 2 {
		return false
	}
	attrs := map[string]string{}
	for _, a := range opening.Attr {
		if a.Namespace != "" || (a.Key != "class" && a.Key != "data-font") {
			return false
		}
		if _, duplicate := attrs[a.Key]; duplicate {
			return false
		}
		attrs[a.Key] = a.Val
	}
	if attrs["class"] != "hash-signature" || attrs["data-font"] != font {
		return false
	}
	if z.Next() != html.TextToken || html.UnescapeString(string(z.Raw())) != name {
		return false
	}
	if z.Next() != html.EndTagToken || !strings.EqualFold(string(z.Raw()), "</span>") || z.Token().Data != "span" {
		return false
	}
	return z.Next() == html.ErrorToken && z.Err() == io.EOF
}
