// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package documentpackage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func captureGuardFixtureV1() CaptureGuardV1 {
	return CaptureGuardV1{time.Date(2026, 10, 17, 21, 22, 23, 456789000, time.UTC), 3, 0}
}
func TestCaptureV1HistoricalCanonicalRoundtrip(t *testing.T) {
	in := mixedFixtureV1()
	in.Binding.Revision = 9007199254740993
	in.Main.Title = "Caf\u00e9 / Cafe\u0301"
	in.Annexes[0].Title = "Terms < > & \"quoted\""
	m := mustManifestV1(t, in)
	c, err := NewCaptureV1(m, captureGuardFixtureV1())
	if err != nil {
		t.Fatal(err)
	}
	h := c.Header()
	raw := c.Manifest().CanonicalJSON()
	if h.Binding != in.Binding || h.MemberCount != 3 || h.ManifestBytes != int32(len(raw)) || h.PDFBytes != m.AggregatePDFBytes() || h.PDFPages != m.AggregatePDFPages() {
		t.Fatal("derived header differs")
	}
	out, err := DecodeCaptureV1(raw, h)
	if err != nil || !bytes.Equal(out.Manifest().CanonicalJSON(), raw) || out.Manifest().Main().PDF.VersionID != in.Main.PDF.VersionID {
		t.Fatal("historical bytes changed", err)
	}
	raw[0] = 'x'
	h.Guard.DraftGeneration = 999
	if !bytes.Equal(c.Manifest().CanonicalJSON(), m.CanonicalJSON()) || c.Header().Guard.DraftGeneration != 3 {
		t.Fatal("caller mutation escaped")
	}
	max := fixtureV1()
	max.Binding.Revision = math.MaxInt64
	if _, err := NewCaptureV1(mustManifestV1(t, max), CaptureGuardV1{captureGuardFixtureV1().RootUpdatedAt, 1, math.MaxInt64 - 1}); err != nil {
		t.Fatal("full bigint lost", err)
	}
}
func TestCaptureV1RejectsCorruptionAndUntrustedHeaders(t *testing.T) {
	m := mustManifestV1(t, mixedFixtureV1())
	c, err := NewCaptureV1(m, captureGuardFixtureV1())
	if err != nil {
		t.Fatal(err)
	}
	raw := m.CanonicalJSON()
	good := c.Header()
	cases := map[string]func(*CaptureHeaderV1){
		"tenant": func(h *CaptureHeaderV1) { h.Binding.OrgID = uuid.New() }, "document": func(h *CaptureHeaderV1) { h.Binding.DocumentID = uuid.New() },
		"package": func(h *CaptureHeaderV1) { h.Binding.PackageID = uuid.New() }, "revision": func(h *CaptureHeaderV1) { h.Binding.Revision++ },
		"zero revision": func(h *CaptureHeaderV1) { h.Binding.Revision = 0 }, "wrong raw hash": func(h *CaptureHeaderV1) { h.CanonicalSHA256 = strings.Repeat("a", 64) },
		"wrong legal hash": func(h *CaptureHeaderV1) { h.CommitmentSHA256 = strings.Repeat("a", 64) },
		"swapped domains": func(h *CaptureHeaderV1) {
			h.CanonicalSHA256, h.CommitmentSHA256 = h.CommitmentSHA256, h.CanonicalSHA256
		},
		"oversize": func(h *CaptureHeaderV1) { h.ManifestBytes = MaxManifestBytesV1 + 1 }, "wrong length": func(h *CaptureHeaderV1) { h.ManifestBytes-- },
		"zero members": func(h *CaptureHeaderV1) { h.MemberCount = 0 }, "oversize members": func(h *CaptureHeaderV1) { h.MemberCount = 18 }, "missing member": func(h *CaptureHeaderV1) { h.MemberCount-- },
		"wrong bytes": func(h *CaptureHeaderV1) { h.PDFBytes++ }, "wrong pages": func(h *CaptureHeaderV1) { h.PDFPages++ },
		"no generation": func(h *CaptureHeaderV1) { h.Guard.DraftGeneration = 0 }, "negative predecessor": func(h *CaptureHeaderV1) { h.Guard.PreviousRevision = -1 },
		"nonadvancing predecessor": func(h *CaptureHeaderV1) { h.Guard.PreviousRevision = h.Binding.Revision }, "missing clock": func(h *CaptureHeaderV1) { h.Guard.RootUpdatedAt = time.Time{} },
		"submicro clock": func(h *CaptureHeaderV1) { h.Guard.RootUpdatedAt = h.Guard.RootUpdatedAt.Add(time.Nanosecond) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			h := good
			change(&h)
			if _, err := DecodeCaptureV1(raw, h); err != ErrCaptureV1 {
				t.Fatal("accepted bad header", err)
			}
		})
	}
	corrupt := bytes.Clone(raw)
	corrupt[len(corrupt)-2] ^= 1
	if _, err := DecodeCaptureV1(corrupt, good); err != ErrCaptureV1 {
		t.Fatal("accepted corruption", err)
	}
	// Both stored digests may correctly match noncanonical bytes. Strict Go
	// decoding, independently of PostgreSQL's jsonb projection, must still refuse.
	for _, bad := range [][]byte{append([]byte(" "), raw...), []byte(strings.Replace(string(raw), "\"schema\":", "\"schema\":\"hash-legal-package-manifest-v1\",\"schema\":", 1))} {
		h := good
		h.ManifestBytes = int32(len(bad))
		sum := sha256.Sum256(bad)
		h.CanonicalSHA256 = hex.EncodeToString(sum[:])
		h.CommitmentSHA256 = legalHashTestV1(bad)
		if _, err := DecodeCaptureV1(bad, h); err != ErrCaptureV1 {
			t.Fatal("accepted noncanonical bytes with matching hashes", err)
		}
	}
	if _, err := NewCaptureV1(nil, captureGuardFixtureV1()); err != ErrCaptureV1 {
		t.Fatal(err)
	}
	if _, err := NewCaptureV1(&ManifestV1{}, captureGuardFixtureV1()); err != ErrCaptureV1 {
		t.Fatal(err)
	}
}

func TestCaptureV1UTCClockBoundariesAndOwnedHashes(t *testing.T) {
	m := mustManifestV1(t, fixtureV1())
	g := captureGuardFixtureV1()
	g.RootUpdatedAt = g.RootUpdatedAt.In(time.FixedZone("offset", 14*60*60))
	c, err := NewCaptureV1(m, g)
	if err != nil || c.Header().Guard.RootUpdatedAt.Location() != time.UTC {
		t.Fatal("normal UTC normalization", err)
	}
	if _, err = DecodeCaptureV1(c.Manifest().CanonicalJSON(), c.Header()); err != nil {
		t.Fatal("returned header cannot roundtrip", err)
	}
	for _, bad := range []time.Time{time.Date(1, 1, 1, 1, 0, 0, 0, time.FixedZone("positive", 14*60*60)), time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("negative", -14*60*60))} {
		g.RootUpdatedAt = bad
		if _, err = NewCaptureV1(m, g); err != ErrCaptureV1 {
			t.Fatal("out-of-range UTC instant", err)
		}
	}
	h := c.Header()
	objBacking := strings.Repeat("x", 1<<20) + h.CanonicalSHA256
	legalBacking := strings.Repeat("y", 1<<20) + h.CommitmentSHA256
	h.CanonicalSHA256 = objBacking[len(objBacking)-64:]
	h.CommitmentSHA256 = legalBacking[len(legalBacking)-64:]
	decoded, err := DecodeCaptureV1(m.CanonicalJSON(), h)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.header.CanonicalSHA256 != decoded.manifest.objectSHA || decoded.header.CommitmentSHA256 != decoded.manifest.commitment {
		t.Fatal("owned manifest digests differ")
	}
}
