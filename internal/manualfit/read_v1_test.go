// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

type fitBlobTestV1 struct {
	pin ObjectPinV1
	raw []byte
}
type fitStoreTestV1 struct {
	blobs      map[string]fitBlobTestV1
	reads      []ObjectPinV1
	retained   []ObjectPinV1
	deadlines  []time.Time
	readHook   func(int, ObjectPinV1, []byte) ([]byte, error)
	retainHook func(int, ObjectPinV1) error
}

func blobIDTestV1(key, version string) string { return key + string(rune(0)) + version }
func (s *fitStoreTestV1) GetVerifiedVersionBounded(ctx context.Context, key, version string, sha []byte, max int64) ([]byte, error) {
	b, ok := s.blobs[blobIDTestV1(key, version)]
	if !ok {
		return nil, errors.New("private missing object detail")
	}
	if hex.EncodeToString(sha) != b.pin.SHA256 || max != b.pin.Bytes {
		return nil, errors.New("read did not use exact digest and declared byte bound")
	}
	s.reads = append(s.reads, b.pin)
	if s.readHook != nil {
		return s.readHook(len(s.reads), b.pin, bytes.Clone(b.raw))
	}
	return bytes.Clone(b.raw), nil
}
func (s *fitStoreTestV1) RetainEvidenceVersion(ctx context.Context, key, version string, sha []byte, until time.Time) error {
	b, ok := s.blobs[blobIDTestV1(key, version)]
	if !ok || hex.EncodeToString(sha) != b.pin.SHA256 {
		return errors.New("unbound retention")
	}
	s.retained = append(s.retained, b.pin)
	s.deadlines = append(s.deadlines, until)
	if s.retainHook != nil {
		return s.retainHook(len(s.retained), b.pin)
	}
	return nil
}

// This is an INTEGRITY-ONLY fixture. It retains genuine current-generated PDF/font/
// DOM measurement bytes and rewrites metadata bindings to a synthetic valid
// application authority. It does not claim a genuine source-bound renderer
// invocation, isolated PDF admission, or glyph paint. Root-owned acceptance
// must generate packages directly from real AuthorityV1.Pages().
type fitReportTestV1 struct {
	Schema           int               `json:"schema"`
	Policy           string            `json:"policy"`
	Plan             signaturefit.Plan `json:"plan"`
	InputSHA256      string            `json:"inputSha256"`
	RecipeSHA256     string            `json:"recipeSha256"`
	HTMLSHA256       string            `json:"htmlSha256"`
	FontFile         string            `json:"fontFile"`
	FontSHA256       string            `json:"fontSha256"`
	PDFSHA256        string            `json:"pdfSha256"`
	PDFBytes         int               `json:"pdfBytes"`
	FragmentPage     int               `json:"fragmentPage"`
	SnapshotSHA256   string            `json:"snapshotSha256"`
	ChromiumProduct  string            `json:"chromiumProduct"`
	ChromiumRevision string            `json:"chromiumRevision"`
	ChromiumProtocol string            `json:"chromiumProtocol"`
	Measurement      json.RawMessage   `json:"measurement"`
}

func retainedFixtureTestV1(t *testing.T, file string) (*ManifestV1, ObjectPinV1, *fitStoreTestV1) {
	t.Helper()
	raw, err := os.ReadFile("../signaturefit/testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var parts [5][]byte
	offset := 60
	for i := range parts {
		n := int(binary.BigEndian.Uint32(raw[8+i*4:]))
		parts[i] = bytes.Clone(raw[offset : offset+n])
		offset += n
	}
	var report fitReportTestV1
	if json.Unmarshal(parts[0], &report) != nil {
		t.Fatal("archive fixture report")
	}
	// Name and archived span are already independently bounded by V1 authority.
	span := []byte(`<span class="hash-signature" data-font="` + report.Plan.Font + `">` + html.EscapeString(report.Plan.Text) + `</span>`)
	org := uuid.MustParse("11111111-1111-4111-8111-111111111111")
	doc := uuid.MustParse("22222222-2222-4222-8222-222222222222")
	rec := uuid.MustParse("33333333-3333-4333-8333-333333333333")
	first := uuid.MustParse(report.Plan.Targets[0].ID)
	second := uuid.MustParse(report.Plan.Targets[1].ID)
	source := SourceTupleV1{"opaque/source.pdf", " original+/version= ", report.Plan.SourceSHA256, 100}
	page := sanitize.PDFManualPage{UserUnit: 1}
	for i := range page.Boxes {
		page.Boxes[i] = [4]float64{0, 0, 1000, 600}
	}
	g := sanitize.PDFManualGeometry{SchemaVersion: 1, SourceSHA256: source.SHA256, SourceBytes: source.Bytes, Pages: []sanitize.PDFManualPage{page}}
	authorityGeometryHashV1(t, &g)
	in := AuthorityInputV1{OrgID: org, DocumentID: doc, RecipientID: rec, CeremonyEpoch: time.Date(2026, 10, 11, 12, 0, 0, 123456000, time.UTC), Source: source,
		TypedName: report.Plan.Text, Font: report.Plan.Font, SpanSHA256: authoritySHA256V1(span), ExpectedTargetIDs: []uuid.UUID{first, second}, Targets: []TargetV1{
			{first, org, doc, rec, 1, true, "5.0000", "5.0000", "90.0000", "35.0000"},
			{second, org, doc, rec, 1, true, "5.0000", "50.0000", "80.0000", "45.0000"},
		}}
	authority, err := BuildAuthorityV1(in, g)
	if err != nil {
		t.Fatal(err)
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
	copy(packageBytes, []byte("HSHFIT01"))
	for i, part := range parts {
		binary.BigEndian.PutUint32(packageBytes[8+i*4:], uint32(len(part)))
		packageBytes = append(packageBytes, part...)
	}
	reportSHA := sha256.Sum256(parts[0])
	copy(packageBytes[28:60], reportSHA[:])
	decoded, err := signaturefit.Decode(packageBytes, plan.Plan)
	if err != nil {
		t.Fatalf("integrity-only rebound fixture: %v", err)
	}
	d := decoded.Digests()
	op := uuid.MustParse("44444444-4444-4444-8444-444444444444")
	prefix := ObjectPrefixV1(op, org, doc)
	spanPin := ObjectPinV1{prefix + "span.html", " span+/opaque=version ", in.SpanSHA256, int64(len(span)), "text/html"}
	pagePin := ObjectPinV1{prefix + "page-1.fit", " page+/opaque=version ", d.PackageSHA256, int64(len(packageBytes)), signaturefit.MediaType}
	artifact := PageArtifactV1{1, plan.InputSHA256, pagePin, d.PDFSHA256, d.ReportSHA256, d.HTMLSHA256, d.FontSHA256, d.SnapshotSHA256}
	m, err := NewManifestV1(op, authority, spanPin, []PageArtifactV1{artifact})
	if err != nil {
		t.Fatal(err)
	}
	manifestPin := ObjectPinV1{m.ManifestKey(), " manifest+/opaque=version ", m.SHA256(), int64(len(m.CanonicalJSON())), "application/json"}
	store := &fitStoreTestV1{blobs: map[string]fitBlobTestV1{}}
	for _, b := range []fitBlobTestV1{{spanPin, span}, {pagePin, packageBytes}, {manifestPin, m.CanonicalJSON()}} {
		store.blobs[blobIDTestV1(b.pin.Key, b.pin.VersionID)] = b
	}
	return m, manifestPin, store
}

func TestVerifyRetainedV1AllFrozenFontsWithoutCurrentAssets(t *testing.T) {
	fixtures := []struct {
		m     *ManifestV1
		pin   ObjectPinV1
		store *fitStoreTestV1
	}{}
	for _, file := range []string{"v1-case-1.fit", "v1-case-3.fit", "v1-case-5.fit", "v1-case-7.fit", "v1-case-9.fit"} {
		m, pin, store := retainedFixtureTestV1(t, file)
		fixtures = append(fixtures, struct {
			m     *ManifestV1
			pin   ObjectPinV1
			store *fitStoreTestV1
		}{m, pin, store})
	}
	t.Chdir(t.TempDir())
	for _, f := range fixtures {
		t.Run(f.m.Authority().Input().Font, func(t *testing.T) {
			retained, err := VerifyRetainedV1(context.Background(), f.store, f.pin, f.m.Binding())
			if err != nil {
				t.Fatal(err)
			}
			if len(f.store.reads) != 3 || retained.ManifestObject() != f.pin || !bytes.Equal(retained.Manifest().CanonicalJSON(), f.m.CanonicalJSON()) {
				t.Fatal("complete exact set was not read")
			}
			raw, err := retained.PackageBytes(1)
			if err != nil {
				t.Fatal(err)
			}
			pdf, err := retained.PDFBytes(1)
			if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
				t.Fatal("retained PDF bytes absent")
			}
			raw[0] = 'x'
			pdf[0] = 'x'
			span := retained.SpanBytes()
			span[0] = 'x'
			mc := retained.Manifest().CanonicalJSON()
			mc[0] = 'x'
			again, _ := retained.PackageBytes(1)
			againPDF, _ := retained.PDFBytes(1)
			if again[0] != 'H' || againPDF[0] != '%' || retained.SpanBytes()[0] != '<' || retained.Manifest().CanonicalJSON()[0] != '{' {
				t.Fatal("retained accessors alias bytes")
			}
			if _, err := retained.PDFBytes(2); err == nil {
				t.Fatal("unassigned page exposed")
			}
			// No mutable recipient/signature row names or font bundles enter this API.
		})
	}
}

func TestVerifyRetainedV1RejectsPinAndReadFailures(t *testing.T) {
	for _, name := range []string{"missing", "same-key newer-version", "span-byte-change", "package-byte-change", "oversized-return", "wrong-length", "cancellation", "private-error"} {
		t.Run(name, func(t *testing.T) {
			m, pin, store := retainedFixtureTestV1(t, "v1-case-1.fit")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			page := m.Pages()[0].Package
			switch name {
			case "missing":
				delete(store.blobs, blobIDTestV1(page.Key, page.VersionID))
			case "same-key newer-version":
				b := store.blobs[blobIDTestV1(page.Key, page.VersionID)]
				delete(store.blobs, blobIDTestV1(page.Key, page.VersionID))
				b.pin.VersionID = "newer"
				store.blobs[blobIDTestV1(b.pin.Key, b.pin.VersionID)] = b
			case "span-byte-change":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) {
					if n == 2 {
						b[len(b)-1] = 'x'
					}
					return b, nil
				}
			case "package-byte-change":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) {
					if n == 3 {
						b[len(b)-1] ^= 1
					}
					return b, nil
				}
			case "oversized-return":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) { return append(b, 'x'), nil }
			case "wrong-length":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) { return b[:len(b)-1], nil }
			case "cancellation":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) { cancel(); return b, nil }
			case "private-error":
				store.readHook = func(n int, p ObjectPinV1, b []byte) ([]byte, error) { return nil, errors.New("PRIVATE_NAME_SECRET") }
			}
			if _, err := VerifyRetainedV1(ctx, store, pin, m.Binding()); err == nil || strings.Contains(err.Error(), "PRIVATE_NAME_SECRET") {
				t.Fatalf("unsafe failure: %v", err)
			} else if name == "cancellation" && !errors.Is(err, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
		})
	}
	m, pin, store := retainedFixtureTestV1(t, "v1-case-1.fit")
	bad := pin
	bad.Key += "/wrong"
	if _, err := VerifyRetainedV1(context.Background(), store, bad, m.Binding()); err == nil || len(store.reads) != 0 {
		t.Fatal("foreign namespace reached storage")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := VerifyRetainedV1(ctx, store, pin, m.Binding()); !errors.Is(err, context.Canceled) || len(store.reads) != 0 {
		t.Fatal("canceled context reached storage")
	}
}

func rewriteManifestTestV1(t *testing.T, m *ManifestV1, pin ObjectPinV1, store *fitStoreTestV1, edit func(*manifestWireV1)) ObjectPinV1 {
	t.Helper()
	var wire manifestWireV1
	if json.Unmarshal(m.CanonicalJSON(), &wire) != nil {
		t.Fatal("fixture")
	}
	edit(&wire)
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	pin.SHA256 = authoritySHA256V1(raw)
	pin.Bytes = int64(len(raw))
	store.blobs[blobIDTestV1(pin.Key, pin.VersionID)] = fitBlobTestV1{pin, raw}
	return pin
}
func TestVerifyRetainedV1CrosschecksEveryDeclaredSection(t *testing.T) {
	for _, field := range []string{"pdf", "report", "html", "snapshot"} {
		t.Run(field, func(t *testing.T) {
			m, pin, store := retainedFixtureTestV1(t, "v1-case-1.fit")
			pin = rewriteManifestTestV1(t, m, pin, store, func(w *manifestWireV1) {
				v := strings.Repeat("a", 64)
				switch field {
				case "pdf":
					w.Pages[0].PDFSHA256 = v
				case "report":
					w.Pages[0].ReportSHA256 = v
				case "html":
					w.Pages[0].HTMLSHA256 = v
				case "snapshot":
					w.Pages[0].SnapshotSHA256 = v
				}
			})
			if _, err := VerifyRetainedV1(context.Background(), store, pin, m.Binding()); err == nil {
				t.Fatal("accepted section digest mismatch")
			}
		})
	}
}

func TestRetainVerifiedV1ExactDeadlineReadbackAndPartialFailure(t *testing.T) {
	m, pin, store := retainedFixtureTestV1(t, "v1-case-1.fit")
	until := time.Date(2033, 10, 11, 12, 0, 1, 0, time.UTC)
	retained, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), until)
	if err != nil || retained == nil || len(store.retained) != 3 || len(store.reads) != 6 {
		t.Fatalf("complete retention/readback: %v", err)
	}
	for _, deadline := range store.deadlines {
		if deadline != until {
			t.Fatal("deadline changed")
		}
	}
	if store.retained[2] != pin {
		t.Fatal("manifest was not retained after all page inputs")
	}
	if _, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), until); err != nil || len(store.retained) != 6 {
		t.Fatal("exact selected retry failed")
	}
	for _, invalid := range []time.Time{time.Time{}, until.Add(time.Nanosecond), until.In(time.FixedZone("not UTC", 0)), m.Binding().CeremonyEpoch.Add(-time.Second)} {
		calls := len(store.retained)
		if _, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), invalid); err == nil || len(store.retained) != calls {
			t.Fatal("invalid deadline touched storage")
		}
	}
	m, pin, store = retainedFixtureTestV1(t, "v1-case-1.fit")
	store.retainHook = func(n int, p ObjectPinV1) error {
		if n == 2 {
			return errors.New("PRIVATE_RETENTION_DETAIL")
		}
		return nil
	}
	if _, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), until); err == nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("partial retention claimed success: %v", err)
	}
	if len(store.retained) != 2 || len(store.blobs) != 3 {
		t.Fatal("partial retention compensated or skipped")
	}
	store.retainHook = nil
	if _, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), until); err != nil {
		t.Fatal("partial exact-version retry failed")
	}
	m, pin, store = retainedFixtureTestV1(t, "v1-case-1.fit")
	store.retainHook = func(n int, p ObjectPinV1) error {
		if n == 3 {
			blob := store.blobs[blobIDTestV1(p.Key, p.VersionID)]
			blob.raw = append(blob.raw, 'x')
			store.blobs[blobIDTestV1(p.Key, p.VersionID)] = blob
		}
		return nil
	}
	if _, err := RetainVerifiedV1(context.Background(), store, store, pin, m.Binding(), until); err == nil {
		t.Fatal("post-retention exact readback failure claimed success")
	}
}

func TestArchivedSpanV1OriginalNameAndInertGrammar(t *testing.T) {
	name := `Åsa <María> & "Example"`
	font := "Caveat"
	raw := []byte(`<SPAN data-font='Caveat' class='hash-signature'>` + html.EscapeString(name) + `</SPAN>`)
	if !validArchivedSpanV1(raw, name, font) {
		t.Fatal("safe original serialization rejected")
	}
	for _, bad := range [][]byte{
		[]byte(`<span class="hash-signature" data-font="Caveat"><b>Åsa</b></span>`),
		[]byte(`<span class="hash-signature" data-font="Caveat" onload="alert(1)">Åsa</span>`),
		append(append([]byte(nil), raw...), []byte("<!--extra-->")...),
		bytes.Replace(raw, []byte("Caveat"), []byte("Great Vibes"), 1),
		bytes.Replace(raw, []byte("class='hash-signature'"), []byte("class='hash-signature' class='hash-signature'"), 1),
	} {
		if validArchivedSpanV1(bad, name, font) {
			t.Fatalf("accepted active or mismatched span %s", fmt.Sprint(len(bad)))
		}
	}
	if validArchivedSpanV1(raw, "[erased]", font) {
		t.Fatal("mutable redaction substituted for original name")
	}
}
