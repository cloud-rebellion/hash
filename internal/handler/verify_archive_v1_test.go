// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/testfitarchive"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Synthetic INTEGRITY ONLY: this deliberately does not establish genuine
// renderer/source admission, committed SQL, provider retention or glyph paint.
func schema4FilesFixtureV1(t *testing.T) (map[string][]byte, *testfitarchive.Fixture, *sign.CertSigner) {
	t.Helper()
	f := testfitarchive.New(t, "v1-case-1.fit")
	binding := f.Input.Binding
	exporter, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	objects, err := f.Index.Index().ArchiveObjects()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"signature-fit-index.json": f.Index.Bytes()}
	for _, object := range objects {
		files[object.Name] = bytes.Clone(f.Store.Blobs[testfitarchive.Identity(object.Object.Key, object.Object.VersionID)].Raw)
	}
	event := &generated.Event{ID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), OrgID: binding.OrgID, DocumentID: pgtype.UUID{Bytes: binding.DocumentID, Valid: true}, Kind: "document.signed", PayloadJson: json.RawMessage("{}"), PayloadHashed: []byte("{}"), CreatedAt: pgtype.Timestamptz{Time: binding.CeremonyEpoch, Valid: true}}
	event.RowHash = audit.ChainHashRecord(audit.HashInput{OrgID: binding.OrgID, DocID: binding.DocumentID, Kind: event.Kind, CreatedAt: event.CreatedAt.Time, Payload: event.PayloadHashed})
	events, eventsDigest, count, err := evidence.BuildCeremonyEventsJSON(binding.DocumentID, []*generated.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	pinSHA, err := manualfit.ObjectPinSHA256V1(f.IndexPin)
	if err != nil {
		t.Fatal(err)
	}
	nameSHA := sha256.Sum256([]byte(f.Input.OriginalDocumentName))
	payload := []byte(fmt.Sprintf("<section data-hash-document-id=\"%s\" data-hash-org-id=\"%s\" data-hash-document-name-sha256=\"%x\" data-hash-final-pdf-sha256=\"%s\" data-hash-completion-effective-at=\"%s\" data-hash-pre-final-chain-scope=\"organization\" data-hash-document-events-scope=\"ceremony-root\" data-hash-pre-final-chain-head-sha256=\"%x\" data-hash-pre-final-chain-head-created-at=\"%s\" data-hash-document-events-sha256=\"%s\" data-hash-document-events-count=\"%d\" data-hash-fits-index-schema=\"%s\" data-hash-fits-index-sha256=\"%s\" data-hash-fits-index-object-sha256=\"%s\" data-hash-evidence-retain-until=\"%s\"></section>", binding.DocumentID, binding.OrgID, nameSHA, binding.FinalPDF.SHA256, binding.CompletionEffectiveAt.Format(time.RFC3339Nano), event.RowHash, event.CreatedAt.Time.Format(time.RFC3339Nano), eventsDigest, count, manualfit.FitsIndexSchemaV1, f.IndexPin.SHA256, pinSHA, binding.RetainUntil.Format(time.RFC3339)))
	signature := []byte(f.Signer.SignPayload(payload))
	certificateKey := []byte(f.Signer.PublicKeyPEM())
	exportKey := []byte(exporter.PublicKeyPEM())
	exportFingerprint, err := evidence.Ed25519PublicKeyFingerprint(exportKey)
	if err != nil {
		t.Fatal(err)
	}
	certificateFingerprint, err := evidence.Ed25519PublicKeyFingerprint(certificateKey)
	if err != nil {
		t.Fatal(err)
	}
	finalPin := binding.FinalPDF
	indexPin := f.IndexPin
	manifest := evidence.Manifest{SchemaVersion: evidence.FittedManifestSchemaVersion, DocumentID: binding.DocumentID.String(), OrgID: binding.OrgID.String(), DocumentName: f.Input.OriginalDocumentName, Issuer: "Synthetic integrity-only issuer", GeneratedAt: binding.CompletionEffectiveAt.Add(time.Second).Format(time.RFC3339Nano), CompletionEffectiveAt: binding.CompletionEffectiveAt.Format(time.RFC3339Nano), CeremonyEpochAt: binding.CeremonyEpoch.Format(time.RFC3339Nano), FinalPDFObject: &finalPin, FinalPDFSHA256: finalPin.SHA256, FitsIndexObject: &indexPin, FitsIndexSHA256: indexPin.SHA256, FitsIndexObjectSHA256: pinSHA, EvidenceRetainUntil: binding.RetainUntil.Format(time.RFC3339), AuditCertSHA256: finalPin.SHA256, EventsSHA256: testfitarchive.SHA(events), VersionsSHA256: testfitarchive.SHA([]byte("{}")), ManifestPublicKeyPEMSHA256: testfitarchive.SHA(exportKey), CertificatePublicKeyPEMSHA256: testfitarchive.SHA(certificateKey), ManifestSigningKeySHA256: exportFingerprint, CertificateSigningKeySHA256: certificateFingerprint, CertPayloadSHA256: testfitarchive.SHA(payload), CertSignatureSHA256: testfitarchive.SHA(signature), SignatureAlgorithm: "ed25519", SignatureDomain: "hash:audit-cert:v1", ManifestSigDomain: "hash:evidence-manifest:v1"}
	canonical, err := evidence.CanonicalManifestForSignature(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSignature = exporter.SignEvidenceManifest(canonical)
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	files["events.json"] = events
	files["versions.json"] = []byte("{}")
	files["audit-cert.pdf"] = bytes.Clone(files["final-pdf.pdf"])
	files["audit-cert-payload.txt"] = payload
	files["audit-cert-signature.txt"] = signature
	files["manifest-public-key.pem"] = exportKey
	files["certificate-public-key.pem"] = certificateKey
	return files, f, exporter
}
func storeZIPTestV1(t *testing.T, files map[string][]byte, method uint16, duplicate string) []byte {
	t.Helper()
	names := []string{}
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	if duplicate != "" {
		names = append(names, duplicate)
	}
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for _, name := range names {
		file, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
func resignSchema4ManifestV1(t *testing.T, files map[string][]byte, signer *sign.CertSigner, edit func(*evidence.Manifest)) {
	t.Helper()
	var manifest evidence.Manifest
	if json.Unmarshal(files["manifest.json"], &manifest) != nil {
		t.Fatal("manifest fixture")
	}
	edit(&manifest)
	canonical, err := evidence.CanonicalManifestForSignature(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ManifestSignature = signer.SignEvidenceManifest(canonical)
	files["manifest.json"], err = json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
}
func TestVerifySchema4ZIPFrozenRecoveryAndKeyRotation(t *testing.T) {
	files, f, exporter := schema4FilesFixtureV1(t)
	raw := storeZIPTestV1(t, files, zip.Store, "")
	report := VerifyEvidenceBundleWithTrust(raw, EvidenceTrustSet{ManifestPublicKeys: []string{exporter.PublicKeyBase64()}, CertificatePublicKeys: []string{f.Signer.PublicKeyBase64()}})
	if !report.OK || !report.FittedArchiveVerified || report.VerificationScope != "schema4-fitted-archive" {
		t.Fatalf("frozen integrity archive rejected: %+v", report)
	}
	report = VerifyEvidenceBundleWithTrust(raw, EvidenceTrustSet{ManifestPublicKeys: []string{exporter.PublicKeyBase64()}, CertificatePublicKeys: []string{exporter.PublicKeyBase64()}})
	if report.OK || report.FittedArchiveVerified || report.CertificateKeyTrusted {
		t.Fatal("index/certificate historical trust replaced by current exporter")
	}
}
func TestVerifySchema4ZIPRefusesMissingTamperedAndResignedDrift(t *testing.T) {
	for _, name := range []string{"missing-page", "page-tamper", "span-tamper", "source-tamper", "missing-source", "index-tamper", "changed-index-version", "name-projection", "retention-drift", "completion-drift", "schema-downgrade", "unknown-member", "duplicate-member", "deflate", "trailing-bytes", "local-name-mismatch"} {
		t.Run(name, func(t *testing.T) {
			files, f, exporter := schema4FilesFixtureV1(t)
			signature := f.Input.Entries[0].SignatureID
			method := uint16(zip.Store)
			duplicate := ""
			switch name {
			case "missing-page":
				delete(files, manualfit.PageArchiveNameV1(signature, 1))
			case "page-tamper":
				files[manualfit.PageArchiveNameV1(signature, 1)][100] ^= 1
			case "span-tamper":
				files[manualfit.SpanArchiveNameV1(signature)][10] ^= 1
			case "source-tamper":
				files[manualfit.SourceArchiveNameV1(f.Input.Binding.DocumentID)][10] ^= 1
			case "missing-source":
				delete(files, manualfit.SourceArchiveNameV1(f.Input.Binding.DocumentID))
			case "index-tamper":
				files["signature-fit-index.json"][100] ^= 1
			case "changed-index-version":
				resignSchema4ManifestV1(t, files, exporter, func(m *evidence.Manifest) {
					m.FitsIndexObject.VersionID = "new latest version"
					m.FitsIndexObjectSHA256, _ = manualfit.ObjectPinSHA256V1(*m.FitsIndexObject)
				})
			case "name-projection":
				resignSchema4ManifestV1(t, files, exporter, func(m *evidence.Manifest) { m.DocumentName = "[erased]" })
			case "retention-drift":
				resignSchema4ManifestV1(t, files, exporter, func(m *evidence.Manifest) { m.EvidenceRetainUntil = "2033-10-11T12:00:00Z" })
			case "completion-drift":
				resignSchema4ManifestV1(t, files, exporter, func(m *evidence.Manifest) { m.CompletionEffectiveAt = "2026-10-11T12:00:03.123456Z" })
			case "schema-downgrade":
				resignSchema4ManifestV1(t, files, exporter, func(m *evidence.Manifest) { m.SchemaVersion = evidence.CurrentManifestSchemaVersion })
			case "unknown-member":
				files["shenanigans.fit"] = []byte("{}")
			case "duplicate-member":
				duplicate = "manifest.json"
			case "deflate":
				method = zip.Deflate
			}
			raw := storeZIPTestV1(t, files, method, duplicate)
			if name == "trailing-bytes" {
				raw = append(raw, 'x')
			}
			if name == "local-name-mismatch" {
				raw[30] ^= 1
			}
			report := VerifyEvidenceBundleWithTrust(raw, EvidenceTrustSet{ManifestPublicKeys: []string{exporter.PublicKeyBase64()}, CertificatePublicKeys: []string{f.Signer.PublicKeyBase64()}})
			if report.OK || report.FittedArchiveVerified {
				t.Fatal("changed or non-frozen archive accepted")
			}
		})
	}
}
func TestRawVerifyFittedCertificateIsOnlyCertificateSignature(t *testing.T) {
	files, f, _ := schema4FilesFixtureV1(t)
	server := &Server{EvidenceTrustedPublicKeys: []string{f.Signer.PublicKeyBase64()}}
	body, err := json.Marshal(verifyInput{PublicKeyB64: f.Signer.PublicKeyBase64(), Payload: string(files["audit-cert-payload.txt"]), SignatureB64: string(files["audit-cert-signature.txt"])})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(body)).WithContext(context.Background())
	response := httptest.NewRecorder()
	server.handleVerify(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("raw certificate rejected %d", response.Code)
	}
	var report map[string]any
	if json.Unmarshal(response.Body.Bytes(), &report) != nil {
		t.Fatal("response JSON")
	}
	if report["valid"] != true || report["issuer_trusted"] != true || report["fitted_archive_required"] != true || report["fitted_archive_verified"] != false || report["authentic_hash_evidence"] != false || report["verification_scope"] != "certificate-signature" {
		t.Fatalf("raw tuple overstated fitted archive coverage: %#v", report)
	}
}
func TestFrozenStoreZIPAndManifestRejectAlternativeStructure(t *testing.T) {
	raw := storeZIPTestV1(t, map[string][]byte{"versions.json": []byte("{}")}, zip.Store, "")
	if _, err := readStoreArchiveV1(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := readStoreArchiveV1(append([]byte("prefix"), raw...)); err == nil {
		t.Fatal("prefixed archive accepted")
	}
	if uniqueJSONObjectV1([]byte("{\"schema_version\":4,\"schema_version\":3}")) == nil {
		t.Fatal("duplicate manifest key accepted")
	}
	if uniqueJSONObjectV1([]byte(strings.Repeat("[", 65)+"0"+strings.Repeat("]", 65))) == nil {
		t.Fatal("deep manifest accepted")
	}
	if uniqueJSONObjectV1([]byte("{} {}")) == nil {
		t.Fatal("trailing JSON accepted")
	}
}
