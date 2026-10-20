// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/testfitarchive"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

type fittedCommitmentStubV1 struct {
	org, doc   uuid.UUID
	commitment manualfit.CommittedFitsIndexV1
	err        error
	calls      int
}

func (s *fittedCommitmentStubV1) LoadCommittedFitsIndexV1(_ context.Context, org, doc uuid.UUID) (manualfit.CommittedFitsIndexV1, error) {
	s.calls++
	if org != s.org || doc != s.doc {
		return manualfit.CommittedFitsIndexV1{}, errors.New("scope mismatch")
	}
	return s.commitment, s.err
}
func fittedBuildFixtureV1(t *testing.T) (*generated.Document, *Builder, *testfitarchive.Fixture, *fittedCommitmentStubV1) {
	t.Helper()
	f := testfitarchive.New(t, "v1-case-1.fit")
	binding := f.Input.Binding
	event := &generated.Event{ID: uuid.MustParse("88888888-8888-4888-8888-888888888888"), OrgID: binding.OrgID, DocumentID: pgtype.UUID{Bytes: binding.DocumentID, Valid: true}, Kind: "document.signed", PayloadJson: json.RawMessage("{}"), PayloadHashed: []byte("{}"), CreatedAt: pgtype.Timestamptz{Time: binding.CeremonyEpoch, Valid: true}}
	event.RowHash = audit.ChainHashRecord(audit.HashInput{OrgID: binding.OrgID, DocID: binding.DocumentID, Kind: event.Kind, CreatedAt: event.CreatedAt.Time, Payload: event.PayloadHashed})
	eventsDigest, err := audit.DocumentEventSetDigest([]*generated.Event{event})
	if err != nil {
		t.Fatal(err)
	}
	objectSHA, err := manualfit.ObjectPinSHA256V1(f.IndexPin)
	if err != nil {
		t.Fatal(err)
	}
	nameSHA := sha256.Sum256([]byte(f.Input.OriginalDocumentName))
	payload := []byte(fmt.Sprintf("<section data-hash-document-id=\"%s\" data-hash-org-id=\"%s\" data-hash-document-name-sha256=\"%x\" data-hash-final-pdf-sha256=\"%s\" data-hash-completion-effective-at=\"%s\" data-hash-pre-final-chain-scope=\"organization\" data-hash-document-events-scope=\"ceremony-root\" data-hash-pre-final-chain-head-sha256=\"%x\" data-hash-pre-final-chain-head-created-at=\"%s\" data-hash-document-events-sha256=\"%x\" data-hash-document-events-count=\"1\" data-hash-fits-index-schema=\"%s\" data-hash-fits-index-sha256=\"%s\" data-hash-fits-index-object-sha256=\"%s\" data-hash-evidence-retain-until=\"%s\"></section>", binding.DocumentID, binding.OrgID, nameSHA, binding.FinalPDF.SHA256, binding.CompletionEffectiveAt.Format(time.RFC3339Nano), event.RowHash, event.CreatedAt.Time.Format(time.RFC3339Nano), eventsDigest, manualfit.FitsIndexSchemaV1, f.IndexPin.SHA256, objectSHA, binding.RetainUntil.Format(time.RFC3339)))
	signature := []byte(f.Signer.SignPayload(payload))
	final := f.Store.Blobs[testfitarchive.Identity(binding.FinalPDF.Key, binding.FinalPDF.VersionID)].Raw
	doc := &generated.Document{ID: binding.DocumentID, OrgID: binding.OrgID, Name: "[erased]", Status: "completed", SentAt: pgtype.Timestamptz{Time: binding.CeremonyEpoch, Valid: true}, CompletionEffectiveAt: pgtype.Timestamptz{Time: binding.CompletionEffectiveAt, Valid: true}, CompletedAt: pgtype.Timestamptz{Time: binding.CompletionEffectiveAt, Valid: true}, FinalizationRetainUntil: pgtype.Timestamptz{Time: binding.RetainUntil, Valid: true}, CompletionEffectiveAtBound: true, EvidenceVersionPinsRequired: true, FinalPdfKey: pgtype.Text{String: binding.FinalPDF.Key, Valid: true}, FinalPdfVersionID: pgtype.Text{String: binding.FinalPDF.VersionID, Valid: true}}
	doc.FitsIndexRequired = true
	doc.FinalPdfSha, _ = hex.DecodeString(binding.FinalPDF.SHA256)
	set := func(kind, extension string, raw []byte) (pgtype.Text, []byte, pgtype.Text) {
		digest := sha256.Sum256(raw)
		key := "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/" + kind + "-" + hex.EncodeToString(digest[:]) + extension
		pin := manualfit.ObjectPinV1{Key: key, VersionID: kind + " exact+/= version", SHA256: hex.EncodeToString(digest[:]), Bytes: int64(len(raw)), ContentType: "application/octet-stream"}
		f.Store.Put(pin, raw)
		return pgtype.Text{String: key, Valid: true}, digest[:], pgtype.Text{String: pin.VersionID, Valid: true}
	}
	doc.AuditCertKey, doc.AuditCertSha256, doc.AuditCertVersionID = set("audit", ".pdf", final)
	doc.AuditPayloadKey, doc.AuditPayloadSha256, doc.AuditPayloadVersionID = set("audit-payload", ".txt", payload)
	doc.AuditSignatureKey, doc.AuditSignatureSha256, doc.AuditSignatureVersionID = set("audit-signature", ".txt", signature)
	commitment := &fittedCommitmentStubV1{org: doc.OrgID, doc: doc.ID, commitment: manualfit.CommittedFitsIndexV1{Required: true, Object: f.IndexPin}}
	exportSigner, err := sign.GenerateCertSigner()
	if err != nil {
		t.Fatal(err)
	}
	return doc, &Builder{Q: &evidenceQueriesStub{events: []*generated.Event{event}}, Versions: &evidenceVersionsStub{}, Storage: f.Store, Signer: exportSigner, CertificateTrustedPublicKeys: []string{f.Signer.PublicKeyBase64()}, FitsIndexCommitments: commitment}, f, commitment
}
func TestBuildSchema4UsesCommittedFrozenIndexAndOriginalName(t *testing.T) {
	doc, builder, f, commitment := fittedBuildFixtureV1(t)
	result, err := builder.Build(context.Background(), doc)
	if err != nil {
		t.Fatal(err)
	}
	if result.ContentType() != "application/zip" || result.Manifest.SchemaVersion != FittedManifestSchemaVersion || result.Manifest.DocumentName != f.Input.OriginalDocumentName || commitment.calls != 1 || !strings.HasSuffix(result.Filename, ".zip") {
		t.Fatal("frozen original name/schema/scope lost")
	}
	reader, err := zip.NewReader(bytes.NewReader(result.Bytes), int64(len(result.Bytes)))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	sizes := []manualfit.ArchiveSizeV1{}
	for _, file := range reader.File {
		if file.Method != zip.Store {
			t.Fatal("unbounded compression format")
		}
		seen[file.Name] = true
		sizes = append(sizes, manualfit.ArchiveSizeV1{Name: file.Name, Bytes: int64(file.UncompressedSize64)})
	}
	expected, err := manualfit.StoreZIPSizeV1(sizes)
	if err != nil || expected != int64(len(result.Bytes)) {
		t.Fatal("actual archive cap/overhead mismatch")
	}
	for _, name := range []string{"signature-fit-index.json", manualfit.SourceArchiveNameV1(doc.ID), manualfit.ManifestArchiveNameV1(f.Input.Entries[0].SignatureID), manualfit.SpanArchiveNameV1(f.Input.Entries[0].SignatureID), manualfit.PageArchiveNameV1(f.Input.Entries[0].SignatureID, 1), "final-pdf.pdf", "audit-cert-payload.txt"} {
		if !seen[name] {
			t.Fatalf("frozen evidence member %s missing", name)
		}
	}
}
func TestBuildSchema4RefusesJournalIndexAndCompletionDrift(t *testing.T) {
	for _, name := range []string{"missing-store", "unexpected-required", "missing-pin", "required-flag-downgrade", "missing-exact-index", "changed-index-version", "completion-drift", "retention-drift", "index-byte-tamper", "historical-issuer-not-trusted"} {
		t.Run(name, func(t *testing.T) {
			doc, builder, f, commitment := fittedBuildFixtureV1(t)
			switch name {
			case "missing-store":
				builder.FitsIndexCommitments = nil
			case "unexpected-required":
				doc.FitsIndexRequired = false
			case "missing-pin":
				commitment.commitment.Object = manualfit.ObjectPinV1{}
			case "required-flag-downgrade":
				commitment.commitment = manualfit.CommittedFitsIndexV1{}
			case "missing-exact-index":
				delete(f.Store.Blobs, testfitarchive.Identity(f.IndexPin.Key, f.IndexPin.VersionID))
			case "changed-index-version":
				commitment.commitment.Object.VersionID = "new latest version"
			case "completion-drift":
				doc.CompletedAt.Time = doc.CompletedAt.Time.Add(time.Second)
				doc.CompletionEffectiveAt.Time = doc.CompletedAt.Time
			case "retention-drift":
				doc.FinalizationRetainUntil.Time = doc.FinalizationRetainUntil.Time.Add(time.Second)
			case "index-byte-tamper":
				blob := f.Store.Blobs[testfitarchive.Identity(f.IndexPin.Key, f.IndexPin.VersionID)]
				blob.Raw[len(blob.Raw)-1] = 'x'
				f.Store.Blobs[testfitarchive.Identity(f.IndexPin.Key, f.IndexPin.VersionID)] = blob
			case "historical-issuer-not-trusted":
				builder.CertificateTrustedPublicKeys = nil
			}
			if _, err := builder.Build(context.Background(), doc); err == nil {
				t.Fatal("exported drifted fitted ceremony")
			}
		})
	}
}
func TestCertificateFitsIndexClaimsAreAtomicAndCanonical(t *testing.T) {
	doc, builder, f, _ := fittedBuildFixtureV1(t)
	_ = doc
	_ = builder
	// The actual fixture certificate carries all four new paired claims.
	var payload []byte
	for _, blob := range f.Store.Blobs {
		if strings.Contains(blob.Pin.Key, "/audit-payload-") {
			payload = blob.Raw
		}
	}
	claims, err := ParseCertificateCommitments(payload)
	if err != nil || claims.FitsIndexSchema != manualfit.FitsIndexSchemaV1 {
		t.Fatal("paired claims rejected")
	}
	for _, attribute := range []string{"data-hash-fits-index-schema", "data-hash-fits-index-sha256", "data-hash-fits-index-object-sha256", "data-hash-evidence-retain-until"} {
		modified := bytes.Replace(payload, []byte(attribute), []byte("omitted-attribute"), 1)
		if _, err := ParseCertificateCommitments(modified); err == nil {
			t.Fatal("partial index claim accepted")
		}
	}
	modified := bytes.Replace(payload, []byte(claims.EvidenceRetainUntil), []byte("2033-10-11T12:00:00Z"), 1)
	if _, err := ParseCertificateCommitments(modified); err == nil {
		t.Fatal("non-completion retention accepted")
	}
}
func TestHistoricalManifestCanonicalBytesOmitNewFittedFields(t *testing.T) {
	for _, schema := range []int{LegacyManifestSchemaVersion, CurrentManifestSchemaVersion} {
		raw, err := CanonicalManifestForSignature(Manifest{SchemaVersion: schema, DocumentName: "Historical"})
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ceremony_epoch_at", "final_pdf_object", "fits_index_sha256", "fits_index_object", "evidence_retain_until"} {
			if bytes.Contains(raw, []byte(name)) {
				t.Fatal("historical signature bytes expanded")
			}
		}
	}
}
func TestSchema4ZIPMemberCapsFailBeforeWriting(t *testing.T) {
	f := testfitarchive.New(t, "v1-case-1.fit")
	public, err := base64.StdEncoding.DecodeString(f.Signer.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manualfit.ReadFitsArchiveSnapshotV1(context.Background(), f.Store, f.IndexPin, f.Input.Binding, public)
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildSchema4ZIPV1(context.Background(), f.Input.Binding.DocumentID, Manifest{SchemaVersion: FittedManifestSchemaVersion}, snapshot, []schema4AttachmentV1{{Name: "events.json", Raw: bytes.Repeat([]byte{'x'}, int(manualfit.MaxEventsJSONBytesV1+1))}})
	if !errors.Is(err, ErrEvidenceTooLarge) {
		t.Fatal("sidecar cap not enforced")
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	cause := errors.New("PRIVATE_CAUSE")
	cancel(cause)
	if _, err := buildSchema4ZIPV1(ctx, f.Input.Binding.DocumentID, Manifest{SchemaVersion: FittedManifestSchemaVersion}, snapshot, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
}
