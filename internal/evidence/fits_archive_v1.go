// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package evidence

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// FitsIndexCommitmentStoreV1 is backed by the scoped immutable COMPLETED
// document+intent journal, including its required flag. No current row-to-index
// reconstruction is permitted; root wiring supplies this callback after SQL86.
type FitsIndexCommitmentStoreV1 interface {
	LoadCommittedFitsIndexV1(context.Context, uuid.UUID, uuid.UUID) (manualfit.CommittedFitsIndexV1, error)
}
type schema4AttachmentV1 struct {
	Name string
	Raw  []byte
}

func (r *EvidenceResult) ContentType() string {
	if r != nil && r.Manifest.SchemaVersion == FittedManifestSchemaVersion {
		return "application/zip"
	}
	return "application/pdf"
}

func (b *Builder) loadCommittedFitsIndexV1(ctx context.Context, doc *generated.Document) (manualfit.CommittedFitsIndexV1, error) {
	if b.FitsIndexCommitments == nil {
		if doc.FitsIndexRequired {
			return manualfit.CommittedFitsIndexV1{}, fmt.Errorf("%w: required fitted index reader unavailable", ErrArtifactIntegrity)
		}
		return manualfit.CommittedFitsIndexV1{}, nil
	}
	pin, err := b.FitsIndexCommitments.LoadCommittedFitsIndexV1(ctx, doc.OrgID, doc.ID)
	if err != nil {
		return manualfit.CommittedFitsIndexV1{}, safeFitsEvidenceErrorV1(ctx, err)
	}
	if pin.Required != doc.FitsIndexRequired {
		return manualfit.CommittedFitsIndexV1{}, fmt.Errorf("%w: fitted index requirement changed", ErrArtifactIntegrity)
	}
	if !pin.Required {
		if pin.Object != (manualfit.ObjectPinV1{}) {
			return manualfit.CommittedFitsIndexV1{}, errors.New("evidence: unexpected index pin on historical ceremony")
		}
		return pin, nil
	}
	if _, err := manualfit.ObjectPinSHA256V1(pin.Object); err != nil {
		return manualfit.CommittedFitsIndexV1{}, fmt.Errorf("%w: required fitted index pin incomplete", ErrArtifactIntegrity)
	}
	return pin, nil
}
func readSchema4OrLegacyArtifactV1(ctx context.Context, store blobStore, doc *generated.Document, key string, digest []byte, version pgtype.Text, fitted bool, limit int64) ([]byte, error) {
	if !fitted {
		return readEvidenceArtifact(ctx, store, doc, key, digest, version)
	}
	reader, ok := store.(manualfit.BoundedReaderV1)
	if !ok || !doc.EvidenceVersionPinsRequired || !version.Valid || version.String == "" {
		return nil, errors.New("evidence: fitted artifacts require bounded exact-version storage")
	}
	raw, err := reader.GetVerifiedVersionBounded(ctx, key, version.String, digest, limit)
	if err != nil {
		return nil, safeFitsEvidenceErrorV1(ctx, err)
	}
	if len(raw) == 0 || int64(len(raw)) > limit {
		return nil, ErrEvidenceTooLarge
	}
	return raw, nil
}
func (b *Builder) loadCompletedFitsArchiveV1(ctx context.Context, doc *generated.Document, indexPin manualfit.ObjectPinV1, claims CertificateCommitments, payload, signature, finalPDF []byte) (*manualfit.FitsArchiveSnapshotV1, error) {
	if !doc.SentAt.Valid || !doc.CompletionEffectiveAt.Valid || !doc.CompletedAt.Valid || !doc.CompletionEffectiveAt.Time.Equal(doc.CompletedAt.Time) || !doc.FinalizationRetainUntil.Valid || doc.FinalizationRetainUntil.Time.UTC().Format(time.RFC3339) != claims.EvidenceRetainUntil || !doc.FinalPdfVersionID.Valid {
		return nil, fmt.Errorf("%w: fitted completion or retention record incoherent", ErrArtifactIntegrity)
	}
	objectSHA, err := manualfit.ObjectPinSHA256V1(indexPin)
	if err != nil || claims.FitsIndexSchema != manualfit.FitsIndexSchemaV1 || indexPin.SHA256 != claims.FitsIndexSHA256 || objectSHA != claims.FitsIndexObjectSHA256 {
		return nil, fmt.Errorf("%w: signed certificate does not bind exact fitted index version", ErrArtifactIntegrity)
	}
	if b.Signer == nil {
		return nil, errors.New("evidence: manifest signer unavailable")
	}
	trusted := append([]string(nil), b.CertificateTrustedPublicKeys...)
	trusted = append(trusted, b.Signer.PublicKeyBase64())
	publicB64, _, _, err := resolveCertificateIssuerKey(payload, signature, trusted)
	if err != nil {
		return nil, err
	}
	public, err := base64.StdEncoding.Strict().DecodeString(publicB64)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("evidence: historical certificate issuer key invalid")
	}
	reader, ok := b.Storage.(manualfit.BoundedReaderV1)
	if !ok {
		return nil, errors.New("evidence: bounded fitted archive storage unavailable")
	}
	binding := manualfit.FitsIndexBindingV1{OrgID: doc.OrgID, DocumentID: doc.ID, CeremonyEpoch: doc.SentAt.Time, CompletionEffectiveAt: doc.CompletionEffectiveAt.Time, RetainUntil: doc.FinalizationRetainUntil.Time,
		FinalPDF: manualfit.ObjectPinV1{Key: doc.FinalPdfKey.String, VersionID: doc.FinalPdfVersionID.String, SHA256: claims.FinalPDFSHA256, Bytes: int64(len(finalPDF)), ContentType: "application/pdf"}}
	snapshot, err := manualfit.ReadFitsArchiveSnapshotV1(ctx, reader, indexPin, binding, ed25519.PublicKey(public))
	if err != nil {
		return nil, safeFitsEvidenceErrorV1(ctx, err)
	}
	return snapshot, nil
}

// fitsEventsFixedJSONBytesV1 conservatively covers each event's field names,
// separators, indentation, five UUID/null values, the RFC3339Nano timestamp and
// the fixed address portion of IP. The envelope uses the same allowance. All
// unbounded strings, payloads and hashes are charged separately below. A scoped
// IPv6 zone is not part of the fixed address allowance.
const fitsEventsFixedJSONBytesV1 int64 = 1024

type fitsEventsJSONBudgetV1 struct{ used int64 }

func (b *fitsEventsJSONBudgetV1) add(n int64) error {
	if n < 0 || b.used < 0 || b.used > manualfit.MaxEventsJSONBytesV1 || n > manualfit.MaxEventsJSONBytesV1-b.used {
		return ErrEvidenceTooLarge
	}
	b.used += n
	return nil
}

// fitsEventsJSONStringBoundV1 counts encoding/json's default HTML-escaped
// string representation without allocating an escaped string. Invalid UTF-8
// bytes use the same six-byte replacement bound as the JSON string encoder.
func fitsEventsJSONStringBoundV1(ctx context.Context, budget fitsJSONStringBudgetV1, value string) error {
	if err := budget.add(2); err != nil { // quotes
		return err
	}
	nextCheckpoint := 0
	for i := 0; i < len(value); {
		if i >= nextCheckpoint {
			if ctx.Err() != nil {
				return safeFitsEvidenceErrorV1(ctx, ctx.Err())
			}
			nextCheckpoint = i + 4096
		}
		r, width := utf8.DecodeRuneInString(value[i:])
		n := int64(width)
		switch {
		case r == utf8.RuneError && width == 1:
			n = 6
		case r == '"' || r == '\\' || r == '\b' || r == '\f' || r == '\n' || r == '\r' || r == '\t':
			n = 2
		case r < 0x20 || r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029':
			n = 6
		}
		if err := budget.add(n); err != nil {
			return err
		}
		i += width
	}
	return nil
}

// fitsEventsRawJSONBoundV1 bounds RawMessage's compact HTML-escaped bytes and
// MarshalIndent's subsequent pretty printing. It deliberately charges original
// whitespace and empty-container line breaks too, so it can reject a borderline
// input that would compact below the cap. Depth is measured inside payload_json;
// that value starts at indentation depth three in CeremonyEventsFile. Every
// addition is admitted before integer arithmetic or a payload copy/encoding.
func fitsEventsRawJSONBoundV1(ctx context.Context, budget *fitsEventsJSONBudgetV1, raw []byte) error {
	if int64(len(raw)) > manualfit.MaxEventsJSONBytesV1 {
		return ErrEvidenceTooLarge
	}
	depth := int64(0)
	quoted, escaped := false, false
	nextCheckpoint := 0
	for i := 0; i < len(raw); {
		if i >= nextCheckpoint {
			if ctx.Err() != nil {
				return safeFitsEvidenceErrorV1(ctx, ctx.Err())
			}
			nextCheckpoint = i + 4096
		}
		r, width := utf8.DecodeRune(raw[i:])
		n := int64(width)
		if r == '<' || r == '>' || r == '&' || r == '\u2028' || r == '\u2029' || (r == utf8.RuneError && width == 1) {
			n = 6
		}
		if err := budget.add(n); err != nil {
			return err
		}
		if quoted {
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == '"' {
				quoted = false
			}
		} else {
			switch r {
			case '"':
				quoted = true
			case '{', '[':
				depth++
				if depth > 10000 { // encoding/json's maximum accepted nesting
					return ErrArtifactIntegrity
				}
				if err := budget.add(1 + 2*(3+depth)); err != nil {
					return err
				}
			case '}', ']':
				if depth == 0 {
					return ErrArtifactIntegrity
				}
				depth--
				if err := budget.add(1 + 2*(3+depth)); err != nil {
					return err
				}
			case ',':
				if err := budget.add(1 + 2*(3+depth)); err != nil {
					return err
				}
			case ':':
				if err := budget.add(1); err != nil {
					return err
				}
			}
		}
		i += width
	}
	if !json.Valid(raw) {
		return ErrArtifactIntegrity
	}
	return nil
}

func fitsEventsJSONBoundV1(ctx context.Context, rows []*generated.Event) (int64, error) {
	if ctx.Err() != nil {
		return 0, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	if len(rows) == 0 || len(rows) > maxEvidenceEvents {
		return 0, ErrArtifactIntegrity
	}
	budget := fitsEventsJSONBudgetV1{}
	if err := budget.add(fitsEventsFixedJSONBytesV1); err != nil {
		return 0, err
	}
	for _, row := range rows {
		if ctx.Err() != nil {
			return 0, safeFitsEvidenceErrorV1(ctx, ctx.Err())
		}
		if row == nil {
			return 0, ErrArtifactIntegrity
		}
		if err := budget.add(fitsEventsFixedJSONBytesV1); err != nil {
			return 0, err
		}
		if err := fitsEventsJSONStringBoundV1(ctx, &budget, row.Kind); err != nil {
			return 0, err
		}
		if row.Ua.Valid {
			if err := fitsEventsJSONStringBoundV1(ctx, &budget, row.Ua.String); err != nil {
				return 0, err
			}
		}
		if row.Ip != nil {
			if err := fitsEventsJSONStringBoundV1(ctx, &budget, row.Ip.Zone()); err != nil {
				return 0, err
			}
		}
		if err := fitsEventsRawJSONBoundV1(ctx, &budget, row.PayloadJson); err != nil {
			return 0, err
		}
		// Check lengths before multiplication: the SQL result already owns these
		// bytes, but canonicalCeremonyEvent must not encode oversized values.
		payloadBytes := int64(len(row.PayloadHashed))
		if payloadBytes > manualfit.MaxEventsJSONBytesV1 {
			return 0, ErrEvidenceTooLarge
		}
		encodedBytes := (payloadBytes / 3) * 4
		if payloadBytes%3 != 0 {
			encodedBytes += 4
		}
		if err := budget.add(encodedBytes); err != nil {
			return 0, err
		}
		for _, digest := range [][]byte{row.PrevHash, row.RowHash} {
			if int64(len(digest)) > manualfit.MaxEventsJSONBytesV1/2 {
				return 0, ErrEvidenceTooLarge
			}
			if err := budget.add(2 * int64(len(digest))); err != nil {
				return 0, err
			}
		}
	}
	return budget.used, nil
}

// buildSchema4CeremonyEventsJSONV1 admits all encoding expansion before the
// historical canonical builder copies payloads, encodes base64/hex or marshals
// the file. It retains the exact existing bytes/commitment and a final observed
// cap. This bounds this producer allocation boundary, not the DB query, other
// decoding allocations, or the historical PDF verifier's isolation.
func buildSchema4CeremonyEventsJSONV1(ctx context.Context, documentID uuid.UUID, rows []*generated.Event) ([]byte, string, int, error) {
	if _, err := fitsEventsJSONBoundV1(ctx, rows); err != nil {
		return nil, "", 0, err
	}
	if ctx.Err() != nil {
		return nil, "", 0, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	raw, commitment, count, err := BuildCeremonyEventsJSON(documentID, rows)
	if err != nil {
		return nil, "", 0, err
	}
	if int64(len(raw)) > manualfit.MaxEventsJSONBytesV1 {
		return nil, "", 0, ErrEvidenceTooLarge
	}
	if ctx.Err() != nil {
		return nil, "", 0, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	return raw, commitment, count, nil
}

type boundedArchiveOutputV1 struct{ bytes.Buffer }

func (w *boundedArchiveOutputV1) Write(raw []byte) (int, error) {
	if int64(len(raw)) > manualfit.MaxArchiveBytesV1-int64(w.Len()) {
		return 0, ErrEvidenceTooLarge
	}
	return w.Buffer.Write(raw)
}

// buildSchema4ZIPV1 creates the actual Store ZIP, enforcing the same bounds used
// by admission/readers/verifiers. Existing schema2/3 PDF construction is kept
// separate; PDF attachment aggregate bytes are not mislabeled a ZIP receipt.
func buildSchema4ZIPV1(ctx context.Context, documentID uuid.UUID, manifest Manifest, snapshot *manualfit.FitsArchiveSnapshotV1, core []schema4AttachmentV1) (*EvidenceResult, error) {
	if snapshot == nil || manifest.SchemaVersion != FittedManifestSchemaVersion {
		return nil, ErrArtifactIntegrity
	}
	objects := snapshot.Objects()
	sizes := make([]manualfit.ArchiveSizeV1, 0, len(objects)+len(core))
	sources := map[string]io.Reader{}
	for _, object := range objects {
		reader, err := snapshot.Open(object.Name)
		if err != nil {
			return nil, err
		}
		sources[object.Name] = reader
		sizes = append(sizes, manualfit.ArchiveSizeV1{Name: object.Name, Bytes: object.Object.Bytes})
	}
	for _, member := range core {
		if _, duplicate := sources[member.Name]; duplicate {
			return nil, ErrArtifactIntegrity
		}
		sources[member.Name] = bytes.NewReader(member.Raw)
		sizes = append(sizes, manualfit.ArchiveSizeV1{Name: member.Name, Bytes: int64(len(member.Raw))})
	}
	expectedBytes, err := manualfit.StoreZIPSizeV1(sizes)
	if err != nil {
		return nil, ErrEvidenceTooLarge
	}
	sort.Slice(sizes, func(a, b int) bool { return sizes[a].Name < sizes[b].Name })
	output := &boundedArchiveOutputV1{}
	writer := zip.NewWriter(output)
	for _, member := range sizes {
		if ctx.Err() != nil {
			return nil, safeFitsEvidenceErrorV1(ctx, ctx.Err())
		}
		// ASCII fixed names, Store, no time extra fields/comments, no ZIP64 (all
		// member/count limits below its thresholds); standard descriptor accounted.
		file, err := writer.CreateHeader(&zip.FileHeader{Name: member.Name, Method: zip.Store})
		if err != nil {
			return nil, fmt.Errorf("evidence: Store ZIP member: %w", err)
		}
		count, err := io.Copy(file, io.LimitReader(sources[member.Name], member.Bytes+1))
		if err != nil || count != member.Bytes {
			return nil, errors.New("evidence: exact ZIP member byte count changed")
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	if int64(output.Len()) != expectedBytes || int64(output.Len()) > manualfit.MaxArchiveBytesV1 {
		return nil, ErrEvidenceTooLarge
	}
	if ctx.Err() != nil {
		return nil, safeFitsEvidenceErrorV1(ctx, ctx.Err())
	}
	return &EvidenceResult{Bytes: output.Bytes(), Manifest: manifest, Filename: fmt.Sprintf("hash-evidence-%s.zip", documentID.String())}, nil
}

// Preserve cancellation and its distinct cause without printing private cause
// text into the HTTP error, audit log or archive.
type fitsEvidenceErrorV1 struct {
	kind  error
	cause error
}

func (e fitsEvidenceErrorV1) Error() string   { return "evidence: fitted archive unavailable" }
func (e fitsEvidenceErrorV1) Unwrap() []error { return []error{ErrArtifactIntegrity, e.kind, e.cause} }
func safeFitsEvidenceErrorV1(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fitsEvidenceErrorV1{kind: ctx.Err(), cause: context.Cause(ctx)}
	}
	if errors.Is(err, context.Canceled) {
		return fitsEvidenceErrorV1{kind: context.Canceled, cause: err}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fitsEvidenceErrorV1{kind: context.DeadlineExceeded, cause: err}
	}
	return ErrArtifactIntegrity
}
