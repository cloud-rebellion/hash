// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/google/uuid"
)

var errFitsArchiveV1 = errors.New("schema4 fitted archive is missing, malformed or differs from its signed exact commitments")

// VerifyEvidenceArchiveWithTrust accepts only the frozen bounded Store ZIP
// format. It does not render, refit, contact storage or assert legal effect.
func VerifyEvidenceArchiveWithTrust(raw []byte, trust EvidenceTrustSet) VerifyBundleReport {
	report := VerifyBundleReport{Checks: []VerifyBundleCheck{}}
	files, err := readStoreArchiveV1(raw)
	if err != nil {
		report.Errors = append(report.Errors, errFitsArchiveV1.Error())
		return report
	}
	return verifyEvidenceFilesWithTrust(files, trust, true)
}
func readStoreArchiveV1(raw []byte) (map[string][]byte, error) {
	if len(raw) < 22 || int64(len(raw)) > manualfit.MaxArchiveBytesV1 {
		return nil, errFitsArchiveV1
	}
	end := raw[len(raw)-22:]
	if binary.LittleEndian.Uint32(end) != 0x06054b50 || binary.LittleEndian.Uint16(end[4:]) != 0 || binary.LittleEndian.Uint16(end[6:]) != 0 || binary.LittleEndian.Uint16(end[20:]) != 0 {
		return nil, errFitsArchiveV1
	}
	count := int(binary.LittleEndian.Uint16(end[10:]))
	centralBytes := int64(binary.LittleEndian.Uint32(end[12:]))
	centralOffset := int64(binary.LittleEndian.Uint32(end[16:]))
	if count < 1 || count > manualfit.MaxArchiveEntriesV1 || int(binary.LittleEndian.Uint16(end[8:])) != count || centralOffset+centralBytes != int64(len(raw)-22) {
		return nil, errFitsArchiveV1
	}
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || reader.Comment != "" || len(reader.File) != count {
		return nil, errFitsArchiveV1
	}
	files := make(map[string][]byte, count)
	sizes := make([]manualfit.ArchiveSizeV1, 0, count)
	var total, localOffset int64
	centralCursor := centralOffset
	for _, file := range reader.File {
		limit, err := manualfit.ArchiveEntryLimitV1(file.Name)
		if err != nil || file.Method != zip.Store || file.Flags != 8 || len(file.Extra) != 0 || file.Comment != "" || file.NonUTF8 || file.FileInfo().IsDir() || !file.Mode().IsRegular() || file.CompressedSize64 != file.UncompressedSize64 || file.UncompressedSize64 < 1 || file.UncompressedSize64 > uint64(limit) {
			return nil, errFitsArchiveV1
		}
		if _, duplicate := files[file.Name]; duplicate {
			return nil, errFitsArchiveV1
		}
		n := int64(file.UncompressedSize64)
		if n > manualfit.MaxArchiveBytesV1-total {
			return nil, errFitsArchiveV1
		}
		total += n
		// No prefix, overlaps, gaps, alternate local names, ZIP64, extras or trailing
		// bytes. The producer uses signed 16-byte descriptors with Store entries.
		dataOffset, err := file.DataOffset()
		localHeaderEnd := localOffset + 30 + int64(len(file.Name))
		descriptorEnd := dataOffset + n + 16
		if err != nil || localOffset < 0 || localHeaderEnd > centralOffset || dataOffset != localHeaderEnd || descriptorEnd > centralOffset {
			return nil, errFitsArchiveV1
		}
		header := raw[localOffset:localHeaderEnd]
		if binary.LittleEndian.Uint32(header) != 0x04034b50 || binary.LittleEndian.Uint16(header[6:]) != 8 || binary.LittleEndian.Uint16(header[8:]) != zip.Store || binary.LittleEndian.Uint32(header[14:]) != 0 || binary.LittleEndian.Uint32(header[18:]) != 0 || binary.LittleEndian.Uint32(header[22:]) != 0 || int(binary.LittleEndian.Uint16(header[26:])) != len(file.Name) || binary.LittleEndian.Uint16(header[28:]) != 0 || !bytes.Equal(header[30:], []byte(file.Name)) {
			return nil, errFitsArchiveV1
		}
		descriptor := raw[dataOffset+n : descriptorEnd]
		if binary.LittleEndian.Uint32(descriptor) != 0x08074b50 || binary.LittleEndian.Uint32(descriptor[4:]) != file.CRC32 || uint64(binary.LittleEndian.Uint32(descriptor[8:])) != file.CompressedSize64 || uint64(binary.LittleEndian.Uint32(descriptor[12:])) != file.UncompressedSize64 {
			return nil, errFitsArchiveV1
		}
		centralEnd := centralCursor + 46 + int64(len(file.Name))
		if centralEnd > int64(len(raw)-22) {
			return nil, errFitsArchiveV1
		}
		central := raw[centralCursor:centralEnd]
		if binary.LittleEndian.Uint32(central) != 0x02014b50 || binary.LittleEndian.Uint16(central[8:]) != 8 || binary.LittleEndian.Uint16(central[10:]) != zip.Store || int(binary.LittleEndian.Uint16(central[28:])) != len(file.Name) || binary.LittleEndian.Uint16(central[30:]) != 0 || binary.LittleEndian.Uint16(central[32:]) != 0 || binary.LittleEndian.Uint16(central[34:]) != 0 || int64(binary.LittleEndian.Uint32(central[42:])) != localOffset || !bytes.Equal(central[46:], []byte(file.Name)) {
			return nil, errFitsArchiveV1
		}
		opened, err := file.Open()
		if err != nil {
			return nil, errFitsArchiveV1
		}
		payload, readErr := io.ReadAll(io.LimitReader(opened, n+1))
		closeErr := opened.Close()
		if readErr != nil || closeErr != nil || int64(len(payload)) != n {
			return nil, errFitsArchiveV1
		}
		files[file.Name] = payload
		sizes = append(sizes, manualfit.ArchiveSizeV1{Name: file.Name, Bytes: n})
		localOffset = descriptorEnd
		centralCursor = centralEnd
	}
	if localOffset != centralOffset || centralCursor != int64(len(raw)-22) {
		return nil, errFitsArchiveV1
	}
	expected, err := manualfit.StoreZIPSizeV1(sizes)
	if err != nil || expected != int64(len(raw)) {
		return nil, errFitsArchiveV1
	}
	return files, nil
}

type frozenArchiveReaderV1 struct {
	objects map[string]frozenArchiveObjectV1
}
type frozenArchiveObjectV1 struct {
	pin manualfit.ObjectPinV1
	raw []byte
}

func objectIdentityV1(key, version string) string { return key + "\x00" + version }
func (r frozenArchiveReaderV1) GetVerifiedVersionBounded(ctx context.Context, key, version string, digest []byte, maximum int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	obj, ok := r.objects[objectIdentityV1(key, version)]
	if !ok || maximum != obj.pin.Bytes || obj.pin.SHA256 != hex.EncodeToString(digest) || int64(len(obj.raw)) != maximum {
		return nil, errFitsArchiveV1
	}
	return bytes.Clone(obj.raw), nil
}
func verifySchema4FilesV1(files map[string][]byte, manifest evidence.Manifest, publicKeyB64 string, verifyBytes bool) ([]VerifyBundleCheck, []string, error) {
	if manifest.SchemaVersion != evidence.FittedManifestSchemaVersion || manifest.FinalPDFObject == nil || manifest.FitsIndexObject == nil || len(manifest.QTSP) != 0 || manifest.OpenTimestamps != nil {
		return nil, nil, errFitsArchiveV1
	}
	org, err := uuid.Parse(manifest.OrgID)
	if err != nil || org == uuid.Nil || org.String() != manifest.OrgID {
		return nil, nil, errFitsArchiveV1
	}
	doc, err := uuid.Parse(manifest.DocumentID)
	if err != nil || doc == uuid.Nil || doc.String() != manifest.DocumentID {
		return nil, nil, errFitsArchiveV1
	}
	epoch, e1 := time.Parse(time.RFC3339Nano, manifest.CeremonyEpochAt)
	completed, e2 := time.Parse(time.RFC3339Nano, manifest.CompletionEffectiveAt)
	until, e3 := time.Parse(time.RFC3339Nano, manifest.EvidenceRetainUntil)
	if e1 != nil || e2 != nil || e3 != nil || epoch.IsZero() || completed.IsZero() || until.IsZero() || epoch.UTC().Format(time.RFC3339Nano) != manifest.CeremonyEpochAt || completed.UTC().Format(time.RFC3339Nano) != manifest.CompletionEffectiveAt || until.UTC().Format(time.RFC3339Nano) != manifest.EvidenceRetainUntil || !until.Equal(manualfit.RetentionFloorV1(completed)) {
		return nil, nil, errFitsArchiveV1
	}
	pin := *manifest.FitsIndexObject
	pinSHA, err := manualfit.ObjectPinSHA256V1(pin)
	raw, ok := files["signature-fit-index.json"]
	if err != nil || !ok || pinSHA != manifest.FitsIndexObjectSHA256 || pin.SHA256 != manifest.FitsIndexSHA256 || int64(len(raw)) != pin.Bytes || digestArchiveV1(raw) != pin.SHA256 {
		return nil, nil, errFitsArchiveV1
	}
	final, ok := files["final-pdf.pdf"]
	if !ok || manifest.FinalPDFObject.SHA256 != manifest.FinalPDFSHA256 || int64(len(final)) != manifest.FinalPDFObject.Bytes || digestArchiveV1(final) != manifest.FinalPDFSHA256 {
		return nil, nil, errFitsArchiveV1
	}
	// Declaration discovery uses the carried historical certificate key only to
	// identify exact safe names. The final verdict independently requires trust
	// and both export/certificate signatures in the common verifier.
	if !verifyBytes {
		publicKeyB64, err = pemPublicKeyToBase64(files["certificate-public-key.pem"])
		if err != nil {
			return nil, nil, errFitsArchiveV1
		}
	}
	key, err := decodeTrustedEd25519Key(publicKeyB64)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, nil, errFitsArchiveV1
	}
	binding := manualfit.FitsIndexBindingV1{OrgID: org, DocumentID: doc, CeremonyEpoch: epoch.UTC(), CompletionEffectiveAt: completed.UTC(), RetainUntil: until.UTC(), FinalPDF: *manifest.FinalPDFObject}
	signed, err := manualfit.DecodeSignedFitsIndexV1(raw, binding, key)
	if err != nil || signed.Index().OriginalDocumentName() != manifest.DocumentName {
		return nil, nil, errFitsArchiveV1
	}
	objects, err := signed.Index().ArchiveObjects()
	if err != nil {
		return nil, nil, errFitsArchiveV1
	}
	objects = append(objects, manualfit.ArchiveObjectV1{Name: "signature-fit-index.json", Object: pin})
	names := make([]string, 0, len(objects))
	for _, obj := range objects {
		names = append(names, obj.Name)
	}
	sort.Strings(names)
	if !verifyBytes {
		return nil, names, nil
	}
	reader := frozenArchiveReaderV1{objects: make(map[string]frozenArchiveObjectV1, len(objects))}
	checks := make([]VerifyBundleCheck, 0, len(objects)+1)
	for _, obj := range objects {
		raw, present := files[obj.Name]
		actual := digestArchiveV1(raw)
		good := present && int64(len(raw)) == obj.Object.Bytes && actual == obj.Object.SHA256
		checks = append(checks, VerifyBundleCheck{Name: obj.Name, OK: good, Expected: obj.Object.SHA256, Actual: actual, Detail: "exact signed archive version and byte count"})
		if !good {
			return checks, names, errFitsArchiveV1
		}
		identity := objectIdentityV1(obj.Object.Key, obj.Object.VersionID)
		if prior, exists := reader.objects[identity]; exists && prior.pin != obj.Object {
			return checks, names, errFitsArchiveV1
		}
		reader.objects[identity] = frozenArchiveObjectV1{pin: obj.Object, raw: raw}
	}
	snapshot, err := manualfit.ReadFitsArchiveSnapshotV1(context.Background(), reader, pin, binding, key)
	if err != nil || snapshot == nil {
		return checks, names, errFitsArchiveV1
	}
	checks = append(checks, VerifyBundleCheck{Name: "signed-fitted-archive", OK: true, Expected: manifest.FitsIndexSHA256, Actual: snapshot.Index().SHA256(), Detail: "frozen exact manifests, spans, packages, source/base versions and ordered processing witness verified without rendering"})
	return checks, names, nil
}
func digestArchiveV1(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

// Reject duplicate members before typed decoding. Pretty historical manifests
// remain valid; unknown typed fields and trailing JSON are rejected separately.
func uniqueJSONObjectV1(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 64 {
			return errFitsArchiveV1
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				member, err := decoder.Token()
				name, ok := member.(string)
				if err != nil || !ok || seen[name] {
					return errFitsArchiveV1
				}
				seen[name] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return errFitsArchiveV1
			}
		case '[':
			for decoder.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return errFitsArchiveV1
			}
		default:
			return errFitsArchiveV1
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errFitsArchiveV1
	}
	return nil
}
