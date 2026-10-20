// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

import (
	"errors"
	"strconv"
	"strings"

	"github.com/bright-interaction/hash/internal/signaturefit"
	"github.com/google/uuid"
)

// These are the shared NEW schema4 producer, exact-read, Store ZIP and verifier
// limits. Historical schema2/3 PDF limits remain separate and unchanged.
const (
	MaxArchiveBytesV1              int64 = 160 << 20
	MaxProcessingBytesV1           int64 = 50 << 20
	MaxArchiveSourcePDFBytesV1     int64 = 50 << 20
	MaxFinalPDFBytesV1             int64 = 50 << 20
	MaxCertificatePDFBytesV1       int64 = 8 << 20
	MaxCertificatePayloadBytesV1   int64 = 4 << 20
	MaxCertificateSignatureBytesV1 int64 = 256
	MaxFitsIndexBytesV1            int64 = 8 << 20
	MaxEventsJSONBytesV1           int64 = 4 << 20
	MaxVersionsJSONBytesV1         int64 = 4 << 20
	MaxIssuerKeyBytesV1            int64 = 16 << 10
	MaxEvidenceManifestBytesV1     int64 = 1 << 20
	MaxArchiveBasePDFBytesV1       int64 = 50 << 20
	MaxArchiveEntriesV1                  = 10000
	MaxFitsIndexDocumentsV1              = 1000
	MaxFitsIndexSignaturesV1             = 1000
	MaxLegacySignatureSpanBytesV1  int64 = 6*800 + 256
)

var ErrArchiveLimitV1 = errors.New("manualfit: invalid schema4 archive member or aggregate limit")

type ArchiveSizeV1 struct {
	Name  string
	Bytes int64
}

func SourceArchiveNameV1(documentID uuid.UUID) string {
	return "source-" + documentID.String() + ".pdf"
}
func BaseArchiveNameV1(documentID uuid.UUID, page int) string {
	return "base-" + documentID.String() + "-page-" + strconv.Itoa(page) + ".pdf"
}
func ManifestArchiveNameV1(signatureID uuid.UUID) string {
	return "fit-" + signatureID.String() + "-manifest.json"
}
func SpanArchiveNameV1(signatureID uuid.UUID) string {
	return "fit-" + signatureID.String() + "-span.html"
}
func PageArchiveNameV1(signatureID uuid.UUID, page int) string {
	return "fit-" + signatureID.String() + "-page-" + strconv.Itoa(page) + ".fit"
}

func LegacySpanArchiveNameV1(signatureID uuid.UUID) string {
	return "legacy-" + signatureID.String() + "-span.html"
}

func archiveUUIDV1(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}
func archivePageNameV1(name, prefix, suffix string) bool {
	if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
		return false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	at := strings.Index(inner, "-page-")
	if at < 0 || !archiveUUIDV1(inner[:at]) {
		return false
	}
	raw := inner[at+6:]
	page, err := strconv.Atoi(raw)
	return err == nil && page >= 1 && page <= 500 && strconv.Itoa(page) == raw
}

// ArchiveEntryLimitV1 recognizes only exact fixed ASCII names; an attacker
// cannot obtain the dedicated private-package cap merely by adding .fit.
func ArchiveEntryLimitV1(name string) (int64, error) {
	switch name {
	case "final-pdf.pdf":
		return MaxFinalPDFBytesV1, nil
	case "audit-cert.pdf":
		return MaxCertificatePDFBytesV1, nil
	case "audit-cert-payload.txt":
		return MaxCertificatePayloadBytesV1, nil
	case "audit-cert-signature.txt":
		return MaxCertificateSignatureBytesV1, nil
	case "signature-fit-index.json":
		return MaxFitsIndexBytesV1, nil
	case "events.json":
		return MaxEventsJSONBytesV1, nil
	case "versions.json":
		return MaxVersionsJSONBytesV1, nil
	case "manifest.json":
		return MaxEvidenceManifestBytesV1, nil
	case "manifest-public-key.pem", "certificate-public-key.pem":
		return MaxIssuerKeyBytesV1, nil
	}
	if strings.HasPrefix(name, "source-") && strings.HasSuffix(name, ".pdf") && archiveUUIDV1(strings.TrimSuffix(strings.TrimPrefix(name, "source-"), ".pdf")) {
		return MaxArchiveSourcePDFBytesV1, nil
	}
	if archivePageNameV1(name, "base-", ".pdf") {
		return MaxArchiveBasePDFBytesV1, nil
	}
	if archivePageNameV1(name, "fit-", ".fit") {
		return int64(signaturefit.MaxPackageBytes), nil
	}
	if strings.HasPrefix(name, "legacy-") && strings.HasSuffix(name, "-span.html") && archiveUUIDV1(strings.TrimSuffix(strings.TrimPrefix(name, "legacy-"), "-span.html")) {
		return MaxLegacySignatureSpanBytesV1, nil
	}
	if strings.HasPrefix(name, "fit-") {
		for _, part := range []struct {
			suffix string
			limit  int64
		}{{suffix: "-manifest.json", limit: MaxManifestBytesV1}, {suffix: "-span.html", limit: MaxSpanBytesV1}} {
			if strings.HasSuffix(name, part.suffix) && archiveUUIDV1(strings.TrimSuffix(strings.TrimPrefix(name, "fit-"), part.suffix)) {
				return part.limit, nil
			}
		}
	}
	return 0, ErrArchiveLimitV1
}

// StoreZIPSizeV1 includes local+central headers, the standard data descriptor
// and end record for ASCII names, no extra fields/comments and Store entries.
// Producers also enforce the actual written byte count; this is admission, not
// a substitute for observing the resulting archive.
func StoreZIPSizeV1(entries []ArchiveSizeV1) (int64, error) {
	if len(entries) < 1 || len(entries) > MaxArchiveEntriesV1 {
		return 0, ErrArchiveLimitV1
	}
	total := int64(22)
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		limit, err := ArchiveEntryLimitV1(entry.Name)
		if err != nil || entry.Bytes <= 0 || entry.Bytes > limit {
			return 0, ErrArchiveLimitV1
		}
		if _, duplicate := seen[entry.Name]; duplicate {
			return 0, ErrArchiveLimitV1
		}
		seen[entry.Name] = struct{}{}
		addition := entry.Bytes + int64(92+2*len(entry.Name))
		if addition > MaxArchiveBytesV1-total {
			return 0, ErrArchiveLimitV1
		}
		total += addition
	}
	return total, nil
}
