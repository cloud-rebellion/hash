// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"crypto/sha256"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
)

type applicationSignerPackageProfileV1 uint8

const (
	signerPackageActiveProfileV1 applicationSignerPackageProfileV1 = iota + 1
	signerPackageCompletedProfileV1
)

func (p applicationSignerPackageProfileV1) readerModeV1() SignerReadModeV1 {
	if p == signerPackageActiveProfileV1 {
		return SignerReadActiveResponseV1
	}
	if p == signerPackageCompletedProfileV1 {
		return SignerReadCompletedV1
	}
	return ""
}

// These pins are copied only from a registered actual Completed reader, after
// their storage has been admitted. They never arrive in an HTTP request.
type applicationCompletedPackagePinsV1 struct {
	effective      pgtype.Timestamptz
	keys, versions [4]string
	sums           [4][sha256.Size]byte
}

func completedPackagePinsV1(d *generated.Document) (applicationCompletedPackagePinsV1, error) {
	var p applicationCompletedPackagePinsV1
	if d == nil || d.Status != "completed" {
		return p, ErrSignerReadCredentialV1
	}
	p.effective = d.CompletionEffectiveAt
	keys := [4]pgtype.Text{d.FinalPdfKey, d.AuditCertKey, d.AuditPayloadKey, d.AuditSignatureKey}
	versions := [4]pgtype.Text{d.FinalPdfVersionID, d.AuditCertVersionID, d.AuditPayloadVersionID, d.AuditSignatureVersionID}
	sums := [4][]byte{d.FinalPdfSha, d.AuditCertSha256, d.AuditPayloadSha256, d.AuditSignatureSha256}
	for i := range keys {
		if len(keys[i].String) > documentpackage.MaxObjectTextBytesV1 || len(versions[i].String) > documentpackage.MaxObjectTextBytesV1 {
			return applicationCompletedPackagePinsV1{}, ErrSignerReadCredentialV1
		}
		if !keys[i].Valid || !versions[i].Valid || len(sums[i]) != sha256.Size {
			continue
		}
		p.keys[i], p.versions[i] = keys[i].String, versions[i].String
		copy(p.sums[i][:], sums[i])
	}
	return p, nil
}
func (p applicationCompletedPackagePinsV1) cloneV1() applicationCompletedPackagePinsV1 {
	for i := range p.keys {
		p.keys[i] = strings.Clone(p.keys[i])
		p.versions[i] = strings.Clone(p.versions[i])
	}
	return p
}
