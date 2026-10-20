// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import "errors"

// SendEvidenceLimitsV1 reports only the existing concrete Client protocol
// limits. It grants no work, transport, provider or physical-retirement credit.
// A generic EvidenceRetainer implementation cannot supply this provenance.
type SendEvidenceLimitsV1 struct {
	ObjectBytes, MetadataBytes, HeaderBytes, VersionIDBytes, VersionCandidates int64
}

func (c *Client) SendEvidenceLimitsV1() (SendEvidenceLimitsV1, error) {
	if c == nil || c.mc == nil || c.bucket == "" {
		return SendEvidenceLimitsV1{}, errors.New("storage: send evidence client unavailable")
	}
	return SendEvidenceLimitsV1{ObjectBytes: maxStoredObjectBytes, MetadataBytes: boundedStorageMetadataBytesV1, HeaderBytes: boundedStorageHeaderBytesV1, VersionIDBytes: maxPersistedVersionIDBytes, VersionCandidates: maxCommittedVersionCandidates}, nil
}
