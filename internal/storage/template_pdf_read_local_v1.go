// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"unsafe"

	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// ReadTemplatePDFLocalOwnedV1 uses the original constructor-owned local IO lane
// and one-shot PDF consumer. A template has no persisted byte count, so the
// fixed 50MiB intake ceiling is positively funded BEFORE HEAD, allocation or GET.
// The ceiling is a cost, not admission authority: the original coordinator can
// refuse either Parent or Provider capacity before any provider dispatch.
// Every nonnil handle, including errors, must be closed; actual IO/consumer
// retirement governs refunds, never cancellation or a successful HTTP status.
func (c *Client) ReadTemplatePDFLocalOwnedV1(ctx context.Context, key, version string, expected []byte, coordinator *workguard.CoordinatorV1, org uuid.UUID) (*PackagePDFLocalReadV1, workguard.AdmissionDenialV1, error) {
	zero := workguard.AdmissionDenialV1{}
	namespace, err := c.PackageEvidenceNamespaceV1()
	if err != nil || !c.requireEvidenceLock || !pinnedPDFOpaqueV1(key) || !pinnedPDFOpaqueV1(version) || strings.TrimSpace(version) == "null" || strings.TrimSpace(version) == DevelopmentVersionID || len(expected) != sha256.Size {
		return nil, zero, ErrPackagePDFLocalReadV1
	}
	if err = c.validatePinnedVersionID(version); err != nil {
		return nil, zero, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	extra := 8*(int64(unsafe.Sizeof(PackagePDFLocalReadV1{}))+int64(unsafe.Sizeof(packagePDFLocalReadStateV1{}))) + 4096
	if !evidenceLocalAddV1(&extra, maxPinnedPDFReadBytesV1, 1) || !evidenceLocalAddV1(&extra, int64(len(c.bucket)), 32) {
		return nil, zero, ErrPackagePDFLocalReadV1
	}
	owner, local, ownedKey, ownedVersion, denial, err := c.newEvidenceLocalReadWithFixedParentV1(ctx, key, version, expected, coordinator, org, extra)
	if owner == nil {
		return nil, denial, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	s := &packagePDFLocalReadStateV1{owner: owner, client: c, ctx: ctx, namespace: namespace}
	s.self = s
	h := &PackagePDFLocalReadV1{state: s}
	if err == nil {
		// HEAD itself is inside the owned provider/metadata lane. Allocate only the
		// actual observed size; retain the conservative admitted ceiling until close.
		info, observed := local.mc.StatObject(ctx, local.bucket, ownedKey, local.statOpts(ownedVersion))
		err = observed
		if err == nil && (info.VersionID != ownedVersion || info.Size < 1 || info.Size > maxPinnedPDFReadBytesV1) {
			err = ErrPackagePDFLocalReadV1
		}
		if err == nil {
			s.body = make([]byte, int(info.Size))
			err = local.readPackagePDFVersionLocalV1(ctx, ownedKey, ownedVersion, owner.data, s.body)
		}
	}
	if err == nil {
		err = ctx.Err()
	}
	err = finishEvidenceLocalReadV1(owner, err)
	s.success = err == nil
	if err != nil {
		return h, zero, errors.Join(ErrPackagePDFLocalReadV1, err)
	}
	return h, zero, nil
}
