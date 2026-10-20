// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"bytes"
	"context"
	"time"
)

func (e *Engine) RecheckCompletedPackageByTokenV1(ctx context.Context, hash []byte, rc *RecipientContext) error {
	return e.recheckCompletedObservationOwnedV1(ctx, hash, rc, checkCompletedPackageObservationV1)
}

// Read-only terminal scope: original expiry, final/report/detached pins and
// source/Send epoch survive every await. It grants no response authority.
func checkCompletedPackageObservationV1(original, current *RecipientContext, now time.Time) error {
	if err := checkCompletedArtifactObservation(original, current, now); err != nil {
		return err
	}
	a, b := original.Document, current.Document
	if !packageReadSourceEqualV1(original, current) || a.CompletionEffectiveAt != b.CompletionEffectiveAt || a.AuditCertKey != b.AuditCertKey || a.AuditCertVersionID != b.AuditCertVersionID || !bytes.Equal(a.AuditCertSha256, b.AuditCertSha256) || a.AuditPayloadKey != b.AuditPayloadKey || a.AuditPayloadVersionID != b.AuditPayloadVersionID || !bytes.Equal(a.AuditPayloadSha256, b.AuditPayloadSha256) || a.AuditSignatureKey != b.AuditSignatureKey || a.AuditSignatureVersionID != b.AuditSignatureVersionID || !bytes.Equal(a.AuditSignatureSha256, b.AuditSignatureSha256) {
		return ErrCompletedArtifactUnavailable
	}
	return nil
}

func completedPackagePortalPathV1(token string) string {
	if token == "" {
		return ""
	}
	return "/completed/" + token
}
