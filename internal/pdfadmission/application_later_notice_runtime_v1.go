// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/noticeaccess"
	"github.com/bright-interaction/hash/internal/storage"
)

// Only the configured actual pool/coordinator are forwarded; this exports no
// caller budget, verifier, generic coordinator or latest-object permission.
func (r *WorkRuntimeV1) NewLaterAmendmentNoticeAccessV1(store *storage.Client, cookies *auth.SignedCookie, publicURL string) (*noticeaccess.EngineV1, error) {
	if r == nil || !r.MatchesPoolV1(r.pool) {
		return nil, ErrWorkRuntimeV1
	}
	return noticeaccess.NewV1(r.pool, store, cookies, r.coordinator, publicURL)
}
