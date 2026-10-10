// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import "github.com/bright-interaction/hash/internal/sourcejson"

var errAmbiguousResponse = sourcejson.ErrAmbiguousResponse

// Shared with the tenant-bound CRM connector; preserve the existing scanner
// response policy and sentinel.
func validateSourceJSON(raw []byte) error { return sourcejson.Validate(raw) }
