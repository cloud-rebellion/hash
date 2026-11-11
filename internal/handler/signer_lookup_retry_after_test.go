// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"testing"
)

// The token lookup is the first statement of every signer action handler, so
// its 503 happens before any work. It alone carries Retry-After.
func TestSignerActionLookupRefusalSetsRetryAfter(t *testing.T) {
	h := newSignerRateLimitRouter(true)
	for _, action := range []string{"sign", "accept", "decline", "request-changes"} {
		res := signerRateLimitRequest(h, http.MethodPost, "/sign/lookup-retry-"+action+"/"+action)
		assertSignerRateLimitRuntimeUnavailable(t, res)
		if got := res.Header().Get("Retry-After"); got != "1" {
			t.Fatalf("%s: Retry-After=%q, want 1", action, got)
		}
	}
}
