// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"net/http"
	"strings"
)

// Set this only after authentication, tenant scope and artifact/render checks
// succeed. Error responses and every other route keep the baseline frame denial.
func setDocumentPreviewHeaders(w http.ResponseWriter, staticHTML bool) {
	h := w.Header()
	h.Set("X-Frame-Options", "SAMEORIGIN")
	if staticHTML {
		// A block preview is inert document content, not an application page.
		// Allow its styles/images/fonts while disabling scripts, network writes,
		// forms, child frames and navigation out of the sandbox.
		h.Set("Content-Security-Policy", "default-src 'none'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; font-src 'self'; script-src 'none'; connect-src 'none'; object-src 'none'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'; sandbox allow-same-origin")
		return
	}
	// Preserve the PDF response's baseline resource policy for native viewers.
	policy := h.Get("Content-Security-Policy")
	if strings.Contains(policy, "frame-ancestors 'none'") {
		policy = strings.ReplaceAll(policy, "frame-ancestors 'none'", "frame-ancestors 'self'")
	} else {
		policy += "; frame-ancestors 'self'"
	}
	h.Set("Content-Security-Policy", strings.TrimPrefix(policy, "; "))
}
