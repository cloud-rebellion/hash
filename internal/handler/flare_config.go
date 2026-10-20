// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"github.com/bright-interaction/hash/internal/flarereport"
	"net/http"
)

// Public ingest-only identity; no arbitrary/general runtime configuration and
// no relay destination is accepted from the request. CSP uses the same parser.
func (s *Server) handleFlareConfiguration(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, flarereport.BrowserConfiguration(s.Release, s.Environment))
}
