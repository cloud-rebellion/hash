// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/branding/catalog"
	"github.com/bright-interaction/hash/internal/malwarescan"
)

func TestBrandCatalog783ScanFailureHTTPClassificationAndPrivacy(t *testing.T) {
	private := "private-provider-object/version/path and scanner detail"
	for _, row := range []struct {
		name string
		in   error
		code int
		body string
	}{
		{"detected", malwarescan.ErrDetected, 400, "upload rejected by malware scanner"},
		{"wrapped-detected", fmt.Errorf("%s: %w", private, malwarescan.ErrDetected), 400, "upload rejected by malware scanner"},
		{"unavailable", malwarescan.ErrUnavailable, 503, "upload scanning unavailable"},
		{"wrapped-unavailable", fmt.Errorf("%s: %w", private, malwarescan.ErrUnavailable), 503, "upload scanning unavailable"},
		{"unknown", errors.New(private), 503, "Brand catalog unavailable. Inspect current state before repeating an uncertain save."},
		{"expired", fmt.Errorf("%s: %w", private, auth.ErrMutationCredentialExpired), 401, "Brand catalog authorization changed."},
		{"revoked", fmt.Errorf("%s: %w", private, auth.ErrMutationPermissionRevoked), 403, "Brand catalog authorization changed."},
		{"input", fmt.Errorf("%s: %w", private, catalog.ErrInputV1), 400, "Invalid brand profile, asset, selection, or contrast pair."},
		{"conflict", fmt.Errorf("%s: %w", private, catalog.ErrConflictV1), 409, "Brand catalog changed. Reload before saving or retrying this request."},
		{"not-found", fmt.Errorf("%s: %w", private, catalog.ErrNotFoundV1), 404, "Brand catalog item not found."},
	} {
		t.Run(row.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			(&Server{}).writeBrandCatalogErrorV1(w, row.in)
			var body map[string]string
			if w.Code != row.code || json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 1 || body["error"] != row.body || strings.Contains(w.Body.String(), private) {
				t.Fatal("catalog HTTP error changed classification or exposed private provider data")
			}
		})
	}
}
