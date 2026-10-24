// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"strings"
	"testing"
)

func TestLoadNativePasswordDoesNotRequireOIDC(t *testing.T) {
	setAllRequired(t)
	for _, key := range []string{"HASH_OIDC_ISSUER", "HASH_OIDC_CLIENT_ID", "HASH_OIDC_CLIENT_SECRET", "HASH_OIDC_REDIRECT_URL"} {
		t.Setenv(key, "")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal("native-password configuration still requires an identity provider", err)
	}
	if cfg.OIDCIssuer != "" || cfg.OIDCClientID != "" || cfg.OIDCRedirectURL != "" {
		t.Fatal("OIDC was implicitly enabled")
	}
	t.Setenv("HASH_PUBLIC_URL", "http://hash.example.test")
	if _, err := Load(); err == nil {
		t.Fatal("disabling OIDC bypassed public HTTPS enforcement")
	}
}

func TestLoadPartialOptionalOIDCFailsClosed(t *testing.T) {
	for _, present := range []string{"HASH_OIDC_ISSUER", "HASH_OIDC_CLIENT_ID", "HASH_OIDC_CLIENT_SECRET", "HASH_OIDC_REDIRECT_URL"} {
		t.Run(present, func(t *testing.T) {
			setAllRequired(t)
			for _, key := range []string{"HASH_OIDC_ISSUER", "HASH_OIDC_CLIENT_ID", "HASH_OIDC_CLIENT_SECRET", "HASH_OIDC_REDIRECT_URL"} {
				t.Setenv(key, "")
			}
			t.Setenv(present, "configured-test-value")
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), "OIDC") {
				t.Fatal("partially configured optional provider accepted", err)
			}
		})
	}
}
