// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/ai"
	"github.com/bright-interaction/hash/internal/config"
	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestAIRuntimeOrganizationCredentialsUseBootResolverV1(t *testing.T) {
	key := bytes.Repeat([]byte{0x63}, 32)
	cfg := &config.Config{PublicURL: "https://hash.example.test", AIShieldKey: hex.EncodeToString(key)}
	runtime, err := buildAIRuntime(cfg, nil)
	if err != nil || runtime.ResolveNativeOrgProvider == nil || runtime.ResolveOrgProvider == nil {
		t.Fatal("configured boot did not wire both organization resolvers", err)
	}
	ciphertext, err := ai.AESEncrypt(key, []byte("synthetic-boot-credential"))
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"mistral", "anthropic"} {
		t.Run(provider, func(t *testing.T) {
			row := &generated.OrgAiSetting{Provider: provider, BaseUrl: "https://provider.example.test/complete", Model: "synthetic-boot-model", Enabled: true, ApiKeyCt: bytes.Clone(ciphertext)}
			selected, enabled, err := runtime.ResolveNativeOrgProvider(context.Background(), row)
			if err != nil || !enabled || selected == nil || selected.Name() != provider || selected.Model() != row.Model || selected.Endpoint() != row.BaseUrl {
				t.Fatal("boot resolver lost the sealed organization provider", err)
			}
			row.ApiKeyCt[len(row.ApiKeyCt)-1] ^= 1
			selected, enabled, err = runtime.ResolveNativeOrgProvider(context.Background(), row)
			if err == nil || selected != nil || enabled || strings.Contains(err.Error(), "synthetic-boot-credential") {
				t.Fatal("boot resolver did not refuse authenticated-ciphertext corruption")
			}
			row.Enabled = false
			if selected, enabled, err = runtime.ResolveNativeOrgProvider(context.Background(), row); err != nil || selected != nil || enabled {
				t.Fatal("disabled organization setting did not permit the instance path", err)
			}
		})
	}
	withoutKey, err := buildAIRuntime(&config.Config{PublicURL: cfg.PublicURL}, nil)
	if err != nil || withoutKey.ResolveNativeOrgProvider != nil || withoutKey.ResolveOrgProvider != nil {
		t.Fatal("boot without a seal key exposed organization credential resolution", err)
	}
}
