// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"strings"
	"testing"
)

func TestCRMTrustedPrivateConfigurationV1IsOptionalButNeverSilentlyIgnored(t *testing.T) {
	if err := validateCRMConfiguration(&Config{}); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, origin, pins, key, environment string }{
		{"pins without connector", "", "10.42.0.1/32", "", "production"},
		{"pins without key", "https://crm.example.test", "10.42.0.1/32", "", "production"},
		{"empty token", "https://crm.example.test", "10.42.0.1/32,", crmConfigTestKey, "production"},
		{"public pin", "https://crm.example.test", "1.1.1.1/32", crmConfigTestKey, "production"},
		{"loopback pin", "https://crm.example.test", "127.0.0.1/32", crmConfigTestKey, "development"},
		{"known metadata pin", "https://crm.example.test", "100.100.100.200/32", crmConfigTestKey, "development"},
		{"HTTP production", "http://crm.example.test", "10.42.0.1/32", crmConfigTestKey, "production"},
		{"HTTP development", "http://127.0.0.1:8080", "10.42.0.1/32", crmConfigTestKey, "development"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := Config{Environment: test.environment, BrightCRMURL: test.origin, BrightCRMTrustedPrivateCIDRs: test.pins, CRMEncryptionKey: test.key}
			if err := validateCRMConfiguration(&c); err == nil {
				t.Fatal("unsafe/ignored strict private CRM policy accepted")
			} else if strings.Contains(err.Error(), "10.42.0.1") || strings.Contains(err.Error(), crmConfigTestKey) {
				t.Fatal("configuration diagnostic leaked setting/key")
			}
		})
	}
	for _, environment := range []string{"production", "development"} {
		c := Config{Environment: environment, BrightCRMURL: "https://CRM.EXAMPLE.TEST:443/", BrightCRMTrustedPrivateCIDRs: "10.42.0.1/32,fd01::1/128", CRMEncryptionKey: crmConfigTestKey}
		if err := validateCRMConfiguration(&c); err != nil || c.BrightCRMURL != "https://crm.example.test" {
			t.Fatalf("strict operator setting with normal canonical origin: %v", err)
		}
	}
	// Empty pins retain the preexisting explicit local-development constructor.
	c := Config{Environment: "development", BrightCRMURL: "http://127.0.0.1:8080", CRMEncryptionKey: crmConfigTestKey}
	if err := validateCRMConfiguration(&c); err != nil {
		t.Fatalf("empty strict setting changed old development grammar: %v", err)
	}
}

func TestLoadCRMTrustedPrivateConfigurationV1RetainsOnlyExplicitOperatorPins(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_BRIGHTCRM_URL", "https://CRM.EXAMPLE.TEST:443/")
	t.Setenv("HASH_CRM_ENCRYPTION_KEY", crmConfigTestKey)
	t.Setenv("HASH_BRIGHTCRM_TRUSTED_PRIVATE_CIDRS", "10.42.0.1/32,fd01::1/128")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.BrightCRMTrustedPrivateCIDRs != "10.42.0.1/32,fd01::1/128" || c.BrightCRMURL != "https://crm.example.test" {
		t.Fatal("Load dropped or reinterpreted explicit strict setting")
	}
	t.Setenv("HASH_CRM_ENCRYPTION_KEY", "")
	t.Setenv("HASH_BRIGHTCRM_URL", "")
	if _, err := Load(); err == nil {
		t.Fatal("explicit pins ignored with disabled connector")
	}
}
