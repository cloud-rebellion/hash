// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package config

import (
	"strings"
	"testing"
)

const crmConfigTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const crmConfigPreviousTestKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

func TestCRMConfigurationRequiresDedicatedCredentialAuthority(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{"global bearer", func(c *Config) { c.BrightCRMToken = "fixture-retired-bearer" }},
		{"global callback secret", func(c *Config) { c.BrightCRMWebhookSecret = "fixture-retired-callback" }},
		{"origin without key", func(c *Config) { c.CRMEncryptionKey = "" }},
		{"key without origin", func(c *Config) { c.BrightCRMURL = "" }},
		{"previous without current", func(c *Config) { c.BrightCRMURL, c.CRMEncryptionKey = "", "" }},
		{"malformed current", func(c *Config) { c.CRMEncryptionKey = strings.Repeat("g", 64) }},
		{"short current", func(c *Config) { c.CRMEncryptionKey = crmConfigTestKey[:62] }},
		{"uniform decoded current", func(c *Config) { c.CRMEncryptionKey = strings.Repeat("ab", 32) }},
		{"malformed previous", func(c *Config) { c.CRMEncryptionKeyPrevious = strings.Repeat("z", 64) }},
		{"same decoded rotation key", func(c *Config) { c.CRMEncryptionKeyPrevious = strings.ToUpper(crmConfigTestKey) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := Config{Environment: "production", BrightCRMURL: "https://crm.example.test", CRMEncryptionKey: crmConfigTestKey, CRMEncryptionKeyPrevious: crmConfigPreviousTestKey}
			test.edit(&c)
			if err := validateCRMConfiguration(&c); err == nil {
				t.Fatal("unsafe CRM credential configuration accepted")
			} else if strings.Contains(err.Error(), "fixture-retired-") || strings.Contains(err.Error(), crmConfigTestKey) {
				t.Fatal("configuration diagnostic disclosed credential material")
			}
		})
	}
	if err := validateCRMConfiguration(&Config{}); err != nil {
		t.Fatalf("disabled optional connector should not require credentials: %v", err)
	}
}

func TestCRMConfigurationSeparatesEveryEncryptionTrustDomain(t *testing.T) {
	for _, slot := range []string{"webhook current", "webhook previous", "signer", "session", "proxy", "AI shield"} {
		for _, usePrevious := range []bool{false, true} {
			name := slot + "/current"
			if usePrevious {
				name = slot + "/previous"
			}
			t.Run(name, func(t *testing.T) {
				c := Config{Environment: "production", BrightCRMURL: "https://crm.example.test", CRMEncryptionKey: crmConfigTestKey, CRMEncryptionKeyPrevious: crmConfigPreviousTestKey}
				key := strings.ToUpper(crmConfigTestKey)
				if usePrevious {
					key = strings.ToUpper(crmConfigPreviousTestKey)
				}
				switch slot {
				case "webhook current":
					c.WebhookEncryptionKey = key
				case "webhook previous":
					c.WebhookEncryptionKeyPrevious = key
				case "signer":
					c.SignerTokenKey = key
				case "session":
					c.SessionKey = key
				case "proxy":
					c.ProxyAuth = key
				case "AI shield":
					c.AIShieldKey = key
				}
				if err := validateCRMConfiguration(&c); err == nil {
					t.Fatal("CRM key reuse across application trust domains accepted")
				}
			})
		}
	}
}

func TestCRMConfigurationPinsCanonicalServerOrigin(t *testing.T) {
	for _, endpoint := range []string{
		"http://crm.example.test", "https://user:private@crm.example.test", "https://crm.example.test/api", "https://crm.example.test?team=x", "https://crm.example.test#private", "https://crm.example.test:0", " https://crm.example.test",
	} {
		t.Run(endpoint, func(t *testing.T) {
			c := Config{Environment: "production", BrightCRMURL: endpoint, CRMEncryptionKey: crmConfigTestKey}
			if err := validateCRMConfiguration(&c); err == nil {
				t.Fatal("untrusted or non-origin CRM address accepted")
			} else if strings.Contains(err.Error(), "private") {
				t.Fatal("CRM origin diagnostic disclosed input userinfo or fragment")
			}
		})
	}
	for _, test := range []struct{ environment, raw, want string }{
		{"production", "https://CRM.EXAMPLE.TEST:443/", "https://crm.example.test"},
		{"development", "http://127.0.0.1:39488", "http://127.0.0.1:39488"},
	} {
		c := Config{Environment: test.environment, BrightCRMURL: test.raw, CRMEncryptionKey: crmConfigTestKey, CRMEncryptionKeyPrevious: crmConfigPreviousTestKey}
		if err := validateCRMConfiguration(&c); err != nil || c.BrightCRMURL != test.want {
			t.Fatalf("canonical configured CRM origin=%q err=%v", c.BrightCRMURL, err)
		}
	}
}

func TestLoadCRMUsesDedicatedOptionalKeyringWithoutGlobalBearer(t *testing.T) {
	setAllRequired(t)
	t.Setenv("HASH_BRIGHTCRM_URL", "https://CRM.EXAMPLE.TEST:443/")
	t.Setenv("HASH_CRM_ENCRYPTION_KEY", crmConfigTestKey)
	t.Setenv("HASH_CRM_ENCRYPTION_KEY_PREVIOUS", crmConfigPreviousTestKey)
	t.Setenv("HASH_BRIGHTCRM_TOKEN", "")
	t.Setenv("HASH_BRIGHTCRM_WEBHOOK_SECRET", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("dedicated optional CRM configuration did not load: %v", err)
	}
	if c.BrightCRMURL != "https://crm.example.test" || c.CRMEncryptionKey != crmConfigTestKey || c.CRMEncryptionKeyPrevious != crmConfigPreviousTestKey {
		t.Fatal("Load did not retain the canonical origin and dedicated rotation keyring")
	}
}
