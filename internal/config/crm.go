// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package config

import (
	"errors"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"strings"
)

func validateCRMConfiguration(c *Config) error {
	if c.BrightCRMToken != "" {
		return errors.New("HASH_BRIGHTCRM_TOKEN is retired: enroll a separately authorized credential for each organization through CRM settings")
	}
	if c.BrightCRMWebhookSecret != "" {
		return errors.New("HASH_BRIGHTCRM_WEBHOOK_SECRET is retired: tenant-bound CRM callbacks require the reviewed producer contract")
	}
	if (c.BrightCRMURL == "") != (c.CRMEncryptionKey == "") {
		return errors.New("HASH_BRIGHTCRM_URL and HASH_CRM_ENCRYPTION_KEY must both be configured or both be empty")
	}
	if c.CRMEncryptionKeyPrevious != "" && c.CRMEncryptionKey == "" {
		return errors.New("HASH_CRM_ENCRYPTION_KEY_PREVIOUS requires HASH_CRM_ENCRYPTION_KEY")
	}
	if c.CRMEncryptionKey == "" {
		return nil
	}
	origin, err := crmconnection.CanonicalOrigin(c.BrightCRMURL, c.Environment == "development")
	if err != nil {
		return errors.New("HASH_BRIGHTCRM_URL must be an HTTPS origin only (HTTP is reserved for development)")
	}
	c.BrightCRMURL = origin
	for _, key := range []string{c.CRMEncryptionKey, c.CRMEncryptionKeyPrevious} {
		if key == "" {
			continue
		}
		if !isStrongEncryptionHexKey(key) {
			return errors.New("CRM encryption keys must be independently generated 32-byte hexadecimal keys")
		}
		for _, other := range []string{c.WebhookEncryptionKey, c.WebhookEncryptionKeyPrevious, c.SignerTokenKey, c.SessionKey, c.ProxyAuth, c.AIShieldKey} {
			if other != "" && strings.EqualFold(key, other) {
				return errors.New("CRM encryption keys must not reuse another Hash application key")
			}
		}
	}
	if _, err := crmconnection.NewKeyring(c.CRMEncryptionKey, c.CRMEncryptionKeyPrevious); err != nil {
		return errors.New("CRM encryption key rotation configuration invalid")
	}
	return nil
}
