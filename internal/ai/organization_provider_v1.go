// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"errors"

	"github.com/bright-interaction/hash/internal/db/generated"
)

// ResolveOrganizationProviderV1 selects a provider from settings already read
// by the caller's scoped store. It grants no database or document authority.
// Both server resolver callbacks use this same decryption/constructor path.
func ResolveOrganizationProviderV1(row *generated.OrgAiSetting, sealKey []byte, allowPrivate bool) (Provider, bool, error) {
	if row == nil {
		return nil, false, nil
	}
	if !row.Enabled {
		return nil, false, nil
	}
	plain, err := AESDecrypt(sealKey, row.ApiKeyCt)
	if err != nil {
		return nil, false, errors.New("AI organization provider credential unavailable")
	}
	switch row.Provider {
	case "anthropic":
		return NewAnthropicProvider(row.BaseUrl, string(plain), row.Model, allowPrivate), true, nil
	case "mistral":
		return NewMistralProvider(row.BaseUrl, string(plain), row.Model, allowPrivate), true, nil
	}
	return nil, false, errors.New("AI organization provider unsupported")
}
