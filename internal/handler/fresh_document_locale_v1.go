// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package handler

import (
	"errors"
	"github.com/bright-interaction/hash/internal/recipients"
	"strings"
)

func normalizeNewDocumentLocaleV1(locale string) (string, error) {
	if locale == "" {
		return "", nil
	}
	if len(locale) > 64 {
		return "", errors.New("default_locale is not supported")
	}
	normal, err := recipients.NormalizeLocale(locale)
	return strings.Clone(normal), err
}
