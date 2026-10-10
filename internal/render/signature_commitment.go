// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// SignatureFontSHA256 identifies the exact bundled font for an explicit
// signature choice. Authority records must use this value rather than a
// client-supplied digest. Unsupported choices fail without selecting a fallback.
func SignatureFontSHA256(font string) (string, error) {
	var asset []byte
	switch font {
	case "Caveat":
		asset = fontCaveat
	case "Dancing Script":
		asset = fontDancingScript
	case "Great Vibes":
		asset = fontGreatVibes
	case "Sacramento":
		asset = fontSacramento
	case "Homemade Apple":
		asset = fontHomemadeApple
	default:
		return "", errors.New("unsupported signature font")
	}
	if len(asset) == 0 {
		return "", errors.New("signature font asset unavailable")
	}
	digest := sha256.Sum256(asset)
	return hex.EncodeToString(digest[:]), nil
}
