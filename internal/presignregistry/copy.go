// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package presignregistry

import (
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/render"
)

const disclosureText = "The provider signature was applied under a named, revocable Hash pre-signing grant for this exact approved document and workflow. This delegated execution is separate from the customer's manual signature."

type DisclosureCopy struct {
	Version int64  `json:"version"`
	SHA256  string `json:"sha256"`
	Text    string `json:"text"`
}

// Disclosure returns app-owned consent/disclosure content, not caller hashes.
func Disclosure() DisclosureCopy {
	return DisclosureCopy{Version: 1, SHA256: domainSHA("hash:presign-disclosure:v1", []byte(disclosureText)), Text: disclosureText}
}

// SignatureStyles returns fresh values bound to actual embedded font bytes.
// Unsupported/missing assets fail; there is no automatic font fallback.
func SignatureStyles() ([]presign.SignatureStyle, error) {
	var styles []presign.SignatureStyle
	for _, font := range []string{"Caveat", "Dancing Script", "Great Vibes", "Sacramento", "Homemade Apple"} {
		h, err := render.SignatureFontSHA256(font)
		if err != nil {
			return nil, err
		}
		styles = append(styles, presign.SignatureStyle{Font: font, FontSHA256: h})
	}
	return styles, nil
}
