// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package manualfit

// ValidateArchivedSpanV1 validates the original inert span against the frozen
// archive grammar and original name/font before transient staging. It does not
// serialize, normalize, refit, authorize or consult current font assets.
func ValidateArchivedSpanV1(raw []byte, name, font string) error {
	if !validArchivedSpanV1(raw, name, font) {
		return ErrRetainedV1
	}
	return nil
}
