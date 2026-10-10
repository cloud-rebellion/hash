// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import "testing"

func TestSignatureFontCommitmentsMatchBundledAssets(t *testing.T) {
	// Independently recorded SHA-256 values from the shipped font files.
	// Updating a font requires a deliberate new authority/rendering review.
	for font, expected := range map[string]string{
		"Caveat":         "d0b7b931b8980049327e8f8f9ac264617c8200b8422d62e886473d3d9527bad3",
		"Dancing Script": "570e4265bbcb453353ce2fdf63d179332d8daa92691d567547b8a383f3b46c3b",
		"Great Vibes":    "c59dc73d29daf142ef2431f455d21464172374aa750d793a79d608735db2d856",
		"Sacramento":     "2fcd867d2812578d001b0eca921848e24de91d01986f26e038be374ec7c5cfd2",
		"Homemade Apple": "bbaa96c741caa479d4647fc567f64e5ddc71eec58ee9849cb9e8a14bee65bc30",
	} {
		t.Run(font, func(t *testing.T) {
			got, err := SignatureFontSHA256(font)
			if err != nil || got != expected {
				t.Fatalf("bundled signature font commitment changed: %v", err)
			}
		})
	}
}

func TestSignatureFontCommitmentRefusesUnapprovedChoices(t *testing.T) {
	for _, font := range []string{"", "caveat", " Caveat", "Inter", "Custom Font", "Caveat\x00"} {
		if digest, err := SignatureFontSHA256(font); err == nil || digest != "" {
			t.Fatalf("unapproved choice %q received a commitment", font)
		}
	}
}
