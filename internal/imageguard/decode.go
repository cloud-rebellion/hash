// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package imageguard

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
)

const (
	MaxBytes     = 4 << 20
	MaxDimension = 4096
	MaxPixels    = 4 << 20
)

var ErrLimit = errors.New("image exceeds upload or decoded dimension limits")

// Decode checks compressed bytes and raster dimensions before allocating pixels.
// Only JPEG and PNG are accepted. expected may be empty for format discovery.
func Decode(r io.Reader, expected string) (image.Image, error) {
	raw, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxBytes {
		return nil, ErrLimit
	}
	cfg, format, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("image header: %w", err)
	}
	if (format != "png" && format != "jpeg") || (expected != "" && format != expected) {
		return nil, errors.New("image format does not match supported upload type")
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > MaxDimension || cfg.Height > MaxDimension || cfg.Width > MaxPixels/cfg.Height {
		return nil, ErrLimit
	}
	img, _, err := image.Decode(bytes.NewReader(raw))
	return img, err
}
