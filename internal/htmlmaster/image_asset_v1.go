// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package htmlmaster

import (
	"bytes"
	"encoding/base64"
	"image"
)

// CanonicalImageAssetV1 reuses the original embedded-asset commitment and raster
// validation. A consumer may narrow existing limits; it cannot expand them.
// Its actual source owner must fund compressed, decoded and canonical copies
// before calling. This helper creates no provider URL or retention authority.
func CanonicalImageAssetV1(asset Asset, maxBytes, maxDimension int) (Asset, error) {
	if maxBytes < 1 || maxBytes > MaxAssetBytes || maxDimension < 1 || maxDimension > 4096 || (asset.MediaType != "image/png" && asset.MediaType != "image/jpeg") || len(asset.DataBase64) > base64.StdEncoding.EncodedLen(maxBytes) {
		return Asset{}, invalid("image asset limits")
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(asset.DataBase64)
	if err != nil || len(raw) == 0 || len(raw) > maxBytes {
		return Asset{}, invalid("image asset bytes")
	}
	config, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil || config.Width < 1 || config.Height < 1 || config.Width > maxDimension || config.Height > maxDimension {
		return Asset{}, invalid("image asset dimensions")
	}
	assets := []Asset{asset}
	if _, err := compileAssets(assets); err != nil {
		return Asset{}, err
	}
	return assets[0], nil
}
