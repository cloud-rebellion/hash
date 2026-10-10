// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/bright-interaction/hash/internal/imageguard"
)

type resolvedAsset struct {
	dataURL string
	image   bool
}

func compileAssets(assets []Asset) (map[string]resolvedAsset, error) {
	if len(assets) > MaxAssets {
		return nil, limited("assets")
	}
	result := map[string]resolvedAsset{}
	total := 0
	for i := range assets {
		asset := &assets[i]
		if !namePattern.MatchString(asset.Name) {
			return nil, invalid("asset name")
		}
		if _, found := result[asset.Name]; found {
			return nil, invalid("duplicate asset name")
		}
		if len(asset.DataBase64) > base64.StdEncoding.EncodedLen(MaxAssetBytes) {
			return nil, limited("encoded asset bytes")
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(asset.DataBase64)
		if err != nil || len(raw) == 0 {
			return nil, invalid("asset base64")
		}
		if len(raw) > MaxAssetBytes || len(raw) > MaxTotalAssetBytes-total {
			return nil, limited("asset bytes")
		}
		total += len(raw)
		digest := sha256.Sum256(raw)
		if asset.SHA256 != hex.EncodeToString(digest[:]) {
			return nil, invalid("asset SHA-256")
		}
		image := false
		switch asset.MediaType {
		case "image/png", "image/jpeg":
			format := "png"
			if asset.MediaType == "image/jpeg" {
				format = "jpeg"
			}
			if _, err := imageguard.Decode(bytes.NewReader(raw), format); err != nil {
				return nil, invalid("asset image format or dimensions")
			}
			image = true
		case "font/woff", "font/woff2":
			if !validFontHeader(raw, asset.MediaType) {
				return nil, invalid("asset font header or expansion bounds")
			}
		default:
			return nil, invalid("unsupported asset media type")
		}
		asset.DataBase64 = base64.StdEncoding.EncodeToString(raw)
		result[asset.Name] = resolvedAsset{"data:" + asset.MediaType + ";base64," + asset.DataBase64, image}
	}
	return result, nil
}

// This validates bounded container structure without invoking a native font
// parser. Owners still review exact font assets, and the isolated renderer is
// responsible for safely decoding them. Fonts cannot reference other assets.
func validFontHeader(raw []byte, mediaType string) bool {
	if len(raw) < 48 || binary.BigEndian.Uint32(raw[8:12]) != uint32(len(raw)) || binary.BigEndian.Uint16(raw[14:16]) != 0 {
		return false
	}
	flavor := binary.BigEndian.Uint32(raw[4:8])
	if flavor != 0x00010000 && flavor != 0x4f54544f {
		return false
	}
	tables := int(binary.BigEndian.Uint16(raw[12:14]))
	if tables < 1 || tables > 128 {
		return false
	}
	sfnt := binary.BigEndian.Uint32(raw[16:20])
	if sfnt < 12 || sfnt > 16<<20 {
		return false
	}
	if mediaType == "font/woff2" {
		return string(raw[:4]) == "wOF2" && binary.BigEndian.Uint32(raw[20:24]) > 0 && binary.BigEndian.Uint32(raw[20:24]) <= uint32(len(raw)-48) && validFontRange(raw, 28, 32, 36) && validFontRange(raw, 40, 44, -1)
	}
	if string(raw[:4]) != "wOFF" || len(raw) < 44+20*tables || !validFontRange(raw, 24, 28, 32) || !validFontRange(raw, 36, 40, -1) {
		return false
	}
	seen := map[string]bool{}
	for i := 0; i < tables; i++ {
		offset := 44 + 20*i
		tag := string(raw[offset : offset+4])
		start := binary.BigEndian.Uint32(raw[offset+4 : offset+8])
		compressed := binary.BigEndian.Uint32(raw[offset+8 : offset+12])
		original := binary.BigEndian.Uint32(raw[offset+12 : offset+16])
		if seen[tag] || start < uint32(44+20*tables) || compressed == 0 || compressed > original || uint64(start)+uint64(compressed) > uint64(len(raw)) || original > 16<<20 {
			return false
		}
		seen[tag] = true
	}
	return true
}

func validFontRange(raw []byte, offsetIndex, lengthIndex, originalIndex int) bool {
	offset := binary.BigEndian.Uint32(raw[offsetIndex : offsetIndex+4])
	length := binary.BigEndian.Uint32(raw[lengthIndex : lengthIndex+4])
	if offset == 0 {
		return length == 0 && (originalIndex < 0 || binary.BigEndian.Uint32(raw[originalIndex:originalIndex+4]) == 0)
	}
	if length == 0 || uint64(offset)+uint64(length) > uint64(len(raw)) {
		return false
	}
	return originalIndex < 0 || binary.BigEndian.Uint32(raw[originalIndex:originalIndex+4]) <= 16<<20
}

func assetURL(raw string, assets map[string]resolvedAsset, imageOnly bool) (string, error) {
	name := strings.TrimPrefix(raw, "hash-asset:")
	if name == raw || !namePattern.MatchString(name) {
		return "", invalid("CSS resource reference")
	}
	asset, found := assets[name]
	if !found || (imageOnly && !asset.image) || (!imageOnly && asset.image) {
		return "", invalid("CSS asset type or name")
	}
	return asset.dataURL, nil
}
