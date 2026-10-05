// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package imageguard

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"image"
	"image/png"
	"testing"
)

func pngWithDimensions(t *testing.T, width, height uint32) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := png.Encode(&out, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	raw := out.Bytes()
	binary.BigEndian.PutUint32(raw[16:20], width)
	binary.BigEndian.PutUint32(raw[20:24], height)
	binary.BigEndian.PutUint32(raw[29:33], crc32.ChecksumIEEE(raw[12:29]))
	return raw
}

func TestRejectsExpansionBeforePixelDecode(t *testing.T) {
	for _, dims := range [][2]uint32{{1 << 20, 1 << 20}, {4096, 4096}, {4097, 1}, {1, 4097}} {
		_, err := Decode(bytes.NewReader(pngWithDimensions(t, dims[0], dims[1])), "png")
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("dimensions %v: expected limit rejection before invalid pixel data, got %v", dims, err)
		}
	}
}

func TestValidImageAndFormatMismatch(t *testing.T) {
	raw := pngWithDimensions(t, 1, 1)
	if _, err := Decode(bytes.NewReader(raw), "png"); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bytes.NewReader(raw), "jpeg"); err == nil {
		t.Fatal("PNG accepted as JPEG")
	}
	if _, err := Decode(bytes.NewReader(make([]byte, MaxBytes+1)), ""); !errors.Is(err, ErrLimit) {
		t.Fatalf("oversized compressed input: %v", err)
	}
}
