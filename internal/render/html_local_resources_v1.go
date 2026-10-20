// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"errors"
	"math"
	"net/http"
	"unsafe"
)

func htmlLocalAddV1(total *int64, count, each int64) bool {
	if total == nil || *total < 0 || count < 0 || each < 0 || each != 0 && count > (math.MaxInt64-*total)/each {
		return false
	}
	*total += count * each
	return true
}

// HTMLToPDFLocalResourcesV1 derives only the actual original multipart recipe
// and original response ceiling. Native Source/REST must keep the actual input
// models owned before this routine. These logical producer bounds make no
// physical Go allocator/transport pool/TLS/remote Chromium capacity claim.
func HTMLToPDFLocalResourcesV1(source string, options PDFOptions) (frameLimit, parent int64, err error) {
	if options.MaxResponseBytes < 0 || options.MaxResponseBytes > maxRenderedPDF {
		return 0, 0, errors.New("invalid PDF response byte limit")
	}
	if options.ExactPaperPoints != [2]float64{} {
		for _, n := range options.ExactPaperPoints {
			if n <= 0 || n > 14400 || math.IsNaN(n) || math.IsInf(n, 0) {
				return 0, 0, errors.New("invalid exact PDF page size")
			}
		}
	}
	response := int64(maxRenderedPDF)
	if options.MaxResponseBytes > 0 {
		response = int64(options.MaxResponseBytes)
	}
	// One index.html and original asset attachments. Actual string quoting,
	// 60byte random multipart boundary and fixed header/form-field spellings
	// are charged per real part; no caller-reported byte/asset count is accepted.
	frameLimit = 0
	if !htmlLocalAddV1(&frameLimit, int64(len(source)), 1) || !htmlLocalAddV1(&frameLimit, 1, 2048) {
		return 0, 0, ErrHTMLLocalIOV1
	}
	assets := options.Assets
	if assets == nil {
		assets = FontAssets()
	}
	for _, asset := range assets {
		mime := asset.Mime
		if mime == "" {
			mime = "font/woff2"
		}
		if !htmlLocalAddV1(&frameLimit, int64(len(asset.Bytes)), 1) || !htmlLocalAddV1(&frameLimit, int64(len(asset.Filename)), 2) || !htmlLocalAddV1(&frameLimit, int64(len(mime)), 1) || !htmlLocalAddV1(&frameLimit, 1, 2048) {
			return 0, 0, ErrHTMLLocalIOV1
		}
	}
	// Thirteen original fixed geometry/background/CSS/delay/expression fields;
	// float32 geometry spelling and exact-point formatting fit128bytes each.
	if !htmlLocalAddV1(&frameLimit, 13, 2048+128) || !htmlLocalAddV1(&frameLimit, int64(len(options.WaitForExpression)), 1) || !htmlLocalAddV1(&frameLimit, int64(len(options.WaitDelay)), 1) {
		return 0, 0, ErrHTMLLocalIOV1
	}
	parent = 4*int64(unsafe.Sizeof(htmlLocalPDFStateV1{})) + 4*int64(unsafe.Sizeof(ownedRequestBodyV1{})) + 4*int64(unsafe.Sizeof(http.Transport{})) + 4*int64(unsafe.Sizeof(htmlLocalReplayFrameV1{})) + 4*int64(unsafe.Sizeof(htmlLocalReplayBodyV1{})) + (128 << 10)
	// Original bytes.Buffer growing frame/HTML byte conversion + private retry
	// io.ReadAll/owned body frame + original response io.ReadAll growth. Actual
	// headers/connections grow this SAME grant before their own producers.
	if !htmlLocalAddV1(&parent, frameLimit, 12) || !htmlLocalAddV1(&parent, response+1, 4) {
		return 0, 0, ErrHTMLLocalIOV1
	}
	return frameLimit, parent, nil
}

func htmlLocalConnectionControlsV1(base *http.Transport, secure bool) (int64, error) {
	// The actual standard Transport sizes; zero and negative configuration use
	// its original4KiB default. This funds each real dial, not a redirect tree.
	read, write := base.ReadBufferSize, base.WriteBufferSize
	if read <= 0 {
		read = 4096
	}
	if write <= 0 {
		write = 4096
	}
	cost := (2 * int64(64<<10)) + 4*int64(unsafe.Sizeof(htmlLocalConnV1{})) + (64 << 10)
	if !htmlLocalAddV1(&cost, int64(read), 4) || !htmlLocalAddV1(&cost, int64(write), 4) {
		return 0, ErrHTMLLocalIOV1
	}
	if secure && !htmlLocalAddV1(&cost, 1, htmlLocalTLSControlsV1()) {
		return 0, ErrHTMLLocalIOV1
	}
	return cost, nil
}

func htmlLocalTLSControlsV1() int64 {
	// Go1.26.9 crypto/tls common.go: certificate message<=256KiB, other
	// handshake message<=64KiB. Fixed current transcript/certificate/vector/
	// record and verification classes are logical active controls, not a
	// measurement of x509 internals, cached roots/session caches or process RSS.
	return 16*((256<<10)+(64<<10)) + (128 << 10)
}

func htmlLocalHeaderResourcesV1(wire, lines int64) (int64, error) {
	cost := int64(0)
	// Actual header wire/continued-line/string copies and MIME map/key/value/
	// slice slots precede the original net/http textproto parser. A real line
	// can add at most one key/value item; this is size inventory, not grammar.
	if !htmlLocalAddV1(&cost, wire, 8) || !htmlLocalAddV1(&cost, lines, 256) {
		return 0, ErrHTMLLocalIOV1
	}
	return cost, nil
}
