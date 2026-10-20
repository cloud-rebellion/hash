// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"math"
	"net/http"
	"unsafe"
)

func aiNativeAddV1(total *int64, count, each int64) bool {
	if total == nil || *total < 0 || count < 0 || each < 0 || each != 0 && count > (math.MaxInt64-*total)/each {
		return false
	}
	*total += count * each
	return true
}
func nativeRequestResourcesV1(req Request, fields ...string) (frame, parent int64, err error) {
	frame = 2048
	for _, v := range []string{req.System, req.User, req.PromptName} {
		if !aiNativeAddV1(&frame, int64(len(v)), 6) {
			return 0, 0, ErrNativeIOV1
		}
	}
	parent = 4*int64(unsafe.Sizeof(aiNativeHTTPStateV1{})) + 4*int64(unsafe.Sizeof(aiNativeReplayFrameV1{})) + 4*int64(unsafe.Sizeof(http.Transport{})) + (256 << 10)
	for _, v := range fields {
		if !aiNativeAddV1(&frame, int64(len(v)), 6) || !aiNativeAddV1(&parent, int64(len(v)), 16) {
			return 0, 0, ErrNativeIOV1
		}
	}
	if !aiNativeAddV1(&parent, frame, 16) {
		return 0, 0, ErrNativeIOV1
	}
	return frame, parent, nil
}
func aiNativeConnectionControlsV1(base *http.Transport, secure bool) (int64, error) {
	// The actual standard Transport sizes; zero and negative configuration use
	// its original4KiB default. This funds each real dial, not a redirect tree.
	read, write := base.ReadBufferSize, base.WriteBufferSize
	if read <= 0 {
		read = 4096
	}
	if write <= 0 {
		write = 4096
	}
	cost := (2 * int64(64<<10)) + 4*int64(unsafe.Sizeof(aiNativeConnV1{})) + (64 << 10)
	if !aiNativeAddV1(&cost, int64(read), 4) || !aiNativeAddV1(&cost, int64(write), 4) {
		return 0, ErrNativeIOV1
	}
	if secure && !aiNativeAddV1(&cost, 1, aiNativeTLSControlsV1()) {
		return 0, ErrNativeIOV1
	}
	return cost, nil
}

func aiNativeTLSControlsV1() int64 {
	// Go1.26.9 crypto/tls common.go: certificate message<=256KiB, other
	// handshake message<=64KiB. Fixed current transcript/certificate/vector/
	// record and verification classes are logical active controls, not a
	// measurement of x509 internals, cached roots/session caches or process RSS.
	return 16*((256<<10)+(64<<10)) + (128 << 10)
}

func aiNativeHeaderResourcesV1(wire, lines int64) (int64, error) {
	cost := int64(0)
	// Actual header wire/continued-line/string copies and MIME map/key/value/
	// slice slots precede the original net/http textproto parser. A real line
	// can add at most one key/value item; this is size inventory, not grammar.
	if !aiNativeAddV1(&cost, wire, 8) || !aiNativeAddV1(&cost, lines, 256) {
		return 0, ErrNativeIOV1
	}
	return cost, nil
}
