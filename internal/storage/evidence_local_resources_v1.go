// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"math"
	"net/http"
	"unsafe"
)

func evidenceLocalAddV1(total *int64, count, each int64) bool {
	if total == nil || *total < 0 || count < 0 || each < 0 || each != 0 && count > (math.MaxInt64-*total)/each {
		return false
	}
	*total += count * each
	return true
}
func evidenceLocalScaledV1(count, each int64) (int64, error) {
	n := int64(0)
	if !evidenceLocalAddV1(&n, count, each) {
		return 0, ErrEvidenceLocalIOV1
	}
	return n, nil
}
func evidenceLocalInitialResourcesV1(data []byte, key, contentType string, profile *evidenceLocalClientProfileV1) (frameLimit, parent int64, err error) {
	if profile == nil || profile.creds == nil || len(data) > maxStoredObjectBytes {
		return 0, 0, ErrEvidenceLocalIOV1
	}
	value, err := profile.creds.Get()
	if err != nil {
		return 0, 0, err
	}
	n := int64(len(data))
	frameLimit = n
	// MinIO77's fixed64KiB v4 streaming chunks add hexadecimal lengths and
	// signatures. Retention/location bodies and the one terminal checksum fit
	// the separately priced64KiB control. The actual declared request length is
	// admitted again before the concrete freeze/copy; this is not caller cost.
	if !evidenceLocalAddV1(&frameLimit, (n+(64<<10)-1)/(64<<10)+2, 256) || !evidenceLocalAddV1(&frameLimit, 1, 64<<10) {
		return 0, 0, ErrEvidenceLocalIOV1
	}
	parent = 8*int64(unsafe.Sizeof(evidenceLocalPutStateV1{})) + 4*int64(unsafe.Sizeof(http.Transport{})) + 4*int64(unsafe.Sizeof(evidenceLocalClientProfileV1{})) + (256 << 10)
	// Independent original payload clone plus the pinned SDK's fixed request,
	// signing, URL escaping and header controls before that producer starts.
	if !evidenceLocalAddV1(&parent, n, 2) {
		return 0, 0, ErrEvidenceLocalIOV1
	}
	for _, text := range []string{key, contentType, profile.endpoint, profile.region, value.AccessKeyID, value.SecretAccessKey, value.SessionToken} {
		if !evidenceLocalAddV1(&parent, int64(len(text)), 32) {
			return 0, 0, ErrEvidenceLocalIOV1
		}
	}
	return frameLimit, parent, nil
}

func evidenceLocalConnectionControlsV1(base *http.Transport, secure bool) (int64, error) {
	// The actual standard Transport sizes; zero and negative configuration use
	// its original4KiB default. This funds each real dial, not a redirect tree.
	read, write := base.ReadBufferSize, base.WriteBufferSize
	if read <= 0 {
		read = 4096
	}
	if write <= 0 {
		write = 4096
	}
	cost := (2 * int64(64<<10)) + 4*int64(unsafe.Sizeof(evidenceLocalConnV1{})) + 4*int64(unsafe.Sizeof(storageAdmittedConnV1{})) + 4*int64(unsafe.Sizeof(storageConnectionHostV1{})) + 4*int64(unsafe.Sizeof(storageConnectionCountV1{})) + (64 << 10)
	if !evidenceLocalAddV1(&cost, int64(read), 4) || !evidenceLocalAddV1(&cost, int64(write), 4) {
		return 0, ErrEvidenceLocalIOV1
	}
	if secure && !evidenceLocalAddV1(&cost, 1, evidenceLocalTLSControlsV1()) {
		return 0, ErrEvidenceLocalIOV1
	}
	return cost, nil
}

func evidenceLocalTLSControlsV1() int64 {
	// Go1.26.9 crypto/tls common.go: certificate message<=256KiB, other
	// handshake message<=64KiB. Fixed current transcript/certificate/vector/
	// record and verification classes are logical active controls, not a
	// measurement of x509 internals, cached roots/session caches or process RSS.
	return 16*((256<<10)+(64<<10)) + (128 << 10)
}

func evidenceLocalHeaderResourcesV1(wire, lines int64) (int64, error) {
	cost := int64(0)
	// Actual header wire/continued-line/string copies and MIME map/key/value/
	// slice slots precede the original net/http textproto parser. A real line
	// can add at most one key/value item; this is size inventory, not grammar.
	if !evidenceLocalAddV1(&cost, wire, 8) || !evidenceLocalAddV1(&cost, lines, 256) {
		return 0, ErrEvidenceLocalIOV1
	}
	return cost, nil
}
