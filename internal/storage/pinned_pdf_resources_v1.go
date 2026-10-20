// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"github.com/minio/minio-go/v7"
	"net/http"
	"sync"
	"unsafe"
)

// PinnedPDFObservationParentWorkV1 derives numeric active controls from this
// actual constructor-owned client/profile, not caller sizes. It covers bounded
// header/XML/error parsing and independently retained opaque observation fields
// before HEAD. No credential value, stream, TLS/RSS or authority is returned.
func (c *Client) PinnedPDFObservationParentWorkV1() (int64, error) {
	profile, err := c.evidenceLocalProfileV1()
	if err != nil {
		return 0, ErrPinnedPDFReadV1
	}
	_, parent, err := evidenceLocalInitialResourcesV1(nil, "", "", profile)
	if err != nil {
		return 0, ErrPinnedPDFReadV1
	}
	headers, err := evidenceLocalHeaderResourcesV1(boundedStorageHeaderBytesV1, boundedStorageHeaderBytesV1)
	if err != nil {
		return 0, ErrPinnedPDFReadV1
	}
	connections, err := evidenceLocalConnectionControlsV1(profile.base, profile.secure)
	if err != nil {
		return 0, ErrPinnedPDFReadV1
	}
	fixed := 8*int64(unsafe.Sizeof(PinnedPDFReadV1{})) + 8*int64(unsafe.Sizeof(pinnedPDFReadStateV1{})) + 4*int64(unsafe.Sizeof(minio.ObjectInfo{})) + 4*int64(unsafe.Sizeof(minio.GetObjectOptions{})) + 4*int64(unsafe.Sizeof(minio.ErrorResponse{})) + 4*int64(unsafe.Sizeof(http.Request{})) + 4*int64(unsafe.Sizeof(http.Response{})) + 4*int64(unsafe.Sizeof(boundedStorageBodyV1{})) + 4*int64(unsafe.Sizeof(boundedStorageBodyStateV1{})) + 4*int64(unsafe.Sizeof(sync.Cond{}))
	for _, part := range [][2]int64{{1, fixed}, {4, boundedStorageMetadataBytesV1}, {8, boundedStorageErrorBytesV1}, {2, headers}, {64, maxPersistedVersionIDBytes}, {32, int64(len(c.bucket))}, {2, connections}} {
		if !evidenceLocalAddV1(&parent, part[0], part[1]) {
			return 0, ErrPinnedPDFReadV1
		}
	}
	return parent, nil
}

// ParentReadWorkV1 adds actual observed-body storage to the same constructor
// controls. The Core reader owns one exact allocation; the conservative factor
// includes active SDK/framing overlap. Caller reserves before that producer.
func (r *PinnedPDFReadV1) ParentReadWorkV1() (int64, error) {
	if r == nil || r.state == nil || r.state.size < 1 || r.state.size > maxPinnedPDFReadBytesV1 {
		return 0, ErrPinnedPDFReadV1
	}
	metadata, err := r.state.client.PinnedPDFObservationParentWorkV1()
	if err != nil {
		return 0, err
	}
	if !evidenceLocalAddV1(&metadata, r.state.size, 4) {
		return 0, ErrPinnedPDFReadV1
	}
	return metadata, nil
}
