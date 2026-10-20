// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"github.com/minio/minio-go/v7"
	"io"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

var ErrPinnedPDFReadV1 = errors.New("storage: exact PDF version could not be verified")

const maxPinnedPDFReadBytesV1 int64 = 50 << 20

// PinnedPDFReadV1 is an opaque immutable provider observation, not document
// authorization or a resource permit. The native caller must reserve its actual
// SizeV1 before ReadV1. Copies share one attempt. No caller-reported size/cost or
// replacement key, version, digest or client can be installed on this handle.
type PinnedPDFReadV1 struct{ state *pinnedPDFReadStateV1 }
type pinnedPDFReadStateV1 struct {
	mu           sync.Mutex
	client       *Client
	key, version string
	digest       [sha256.Size]byte
	size         int64
	attempted    bool
}

func pinnedPDFOpaqueV1(value string) bool {
	if len(value) < 1 || len(value) > 1024 || !utf8.ValidString(value) || strings.TrimSpace(value) == "" {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
func (c *Client) ObservePinnedPDFV1(ctx context.Context, key, version string, expected []byte) (*PinnedPDFReadV1, error) {
	if c == nil || c.mc == nil || ctx == nil || ctx.Err() != nil || !pinnedPDFOpaqueV1(key) || !pinnedPDFOpaqueV1(version) || len(expected) != sha256.Size {
		return nil, ErrPinnedPDFReadV1
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrPinnedPDFReadV1
	}
	if strings.TrimSpace(version) == "null" || strings.TrimSpace(version) == DevelopmentVersionID || strings.TrimSpace(key) != key {
		return nil, ErrPinnedPDFReadV1
	}
	var digest [sha256.Size]byte
	copy(digest[:], expected)
	if digest == ([sha256.Size]byte{}) {
		return nil, ErrPinnedPDFReadV1
	}
	// HEAD carries no object body and retains the existing bounded metadata/header
	// transport. The exact VersionID is required even in development.
	info, err := c.mc.StatObject(ctx, c.bucket, key, minio.StatObjectOptions(c.getOpts(version)))
	if err != nil {
		return nil, errors.Join(ErrPinnedPDFReadV1, err)
	}
	if info.VersionID != version || info.Size < 1 || info.Size > maxPinnedPDFReadBytesV1 {
		return nil, ErrPinnedPDFReadV1
	}
	return &PinnedPDFReadV1{state: &pinnedPDFReadStateV1{client: c, key: strings.Clone(key), version: strings.Clone(version), digest: digest, size: info.Size}}, nil
}
func (r *PinnedPDFReadV1) SizeV1() int64 {
	if r == nil || r.state == nil {
		return 0
	}
	return r.state.size
}

// ReadV1 owns the synchronous Core HTTP response through its actual Close.
// The high-level SDK Object.Close only cancels a goroutine and is not a join.
func (r *PinnedPDFReadV1) ReadV1(ctx context.Context) (body []byte, failure error) {
	if r == nil || r.state == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrPinnedPDFReadV1
	}
	if _, ok := ctx.Deadline(); !ok {
		return nil, ErrPinnedPDFReadV1
	}
	s := r.state
	s.mu.Lock()
	if s.attempted {
		s.mu.Unlock()
		return nil, ErrPinnedPDFReadV1
	}
	s.attempted = true
	s.mu.Unlock()
	response, info, _, err := (minio.Core{Client: s.client.mc}).GetObject(withObjectResponseLimitV1(ctx, s.size), s.client.bucket, s.key, s.client.getOpts(s.version))
	var ownedBody []byte
	if response != nil {
		defer func() {
			if e := response.Close(); e != nil {
				failure = errors.Join(ErrPinnedPDFReadV1, failure, e)
			}
			if e := ctx.Err(); e != nil {
				failure = errors.Join(ErrPinnedPDFReadV1, failure, e)
			}
			if failure != nil {
				clear(ownedBody)
				body = nil
			}
		}()
	}
	if err != nil {
		return nil, errors.Join(ErrPinnedPDFReadV1, err)
	}
	if response == nil || info.VersionID != s.version || info.Size != s.size {
		return nil, ErrPinnedPDFReadV1
	}
	// Actual GET metadata is checked before this one exact funded allocation.
	// There is no ReadAll growth envelope. One stack byte detects excess input.
	ownedBody = make([]byte, int(s.size))
	if _, err = io.ReadFull(response, ownedBody); err != nil {
		return nil, errors.Join(ErrPinnedPDFReadV1, err)
	}
	var extra [1]byte
	n, err := response.Read(extra[:])
	if n != 0 || err != io.EOF {
		return nil, errors.Join(ErrPinnedPDFReadV1, err)
	}
	actual := sha256.Sum256(ownedBody)
	if subtle.ConstantTimeCompare(actual[:], s.digest[:]) != 1 {
		return nil, ErrPinnedPDFReadV1
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(ErrPinnedPDFReadV1, err)
	}
	body = ownedBody
	return body, nil
}
