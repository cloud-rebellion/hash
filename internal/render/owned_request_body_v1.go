// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"io"
	"sync"
)

const ownedRequestReadLimitV1 = 64 << 10

// ownedRequestBodyV1 takes sole ownership of a freshly encoded private request.
// Read copies one bounded chunk while holding mu; Close waits for that copy,
// erases the owned frame and prevents every later read. The prepare caller must
// also defer Close: net/http may close a request body after RoundTrip returns.
// This proves quiescence of this frame only, not transport-wide or remote
// renderer termination. The global coordinator must retain those separate debts.
type ownedRequestBodyV1 struct {
	mu     sync.Mutex
	raw    []byte
	offset int
	closed bool
}

func newOwnedRequestBodyV1(encoded []byte) *ownedRequestBodyV1 {
	return &ownedRequestBodyV1{raw: encoded}
}

func (b *ownedRequestBodyV1) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.offset == len(b.raw) {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > ownedRequestReadLimitV1 {
		p = p[:ownedRequestReadLimitV1]
	}
	n := copy(p, b.raw[b.offset:])
	b.offset += n
	return n, nil
}

func (b *ownedRequestBodyV1) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.closed {
		b.closed = true
		clear(b.raw)
		b.raw = nil
		b.offset = 0
	}
	return nil
}
