// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package render

import (
	"io"
	"sync"
)

// One concrete standard Transport replay frame. Only this private RoundTrip
// owner can retire the slice. Body.Close retires one opaque reader; it cannot
// erase a frame still needed by original safe transparent replay. Readers copy
// under the same mutex, so owner close joins every actual copy and invalidates
// all captured GetBody callbacks, including callbacks retained by Transport.
type htmlLocalReplayFrameV1 struct {
	mu     sync.Mutex
	frame  []byte
	closed bool
}
type htmlLocalReplayBodyV1 struct {
	frame  *htmlLocalReplayFrameV1
	offset int
	closed bool
}

func newHTMLLocalReplayFrameV1(frame []byte) *htmlLocalReplayFrameV1 {
	return &htmlLocalReplayFrameV1{frame: frame}
}
func (f *htmlLocalReplayFrameV1) bodyV1() (io.ReadCloser, error) {
	if f == nil {
		return nil, ErrHTMLLocalIOV1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, ErrHTMLLocalIOV1
	}
	return &htmlLocalReplayBodyV1{frame: f}, nil
}
func (f *htmlLocalReplayFrameV1) closeV1() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	clear(f.frame)
	f.frame = nil
	f.mu.Unlock()
}
func (b *htmlLocalReplayBodyV1) Read(p []byte) (int, error) {
	if b == nil || b.frame == nil {
		return 0, io.ErrClosedPipe
	}
	f := b.frame
	f.mu.Lock()
	defer f.mu.Unlock()
	if b.closed || f.closed {
		return 0, io.ErrClosedPipe
	}
	if len(p) == 0 {
		return 0, nil
	}
	if b.offset >= len(f.frame) {
		return 0, io.EOF
	}
	n := copy(p[:min(len(p), 64<<10)], f.frame[b.offset:])
	b.offset += n
	return n, nil
}
func (b *htmlLocalReplayBodyV1) Close() error {
	if b == nil || b.frame == nil {
		return nil
	}
	f := b.frame
	f.mu.Lock()
	b.closed = true
	f.mu.Unlock()
	return nil
}
