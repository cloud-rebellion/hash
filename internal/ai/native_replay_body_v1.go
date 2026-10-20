// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package ai

import (
	"io"
	"sync"
)

// One concrete standard Transport replay frame. RoundTrip return seals GetBody,
// but a final response can arrive while Transport is still uploading the body.
// Every issued reader remains usable until Transport actually closes it. The
// owner retires the frame only after sealing and all real reader Close/read
// joins. Closing the first reader before a safe retry cannot erase its frame.
type aiNativeReplayFrameV1 struct {
	mu     sync.Mutex
	frame  []byte
	bodies int
	sealed bool
	closed bool
	done   chan struct{}
}
type aiNativeReplayBodyV1 struct {
	frame  *aiNativeReplayFrameV1
	offset int
	closed bool
}

func newAINativeReplayFrameV1(frame []byte) *aiNativeReplayFrameV1 {
	return &aiNativeReplayFrameV1{frame: frame, done: make(chan struct{})}
}
func (f *aiNativeReplayFrameV1) bodyV1() (io.ReadCloser, error) {
	if f == nil {
		return nil, ErrNativeIOV1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sealed || f.closed {
		return nil, ErrNativeIOV1
	}
	f.bodies++
	return &aiNativeReplayBodyV1{frame: f}, nil
}
func (f *aiNativeReplayFrameV1) retireLockedV1() {
	if !f.sealed || f.bodies != 0 || f.closed {
		return
	}
	f.closed = true
	clear(f.frame)
	f.frame = nil
	close(f.done)
}
func (f *aiNativeReplayFrameV1) closeV1() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.sealed = true
	f.retireLockedV1()
	f.mu.Unlock()
}
func (f *aiNativeReplayFrameV1) waitV1() {
	if f != nil {
		<-f.done
	}
}
func (b *aiNativeReplayBodyV1) Read(p []byte) (int, error) {
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
func (b *aiNativeReplayBodyV1) Close() error {
	if b == nil || b.frame == nil {
		return nil
	}
	f := b.frame
	f.mu.Lock()
	if !b.closed {
		b.closed = true
		f.bodies--
		f.retireLockedV1()
	}
	f.mu.Unlock()
	return nil
}
