// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
	"io"
	"sync"
)

// One concrete standard Transport replay frame. Only this private RoundTrip
// owner can retire the slice. Body.Close retires one opaque reader; it cannot
// erase a frame still needed by original safe transparent replay. Readers copy
// under the same mutex, so owner close joins every actual copy and invalidates
// all captured GetBody callbacks, including callbacks retained by Transport.
type evidenceLocalReplayFrameV1 struct {
	mu     sync.Mutex
	frame  []byte
	grant  *workguard.GrantV1
	ctx    context.Context
	closed bool
}
type evidenceLocalReplayBodyV1 struct {
	frame  *evidenceLocalReplayFrameV1
	offset int
	closed bool
}

func newEvidenceLocalReplayFrameV1(frame []byte, grant *workguard.GrantV1, ctx context.Context) *evidenceLocalReplayFrameV1 {
	return &evidenceLocalReplayFrameV1{frame: frame, grant: grant, ctx: ctx}
}
func (f *evidenceLocalReplayFrameV1) bodyV1() (io.ReadCloser, error) {
	if f == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed || f.grant == nil {
		return nil, ErrEvidenceLocalIOV1
	}
	if err := f.grant.TryGrowParentV1(f.ctx, 256); err != nil {
		return nil, err
	}
	return &evidenceLocalReplayBodyV1{frame: f}, nil
}
func (f *evidenceLocalReplayFrameV1) closeV1() {
	if f == nil {
		return
	}
	f.mu.Lock()
	f.closed = true
	clear(f.frame)
	f.frame = nil
	f.grant = nil
	f.ctx = nil
	f.mu.Unlock()
}
func (b *evidenceLocalReplayBodyV1) Read(p []byte) (int, error) {
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
func (b *evidenceLocalReplayBodyV1) Close() error {
	if b == nil || b.frame == nil {
		return nil
	}
	f := b.frame
	f.mu.Lock()
	b.closed = true
	f.mu.Unlock()
	return nil
}
