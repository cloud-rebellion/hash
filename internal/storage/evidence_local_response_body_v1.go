// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package storage

import (
	"errors"
	"io"
	"sync"
	"unsafe"
)

// This private response frame is never returned to the SDK or parser. Read
// admits the actual copied wire/token producers before exposing their bytes.
// Close joins every actual Read and clears only after underlying Close returns.
type evidenceLocalResponseBodyV1 struct {
	owner      *evidenceLocalPutStateV1
	inner      io.ReadCloser
	mu, readMu sync.Mutex
	joined     *sync.Cond
	active     int
	closed     bool
	once       sync.Once
	closeErr   error
	scratch    []byte
	fundXML    bool
}

func (s *evidenceLocalPutStateV1) responseBodyV1(inner io.ReadCloser, fundXML bool) (*evidenceLocalResponseBodyV1, error) {
	cost := 4*int64(unsafe.Sizeof(evidenceLocalResponseBodyV1{})) + (128 << 10)
	if err := s.grant.TryGrowParentV1(s.ctx, cost); err != nil {
		return nil, errors.Join(ErrEvidenceLocalIOV1, err)
	}
	b := &evidenceLocalResponseBodyV1{owner: s, inner: inner, scratch: make([]byte, 64<<10), fundXML: fundXML}
	b.joined = sync.NewCond(&b.mu)
	s.mu.Lock()
	s.bodies[b] = struct{}{}
	s.mu.Unlock()
	return b, nil
}
func (b *evidenceLocalResponseBodyV1) Read(p []byte) (int, error) {
	if b == nil {
		return 0, io.ErrClosedPipe
	}
	b.readMu.Lock()
	defer b.readMu.Unlock()
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	b.active++
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		b.active--
		if b.active == 0 {
			b.joined.Broadcast()
		}
		b.mu.Unlock()
	}()
	if len(p) == 0 {
		return 0, nil
	}
	scratch := b.scratch[:min(len(p), len(b.scratch))]
	n, err := b.inner.Read(scratch)
	if n < 0 || n > len(scratch) {
		return 0, io.ErrNoProgress
	}
	if n > 0 {
		if b.fundXML {
			// Only location/retention/error XML expands retained SDK tokens/strings.
			// Exact object verification instead streams into its fixed hash state.
			tokens := int64(0)
			for _, v := range scratch[:n] {
				if v == '<' || v == '=' {
					tokens++
				}
			}
			cost, costErr := evidenceLocalHeaderResourcesV1(int64(n), tokens)
			if costErr == nil {
				costErr = b.owner.grant.TryGrowParentV1(b.owner.ctx, cost)
			}
			if costErr != nil {
				clear(scratch[:n])
				return 0, errors.Join(ErrEvidenceLocalIOV1, costErr)
			}
		}
		copy(p, scratch[:n])
		clear(scratch[:n])
	}
	return n, err
}
func (b *evidenceLocalResponseBodyV1) Close() error {
	if b == nil {
		return nil
	}
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		err := b.inner.Close()
		b.mu.Lock()
		for b.active != 0 {
			b.joined.Wait()
		}
		clear(b.scratch)
		b.scratch = nil
		b.inner = nil
		b.closeErr = err
		b.mu.Unlock()
	})
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeErr
}
