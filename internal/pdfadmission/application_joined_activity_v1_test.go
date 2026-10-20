// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
)

func TestJoinedActivityCloseBeforeAfterAndQueuedFramesV1(t *testing.T) {
	for _, count := range []int{0, 1, 2, 32} {
		g := &applicationJoinedActivityV1{}
		for i := 0; i < count; i++ {
			if !g.enterV1() {
				t.Fatal("open frame refused")
			}
		}
		claims := 0
		if g.closeV1() {
			claims++
		}
		if g.enterV1() {
			t.Fatal("closed activity admitted a new frame")
		}
		if g.closeV1() {
			claims++
		}
		for i := 0; i < count; i++ {
			if g.leaveV1() {
				claims++
			}
		}
		if g.closeV1() {
			claims++
		}
		if claims != 1 || g.state.Load() != 1 {
			t.Fatal("closed+joined state did not elect exactly one typed cleanup", count, claims)
		}
	}
	overflow := &applicationJoinedActivityV1{}
	overflow.state.Store(math.MaxUint64 - 1)
	if overflow.enterV1() || overflow.state.Load() != math.MaxUint64-1 {
		t.Fatal("frame registration wrapped into fake zero")
	}
}

func TestJoinedActivityConcurrentCloseAndFinalReleaseV1(t *testing.T) {
	for iteration := 0; iteration < 256; iteration++ {
		g := &applicationJoinedActivityV1{}
		if !g.enterV1() {
			t.Fatal("initial frame refused")
		}
		var claims atomic.Int32
		var joined sync.WaitGroup
		for i := 0; i < 4; i++ {
			joined.Add(1)
			go func() {
				defer joined.Done()
				if g.closeV1() {
					claims.Add(1)
				}
			}()
		}
		joined.Add(1)
		go func() {
			defer joined.Done()
			if g.leaveV1() {
				claims.Add(1)
			}
		}()
		joined.Wait()
		if claims.Load() != 1 || g.state.Load() != 1 || g.enterV1() {
			t.Fatal("actual close/final-release race stranded or doubled cleanup")
		}
	}
}
