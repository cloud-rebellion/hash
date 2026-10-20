// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "sync/atomic"

// Coordination only. This gate owns no SQL, authority, capacity or resource
// grant. A typed owner registers BEFORE waiting on its producer mutex and ends
// that registration AFTER actual last use/unlock. Closed admissions never
// resume. Exactly one true result elects the owner's fixed typed cleanup.
type applicationJoinedActivityV1 struct {
	state   atomic.Uint64 // low bit closed; each admitted frame adds two
	claimed atomic.Bool
}

func (g *applicationJoinedActivityV1) enterV1() bool {
	for {
		before := g.state.Load()
		if before&1 != 0 || before > ^uint64(0)-2 {
			return false
		}
		if g.state.CompareAndSwap(before, before+2) {
			return true
		}
	}
}

func (g *applicationJoinedActivityV1) leaveV1() bool {
	return g.state.Add(^uint64(1)) == 1 && g.claimed.CompareAndSwap(false, true)
}

func (g *applicationJoinedActivityV1) closeV1() bool {
	before := g.state.Or(1)
	return before&^uint64(1) == 0 && g.claimed.CompareAndSwap(false, true)
}
