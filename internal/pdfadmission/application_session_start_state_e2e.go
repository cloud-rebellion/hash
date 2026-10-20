//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

// ApplicationSessionStartStateE2EV1 is a test-only scalar observation. Pointer
// presence is not connection liveness, backend identity or retirement evidence.
type ApplicationSessionStartStateE2EV1 struct {
	Work, Observer ApplicationSessionOwnerStartStateE2EV1
}

type ApplicationSessionOwnerStartStateE2EV1 struct {
	Owners, Charged, UnknownStarts, Dialed, SocketPresent, ConnPresent, FencePresent int
	Creating, Active, Closed, Ended, Retired, ClosingClient                          int
}

func (f *ApplicationSessionFactoryV1) StartStateE2EV1() ApplicationSessionStartStateE2EV1 {
	var out ApplicationSessionStartStateE2EV1
	if f == nil || f.state == nil {
		return out
	}
	p := f.state
	p.mu.Lock()
	defer p.mu.Unlock()
	copyOwner := func(s *applicationOwnedSessionV1, dst *ApplicationSessionOwnerStartStateE2EV1) {
		s.mu.Lock()
		defer s.mu.Unlock()
		dst.Owners++
		count := func(v bool, target *int) {
			if v {
				*target++
			}
		}
		count(s.grant != nil, &dst.Charged)
		count(s.unknown && s.dialed && s.fence == nil, &dst.UnknownStarts)
		count(s.dialed, &dst.Dialed)
		count(s.socket != nil, &dst.SocketPresent)
		count(s.conn != nil, &dst.ConnPresent)
		count(s.fence != nil, &dst.FencePresent)
		count(s.creating, &dst.Creating)
		dst.Active += s.active
		count(s.closed, &dst.Closed)
		count(s.ended, &dst.Ended)
		count(s.retired, &dst.Retired)
		count(s.closingClient, &dst.ClosingClient)
	}
	for owner := range p.sessions {
		copyOwner(owner, &out.Work)
	}
	for _, org := range p.controlsV1Locked() {
		org.mu.Lock()
		observer := org.observer
		org.mu.Unlock()
		if observer != nil {
			copyOwner(observer, &out.Observer)
		}
	}
	return out
}
