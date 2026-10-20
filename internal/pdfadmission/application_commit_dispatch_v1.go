// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

// ApplicationCommitDispatchObservationV1 is a value-only observation of this
// exact owned session's serialized dispatch state. Its zero value is unknown;
// callers cannot construct the private never-dispatched state from booleans,
// metadata, deadlines or a different session. It grants no retirement/refund,
// writer fence, row reconciliation or replay permission.
type ApplicationCommitDispatchObservationV1 struct{ state uint8 }

const (
	applicationCommitDispatchUnknownV1 uint8 = iota
	applicationCommitNeverDispatchedV1
	applicationCommitDispatchedV1
)

func (o ApplicationCommitDispatchObservationV1) NeverDispatchedV1() bool {
	return o.state == applicationCommitNeverDispatchedV1
}

// Inspect only after the synchronous CommitV1 call returned, on its SAME
// private owner. commitAttempted is set under the owned session mutex before
// calling the actual transaction's Commit and is never reset. A true attempt
// remains conservatively dispatched even after an error or uncertain result.
func (h *ApplicationSessionV1) CommitDispatchObservationV1() ApplicationCommitDispatchObservationV1 {
	if h == nil || h.state == nil {
		return ApplicationCommitDispatchObservationV1{}
	}
	s := h.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitAttempted {
		return ApplicationCommitDispatchObservationV1{state: applicationCommitDispatchedV1}
	}
	return ApplicationCommitDispatchObservationV1{state: applicationCommitNeverDispatchedV1}
}
