// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import "context"

// ApplicationSessionStartObservationV1 contains only closed numeric classes,
// frozen at the original failure before startup cancellation or cleanup.
// Phases: 1 endpoint, 2 connect, 3 identity query, 4 first row, 5 identity
// validation, 6 trailing drain. ContextState: 1 nil, 2 live, 3 canceled,
// 4 expired, 5 other. ErrorClass uses the existing private failure taxonomy.
// These observations confer no retry, admission or retirement authority.
type ApplicationSessionStartObservationV1 struct {
	Phase, ErrorClass, ContextState uint8
}

func applicationSessionStartErrorV1(ctx context.Context, phase, cause error, startPhase uint8) error {
	var contextErr error
	contextState := uint8(1)
	if ctx != nil {
		contextErr = ctx.Err()
		switch contextErr {
		case nil:
			contextState = 2
		case context.Canceled:
			contextState = 3
		case context.DeadlineExceeded:
			contextState = 4
		default:
			contextState = 5
		}
	}
	// Preserve the original cause order and identity. No diagnostic error is
	// appended; Error and Unwrap retain the existing session-error contract.
	causes := []error{ErrApplicationSessionV1}
	if phase != nil {
		causes = append(causes, phase)
	}
	if cause != nil {
		causes = append(causes, cause)
	}
	if contextErr != nil {
		causes = append(causes, contextErr)
	}
	classified := cause
	if classified == nil {
		classified = contextErr
	}
	return &applicationSessionFailureV1{causes: causes, start: ApplicationSessionStartObservationV1{
		Phase: startPhase, ErrorClass: signerReadFailureClassV1(classified), ContextState: contextState,
	}}
}

// ApplicationSessionStartObservationForV1 finds a captured nested observation,
// including inside an uncaptured session wrapper or errors.Join. The bounded
// walk retains neither errors nor contexts and tolerates cyclic wrappers.
func ApplicationSessionStartObservationForV1(err error) (ApplicationSessionStartObservationV1, bool) {
	remaining := 32
	var walk func(error, int) (ApplicationSessionStartObservationV1, bool)
	walk = func(current error, depth int) (ApplicationSessionStartObservationV1, bool) {
		if remaining == 0 || depth == 16 {
			return ApplicationSessionStartObservationV1{}, false
		}
		remaining--
		if current == nil {
			return ApplicationSessionStartObservationV1{}, false
		}
		if failure, ok := current.(*applicationSessionFailureV1); ok {
			if failure == nil {
				return ApplicationSessionStartObservationV1{}, false
			}
			if failure.start.Phase >= 1 && failure.start.Phase <= 6 {
				return failure.start, true
			}
			for _, cause := range failure.causes {
				if remaining == 0 || depth+1 == 16 {
					break
				}
				if observed, found := walk(cause, depth+1); found {
					return observed, true
				}
			}
			return ApplicationSessionStartObservationV1{}, false
		}
		switch wrapped := current.(type) {
		case interface{ Unwrap() []error }:
			for _, cause := range wrapped.Unwrap() {
				if remaining == 0 || depth+1 == 16 {
					break
				}
				if observed, found := walk(cause, depth+1); found {
					return observed, true
				}
			}
		case interface{ Unwrap() error }:
			return walk(wrapped.Unwrap(), depth+1)
		}
		return ApplicationSessionStartObservationV1{}, false
	}
	return walk(err, 0)
}
