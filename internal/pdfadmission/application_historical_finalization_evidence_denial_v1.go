// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/workguard"
)

// This fixed immutable observation belongs to the real native Evidence error
// consumer. Its exact sizeof is admitted in the existing retained control
// recipe before allocation; that Work/readLease continues to own the error.
// It contains no body/key/org/grant/coordinator alias, permits no retry and
// grants no source, SQL, provider or retirement authority.
type HistoricalFinalizationEvidenceCapacityErrorV1 struct {
	cause  error
	denial workguard.AdmissionDenialV1
}

func (e *HistoricalFinalizationEvidenceCapacityErrorV1) Error() string { return e.cause.Error() }
func (e *HistoricalFinalizationEvidenceCapacityErrorV1) Unwrap() error { return e.cause }
func (e *HistoricalFinalizationEvidenceCapacityErrorV1) DenialV1() workguard.AdmissionDenialSnapshotV1 {
	return e.denial.SnapshotV1()
}
