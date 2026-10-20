// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/workguard"
)

const applicationSignerScopeHeaderBytesV1 int64 = 8 << 20

func (a *WorkAdmissionV1) signerProcessSQLV1(ctx context.Context) (func(), error) {
	if a == nil || a.coordinator == nil {
		return nil, workguard.ErrUnavailableV1
	}
	grant, err := a.coordinator.TryAcquireProcessV1(ctx, workguard.VectorV1{SQLSessions: 1})
	if err != nil {
		return nil, err
	}
	return grant.Close, nil
}

func (a *WorkAdmissionV1) signerProcessSQLWithDenialV1(ctx context.Context) (func(), workguard.AdmissionDenialV1, error) {
	if a == nil || a.coordinator == nil {
		return nil, workguard.AdmissionDenialV1{}, workguard.ErrUnavailableV1
	}
	grant, denial, err := a.coordinator.TryAcquireProcessWithDenialV1(ctx, workguard.VectorV1{SQLSessions: 1})
	if err != nil {
		return nil, denial, err
	}
	return grant.Close, denial, nil
}
func (a *WorkAdmissionV1) signerProcessHeaderV1(ctx context.Context) (func(), error) {
	if a == nil || a.coordinator == nil || applicationSignerReadDiagnosticControlBytesV1 > applicationSignerScopeHeaderBytesV1 {
		return nil, workguard.ErrUnavailableV1
	}
	grant, err := a.coordinator.TryAcquireProcessV1(ctx, workguard.VectorV1{ParentBytes: applicationSignerScopeHeaderBytesV1, DBStagingBytes: applicationSignerScopeHeaderBytesV1})
	if err != nil {
		return nil, err
	}
	return grant.Close, nil
}
