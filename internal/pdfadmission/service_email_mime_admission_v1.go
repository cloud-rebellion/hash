// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"context"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
)

// Same actual worker coordinator and organization as its validated delivery.
// No new coordinator, resource default, caller vector or network grant exists.
func (a *WorkAdmissionV1) ServiceEmailMIMEV1(ctx context.Context, msg dispatch.Message) (func(), error) {
	if a == nil || a.coordinator == nil || msg.OrgID == uuid.Nil {
		return nil, ErrWorkRuntimeV1
	}
	n, err := dispatch.ServiceEmailMIMEWorkingBytesV1(msg)
	if err != nil {
		return nil, err
	}
	return a.acquire(ctx, msg.OrgID, workguard.VectorV1{ParentBytes: n})
}
