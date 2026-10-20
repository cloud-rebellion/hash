// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"errors"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

var ErrPackageResponseRequiredV1 = pdfadmission.ErrPackageResponseRequiredV1
var ErrPackageResponseChangedV1 = pdfadmission.ErrPackageResponseChangedV1
var ErrPackageResponseUnavailableV1 = errors.New("sign: whole-package response unavailable")

func (l *signerReadLeaseV1) registerPackageResponseRequestV1(e *Engine, request *pdfadmission.ApplicationPackageResponseRequestV1) error {
	if l == nil || request == nil {
		return ErrPackageResponseUnavailableV1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.issuer != e || l.reader == nil || l.original == nil {
		return ErrPackageResponseUnavailableV1
	}
	l.packageResponseRequests = append(l.packageResponseRequests, request)
	return nil
}
