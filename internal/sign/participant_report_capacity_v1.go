// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"errors"

	"github.com/bright-interaction/hash/internal/pdfadmission"
)

var ErrParticipantReportCapacityV1 = pdfadmission.ErrParticipantReportCapacityV1

func responseReportAdmissionErrorV1(err error) error {
	if err == nil || errors.Is(err, ErrParticipantReportCapacityV1) {
		return err
	}
	return errors.Join(ErrSigningAdmissionUnavailableV1, err)
}
