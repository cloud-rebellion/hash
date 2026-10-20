// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
)

// PackageSendObservationV1 is the common REST/MCP wire observation, not a
// capability or consent. Native source/actor/transaction owners supply authority.
type PackageSendObservationV1 struct {
	ExpectedUpdatedAt string `json:"expected_updated_at"`
	PackageID         string `json:"package_id"`
	Generation        string `json:"generation"`
}

func (v *PackageSendObservationV1) SelectionV1() (pdfadmission.HTMLSendPackageSelectionV1, error) {
	if v == nil {
		return pdfadmission.HTMLSendPackageSelectionV1{}, nil
	}
	invalid := pdfadmission.ErrPackageSendSelectionChangedV1
	if len(v.ExpectedUpdatedAt) < 20 || len(v.ExpectedUpdatedAt) > 30 || !strings.HasSuffix(v.ExpectedUpdatedAt, "Z") || len(v.PackageID) != 36 || len(v.Generation) < 1 || len(v.Generation) > 19 || v.Generation[0] == '0' {
		return pdfadmission.HTMLSendPackageSelectionV1{}, invalid
	}
	stamp, err := time.Parse(time.RFC3339Nano, v.ExpectedUpdatedAt)
	if err != nil {
		return pdfadmission.HTMLSendPackageSelectionV1{}, invalid
	}
	id, err := uuid.Parse(v.PackageID)
	if err != nil || id.String() != v.PackageID {
		return pdfadmission.HTMLSendPackageSelectionV1{}, invalid
	}
	generation, err := strconv.ParseInt(v.Generation, 10, 64)
	if err != nil || strconv.FormatInt(generation, 10) != v.Generation {
		return pdfadmission.HTMLSendPackageSelectionV1{}, invalid
	}
	out := pdfadmission.HTMLSendPackageSelectionV1{ExpectedUpdatedAt: stamp, PackageID: id, Generation: generation}
	if !out.ValidV1() {
		return pdfadmission.HTMLSendPackageSelectionV1{}, invalid
	}
	return out, nil
}
