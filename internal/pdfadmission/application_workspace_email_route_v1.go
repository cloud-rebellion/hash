// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Cloud Rebellion
package pdfadmission

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// Fixed native route fields, derived from this actual parent's org. Returned
// purpose TEXT is priced independently from generated struct headers; UUID wire
// is fixed16B. Fresh enqueue has no claim nonce; claimed rows belong to worker.
const applicationWorkspaceSMTPPurposeBytesV1 = int64(len("workspace"))
const applicationWorkspaceSMTPWireBytesV1 = 16 + applicationWorkspaceSMTPPurposeBytesV1

func applicationWorkspaceEmailDeliveryMatchesV1(row *generated.EmailDelivery, org uuid.UUID) bool {
	return row != nil && org != uuid.Nil && row.SmtpOrgID.Valid && uuid.UUID(row.SmtpOrgID.Bytes) == org && row.SmtpPurpose == "workspace" && !row.SmtpClaimNonce.Valid && row.StaffAuthCiphertext == nil
}
