// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

// Fixed standalone pre-sign topology. It uses the existing sixteen-stage cap;
// no caller can allocate a new program phase or extend an original deadline.
const (
	HTMLPreSignReadV1 HTMLSendSQLPurposeV1 = HTMLReminderScheduledV1 + 1 + iota
	HTMLPreSignPreparationV1
	HTMLPreSignReservationV1
	HTMLPreSignCommitV1
	HTMLPreSignRetentionV1
	HTMLPreSignPublicationV1
	HTMLPreSignRecoveryV1
)
