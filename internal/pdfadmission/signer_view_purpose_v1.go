// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

// Viewing has its own fixed mutation. It does not grant acknowledgement,
// signing, or access to another stage's status/collection predicates.
const HTMLSignerViewMutationV1 HTMLSendSQLPurposeV1 = HTMLAcknowledgementMutationV1 + 1
