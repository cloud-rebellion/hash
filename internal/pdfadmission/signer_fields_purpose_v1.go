// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

const HTMLSignerFieldsMutationV1 HTMLSendSQLPurposeV1 = HTMLSignerViewMutationV1 + 1

// Same existing public JSON body limit, enforced before decoding. This is a
// capture bound, not a grant, credential or change to application capacity.
const SignerFieldsBodyLimitV1 = 128 * 1024

type SignerFieldValueInputV1 struct {
	FieldID string `json:"field_id"`
	Value   string `json:"value"`
}
