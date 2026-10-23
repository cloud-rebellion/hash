// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

// These fixed pre-allocation shapes belong only to the two authenticated
// production routes. They do not replace the existing exact duplicate/name,
// typed/null, UUID/digest/authority or original-source decoders. The API birth
// route admits no values, HTML, PDF, connection/path override or review flags.
var htmlPreSignAPISourceFieldsV1 = [...]htmlInputFieldV1{
	{"request_id", htmlInputScalarV1}, {"expected_org_id", htmlInputScalarV1}, {"expected_user_id", htmlInputScalarV1},
	{"policy", htmlInputPreSignReferenceV1}, {"grant", htmlInputPreSignReferenceV1}, {"document_name", htmlInputScalarV1},
	{"crm_records", htmlInputPreSignRecordsV1}, {"prior", htmlInputPreSignPriorV1},
}
var htmlPreSignReferenceFieldsV1 = [...]htmlInputFieldV1{
	{"id", htmlInputScalarV1}, {"revision", htmlInputScalarV1}, {"sha256", htmlInputScalarV1},
}
var htmlPreSignRecordFieldsV1 = [...]htmlInputFieldV1{
	{"kind", htmlInputScalarV1}, {"id", htmlInputScalarV1},
}
var htmlPreSignSupersessionFieldsV1 = [...]htmlInputFieldV1{
	{"prior", htmlInputPreSignPriorV1}, {"template_id", htmlInputScalarV1}, {"source", htmlInputDocumentV1},
}
var htmlPreSignPriorFieldsV1 = [...]htmlInputFieldV1{
	{"execution_id", htmlInputScalarV1}, {"execution_sha256", htmlInputScalarV1}, {"document_id", htmlInputScalarV1},
	{"source_commitment", htmlInputScalarV1}, {"materialization_id", htmlInputScalarV1}, {"materialization_revision", htmlInputScalarV1},
	{"template", htmlInputPreSignTemplateV1},
}
var htmlPreSignTemplateFieldsV1 = [...]htmlInputFieldV1{
	{"id", htmlInputScalarV1}, {"version", htmlInputScalarV1}, {"content_sha256", htmlInputScalarV1},
	{"approved_by", htmlInputScalarV1}, {"approved_at", htmlInputScalarV1},
}

func htmlPreSignInputFieldsV1(n htmlInputNodeV1) []htmlInputFieldV1 {
	switch n {
	case htmlInputPreSignAPISourceV1:
		return htmlPreSignAPISourceFieldsV1[:]
	case htmlInputPreSignReferenceV1:
		return htmlPreSignReferenceFieldsV1[:]
	case htmlInputPreSignRecordV1:
		return htmlPreSignRecordFieldsV1[:]
	case htmlInputPreSignSupersessionV1:
		return htmlPreSignSupersessionFieldsV1[:]
	case htmlInputPreSignPriorV1:
		return htmlPreSignPriorFieldsV1[:]
	case htmlInputPreSignTemplateV1:
		return htmlPreSignTemplateFieldsV1[:]
	}
	return nil
}
