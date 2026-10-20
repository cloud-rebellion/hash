// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package htmlmaterialization

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// PrepareOriginValidationV1 is the exact original RegisterOrigin pre-write
// document/page/actor/report prefix for the fixed owned fresh-origin writer.
// It grants no source validation, native work, transaction or row authority.
func PrepareOriginValidationV1(doc *generated.Document, pages int32, actor uuid.UUID) error {
	if doc == nil || actor == uuid.Nil || pages < 1 || pages > 500 || doc.Status != "draft" || !doc.UpdatedAt.Valid {
		return ErrInvalid
	}
	return validateMaterializationReport(doc.MetadataRedactionReport, doc.PdfSha256, pages)
}
