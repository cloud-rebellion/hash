// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaterialization

import (
	"bytes"
	"encoding/hex"
	"encoding/json"

	"github.com/bright-interaction/hash/internal/sanitize"
)

// validateMaterializationReport binds measured PDF sanitation to the artifact
// selected by this immutable row. Legacy data carries no measured assertion;
// preserving it never converts its old stripped-category list into proof.
// PDF parsing remains exclusively in the isolated sanitation worker.
func validateMaterializationReport(raw json.RawMessage, pdfSHA []byte, pages int32) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte(`{}`)) {
		return nil
	}
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || (envelope.SchemaVersion != 1 && envelope.SchemaVersion != 2) {
		return ErrInvalid
	}
	observed := 0
	for _, itemRaw := range envelope.Items {
		var item sanitize.Report
		if json.Unmarshal(itemRaw, &item) != nil {
			return ErrInvalid
		}
		if item.PDF == nil && item.Provenance != "observed" {
			if item.Provenance != "" && item.Provenance != "legacy-unknown" {
				return ErrInvalid
			}
			if item.Provenance == "legacy-unknown" && len(item.Stripped) != 0 {
				return ErrInvalid
			}
			continue
		}
		observed++
		measured, err := sanitize.DecodePDFReport(itemRaw)
		if envelope.SchemaVersion != 2 || observed > 1 || err != nil ||
			len(pdfSHA) != 32 || measured.PDF.OutputSHA256 != hex.EncodeToString(pdfSHA) || measured.PDF.PagesAfter != int(pages) {
			return ErrInvalid
		}
	}
	return nil
}
