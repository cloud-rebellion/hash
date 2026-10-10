// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package authoring

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/sanitize"
)

// This storage binding stays internal. Document/certificate reports include
// the measured artifact digests, never bucket keys or storage capabilities.
type pdfTemplateSanitization struct {
	SchemaVersion   int             `json:"schema_version"`
	ObjectKey       string          `json:"object_key"`
	ObjectSHA256    string          `json:"object_sha256"`
	ObjectVersionID string          `json:"object_version_id"`
	Report          json.RawMessage `json:"report"`
}

var errTemplateSanitization = errors.New("PDF template sanitization provenance does not match its source")

// BindPDFTemplateSanitization binds an observed intake report to the exact
// versioned object written by the upload path, before the authorized row insert.
func BindPDFTemplateSanitization(report sanitize.Report, key string, sha []byte, version string, pages int32) (json.RawMessage, error) {
	if err := sanitize.ValidatePDFReport(report); err != nil {
		return nil, errTemplateSanitization
	}
	if key == "" || key != strings.TrimSpace(key) || len(key) > 4096 || version == "" || version != strings.TrimSpace(version) || len(version) > 1024 || len(sha) != 32 || report.Asset != "template-pdf" || report.PDF.OutputSHA256 != hex.EncodeToString(sha) || report.PDF.PagesAfter != int(pages) {
		return nil, errTemplateSanitization
	}
	observed, err := json.Marshal(report)
	if err != nil {
		return nil, errTemplateSanitization
	}
	if _, err := sanitize.DecodePDFReport(observed); err != nil {
		return nil, errTemplateSanitization
	}
	return json.Marshal(pdfTemplateSanitization{SchemaVersion: 1, ObjectKey: key, ObjectSHA256: hex.EncodeToString(sha), ObjectVersionID: version, Report: observed})
}

// PDFTemplateDocumentReport uses the caller's SHARE-locked template snapshot.
// A missing legacy observation remains explicit unknown. A present but corrupt
// or stale binding fails closed; it cannot be downgraded to a legacy claim.
func PDFTemplateDocumentReport(tpl *generated.Template) (json.RawMessage, error) {
	if tpl == nil || tpl.SourceKind != "pdf" {
		return nil, errTemplateSanitization
	}
	raw := bytes.TrimSpace(tpl.PdfSanitizationReport)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return sanitize.SyntheticTemplateReport()
	}
	if len(raw) > 65536 {
		return nil, errTemplateSanitization
	}
	if !validPDFTemplateBindingKeys(raw) {
		return nil, errTemplateSanitization
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var binding pdfTemplateSanitization
	if err := decoder.Decode(&binding); err != nil {
		return nil, errTemplateSanitization
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errTemplateSanitization
	}
	if binding.SchemaVersion != 1 || !tpl.PdfStorageKey.Valid || !tpl.PdfStorageVersionID.Valid || !tpl.PageCount.Valid || binding.ObjectKey != tpl.PdfStorageKey.String || binding.ObjectVersionID != tpl.PdfStorageVersionID.String || binding.ObjectSHA256 != hex.EncodeToString(tpl.PdfSha256) {
		return nil, errTemplateSanitization
	}
	observed, err := sanitize.DecodePDFReport(binding.Report)
	if err != nil {
		return nil, errTemplateSanitization
	}
	if _, err := BindPDFTemplateSanitization(observed, binding.ObjectKey, tpl.PdfSha256, binding.ObjectVersionID, tpl.PageCount.Int32); err != nil {
		return nil, err
	}
	return sanitize.MergeReports(nil, observed)
}

// Validate outer keys before encoding/json can fold case or replace duplicate
// fields. The observed nested report is independently decoded by the worker
// policy validator, with the same strict treatment of all nested observations.
func validPDFTemplateBindingKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return false
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		switch key {
		case "schema_version", "object_key", "object_sha256", "object_version_id", "report":
		default:
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || len(seen) != 5 {
		return false
	}
	_, err = decoder.Token()
	return err == io.EOF
}
