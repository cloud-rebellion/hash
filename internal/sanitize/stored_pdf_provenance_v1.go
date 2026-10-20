// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sanitize

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

var ErrStoredPDFProvenanceV1 = errors.New("sanitize: stored PDF lacks exact observed intake proof")

// ValidateStoredPDFProvenanceV1 binds retained intake evidence to an already
// hash-verified exact object and an isolated page measurement. It does not
// re-clean bytes, follow a current key, or certify malware-scanner efficacy.
// Multiple historical PDF items are allowed, but exactly one must prove THIS
// output tuple. Legacy/absent reports cannot enable a new package selection.
func ValidateStoredPDFProvenanceV1(raw []byte, outputSHA string, actualBytes int64, pages int) error {
	if len(raw) < 1 || len(raw) > 65536 || !utf8.Valid(raw) || strictPDFWorkerJSON(raw) != nil || !validPDFSHA(outputSHA) || actualBytes < 1 || actualBytes > MaxPDFBytes || pages < 1 || pages > MaxPDFPages {
		return ErrStoredPDFProvenanceV1
	}
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Items         []json.RawMessage `json:"items"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&envelope) != nil || d.Decode(new(any)) != io.EOF || envelope.SchemaVersion != 2 || len(envelope.Items) < 1 || len(envelope.Items) > 128 {
		return ErrStoredPDFProvenanceV1
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || bytes.Equal(bytes.TrimSpace(top["items"]), []byte("null")) {
		return ErrStoredPDFProvenanceV1
	}
	if len(top) != 2 {
		return ErrStoredPDFProvenanceV1
	}
	for _, key := range []string{"schema_version", "items"} {
		value, ok := top[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrStoredPDFProvenanceV1
		}
	}
	matches := 0
	for _, item := range envelope.Items {
		var fields map[string]json.RawMessage
		if json.Unmarshal(item, &fields) != nil || fields == nil {
			return ErrStoredPDFProvenanceV1
		}
		var ct string
		if json.Unmarshal(fields["content_type"], &ct) != nil {
			return ErrStoredPDFProvenanceV1
		}
		_, hasPDF := fields["pdf"]
		if ct != "application/pdf" && !hasPDF {
			continue
		}
		report, err := DecodePDFReport(item)
		if err != nil {
			return ErrStoredPDFProvenanceV1
		}
		if report.PDF.OutputSHA256 != outputSHA {
			continue
		}
		if report.BytesAfter != actualBytes || report.PDF.PagesAfter != pages || ValidatePDFResult(report, report.PDF.SourceSHA256, outputSHA, report.BytesBefore, actualBytes) != nil {
			return ErrStoredPDFProvenanceV1
		}
		matches++
	}
	if matches != 1 {
		return ErrStoredPDFProvenanceV1
	}
	return nil
}
