// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"encoding/json"
	"fmt"
	"html"
	"strings"

	"github.com/bright-interaction/hash/internal/sanitize"
)

type redactionReport struct {
	SchemaVersion int               `json:"schema_version"`
	Items         []json.RawMessage `json:"items"`
}

// renderRedactionReportSection renders recorded source-intake evidence for a
// new certificate. It never reads or rewrites a stored historical certificate.
// Empty reports emit nothing; unreadable or unsupported records make no
// sanitization claim. Schema 1 categories were not independently measured.
//
// The section is embedded BEFORE the ed25519 signature is computed, so
// the signature binds these recorded statements, not their legal sufficiency.
func renderRedactionReportSection(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" || trimmed == "{}" {
		return ""
	}
	var rep redactionReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return redactionUnknownSection("The report could not be read. Source-intake observations are unknown.")
	}
	if rep.SchemaVersion != 1 && rep.SchemaVersion != 2 {
		return redactionUnknownSection("The report format is not supported. Source-intake observations are unknown.")
	}
	if len(rep.Items) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(redactionSectionStart())
	sb.WriteString(`<table><colgroup><col style="width:12%"><col style="width:16%"><col style="width:10%"><col style="width:48%"><col style="width:14%"></colgroup><thead><tr><th>Asset</th><th>Type</th><th>Method</th><th>Source-intake observations</th><th>Bytes (before -> after)</th></tr></thead><tbody>`)
	for _, itemRaw := range rep.Items {
		var it sanitize.Report
		if err := json.Unmarshal(itemRaw, &it); err != nil || strings.TrimSpace(string(itemRaw)) == "null" {
			sb.WriteString(`<tr><td>Unknown</td><td>Unknown</td><td>Unknown</td><td>The processing record could not be read; observations are unknown.</td><td>Unknown</td></tr>`)
			continue
		}
		observations := redactionItemObservations(rep.SchemaVersion, it, itemRaw)
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			redactionLabel(it.Asset),
			redactionLabel(it.ContentType),
			redactionLabel(it.Method),
			observations,
			redactionBytes(it),
		)
	}
	sb.WriteString(`</tbody></table>`)
	sb.WriteString(`</section>`)
	return sb.String()
}

func redactionSectionStart() string {
	return `<section class="hash-redaction-report"><h2>Source sanitization report</h2><p>This section records source processing at intake and is part of the signed certificate payload. Measured PDF observations cover the listed facilities in that intake pass only. They do not attest to later signature stamping, the final PDF, certificate rendering, malware detection, or information printed on document pages.</p>`
}

func redactionUnknownSection(message string) string {
	return redactionSectionStart() + `<p>` + html.EscapeString(message) + `</p></section>`
}

func redactionLabel(value string) string {
	if strings.TrimSpace(value) == "" {
		return "Unknown"
	}
	return html.EscapeString(value)
}

func redactionItemObservations(schema int, it sanitize.Report, raw json.RawMessage) string {
	if schema == 1 || it.Provenance == "legacy-unknown" {
		return "Historical processing report; not independently measured. Source-intake observations are unknown."
	}
	if it.UnsupportedT || it.Method == "passthrough" {
		return "Unsupported processing record; source-intake observations are unknown."
	}
	if it.Asset == "" || it.ContentType == "" || it.Method == "" {
		return "The processing record is incomplete; source-intake observations are unknown."
	}
	if it.ContentType != "application/pdf" {
		return "Processing recorded; measured PDF intake observations do not apply."
	}
	// DecodePDFReport validates the policy and complete, unambiguous wire shape
	// without parsing a PDF. Missing observations cannot be called absence.
	observed, err := sanitize.DecodePDFReport(raw)
	if err != nil {
		return "PDF processing recorded; source-intake observations are unknown or invalid."
	}
	p := observed.PDF
	return fmt.Sprintf(`<strong>Measured PDF intake</strong><br>Removed: %s<br>Absent before intake: %s<br>Generated at intake: %s<br>Pages: %d -> %d; page geometry unchanged.<div>Policy: %s<br>Source SHA-256: <code style="overflow-wrap:anywhere;word-break:break-all;">%s</code><br>Cleaned SHA-256: <code style="overflow-wrap:anywhere;word-break:break-all;">%s</code><br>Page geometry SHA-256: <code style="overflow-wrap:anywhere;word-break:break-all;">%s</code></div>`,
		redactionCategories(p.Removed), redactionCategories(p.Absent), redactionCategories(p.Generated), p.PagesBefore, p.PagesAfter,
		html.EscapeString(p.Policy), html.EscapeString(p.SourceSHA256), html.EscapeString(p.OutputSHA256), html.EscapeString(p.GeometrySHA256After))
}

func redactionBytes(it sanitize.Report) string {
	if it.BytesBefore < 1 || it.BytesAfter < 1 {
		return "Unknown"
	}
	return fmt.Sprintf("Recorded: %d -> %d", it.BytesBefore, it.BytesAfter)
}

func redactionCategories(values []string) string {
	if len(values) == 0 {
		return "None"
	}
	return html.EscapeString(strings.Join(values, ", "))
}
