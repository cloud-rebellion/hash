// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
	"strings"
	"time"
	"unicode/utf8"
)

// Prefix is separate so the original completion-time policy precedes the
// original filled-field SQL read. It uses only native private row projections.
func CertificatePrefixV1(doc *generated.Document, recs []*generated.Recipient, sigs []*generated.Signature, claims CertificateEvidenceClaimsV1) (string, error) {
	sigByRec := map[string]*generated.Signature{}
	for _, s := range sigs {
		sigByRec[s.RecipientID.String()] = s
	}

	var sb strings.Builder
	sb.WriteString(`<div class="hash-cert-page">`)
	sb.WriteString(`<h2>Audit Certificate</h2>`)
	fmt.Fprintf(&sb, `<p><strong>Document:</strong> %s</p>`, certificateEscapeV1(doc.Name))
	fmt.Fprintf(&sb, `<p><strong>Document ID:</strong> %s</p>`, doc.ID)
	fmt.Fprintf(&sb, `<p><strong>Sent at:</strong> %s</p>`, certificateFormatNullableTSV1(doc.SentAt))
	if !doc.CompletionEffectiveAtBound {
		return "", errors.New("audit certificate: completion-effective timestamp is not bound for this ceremony")
	}
	completionEffectiveAt, err := certificateCanonicalCompletionEffectiveAtV1(doc.CompletionEffectiveAt)
	if err != nil {
		return "", fmt.Errorf("audit certificate: %w", err)
	}
	if claims.CompletionEffectiveAt != completionEffectiveAt {
		return "", errors.New("audit certificate: completion-effective timestamp claim does not match document")
	}
	fmt.Fprintf(&sb, `<p><strong>Completion effective at:</strong> %s</p>`, certificateEscapeV1(completionEffectiveAt))

	sb.WriteString(`<table><thead><tr><th>Role</th><th>Recipient</th><th>Status</th><th>Signed at</th><th>Font</th><th>Image SHA-256</th></tr></thead><tbody>`)
	for _, rec := range recs {
		var sig *generated.Signature
		if s, ok := sigByRec[rec.ID.String()]; ok {
			sig = s
		}
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s &lt;%s&gt;</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			certificateEscapeV1(rec.Role),
			certificateEscapeV1(rec.Name),
			certificateEscapeV1(rec.Email),
			certificateEscapeV1(rec.Status),
			certificateFormatNullableTSV1(rec.SignedAt),
			certificateSignatureFontOrNAV1(sig),
			certificateSignatureSHAOrNAV1(sig),
		)
	}
	sb.WriteString(`</tbody></table>`)

	return sb.String(), nil
}
func CertificateFieldValuesSectionV1(rows []*generated.DocumentField) string {
	var visible []*generated.DocumentField
	for _, f := range rows {
		switch f.Type {
		case "text", "date", "checkbox", "dropdown", "initial":
		default:
			continue
		}
		if !f.Value.Valid || f.Value.String == "" {
			continue
		}
		visible = append(visible, f)
	}
	if len(visible) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString(`<h3 style="margin-top:24px">Filled fields</h3>`)
	sb.WriteString(`<table><thead><tr><th>Label</th><th>Type</th><th>Page</th><th>Value</th><th>Filled at</th></tr></thead><tbody>`)
	for _, f := range visible {
		label := ""
		if f.Label.Valid {
			label = f.Label.String
		}
		fmt.Fprintf(&sb,
			`<tr><td>%s</td><td>%s</td><td>%d</td><td>%s</td><td>%s</td></tr>`,
			certificateEscapeV1(label),
			certificateEscapeV1(f.Type),
			f.Page,
			certificateEscapeV1(CertificateTruncateFieldValueV1(f.Value.String)),
			certificateFormatNullableTSV1(f.CompletedAt),
		)
	}
	sb.WriteString(`</tbody></table>`)
	return sb.String()
}
func CertificateTruncateFieldValueV1(v string) string {
	const max = 200
	if utf8.RuneCountInString(v) <= max {
		return v
	}
	return string([]rune(v)[:max]) + "… [truncated, full value in document_fields]"
}

const MaxCertificatePayloadBytesV1 = 4 << 20

// Retain ErrParticipantReportV1 compatibility while allowing native admission
// to distinguish a measured payload overflow from malformed report evidence.
var ErrCertificatePayloadCapacityV1 = errors.New("audit certificate: signed payload size limit exceeded")

// CertificatePayloadV1 builds the complete exact unsigned payload used by the
// detached signature. It performs no signing, IO, native admission or evidence
// authorization. Callers own its input/formatter/output allocation lifetimes.
// The existing limit applies to mandatory participant-report certificates;
// historical certificates without those additive claims retain their behavior.
func CertificatePayloadV1(prefix string, doc *generated.Document, fields []*generated.DocumentField, claims CertificateEvidenceClaimsV1, manifestHTML *string) (string, error) {
	var sb strings.Builder
	sb.WriteString(prefix)
	if section := CertificateFieldValuesSectionV1(fields); section != "" {
		sb.WriteString(section)
	}
	// Bind the exact final contract body and a pre-final prefix of the
	// immutable org audit ledger. These machine-readable claims are inside the
	// detached signed payload, not merely in the later unsigned export manifest.
	sb.WriteString(claims.HTML())
	if claims.ParticipantReportSchema != "" {
		if claims.ParticipantReportSchema != ParticipantReportSchemaV1 || claims.ParticipantReportHTML == "" || len(claims.ParticipantReportSHA256) != 64 {
			return "", ErrParticipantReportV1
		}
		sb.WriteString(claims.ParticipantReportHTML)
	}

	// Append the content-snapshot manifest BEFORE signing so the detached
	// ed25519 signature binds every frozen child body without a final-PDF
	// self-hash cycle.
	if manifestHTML != nil {
		if *manifestHTML == "" {
			return "", errors.New("audit certificate: empty envelope manifest override")
		}
		sb.WriteString(*manifestHTML)
	}

	// Bind measured source-intake observations and their artifact digests in
	// the signed payload. Historical/unmeasured records remain explicitly
	// unknown; this section does not certify legal sufficiency or final-PDF
	// metadata. Stored historical certificates retain their original bytes.
	if section := RedactionReportSectionV1(doc.MetadataRedactionReport); section != "" {
		sb.WriteString(section)
	}

	signedPayload := sb.String()
	if claims.ParticipantReportSchema != "" && len(signedPayload) > MaxCertificatePayloadBytesV1 {
		return "", errors.Join(ErrParticipantReportV1, ErrCertificatePayloadCapacityV1)
	}
	return signedPayload, nil
}

func CertificateFinishV1(prefix string, doc *generated.Document, fields []*generated.DocumentField, claims CertificateEvidenceClaimsV1, manifestHTML *string, key *AuditCertificateKeyV1, orgName, baseURL string) (string, string, string, error) {
	signedPayload, err := CertificatePayloadV1(prefix, doc, fields, claims, manifestHTML)
	if err != nil {
		return "", "", "", err
	}
	// Bind the exact shared payload. The independent rendered certificate also
	// retains a complete payload copy until its own actual consumer retires.
	signature := key.SignPayload([]byte(signedPayload))
	if signature == "" {
		return "", "", "", errors.New("audit certificate: signer returned an empty signature")
	}
	issuer := strings.TrimSpace(orgName)
	if issuer == "" {
		issuer = "Hash"
	}
	verifyURL := strings.TrimRight(strings.TrimSpace(baseURL), "/") + "/verify"
	var sb strings.Builder
	sb.WriteString(signedPayload)
	fmt.Fprintf(&sb, `<div style="margin-top:24px;padding:12px;border:1px solid #ddd;background:#fafafa;font-family:monospace;font-size:9px;line-height:1.5;">
<div><strong>Issuer:</strong> Hash / %s</div>
<div><strong>Public key (ed25519, base64):</strong> %s</div>
<div><strong>Signature (ed25519 over SHA-256(domain ‖ cert)):</strong> %s</div>
<div style="color:#666;margin-top:6px">Server-assisted verification (uploads certificate data): %s</div>
</div>`,
		certificateEscapeV1(issuer),
		certificateEscapeV1(key.PublicKeyBase64()),
		certificateEscapeV1(signature),
		certificateEscapeV1(verifyURL))
	sb.WriteString(`</div>`)
	return sb.String(), signedPayload, signature, nil
}

func certificateSignatureFontOrNAV1(s *generated.Signature) string {
	if s == nil {
		return ", "
	}
	return certificateEscapeV1(s.Font)
}
func certificateSignatureSHAOrNAV1(s *generated.Signature) string {
	if s == nil {
		return ", "
	}
	return fmt.Sprintf("<code>%x</code>", s.ImageSha256)
}
func certificateFormatNullableTSV1(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ", "
	}
	return t.Time.UTC().Format(time.RFC3339)
}
