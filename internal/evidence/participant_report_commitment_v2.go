// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package evidence

import (
	"bytes"
	"errors"
	"strconv"

	"github.com/bright-interaction/hash/internal/render"
)

// Version dispatch preserves the archived parser's exact behavior/bytes. An
// unknown or partial new schema cannot silently fall back to a legacy reader.
func parseParticipantReportClaimVersioned(payload []byte, document string) (participantReportClaimV1, error) {
	schema, present, err := optionalCertificateTextClaim(payload, "data-hash-participant-report-schema")
	if err != nil {
		return participantReportClaimV1{}, err
	}
	if !present || schema == render.ParticipantReportSchemaV1 {
		if bytes.Contains(payload, []byte(render.ParticipantReportCanonicalCarrierV2)) || bytes.Contains(payload, []byte(render.ParticipantReportHTMLV3Start)) {
			return participantReportClaimV1{}, errors.New("new participant report lacks its exact signed schema")
		}
		return parseParticipantReportClaimV1(payload, document)
	}
	if schema != render.ParticipantReportSchemaV2 {
		return participantReportClaimV1{}, errors.New("signed participant report schema is unsupported")
	}
	return parseParticipantReportClaimV2(payload, document)
}

func parseParticipantReportClaimV2(payload []byte, document string) (participantReportClaimV1, error) {
	var zero participantReportClaimV1
	if len(payload) > render.MaxCertificatePayloadBytesV1 {
		return zero, errors.New("signed participant report payload is oversized")
	}
	keys := []string{"data-hash-participant-report-schema", "data-hash-participant-report-sha256", "data-hash-participant-report-cutoff", "data-hash-participant-report-rows"}
	var values [4]string
	for i, key := range keys {
		value, present, err := optionalCertificateTextClaim(payload, key)
		if err != nil || !present {
			return zero, errors.New("signed participant report claims are incomplete or ambiguous")
		}
		values[i] = value
	}
	startMarker := []byte(`<section class="hash-participant-report">`)
	if values[0] != render.ParticipantReportSchemaV2 || bytes.Count(payload, startMarker) != 1 || bytes.Count(payload, []byte(render.ParticipantReportCanonicalCarrierV2)) != 1 || bytes.Contains(payload, []byte(`<section class="hash-redaction-report">`)) || bytes.Contains(payload, []byte(`<pre class="hash-participant-report-canonical"`)) {
		return zero, errors.New("signed participant report body/version/privacy is inconsistent")
	}
	start := bytes.Index(payload, startMarker)
	endMarker := []byte(`</pre></div></section>`)
	end := bytes.Index(payload[start:], endMarker)
	if end < 0 {
		return zero, errors.New("signed participant report body is incomplete")
	}
	section := string(payload[start : start+end+len(endMarker)])
	report, digest, err := render.ParseParticipantReportHTMLV3(section)
	if err != nil {
		return zero, errors.New("signed participant report visible text contradicts exact canonical evidence")
	}
	org, err := certificateTextClaim(payload, "data-hash-org-id")
	if err != nil {
		return zero, err
	}
	rows, err := strconv.ParseInt(values[3], 10, 64)
	if err != nil || rows < 0 || rows > render.MaxParticipantReportRowsV1 || strconv.FormatInt(rows, 10) != values[3] || report.SourceRowsV2() != rows || report.DocumentID != document || report.HistoryScope.RootDocumentID != document || report.HistoryScope.OrgID != org || report.Cutoff != values[2] || digest != values[1] {
		return zero, errors.New("signed participant report canonical evidence contradicts its document, organization, cutoff, count or digest claims")
	}
	return participantReportClaimV1{schema: values[0], digest: digest, cutoff: values[2], rows: rows}, nil
}
