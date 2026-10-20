// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/manualfit"
	"github.com/bright-interaction/hash/internal/render"
)

type participantReportClaimV1 struct {
	schema, digest, cutoff string
	rows                   int64
}

// The exact canonical JSON and its visible HTML are both inside the detached
// signature. Parsing checks their association as well as the scalar digest;
// a valid issuer signature cannot make conflicting report claims consistent.
// Absence preserves archived certificate parsing without inventing new proof.
func parseParticipantReportClaimV1(payload []byte, document string) (participantReportClaimV1, error) {
	var result participantReportClaimV1
	keys := []string{"data-hash-participant-report-schema", "data-hash-participant-report-sha256", "data-hash-participant-report-cutoff", "data-hash-participant-report-rows"}
	values := [4]string{}
	presence := 0
	for i, k := range keys {
		v, p, err := optionalCertificateTextClaim(payload, k)
		if err != nil {
			return result, err
		}
		if p {
			presence++
		}
		values[i] = v
	}
	sectionStart := []byte(`<section class="hash-participant-report">`)
	preStart := []byte(`<pre class="hash-participant-report-canonical" style="white-space:pre-wrap;font-size:7px">`)
	if presence == 0 {
		if bytes.Contains(payload, sectionStart) || bytes.Contains(payload, preStart) {
			return result, errors.New("participant report body lacks signed versioned claims")
		}
		return result, nil
	}
	if presence != 4 || values[0] != render.ParticipantReportSchemaV1 || len(payload) > int(manualfit.MaxCertificatePayloadBytesV1) || bytes.Count(payload, sectionStart) != 1 || bytes.Count(payload, preStart) != 1 {
		return result, errors.New("signed participant report is incomplete, ambiguous or oversized")
	}
	digest, err := certificateSHA256Claim(payload, keys[1])
	if err != nil {
		return result, err
	}
	cutoff, err := time.Parse(time.RFC3339Nano, values[2])
	if err != nil || cutoff.IsZero() || cutoff.UTC().Format(time.RFC3339Nano) != values[2] {
		return result, errors.New("signed participant report cutoff is invalid")
	}
	rows, err := strconv.ParseInt(values[3], 10, 64)
	if err != nil || rows < 0 || rows > render.MaxParticipantReportRowsV1 || strconv.FormatInt(rows, 10) != values[3] {
		return result, errors.New("signed participant report row count is invalid")
	}
	start := bytes.Index(payload, preStart) + len(preStart)
	end := bytes.Index(payload[start:], []byte(`</pre>`))
	if end < 0 {
		return result, errors.New("signed participant report canonical body is absent")
	}
	raw := []byte(html.UnescapeString(string(payload[start : start+end])))
	if int64(len(raw)) > render.MaxParticipantReportRawBytesV1 {
		return result, errors.New("signed participant report canonical body is oversized")
	}
	var report render.ParticipantReportV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil {
		return result, errors.New("signed participant report canonical body is invalid")
	}
	canonical, sum, err := report.CanonicalV1()
	if err != nil || !bytes.Equal(raw, canonical) || hex.EncodeToString(sum[:]) != digest || report.DocumentID != document || report.Cutoff != values[2] || int64(len(report.Events)+len(report.Comments)+len(report.Revisions)+len(report.Proposals)+len(report.Members)+len(report.Responses)) != rows {
		return result, errors.New("signed participant report canonical body contradicts its claims")
	}
	sectionOffset := bytes.Index(payload, sectionStart)
	var section, generatedDigest string
	if bytes.HasPrefix(payload[sectionOffset:], []byte(render.ParticipantReportHTMLV2Start)) {
		section, generatedDigest, err = report.HTMLV2()
	} else {
		section, generatedDigest, err = report.HTMLV1()
	}
	if err != nil || generatedDigest != digest {
		return result, errors.New("signed participant report formatting is inconsistent")
	}
	if !bytes.HasPrefix(payload[sectionOffset:], []byte(section)) {
		return result, errors.New("signed participant report visible text contradicts canonical evidence")
	}
	// Canonical exactness rejects duplicate JSON members and trailing values.
	actual := sha256.Sum256(canonical)
	if hex.EncodeToString(actual[:]) != digest {
		return result, errors.New("signed participant report digest differs")
	}
	return participantReportClaimV1{schema: values[0], digest: digest, cutoff: values[2], rows: rows}, nil
}
