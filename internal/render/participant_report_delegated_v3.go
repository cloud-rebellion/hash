// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/db/generated"
)

const ParticipantReportSchemaV3 = "hash-participant-report-v3"
const ParticipantEventProjectionVersionV2 = "hash-participant-event-projection-v2"
const ParticipantReportHTMLV4Start = `<section class="hash-participant-report"><div class="hash-participant-report-v3 hash-participant-report-v4" data-hash-participant-report-layout="4">`
const ParticipantReportCanonicalCarrierV3 = `<pre class="hash-participant-report-canonical-v3" style="white-space:pre-wrap;font-size:7px">`
const delegatedDisclosureTextV1 = "The provider signature was applied under a named, revocable Hash pre-signing grant for this exact approved document and workflow. This delegated execution is separate from the customer's manual signature."

// This closed PUBLIC projection is an issuer's versioned account of retained
// delegated execution, separate from the customer's manual response. It has no
// credential, private locator, company-registry verification or QES assertion.
// Native owners verify the exact original event and immutable execution/assets;
// these scalar fields alone never grant signing or publication authority.
type ParticipantDelegatedExecutionV1 struct {
	SchemaVersion       int    `json:"schema_version"`
	EventID             string `json:"event_id"`
	EventRowSHA256      string `json:"event_row_sha256"`
	EventAt             string `json:"event_at"`
	ExecutionID         string `json:"execution_id"`
	ExecutionSHA256     string `json:"execution_sha256"`
	PolicyID            string `json:"policy_id"`
	PolicyRevision      int64  `json:"policy_revision"`
	PolicySHA256        string `json:"policy_sha256"`
	GrantID             string `json:"grant_id"`
	GrantRevision       int64  `json:"grant_revision"`
	GrantSHA256         string `json:"grant_sha256"`
	UseNumber           int64  `json:"use_number"`
	ProviderRecipientID string `json:"provider_recipient_id"`
	ProviderSignatureID string `json:"provider_signature_id"`
	ProviderName        string `json:"provider_name"`
	ExecutedAt          string `json:"executed_at"`
	BasePDFSHA256       string `json:"base_pdf_sha256"`
	VisiblePDFSHA256    string `json:"visible_pdf_sha256"`
	AssetsSHA256        string `json:"assets_sha256"`
	OverlayProofSHA256  string `json:"overlay_proof_sha256"`
	DisclosureVersion   int64  `json:"disclosure_version"`
	DisclosureSHA256    string `json:"disclosure_sha256"`
	DisclosureText      string `json:"disclosure_text"`
}

func (d ParticipantDelegatedExecutionV1) validateV1(cutoff time.Time) error {
	if d.SchemaVersion != 1 || d.PolicyRevision < 1 || d.PolicyRevision > 1000000 || d.GrantRevision < 1 || d.GrantRevision > 1000000 || d.UseNumber < 1 || d.UseNumber > 1000000 ||
		d.DisclosureVersion != 1 || d.DisclosureText != delegatedDisclosureTextV1 || len(d.ProviderName) < 1 || len(d.ProviderName) > 800 || !utf8.ValidString(d.ProviderName) || utf8.RuneCountInString(d.ProviderName) > 200 || strings.TrimSpace(d.ProviderName) == "" || d.BasePDFSHA256 == d.VisiblePDFSHA256 ||
		!reportTimeV2(d.EventAt, cutoff) || !reportTimeV2(d.ExecutedAt, cutoff) {
		return ErrParticipantReportV1
	}
	for _, id := range []string{d.EventID, d.ExecutionID, d.PolicyID, d.GrantID, d.ProviderRecipientID, d.ProviderSignatureID} {
		if !reportIDV2(id) {
			return ErrParticipantReportV1
		}
	}
	for _, hash := range []string{d.EventRowSHA256, d.ExecutionSHA256, d.PolicySHA256, d.GrantSHA256, d.BasePDFSHA256, d.VisiblePDFSHA256, d.AssetsSHA256, d.OverlayProofSHA256, d.DisclosureSHA256} {
		if !reportSHA256V2(hash) {
			return ErrParticipantReportV1
		}
	}
	sum := sha256.Sum256([]byte("hash:presign-disclosure:v1\x00" + d.DisclosureText))
	if hex.EncodeToString(sum[:]) != d.DisclosureSHA256 {
		return ErrParticipantReportV1
	}
	at, _ := time.Parse(time.RFC3339Nano, d.EventAt)
	executed, _ := time.Parse(time.RFC3339Nano, d.ExecutedAt)
	if at.Before(executed) {
		return ErrParticipantReportV1
	}
	return nil
}

func NewParticipantReportV3(scope ParticipantNarrativeScopeDraft402, events []*generated.Event, retained ParticipantReportV1, delegated ParticipantDelegatedExecutionV1) (ParticipantReportV2, error) {
	r, err := NewParticipantReportV2(scope, events, retained)
	if err != nil {
		return ParticipantReportV2{}, err
	}
	r.Schema = ParticipantReportSchemaV3
	r.EventProjectionVersion = ParticipantEventProjectionVersionV2
	r.DelegatedExecution = &delegated
	if err := r.validateV2(); err != nil {
		return ParticipantReportV2{}, err
	}
	if err := verifyDelegatedOriginalEventV3(scope, events, r); err != nil {
		return ParticipantReportV2{}, err
	}
	return r, nil
}

func verifyDelegatedOriginalEventV3(scope ParticipantNarrativeScopeDraft402, events []*generated.Event, r ParticipantReportV2) error {
	if r.DelegatedExecution == nil || len(scope.Documents) != 1 || scope.Documents[0] != scope.Root {
		return ErrParticipantReportV1
	}
	d := r.DelegatedExecution
	found := false
	for _, e := range events {
		if e != nil && e.ID.String() == d.EventID {
			if found || e.OrgID != scope.Org || !e.DocumentID.Valid || e.DocumentID.Bytes != scope.Root || e.Kind != "presign.execution.committed" ||
				!e.CreatedAt.Valid || e.CreatedAt.Time.UTC().Format(time.RFC3339Nano) != d.EventAt || hex.EncodeToString(e.RowHash) != d.EventRowSHA256 {
				return ErrParticipantReportV1
			}
			found = true
		}
	}
	if !found {
		return ErrParticipantReportV1
	}
	return nil
}

func (w *participantHTMLWriterV3) delegatedV3(d *ParticipantDelegatedExecutionV1) {
	w.write(`<h4>Delegated provider execution</h4><p>The provider mark was applied by Hash under the recorded grant. This is separate from the customer's later manual signature. Retained execution and object commitments establish the issuer's account of that delegated operation; they do not independently verify company representation, current grant eligibility or qualified legal effect.</p>`)
	w.field("Provider name (retained declaration)", d.ProviderName, false)
	w.field("Executed at (UTC)", d.ExecutedAt, false)
	w.field("Execution ID", d.ExecutionID, true)
	w.field("Execution SHA-256", d.ExecutionSHA256, true)
	w.field("Policy ID", d.PolicyID, true)
	w.field("Policy revision", strconv.FormatInt(d.PolicyRevision, 10), false)
	w.field("Policy SHA-256", d.PolicySHA256, true)
	w.field("Grant ID", d.GrantID, true)
	w.field("Grant revision", strconv.FormatInt(d.GrantRevision, 10), false)
	w.field("Grant SHA-256", d.GrantSHA256, true)
	w.field("Recorded use number", strconv.FormatInt(d.UseNumber, 10), false)
	w.field("Provider recipient ID", d.ProviderRecipientID, true)
	w.field("Provider signature ID", d.ProviderSignatureID, true)
	w.field("Original base PDF SHA-256", d.BasePDFSHA256, true)
	w.field("Customer-visible provider PDF SHA-256", d.VisiblePDFSHA256, true)
	w.field("Exact archived asset-set commitment", d.AssetsSHA256, true)
	w.field("Original visible-overlay proof SHA-256", d.OverlayProofSHA256, true)
	w.field("Original committed event ID", d.EventID, true)
	w.field("Original committed event row SHA-256", d.EventRowSHA256, true)
	w.field("Original committed event at (UTC)", d.EventAt, false)
	w.field("Disclosure version", strconv.FormatInt(d.DisclosureVersion, 10), false)
	w.field("Disclosure SHA-256", d.DisclosureSHA256, true)
	w.textField("Complete provider disclosure", d.DisclosureText)
}
