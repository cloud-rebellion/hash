// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

// Pure original-event projection. Native owners establish authorized family
// scope and fund all parser/projection/output lifetimes before calling it.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

// Scope comes from the genuine funded root/family snapshot. These scalar IDs
// validate consistency only: a caller-provided scope grants no read authority.
// Separate attachment source documents do not become envelope-family members.
type ParticipantNarrativeScopeDraft402 struct {
	Org, Root uuid.UUID
	Documents []uuid.UUID
}

type ParticipantChangeRequestDraft402 struct {
	ID, Message, BlockID, Quote, Context, Proposed string
}

type ParticipantChangeDecisionDraft402 struct {
	RequestID, Resolution, RequestEventID, Link string
}

// No raw payload, notice, IP/UA, internal intake, guessed identity or generated
// legal conclusion is representable in this closed output. Name/role/company
// lookup is deliberately absent. Metadata actors and recipient subjects differ.
type ParticipantEventFactDraft402 struct {
	Event    ParticipantReportEventV1           `json:"event"`
	Detail   string                             `json:"detail"`
	Request  *ParticipantChangeRequestDraft402  `json:"change_request,omitempty"`
	Decision *ParticipantChangeDecisionDraft402 `json:"change_decision,omitempty"`
}

const (
	narrativeUnavailable402 = "details-unavailable"
	narrativeRequest402     = "change-request"
	narrativeDecision402    = "change-decision"
)

// Every original row, including filtered private kinds, is hash-verified by
// ParticipantReportEventsV1 BEFORE any PayloadHashed field is interpreted.
// PayloadJson is display data and is never used to create a verified fact.
func ParticipantEventNarrativesDraft402(scope ParticipantNarrativeScopeDraft402, events []*generated.Event, cutoff time.Time) ([]ParticipantEventFactDraft402, error) {
	if scope.Org == uuid.Nil || scope.Root == uuid.Nil || cutoff.IsZero() || len(scope.Documents) == 0 || len(scope.Documents) > MaxParticipantReportRowsV1 || len(events) > MaxParticipantReportRowsV1 {
		return nil, ErrParticipantReportV1
	}
	rootFound := false
	documents := make(map[uuid.UUID]struct{}, len(scope.Documents))
	for _, id := range scope.Documents {
		if id == uuid.Nil {
			return nil, ErrParticipantReportV1
		}
		if id == scope.Root {
			rootFound = true
		}
		if _, duplicate := documents[id]; duplicate {
			return nil, ErrParticipantReportV1
		}
		documents[id] = struct{}{}
	}
	if !rootFound {
		return nil, ErrParticipantReportV1
	}
	var raw int64
	for _, event := range events {
		if event == nil || event.OrgID != scope.Org || !event.DocumentID.Valid || (event.ActorUserID.Valid && uuid.UUID(event.ActorUserID.Bytes) == uuid.Nil) || (event.RecipientID.Valid && uuid.UUID(event.RecipientID.Bytes) == uuid.Nil) || int64(len(event.PayloadHashed)) > MaxParticipantReportRawBytesV1-raw {
			return nil, ErrParticipantReportV1
		}
		raw += int64(len(event.PayloadHashed))
		id := uuid.UUID(event.DocumentID.Bytes)
		_, found := documents[id]
		if !found {
			return nil, ErrParticipantReportV1
		}
	}
	metadata, err := ParticipantReportEventsV1(events, cutoff)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]*generated.Event, len(events))
	for _, event := range events {
		byID[event.ID.String()] = event
	}
	result := make([]ParticipantEventFactDraft402, 0, len(metadata))
	for _, meta := range metadata {
		fact := ParticipantEventFactDraft402{Event: meta, Detail: narrativeUnavailable402}
		if meta.Kind == audit.KindChangesRequested {
			fact, err = projectNegotiationFactDraft402(meta, byID[meta.ID].PayloadHashed)
			if err != nil {
				return nil, err
			}
		}
		result = append(result, fact)
	}
	// A decision's request ID alone does not prove which historical text it
	// decided. Link only one earlier original request in the same document.
	requests := make(map[string]int)
	for i := range result {
		fact := &result[i]
		if fact.Request != nil {
			if _, duplicate := requests[fact.Request.ID]; duplicate {
				return nil, ErrParticipantReportV1
			}
			requests[fact.Request.ID] = i
		}
	}
	for i := range result {
		fact := &result[i]
		if fact.Decision == nil {
			continue
		}
		prior, found := requests[fact.Decision.RequestID]
		if !found {
			fact.Decision.Link = "referenced-request-details-unavailable"
			continue
		}
		request := result[prior]
		if prior >= i || request.Event.DocumentID != fact.Event.DocumentID {
			return nil, ErrParticipantReportV1
		}
		fact.Decision.RequestEventID = request.Event.ID
		fact.Decision.Link = "associated-original-request"
	}
	return result, nil
}

// The caller owns/funds original rows and parser/projection/formatter copies.
// This decoder accepts only one complete root object and rejects duplicate
// decoded root keys (including escaped aliases). Nested private notice content
// is never interpreted or copied to a public output; no claim is made about
// its semantic correctness. The full original bytes still enter the row hash.
func narrativeRootDraft402(raw []byte) (map[string]json.RawMessage, bool, error) {
	if len(raw) == 0 || int64(len(raw)) > MaxParticipantReportRawBytesV1 || !utf8.Valid(raw) {
		return nil, false, ErrParticipantReportV1
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false, ErrParticipantReportV1
	}
	// Even unknown keys participate in duplicate detection. Keep their decoded
	// names in one measured slice, rather than an attacker-sized RawMessage map.
	// A root member consumes at least five source bytes ("":0 plus separator).
	keys := make([]string, 0, len(raw)/5)
	result := make(map[string]json.RawMessage, 10)
	unknown := false
	for d.More() {
		key, err := d.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, false, ErrParticipantReportV1
		}
		if len(keys) == cap(keys) {
			return nil, false, ErrParticipantReportV1
		}
		keys = append(keys, name)
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false, ErrParticipantReportV1
		}
		if narrativeKnownKey402(name, true) || narrativeKnownKey402(name, false) {
			result[name] = value
		} else {
			unknown = true
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, false, ErrParticipantReportV1
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, false, ErrParticipantReportV1
	}
	sort.Strings(keys)
	for i := 1; i < len(keys); i++ {
		if keys[i] == keys[i-1] {
			return nil, false, ErrParticipantReportV1
		}
	}
	return result, unknown, nil
}

func narrativeTextDraft402(values map[string]json.RawMessage, key string) (string, error) {
	raw, found := values[key]
	if !found {
		return "", ErrParticipantReportV1
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || !utf8.ValidString(value) {
		return "", ErrParticipantReportV1
	}
	// Exact known-writer scalar spelling also rejects lossy replacement of
	// malformed escaped UTF16 in a public string. Historical other spellings
	// require a separately declared reader variant, never silent normalization.
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return "", ErrParticipantReportV1
	}
	return value, nil
}

func narrativeKnownKey402(key string, request bool) bool {
	switch key {
	case "change_request":
		return true
	case "resolution":
		return !request
	case "message", "block_id", "quote", "context", "proposed", "notice_schema", "notice_digest", "notice_snapshot":
		return request
	}
	return false
}

func narrativeID402(value string) bool {
	id, err := uuid.Parse(value)
	return err == nil && id != uuid.Nil && id.String() == value
}

func projectNegotiationFactDraft402(meta ParticipantReportEventV1, raw []byte) (ParticipantEventFactDraft402, error) {
	fact := ParticipantEventFactDraft402{Event: meta, Detail: narrativeUnavailable402}
	values, unknown, err := narrativeRootDraft402(raw)
	if err != nil {
		return fact, err
	}
	_, decision := values["resolution"]
	_, request := values["message"]
	if decision && request {
		return fact, ErrParticipantReportV1
	}
	if unknown {
		return fact, nil
	}
	for key := range values {
		if !narrativeKnownKey402(key, request) {
			return fact, nil
		}
	}
	// Legacy requests without an original ID/full text binding retain metadata
	// only. Do not infer missing context/proposed text from mutable live rows.
	if !decision && (!request || values["change_request"] == nil || values["context"] == nil || values["proposed"] == nil) {
		return fact, nil
	}
	if !decision && !request {
		return fact, nil
	}
	id, err := narrativeTextDraft402(values, "change_request")
	if err != nil || !narrativeID402(id) {
		return fact, ErrParticipantReportV1
	}
	if decision {
		resolution, err := narrativeTextDraft402(values, "resolution")
		if err != nil || (resolution != "approved" && resolution != "denied") || meta.RecipientID != "" {
			return fact, ErrParticipantReportV1
		}
		fact.Detail = narrativeDecision402
		fact.Decision = &ParticipantChangeDecisionDraft402{RequestID: id, Resolution: resolution}
		return fact, nil
	}
	if meta.RecipientID == "" || meta.ActorID != "" {
		return fact, ErrParticipantReportV1
	}
	parts := make([]string, 0, 5)
	for _, key := range []string{"message", "block_id", "quote", "context", "proposed"} {
		value, err := narrativeTextDraft402(values, key)
		if err != nil {
			return fact, err
		}
		parts = append(parts, value)
	}
	fact.Detail = narrativeRequest402
	fact.Request = &ParticipantChangeRequestDraft402{ID: id, Message: parts[0], BlockID: parts[1], Quote: parts[2], Context: parts[3], Proposed: parts[4]}
	return fact, nil
}

// Independent comparison reprojects from original complete forensic rows.
// It does not trust an issuer signature or caller-provided verified boolean to
// excuse changed facts, omitted rows, identity substitution or scope changes.
func VerifyParticipantEventNarrativesDraft402(scope ParticipantNarrativeScopeDraft402, events []*generated.Event, cutoff time.Time, supplied []ParticipantEventFactDraft402) error {
	wanted, err := ParticipantEventNarrativesDraft402(scope, events, cutoff)
	if err != nil {
		return err
	}
	// Supplied strings may be untrusted or oversized. Compare concrete fields
	// without marshaling/copying them or creating a second arbitrary buffer.
	if len(supplied) != len(wanted) {
		return ErrParticipantReportV1
	}
	for i, expected := range wanted {
		actual := supplied[i]
		if actual.Event != expected.Event || actual.Detail != expected.Detail || (actual.Request == nil) != (expected.Request == nil) || (actual.Decision == nil) != (expected.Decision == nil) {
			return ErrParticipantReportV1
		}
		if actual.Request != nil && *actual.Request != *expected.Request {
			return ErrParticipantReportV1
		}
		if actual.Decision != nil && *actual.Decision != *expected.Decision {
			return ErrParticipantReportV1
		}
	}
	return nil
}

// Small deterministic formatter only. Full new report canonical/HTML binding,
// native receipt and participant-safe certificate assembly are NOT implemented
// here. Returns an ordinary escaped string, never trusted template.HTML.
func ParticipantEventNarrativeSectionDraft402(facts []ParticipantEventFactDraft402) (string, error) {
	if len(facts) > MaxParticipantReportRowsV1 {
		return "", ErrParticipantReportV1
	}
	var out narrativeHTMLDraft402
	out.write(`<section class="hash-event-narrative-draft402"><h4>Recorded negotiation events</h4><p>Details below were projected from original row preimages at the report cutoff. This is an issuer statement about recorded events, not independent identity, authority, contractual effect or organization-chain verification.</p>`)
	for _, fact := range facts {
		if !narrativeID402(fact.Event.ID) || !narrativeID402(fact.Event.DocumentID) || !ParticipantReportVisibleEventV1(fact.Event.Kind) {
			return "", ErrParticipantReportV1
		}
		if fact.Event.ActorID != "" && !narrativeID402(fact.Event.ActorID) {
			return "", ErrParticipantReportV1
		}
		if fact.Event.RecipientID != "" && !narrativeID402(fact.Event.RecipientID) {
			return "", ErrParticipantReportV1
		}
		at, err := time.Parse(time.RFC3339Nano, fact.Event.At)
		sum, hexErr := hex.DecodeString(fact.Event.RowSHA256)
		if err != nil || at.IsZero() || at.UTC().Format(time.RFC3339Nano) != fact.Event.At || hexErr != nil || len(sum) != 32 || hex.EncodeToString(sum) != fact.Event.RowSHA256 {
			return "", ErrParticipantReportV1
		}
		out.write(`<article class="hash-report-record"><p>`)
		out.text(fact.Event.At)
		out.write(` · `)
		out.text(fact.Event.Kind)
		out.write(`</p>`)
		out.field("Document", fact.Event.DocumentID)
		out.field("Staff actor record", fact.Event.ActorID)
		out.field("Recipient subject record", fact.Event.RecipientID)
		switch fact.Detail {
		case narrativeUnavailable402:
			if fact.Request != nil || fact.Decision != nil {
				return "", ErrParticipantReportV1
			}
			out.write(`<p>Details unavailable for this historical or unsupported event shape. No additional fact or legal effect is inferred.</p>`)
		case narrativeRequest402:
			if fact.Event.Kind != audit.KindChangesRequested || fact.Request == nil || fact.Decision != nil || fact.Event.RecipientID == "" || fact.Event.ActorID != "" || !narrativeID402(fact.Request.ID) {
				return "", ErrParticipantReportV1
			}
			out.write(`<h5>A participant requested changes</h5>`)
			out.field("Request", fact.Request.ID)
			out.field("Message", fact.Request.Message)
			out.field("Document reference", fact.Request.BlockID)
			out.field("Quoted text", fact.Request.Quote)
			out.field("Context", fact.Request.Context)
			out.field("Proposed wording", fact.Request.Proposed)
		case narrativeDecision402:
			if fact.Event.Kind != audit.KindChangesRequested || fact.Decision == nil || fact.Request != nil || fact.Event.RecipientID != "" || !narrativeID402(fact.Decision.RequestID) || (fact.Decision.Resolution != "approved" && fact.Decision.Resolution != "denied") {
				return "", ErrParticipantReportV1
			}
			if fact.Decision.Link == "associated-original-request" {
				if !narrativeID402(fact.Decision.RequestEventID) {
					return "", ErrParticipantReportV1
				}
			} else if fact.Decision.Link != "referenced-request-details-unavailable" || fact.Decision.RequestEventID != "" {
				return "", ErrParticipantReportV1
			}
			out.write(`<h5>A request decision was recorded</h5>`)
			out.field("Request", fact.Decision.RequestID)
			out.field("Recorded decision", fact.Decision.Resolution)
			out.field("Original request event", fact.Decision.RequestEventID)
			out.field("Association", fact.Decision.Link)
			out.write(`<p>Approval records a decision about the request. It does not itself prove applied wording, signature, acknowledgement or acceptance of a later version.</p>`)
		default:
			return "", ErrParticipantReportV1
		}
		out.field("Original event", fact.Event.ID)
		out.field("Original row SHA256", fact.Event.RowSHA256)
		out.write(`</article>`)
	}
	out.write(`</section>`)
	if out.err != nil {
		return "", out.err
	}
	return out.builder.String(), nil
}

type narrativeHTMLDraft402 struct {
	builder strings.Builder
	err     error
}

func (w *narrativeHTMLDraft402) write(value string) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.builder.Len() {
		w.err = fmt.Errorf("%w: narrative framing", ErrCertificatePayloadCapacityV1)
		return
	}
	_, _ = w.builder.WriteString(value)
}
func (w *narrativeHTMLDraft402) text(value string) {
	if w.err != nil {
		return
	}
	// Escaping never shortens a string; refuse before scanning a value that
	// already cannot fit the original payload cap. No escaped copy is made.
	if len(value) > MaxCertificatePayloadBytesV1-w.builder.Len() {
		w.err = fmt.Errorf("%w: narrative text", ErrCertificatePayloadCapacityV1)
		return
	}
	if !utf8.ValidString(value) {
		w.err = ErrParticipantReportV1
		return
	}
	start := 0
	for i := 0; i < len(value); i++ {
		var replacement string
		switch value[i] {
		case '&':
			replacement = "&amp;"
		case '<':
			replacement = "&lt;"
		case '>':
			replacement = "&gt;"
		case '"':
			replacement = "&#34;"
		case '\'':
			replacement = "&#39;"
		default:
			continue
		}
		w.write(value[start:i])
		w.write(replacement)
		start = i + 1
		if w.err != nil {
			return
		}
	}
	w.write(value[start:])
}
func (w *narrativeHTMLDraft402) field(label, value string) {
	if value == "" {
		return
	}
	w.write(`<p><strong>`)
	w.text(label)
	w.write(`:</strong> <span style="white-space:pre-wrap;overflow-wrap:anywhere">`)
	w.text(value)
	w.write(`</span></p>`)
}
