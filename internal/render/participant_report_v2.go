// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"io"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
)

const ParticipantReportSchemaV2 = "hash-participant-report-v2"
const ParticipantEventProjectionVersionV1 = "hash-participant-event-projection-v1"
const ParticipantReportHistoryScopeKindV2 = "root-and-direct-envelope-children"

// The native locked snapshot supplies this complete family, including children
// without visible events. This declaration grants no authority to read rows.
// Selected attachment source documents are not implicitly envelope children.
type ParticipantReportHistoryScopeV2 struct {
	Kind           string   `json:"kind"`
	OrgID          string   `json:"org_id"`
	RootDocumentID string   `json:"root_document_id"`
	DocumentIDs    []string `json:"document_ids"`
}

// V2 is a new public projection, not a relabelled V1 or forensic preimage dump.
// Only request/decision variants currently have typed original-payload facts.
// Other visible events retain their metadata and an explicit unavailable label.
type ParticipantReportV2 struct {
	Schema                 string                           `json:"schema"`
	DocumentID             string                           `json:"document_id"`
	Cutoff                 string                           `json:"cutoff"`
	HistoryScope           ParticipantReportHistoryScopeV2  `json:"history_scope"`
	EventProjectionVersion string                           `json:"event_projection_version"`
	Events                 []ParticipantEventFactDraft402   `json:"events"`
	Comments               []ParticipantReportCommentV1     `json:"comments"`
	Revisions              []ParticipantReportRevisionV1    `json:"revisions"`
	Proposals              []ParticipantReportProposalV1    `json:"proposals"`
	Members                []ParticipantReportMemberV1      `json:"members"`
	Responses              []ParticipantReportResponseV1    `json:"responses"`
	DelegatedExecution     *ParticipantDelegatedExecutionV1 `json:"delegated_execution,omitempty"`
}

// NewParticipantReportV2 must be called within the funded original native
// snapshot. Sections borrow that snapshot's strings/slices through formatter
// retirement; the constructor does not deep-copy all retained shared text.
// Native code, not these scalar arguments, establishes authorized completeness.
func NewParticipantReportV2(scope ParticipantNarrativeScopeDraft402, originalEvents []*generated.Event, retained ParticipantReportV1) (ParticipantReportV2, error) {
	var zero ParticipantReportV2
	if retained.Schema != ParticipantReportSchemaV1 || retained.DocumentID != scope.Root.String() {
		return zero, ErrParticipantReportV1
	}
	cutoff, err := time.Parse(time.RFC3339Nano, retained.Cutoff)
	if err != nil || cutoff.IsZero() || cutoff.UTC().Format(time.RFC3339Nano) != retained.Cutoff {
		return zero, ErrParticipantReportV1
	}
	facts, err := ParticipantEventNarrativesDraft402(scope, originalEvents, cutoff)
	if err != nil {
		return zero, err
	}
	if len(facts) != len(retained.Events) {
		return zero, ErrParticipantReportV1
	}
	for i := range facts {
		if facts[i].Event != retained.Events[i] {
			return zero, ErrParticipantReportV1
		}
	}
	documents := make([]string, len(scope.Documents))
	for i, id := range scope.Documents {
		documents[i] = id.String()
	}
	sort.Strings(documents)
	r := ParticipantReportV2{Schema: ParticipantReportSchemaV2, DocumentID: retained.DocumentID, Cutoff: retained.Cutoff,
		HistoryScope:           ParticipantReportHistoryScopeV2{Kind: ParticipantReportHistoryScopeKindV2, OrgID: scope.Org.String(), RootDocumentID: scope.Root.String(), DocumentIDs: documents},
		EventProjectionVersion: ParticipantEventProjectionVersionV1, Events: facts,
		Comments: retained.Comments, Revisions: retained.Revisions, Proposals: retained.Proposals, Members: retained.Members, Responses: retained.Responses}
	if err := r.validateV2(); err != nil {
		return zero, err
	}
	return r, nil
}

// SourceRowsV2 counts each retained PUBLIC source entry once, matching V1 claim
// semantics. Native header cardinality independently includes filtered private
// source rows; facts/labels never inflate either count or substitute for it.
func (r ParticipantReportV2) SourceRowsV2() int64 {
	rows := int64(len(r.Events)) + int64(len(r.Comments)) + int64(len(r.Revisions)) + int64(len(r.Proposals)) + int64(len(r.Members)) + int64(len(r.Responses))
	if r.DelegatedExecution != nil {
		rows++
	}
	return rows
}

func reportStringV2(value string) bool {
	return len(value) <= MaxCertificatePayloadBytesV1 && utf8.ValidString(value)
}
func reportSHA256V2(value string) bool {
	if len(value) != 64 {
		return false
	}
	for i := range value {
		if !(value[i] >= '0' && value[i] <= '9') && !(value[i] >= 'a' && value[i] <= 'f') {
			return false
		}
	}
	return true
}
func reportTimeV2(value string, cutoff time.Time) bool {
	if len(value) > 40 {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !at.IsZero() && at.UTC().Format(time.RFC3339Nano) == value && !at.After(cutoff)
}
func reportIDV2(value string) bool         { return len(value) == 36 && narrativeID402(value) }
func reportOptionalIDV2(value string) bool { return value == "" || reportIDV2(value) }

// Scalar length accounting runs before any UTF8/escape scanning of caller
// strings. The closed model has no maps/cycles; no string contents are copied.
func reportInputBytesV2(v reflect.Value, total *int) bool {
	switch v.Kind() {
	case reflect.String:
		if v.Len() > MaxCertificatePayloadBytesV1-*total {
			return false
		}
		*total += v.Len()
	case reflect.Pointer:
		if !v.IsNil() {
			return reportInputBytesV2(v.Elem(), total)
		}
	case reflect.Slice:
		if v.Len() > MaxParticipantReportRowsV1 {
			return false
		}
		for i := 0; i < v.Len(); i++ {
			if !reportInputBytesV2(v.Index(i), total) {
				return false
			}
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if !reportInputBytesV2(v.Field(i), total) {
				return false
			}
		}
	}
	return true
}

func (r ParticipantReportV2) validateV2() error {
	if !reportInputBytesV2(reflect.ValueOf(r), new(int)) {
		return errors.Join(ErrParticipantReportV1, ErrCertificatePayloadCapacityV1)
	}
	variant := (r.Schema == ParticipantReportSchemaV2 && r.EventProjectionVersion == ParticipantEventProjectionVersionV1 && r.DelegatedExecution == nil) || (r.Schema == ParticipantReportSchemaV3 && r.EventProjectionVersion == ParticipantEventProjectionVersionV2 && r.DelegatedExecution != nil)
	if !variant || !reportIDV2(r.DocumentID) || len(r.Cutoff) > 40 || r.SourceRowsV2() > MaxParticipantReportRowsV1 || len(r.Members) > 17 {
		return ErrParticipantReportV1
	}
	cutoff, err := time.Parse(time.RFC3339Nano, r.Cutoff)
	if err != nil || cutoff.IsZero() || cutoff.UTC().Format(time.RFC3339Nano) != r.Cutoff {
		return ErrParticipantReportV1
	}
	scope := r.HistoryScope
	if scope.Kind != ParticipantReportHistoryScopeKindV2 || !reportIDV2(scope.OrgID) || scope.RootDocumentID != r.DocumentID || len(scope.DocumentIDs) == 0 || len(scope.DocumentIDs) > MaxParticipantReportRowsV1 {
		return ErrParticipantReportV1
	}
	documents := make(map[string]bool, len(scope.DocumentIDs))
	for i, id := range scope.DocumentIDs {
		if !reportIDV2(id) || (i > 0 && scope.DocumentIDs[i-1] >= id) {
			return ErrParticipantReportV1
		}
		documents[id] = true
	}
	if r.DelegatedExecution != nil && (len(scope.DocumentIDs) != 1 || r.DelegatedExecution.validateV1(cutoff) != nil) {
		return ErrParticipantReportV1
	}
	if !documents[r.DocumentID] {
		return ErrParticipantReportV1
	}
	byEvent := make(map[string]int, len(r.Events))
	requests := make(map[string]int)
	for i, f := range r.Events {
		e := f.Event
		if !reportIDV2(e.ID) || !documents[e.DocumentID] || !ParticipantReportVisibleEventV1(e.Kind) || !reportOptionalIDV2(e.ActorID) || !reportOptionalIDV2(e.RecipientID) || !reportSHA256V2(e.RowSHA256) || !reportTimeV2(e.At, cutoff) {
			return ErrParticipantReportV1
		}
		if _, found := byEvent[e.ID]; found {
			return ErrParticipantReportV1
		}
		if r.DelegatedExecution != nil && r.DelegatedExecution.EventID == e.ID {
			return ErrParticipantReportV1
		}
		byEvent[e.ID] = i
		if i > 0 {
			prior := r.Events[i-1].Event
			a, _ := time.Parse(time.RFC3339Nano, prior.At)
			b, _ := time.Parse(time.RFC3339Nano, e.At)
			if a.After(b) || (a.Equal(b) && prior.ID >= e.ID) {
				return ErrParticipantReportV1
			}
		}
		switch f.Detail {
		case narrativeUnavailable402:
			if f.Request != nil || f.Decision != nil {
				return ErrParticipantReportV1
			}
		case narrativeRequest402:
			if e.Kind != audit.KindChangesRequested || e.ActorID != "" || e.RecipientID == "" || f.Request == nil || f.Decision != nil || !reportIDV2(f.Request.ID) {
				return ErrParticipantReportV1
			}
			q := f.Request
			for _, value := range []string{q.Message, q.BlockID, q.Quote, q.Context, q.Proposed} {
				if !reportStringV2(value) {
					return ErrParticipantReportV1
				}
			}
			if _, found := requests[q.ID]; found {
				return ErrParticipantReportV1
			}
			requests[q.ID] = i
		case narrativeDecision402:
			if e.Kind != audit.KindChangesRequested || e.RecipientID != "" || f.Decision == nil || f.Request != nil || !reportIDV2(f.Decision.RequestID) || (f.Decision.Resolution != "approved" && f.Decision.Resolution != "denied") {
				return ErrParticipantReportV1
			}
		default:
			return ErrParticipantReportV1
		}
	}
	for i, f := range r.Events {
		if f.Decision == nil {
			continue
		}
		d := f.Decision
		prior, found := requests[d.RequestID]
		if found {
			if prior >= i || r.Events[prior].Event.DocumentID != f.Event.DocumentID || d.Link != "associated-original-request" || d.RequestEventID != r.Events[prior].Event.ID {
				return ErrParticipantReportV1
			}
		} else if d.Link != "referenced-request-details-unavailable" || d.RequestEventID != "" {
			return ErrParticipantReportV1
		}
	}
	seen := make(map[string]bool)
	for _, c := range r.Comments {
		if !reportIDV2(c.ID) || seen[c.ID] || !documents[c.DocumentID] || !reportIDV2(c.ActorID) || !reportTimeV2(c.At, cutoff) || !reportStringV2(c.AuthorName) || !reportStringV2(c.Body) || (c.Side != "sender" && c.Side != "signer") {
			return ErrParticipantReportV1
		}
		seen[c.ID] = true
		if c.Evidence == "legacy-text-not-verified" {
			if c.EventID != "" || c.EventRowSHA256 != "" {
				return ErrParticipantReportV1
			}
		} else if c.Evidence == "body-and-actor-associated" {
			i, found := byEvent[c.EventID]
			if !found {
				return ErrParticipantReportV1
			}
			e := r.Events[i].Event
			if e.Kind != audit.KindCommentPosted || e.DocumentID != c.DocumentID || e.RowSHA256 != c.EventRowSHA256 || (c.Side == "sender" && (e.ActorID != c.ActorID || e.RecipientID != "")) || (c.Side == "signer" && (e.RecipientID != c.ActorID || e.ActorID != "")) {
				return ErrParticipantReportV1
			}
		} else {
			return ErrParticipantReportV1
		}
	}
	seen = make(map[string]bool)
	for _, v := range r.Revisions {
		if !reportIDV2(v.ID) || seen[v.ID] || !documents[v.DocumentID] || v.Number < 1 || !reportTimeV2(v.At, cutoff) || !reportStringV2(v.Name) || !reportStringV2(v.SourceKind) {
			return ErrParticipantReportV1
		}
		seen[v.ID] = true
	}
	seen = make(map[string]bool)
	for _, p := range r.Proposals {
		if !reportIDV2(p.ID) || seen[p.ID] || !documents[p.DocumentID] || !reportTimeV2(p.At, cutoff) || !reportTimeV2(p.UpdatedAt, cutoff) {
			return ErrParticipantReportV1
		}
		seen[p.ID] = true
		created, _ := time.Parse(time.RFC3339Nano, p.At)
		updated, _ := time.Parse(time.RFC3339Nano, p.UpdatedAt)
		if updated.Before(created) {
			return ErrParticipantReportV1
		}
		for _, value := range []string{p.Kind, p.BlockID, p.Text, p.Rationale, p.Status} {
			if !reportStringV2(value) {
				return ErrParticipantReportV1
			}
		}
	}
	seen = make(map[string]bool)
	for i, m := range r.Members {
		if int(m.Position) != i || !reportIDV2(m.DocumentID) || seen[m.DocumentID] || !reportSHA256V2(m.PDFSHA256) || m.PDFBytes <= 0 || m.PDFPages <= 0 || !reportStringV2(m.Title) || !reportStringV2(m.Category) || !reportStringV2(m.PDFVersionID) || strings.TrimSpace(m.PDFVersionID) == "" {
			return ErrParticipantReportV1
		}
		seen[m.DocumentID] = true
		// Legal member documents may be independent attachment source documents;
		// their inclusion here does not add their earlier history to the scope.
		if i == 0 && m.DocumentID != r.DocumentID {
			return ErrParticipantReportV1
		}
	}
	seen = make(map[string]bool)
	for _, p := range r.Responses {
		if !reportIDV2(p.RecipientID) || !reportIDV2(p.AttemptID) || !reportIDV2(p.EventID) || seen[p.EventID] || !reportSHA256V2(p.ManifestSHA256) || !reportSHA256V2(p.LegalCommitmentSHA256) || !reportSHA256V2(p.EventRowSHA256) || !reportSHA256V2(p.IncorporationSHA256) || !reportStringV2(p.IncorporationVersion) || p.IncorporationVersion == "" || !reportTimeV2(p.At, cutoff) {
			return ErrParticipantReportV1
		}
		seen[p.EventID] = true
		if p.Kind == "signed" {
			if !reportIDV2(p.SignatureID) {
				return ErrParticipantReportV1
			}
		} else if p.Kind == "accepted" {
			if p.SignatureID != "" {
				return ErrParticipantReportV1
			}
		} else {
			return ErrParticipantReportV1
		}
		i, found := byEvent[p.EventID]
		if !found {
			return ErrParticipantReportV1
		}
		e := r.Events[i].Event
		if e.DocumentID != r.DocumentID || e.RecipientID != p.RecipientID || e.ActorID != "" || e.RowSHA256 != p.EventRowSHA256 || e.At != p.At || (p.Kind == "signed" && e.Kind != audit.KindDocumentSigned) || (p.Kind == "accepted" && e.Kind != audit.KindDocumentAccepted) {
			return ErrParticipantReportV1
		}
	}
	return nil
}

// Verify original association only with a separately authorized COMPLETE native
// family input. Root-only events.json cannot establish this full-family claim.
// Shared row completeness/body association remains the native snapshot's duty.
func VerifyParticipantReportOriginalEventsV2(scope ParticipantNarrativeScopeDraft402, originalEvents []*generated.Event, report ParticipantReportV2) error {
	if report.validateV2() != nil || scope.Org.String() != report.HistoryScope.OrgID || scope.Root.String() != report.DocumentID || len(scope.Documents) != len(report.HistoryScope.DocumentIDs) {
		return ErrParticipantReportV1
	}
	ids := make([]string, len(scope.Documents))
	for i, id := range scope.Documents {
		ids[i] = id.String()
	}
	sort.Strings(ids)
	for i, id := range ids {
		if id != report.HistoryScope.DocumentIDs[i] {
			return ErrParticipantReportV1
		}
	}
	cutoff, _ := time.Parse(time.RFC3339Nano, report.Cutoff)
	if err := VerifyParticipantEventNarrativesDraft402(scope, originalEvents, cutoff, report.Events); err != nil {
		return err
	}
	if report.Schema == ParticipantReportSchemaV3 {
		return verifyDelegatedOriginalEventV3(scope, originalEvents, report)
	}
	return nil
}

// Bounded streaming canonical encoding of the closed public model. There are
// no maps, arbitrary interfaces, RawMessage or user-defined marshalers. Exactly
// one exactly measured capped buffer is allocated; no escaped field copies.
type participantJSONWriterV2 struct {
	raw   []byte
	count int
	err   error
}

func (w *participantJSONWriterV2) write(value string) {
	if w.err != nil {
		return
	}
	if len(value) > MaxCertificatePayloadBytesV1-w.count {
		w.err = ErrCertificatePayloadCapacityV1
		return
	}
	w.count += len(value)
	if w.raw != nil {
		w.raw = append(w.raw, value...)
	}
}
func (w *participantJSONWriterV2) text(value string) {
	if w.err != nil {
		return
	}
	if !reportStringV2(value) {
		w.err = ErrParticipantReportV1
		return
	}
	w.write(`"`)
	const hex = "0123456789abcdef"
	start := 0
	for i := 0; i < len(value); {
		n := 1
		replacement := ""
		switch value[i] {
		case '"':
			replacement = `\"`
		case '\\':
			replacement = `\\`
		case '\b':
			replacement = `\b`
		case '\f':
			replacement = `\f`
		case '\n':
			replacement = `\n`
		case '\r':
			replacement = `\r`
		case '\t':
			replacement = `\t`
		case '<':
			replacement = `\u003c`
		case '>':
			replacement = `\u003e`
		case '&':
			replacement = `\u0026`
		default:
			if value[i] < 0x20 {
				replacement = "\\u00" + string([]byte{hex[value[i]>>4], hex[value[i]&15]})
			} else if value[i] >= utf8.RuneSelf {
				r, size := utf8.DecodeRuneInString(value[i:])
				n = size
				if r == '\u2028' {
					replacement = `\u2028`
				}
				if r == '\u2029' {
					replacement = `\u2029`
				}
			}
		}
		if replacement != "" {
			w.write(value[start:i])
			w.write(replacement)
			start = i + n
		}
		i += n
		if w.err != nil {
			return
		}
	}
	w.write(value[start:])
	w.write(`"`)
}
func (w *participantJSONWriterV2) value(v reflect.Value) {
	if w.err != nil {
		return
	}
	switch v.Kind() {
	case reflect.String:
		w.text(v.String())
	case reflect.Int, reflect.Int32, reflect.Int64:
		w.write(strconv.FormatInt(v.Int(), 10))
	case reflect.Pointer:
		if v.IsNil() {
			w.write("null")
		} else {
			w.value(v.Elem())
		}
	case reflect.Slice:
		if v.IsNil() {
			w.write("null")
			return
		}
		w.write("[")
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				w.write(",")
			}
			w.value(v.Index(i))
		}
		w.write("]")
	case reflect.Struct:
		w.write("{")
		count := 0
		typ := v.Type()
		for i := 0; i < v.NumField(); i++ {
			field := typ.Field(i)
			name := field.Name
			tag := field.Tag.Get("json")
			if tag == "-" {
				continue
			}
			if tag != "" {
				fieldName, option, _ := strings.Cut(tag, ",")
				name = fieldName
				if option == "omitempty" && v.Field(i).IsZero() {
					continue
				}
			}
			if count > 0 {
				w.write(",")
			}
			count++
			w.text(name)
			w.write(":")
			w.value(v.Field(i))
		}
		w.write("}")
	default:
		w.err = ErrParticipantReportV1
	}
}
func (r ParticipantReportV2) CanonicalV2() ([]byte, [32]byte, error) {
	var zero [32]byte
	if err := r.validateV2(); err != nil {
		return nil, zero, err
	}
	measure := participantJSONWriterV2{}
	measure.value(reflect.ValueOf(r))
	if measure.err != nil {
		return nil, zero, measure.err
	}
	w := participantJSONWriterV2{raw: make([]byte, 0, measure.count)}
	w.value(reflect.ValueOf(r))
	if w.err != nil || w.count != measure.count {
		return nil, zero, ErrParticipantReportV1
	}
	return w.raw, sha256.Sum256(w.raw), nil
}

// Structural admission precedes typed JSON allocation. Canonical regeneration
// below remains the authority for field spelling, ordering, semantics and bytes.
// Token traversal retains no per-row map or model; its depth and every array's
// cumulative cardinality are bounded even for unknown, repeated or folded keys.
const participantReportJSONDepthV2 = 12

type participantReportJSONRoleV2 uint8

const (
	participantReportJSONAnyV2 participantReportJSONRoleV2 = iota
	participantReportJSONRootV2
	participantReportJSONScopeV2
	participantReportJSONSourceV2
	participantReportJSONMembersV2
	participantReportJSONScopeIDsV2
)

type participantReportJSONPreflightV2 struct {
	decoder           *json.Decoder
	sourceRows        int
	scopeIDs          int
	members           int
	unexpectedEntries int
}

func participantReportJSONFieldRoleV2(parent participantReportJSONRoleV2, key string) participantReportJSONRoleV2 {
	// encoding/json also accepts Unicode case-fold aliases for tagged fields.
	// Count those aliases, escaped names and duplicate arrays cumulatively.
	if parent == participantReportJSONRootV2 {
		for _, name := range [...]string{"events", "comments", "revisions", "proposals", "responses"} {
			if strings.EqualFold(key, name) {
				return participantReportJSONSourceV2
			}
		}
		if strings.EqualFold(key, "members") {
			return participantReportJSONMembersV2
		}
		if strings.EqualFold(key, "history_scope") {
			return participantReportJSONScopeV2
		}
	}
	if parent == participantReportJSONScopeV2 && strings.EqualFold(key, "document_ids") {
		return participantReportJSONScopeIDsV2
	}
	return participantReportJSONAnyV2
}

func (p *participantReportJSONPreflightV2) arrayEntry(role participantReportJSONRoleV2) error {
	switch role {
	case participantReportJSONMembersV2:
		p.members++
		if p.members > 17 {
			return ErrParticipantReportV1
		}
		fallthrough
	case participantReportJSONSourceV2:
		p.sourceRows++
		if p.sourceRows > MaxParticipantReportRowsV1 {
			return ErrParticipantReportV1
		}
	case participantReportJSONScopeIDsV2:
		p.scopeIDs++
		if p.scopeIDs > MaxParticipantReportRowsV1 {
			return ErrParticipantReportV1
		}
	default:
		p.unexpectedEntries++
		if p.unexpectedEntries > MaxParticipantReportRowsV1 {
			return ErrParticipantReportV1
		}
	}
	return nil
}

func (p *participantReportJSONPreflightV2) value(depth int, role participantReportJSONRoleV2) error {
	if depth > participantReportJSONDepthV2 {
		return ErrParticipantReportV1
	}
	token, err := p.decoder.Token()
	if err != nil {
		return ErrParticipantReportV1
	}
	if role == participantReportJSONRootV2 && token != json.Delim('{') {
		return ErrParticipantReportV1
	}
	delim, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delim {
	case '{':
		for p.decoder.More() {
			token, err := p.decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok {
				return ErrParticipantReportV1
			}
			if err := p.value(depth+1, participantReportJSONFieldRoleV2(role, key)); err != nil {
				return err
			}
		}
	case '[':
		for p.decoder.More() {
			if err := p.arrayEntry(role); err != nil {
				return err
			}
			if err := p.value(depth+1, participantReportJSONAnyV2); err != nil {
				return err
			}
		}
	default:
		return ErrParticipantReportV1
	}
	closing, err := p.decoder.Token()
	if err != nil || (delim == '{' && closing != json.Delim('}')) || (delim == '[' && closing != json.Delim(']')) {
		return ErrParticipantReportV1
	}
	return nil
}

func preflightParticipantReportCanonicalV2(raw []byte) error {
	if len(raw) == 0 || len(raw) > MaxCertificatePayloadBytesV1 {
		return ErrParticipantReportV1
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	p := participantReportJSONPreflightV2{decoder: decoder}
	if err := p.value(1, participantReportJSONRootV2); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrParticipantReportV1
	}
	return nil
}

// DecodeParticipantReportCanonicalV2 accepts only exact closed canonical bytes.
// Unknown/duplicate/aliased keys, trailing values, changed order/number spelling
// and lossy string decoding cannot survive exact canonical regeneration.
func DecodeParticipantReportCanonicalV2(raw []byte) (ParticipantReportV2, error) {
	var report ParticipantReportV2
	if len(raw) == 0 || len(raw) > MaxCertificatePayloadBytesV1 || !utf8.Valid(raw) {
		return report, ErrParticipantReportV1
	}
	if preflightParticipantReportCanonicalV2(raw) != nil {
		return report, ErrParticipantReportV1
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil {
		return ParticipantReportV2{}, ErrParticipantReportV1
	}
	canonical, _, err := report.CanonicalV2()
	if err != nil || !bytes.Equal(raw, canonical) {
		return ParticipantReportV2{}, ErrParticipantReportV1
	}
	return report, nil
}

const ParticipantReportCanonicalCarrierV2 = `<pre class="hash-participant-report-canonical-v2" style="white-space:pre-wrap;font-size:7px">`

// ParseParticipantReportHTMLV3 returns only an EXACT standalone formatter result.
// The surrounding evidence verifier separately binds signed document/org/scalars.
func ParseParticipantReportHTMLV3(section string) (ParticipantReportV2, string, error) {
	var zero ParticipantReportV2
	marker, carrier := ParticipantReportHTMLV3Start, ParticipantReportCanonicalCarrierV2
	if strings.HasPrefix(section, ParticipantReportHTMLV4Start) {
		marker, carrier = ParticipantReportHTMLV4Start, ParticipantReportCanonicalCarrierV3
	}
	if len(section) > MaxCertificatePayloadBytesV1 || !strings.HasPrefix(section, marker) || strings.Count(section, carrier) != 1 {
		return zero, "", ErrParticipantReportV1
	}
	start := strings.Index(section, carrier) + len(carrier)
	end := strings.Index(section[start:], "</pre>")
	if end < 0 {
		return zero, "", ErrParticipantReportV1
	}
	raw := []byte(html.UnescapeString(section[start : start+end]))
	r, err := DecodeParticipantReportCanonicalV2(raw)
	if err != nil {
		return zero, "", err
	}
	expected, digest, err := r.HTMLV3()
	if err != nil || section != expected {
		return zero, "", ErrParticipantReportV1
	}
	return r, digest, nil
}

// Used by evidence/native callers without re-marshaling arbitrary fact input.
func ParticipantReportCanonicalSHA256V2(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
