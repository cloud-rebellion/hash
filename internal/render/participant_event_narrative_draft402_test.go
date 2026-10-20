// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

// Future tests for the isolated pure Draft402 slice. Not executed by its author.
// They do not enable or qualify a new report, schema, receipt or PDF pipeline.
import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestNarrativeManyUnknownFieldsStillRejectsLateDuplicate402(t *testing.T) {
	f := newNarrativeFixture402(t)
	var payload strings.Builder
	payload.WriteString(`{"message":"legacy"`)
	for i := 0; i < 2048; i++ {
		payload.WriteString(`,"private_` + strconv.Itoa(i) + `":{"nested":"not public"}`)
	}
	payload.WriteByte('}')
	f.request.PayloadHashed = []byte(payload.String())
	narrativeHash402(t, f.request)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{f.request}, f.cutoff)
	if err != nil || len(facts) != 1 || facts[0].Detail != narrativeUnavailable402 || facts[0].Request != nil {
		t.Fatalf("unknown legacy fields must retain metadata only: %v", err)
	}
	// Decoded aliases of unknown keys are duplicates too, even at the end of
	// a large object whose unknown values will never enter the public report.
	f.request.PayloadHashed = []byte(strings.TrimSuffix(payload.String(), "}") + `,"privat\u0065_0":null}`)
	narrativeHash402(t, f.request)
	if _, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{f.request}, f.cutoff); err == nil {
		t.Fatal("late escaped duplicate accepted")
	}
}

type narrativeFixture402 struct {
	scope             ParticipantNarrativeScopeDraft402
	cutoff            time.Time
	request, decision *generated.Event
}

func newNarrativeFixture402(t *testing.T) narrativeFixture402 {
	t.Helper()
	org := uuid.MustParse("10000000-0000-0000-0000-000000000001")
	root := uuid.MustParse("20000000-0000-0000-0000-000000000002")
	recipient := uuid.MustParse("30000000-0000-0000-0000-000000000003")
	actor := uuid.MustParse("40000000-0000-0000-0000-000000000004")
	at := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	request := &generated.Event{ID: uuid.MustParse("50000000-0000-0000-0000-000000000005"), OrgID: org, DocumentID: pgtype.UUID{Bytes: root, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient, Valid: true}, Kind: audit.KindChangesRequested, CreatedAt: pgtype.Timestamptz{Time: at, Valid: true}, Ua: pgtype.Text{String: "PRIVATE-UA-402", Valid: true}, PrevHash: bytes.Repeat([]byte{1}, 32)}
	body := map[string]any{"change_request": "60000000-0000-0000-0000-000000000006", "message": "Please adjust <payment> & Å terms", "block_id": "scope", "quote": "Agreed terms", "context": "Shared context", "proposed": "Revised agreed terms", "notice_schema": "private-notice-schema-402", "notice_digest": strings.Repeat("b", 64), "notice_snapshot": map[string]any{"private": "PRIVATE-NOTICE-402"}}
	request.PayloadHashed, _ = json.Marshal(body)
	request.PayloadJson = []byte(`{"message":"DISPLAY-PAYLOAD-MUST-NOT-ATTEST"}`)
	narrativeHash402(t, request)
	decision := &generated.Event{ID: uuid.MustParse("70000000-0000-0000-0000-000000000007"), OrgID: org, DocumentID: request.DocumentID, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true}, Kind: audit.KindChangesRequested, CreatedAt: pgtype.Timestamptz{Time: at.Add(time.Microsecond), Valid: true}, PrevHash: bytes.Clone(request.RowHash), PayloadHashed: []byte(`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"approved"}`)}
	narrativeHash402(t, decision)
	return narrativeFixture402{ParticipantNarrativeScopeDraft402{Org: org, Root: root, Documents: []uuid.UUID{root}}, at.Add(time.Second), request, decision}
}
func narrativeHash402(t *testing.T, e *generated.Event) {
	t.Helper()
	var err error
	e.RowHash, err = audit.RecomputeEventRowHash(e)
	if err != nil {
		t.Fatal(err)
	}
}
func narrativeRows402(f narrativeFixture402) []*generated.Event {
	return []*generated.Event{f.decision, f.request}
}
func narrativeCloneFacts402(t *testing.T, in []ParticipantEventFactDraft402) []ParticipantEventFactDraft402 {
	t.Helper()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []ParticipantEventFactDraft402
	if json.Unmarshal(raw, &out) != nil {
		t.Fatal("clone")
	}
	return out
}

func TestDraft402ModernOriginalFactsAndDecisionLink(t *testing.T) {
	f := newNarrativeFixture402(t)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff)
	if err != nil || len(facts) != 2 || facts[0].Request == nil || facts[0].Request.Message != "Please adjust <payment> & Å terms" || facts[1].Decision == nil || facts[1].Decision.RequestEventID != f.request.ID.String() || facts[1].Decision.Link != "associated-original-request" {
		t.Fatal("original facts or same-document link", facts, err)
	}
	if facts[0].Event.ActorID != "" || facts[0].Event.RecipientID == "" || facts[1].Event.ActorID == "" || facts[1].Event.RecipientID != "" {
		t.Fatal("actor and subject conflated")
	}
	raw, _ := json.Marshal(facts)
	for _, private := range []string{"PRIVATE-UA-402", "PRIVATE-NOTICE-402", "private-notice-schema-402", "DISPLAY-PAYLOAD-MUST-NOT-ATTEST", "notice_snapshot", "notice_digest"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private/display input escaped closed output", private)
		}
	}
	f.request.PayloadJson = []byte(`{"message":"OTHER-DISPLAY"}`)
	if err := VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, facts); err != nil {
		t.Fatal("display payload became authority", err)
	}
}

func TestDraft402OriginalTamperingFailsBeforeProjection(t *testing.T) {
	for _, name := range []string{"hashed-payload", "row-hash", "actor", "recipient", "document", "organization", "time", "ua", "prev-hash", "duplicate", "cutoff"} {
		t.Run(name, func(t *testing.T) {
			f := newNarrativeFixture402(t)
			copy := *f.request
			rows := []*generated.Event{&copy, f.decision}
			cutoff := f.cutoff
			switch name {
			case "hashed-payload":
				copy.PayloadHashed = []byte(`{"message":"tampered"}`)
			case "row-hash":
				copy.RowHash = bytes.Repeat([]byte{9}, 32)
			case "actor":
				copy.ActorUserID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
			case "recipient":
				copy.RecipientID.Bytes = uuid.New()
			case "document":
				copy.DocumentID.Bytes = uuid.New()
			case "organization":
				copy.OrgID = uuid.New()
			case "time":
				copy.CreatedAt.Time = copy.CreatedAt.Time.Add(time.Microsecond)
			case "ua":
				copy.Ua.String = "changed"
			case "prev-hash":
				copy.PrevHash = bytes.Repeat([]byte{8}, 32)
			case "duplicate":
				rows = append(rows, &copy)
			case "cutoff":
				cutoff = copy.CreatedAt.Time.Add(-time.Microsecond)
			}
			if _, err := ParticipantEventNarrativesDraft402(f.scope, rows, cutoff); err == nil {
				t.Fatal("changed original accepted")
			}
		})
	}
}

func TestDraft402LegacyUnknownAndPrivateVisibility(t *testing.T) {
	f := newNarrativeFixture402(t)
	legacy := *f.request
	legacy.PayloadHashed = []byte(`{"message":"historical text without original request ID"}`)
	narrativeHash402(t, &legacy)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{&legacy, f.decision}, f.cutoff)
	if err != nil || len(facts) != 2 || facts[0].Detail != narrativeUnavailable402 || facts[0].Request != nil || facts[1].Decision.Link != "referenced-request-details-unavailable" || facts[1].Decision.RequestEventID != "" {
		t.Fatal("legacy text/link retrospectively attested", facts, err)
	}
	unknown := *f.request
	var payload map[string]any
	_ = json.Unmarshal(unknown.PayloadHashed, &payload)
	payload["internal_extra"] = "SECRET-UNKNOWN-402"
	unknown.PayloadHashed, _ = json.Marshal(payload)
	narrativeHash402(t, &unknown)
	facts, err = ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{&unknown}, f.cutoff)
	if err != nil || len(facts) != 1 || facts[0].Request != nil || facts[0].Detail != narrativeUnavailable402 {
		t.Fatal("unknown shape was promoted", facts, err)
	}
	private := *f.request
	private.ID = uuid.New()
	private.Kind = "crm.variables.observed"
	private.PayloadHashed = []byte(`{"internal":"PRIVATE-INTERNAL-402"}`)
	narrativeHash402(t, &private)
	facts, err = ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{f.request, &private}, f.cutoff)
	if err != nil || len(facts) != 1 {
		t.Fatal("private event became participant-visible", facts, err)
	}
	private.RowHash = bytes.Repeat([]byte{7}, 32)
	if _, err = ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{f.request, &private}, f.cutoff); err == nil {
		t.Fatal("private row bypassed original commitment verification")
	}
}

func TestDraft402PayloadAmbiguityAndBadTypedFieldsRefuse(t *testing.T) {
	for _, body := range []string{
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"approved","resolution":"denied"}`,
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"approved","resolutio\u006e":"denied"}`,
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"approved"} {}`,
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":true}`,
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"accepted"}`,
		`{"change_request":"60000000-0000-0000-0000-000000000006","resolution":"approved","message":"contradictory request"}`,
		`{"change_request":"invalid","resolution":"approved"}`,
	} {
		t.Run(body, func(t *testing.T) {
			f := newNarrativeFixture402(t)
			e := *f.decision
			e.PayloadHashed = []byte(body)
			narrativeHash402(t, &e)
			if _, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{&e}, f.cutoff); err == nil {
				t.Fatal("ambiguous/incorrect typed body accepted")
			}
		})
	}
	f := newNarrativeFixture402(t)
	e := *f.request
	e.PayloadHashed = []byte(`{"block_id":"scope","change_request":"60000000-0000-0000-0000-000000000006","context":"","message":"\ud800","proposed":"","quote":""}`)
	narrativeHash402(t, &e)
	if _, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{&e}, f.cutoff); err == nil {
		t.Fatal("lossy public UTF16 replacement accepted")
	}
}

func TestDraft402RequestAssociationIsSameDocumentUniqueAndEarlier(t *testing.T) {
	for _, name := range []string{"cross-document", "duplicate-request", "decision-earlier"} {
		t.Run(name, func(t *testing.T) {
			f := newNarrativeFixture402(t)
			request := *f.request
			decision := *f.decision
			rows := []*generated.Event{&request, &decision}
			switch name {
			case "cross-document":
				child := uuid.New()
				f.scope.Documents = append(f.scope.Documents, child)
				request.DocumentID.Bytes = child
				narrativeHash402(t, &request)
			case "duplicate-request":
				other := request
				other.ID = uuid.New()
				other.CreatedAt.Time = other.CreatedAt.Time.Add(time.Nanosecond)
				narrativeHash402(t, &other)
				rows = append(rows, &other)
			case "decision-earlier":
				decision.CreatedAt.Time = request.CreatedAt.Time.Add(-time.Microsecond)
				narrativeHash402(t, &decision)
			}
			if _, err := ParticipantEventNarrativesDraft402(f.scope, rows, f.cutoff); err == nil {
				t.Fatal("false request association accepted")
			}
		})
	}
}

func TestDraft402AssociationComparisonRejectsChangedOrOmittedFacts(t *testing.T) {
	f := newNarrativeFixture402(t)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"message", "decision", "request-link", "actor", "row", "omitted", "reordered", "duplicate"} {
		t.Run(name, func(t *testing.T) {
			changed := narrativeCloneFacts402(t, facts)
			switch name {
			case "message":
				changed[0].Request.Message = "freshly signed but false"
			case "decision":
				changed[1].Decision.Resolution = "denied"
			case "request-link":
				changed[1].Decision.RequestEventID = uuid.NewString()
			case "actor":
				changed[1].Event.ActorID = uuid.NewString()
			case "row":
				changed[0].Event.RowSHA256 = strings.Repeat("f", 64)
			case "omitted":
				changed = changed[:1]
			case "reordered":
				changed[0], changed[1] = changed[1], changed[0]
			case "duplicate":
				changed = append(changed, changed[0])
			}
			if err := VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, changed); err == nil {
				t.Fatal("supplied claim replaced original evidence")
			}
		})
	}
}

func TestDraft402EscapedCompleteTextAndOriginalPayloadCap(t *testing.T) {
	f := newNarrativeFixture402(t)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff)
	if err != nil {
		t.Fatal(err)
	}
	facts[0].Request.Message = `<script>alert("x")</script> & 'quoted' ÅÄÖ 中文` + strings.Repeat(" Full shared text.", 100) + " END-402"
	html, err := ParticipantEventNarrativeSectionDraft402(facts)
	if err != nil || strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") || !strings.Contains(html, "&#34;x&#34;") || !strings.Contains(html, "END-402") || !strings.Contains(html, "ÅÄÖ 中文") {
		t.Fatal("unsafe or truncated text", err)
	}
	facts[0].Request.Message = strings.Repeat("<", MaxCertificatePayloadBytesV1/3)
	if html, err = ParticipantEventNarrativeSectionDraft402(facts); !errors.Is(err, ErrCertificatePayloadCapacityV1) || html != "" {
		t.Fatal("overflow did not refuse entire output", len(html), err)
	}
	facts[0].Detail = "invented-legal-effect"
	if _, err = ParticipantEventNarrativeSectionDraft402(facts); err == nil {
		t.Fatal("unrecognized legal narrative accepted")
	}
}

func TestDraft402ExistingRowRawScopeLimitsRefuse(t *testing.T) {
	f := newNarrativeFixture402(t)
	if _, err := ParticipantEventNarrativesDraft402(f.scope, make([]*generated.Event, MaxParticipantReportRowsV1+1), f.cutoff); err == nil {
		t.Fatal("row overflow accepted")
	}
	e := *f.request
	e.PayloadHashed = bytes.Repeat([]byte{'x'}, int(MaxParticipantReportRawBytesV1)+1)
	if _, err := ParticipantEventNarrativesDraft402(f.scope, []*generated.Event{&e}, f.cutoff); err == nil {
		t.Fatal("raw overflow accepted")
	}
	f.scope.Documents = append(f.scope.Documents, f.scope.Root)
	if _, err := ParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff); err == nil {
		t.Fatal("ambiguous family scope accepted")
	}
}

func TestDraft402OversizedOrStructurallyDifferentSuppliedFactsRefuse(t *testing.T) {
	f := newNarrativeFixture402(t)
	facts, err := ParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff)
	if err != nil {
		t.Fatal(err)
	}
	changed := narrativeCloneFacts402(t, facts)
	changed[0].Request.Message = strings.Repeat("x", MaxCertificatePayloadBytesV1+1)
	if err = VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, changed); err == nil {
		t.Fatal("oversized supplied fact accepted")
	}
	if html, err := ParticipantEventNarrativeSectionDraft402(changed); !errors.Is(err, ErrCertificatePayloadCapacityV1) || html != "" {
		t.Fatal("oversized supplied text was partially emitted", len(html), err)
	}
	changed = narrativeCloneFacts402(t, facts)
	changed[0].Request = nil
	if err = VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, changed); err == nil {
		t.Fatal("missing tagged request accepted")
	}
	changed = narrativeCloneFacts402(t, facts)
	changed[0].Decision = &ParticipantChangeDecisionDraft402{}
	if err = VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, changed); err == nil {
		t.Fatal("extra tagged decision accepted")
	}
	if err = VerifyParticipantEventNarrativesDraft402(f.scope, narrativeRows402(f), f.cutoff, make([]ParticipantEventFactDraft402, MaxParticipantReportRowsV1+1)); err == nil {
		t.Fatal("oversized supplied row set accepted")
	}
}
