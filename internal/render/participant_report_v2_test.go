// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package render

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
)

type reportFixture404 struct {
	scope  ParticipantNarrativeScopeDraft402
	rows   []*generated.Event
	old    ParticipantReportV1
	report ParticipantReportV2
}

func newReportFixture404(t *testing.T) reportFixture404 {
	t.Helper()
	f := newNarrativeFixture402(t)
	child := uuid.MustParse("20000000-0000-0000-0000-000000000003")
	f.scope.Documents = []uuid.UUID{child, f.scope.Root}
	comment, event := reportCommentFixtureV1(t)
	comment.DocumentID = f.scope.Root
	event.DocumentID.Bytes = f.scope.Root
	event.OrgID = f.scope.Org
	narrativeHash402(t, event)
	rows := []*generated.Event{event, f.request, f.decision}
	for i, kind := range []string{audit.KindDocumentViewed, audit.KindDocumentSigned, audit.KindDocumentAccepted, "private.intake.observed"} {
		e := *f.request
		e.ID = uuid.New()
		e.CreatedAt.Time = e.CreatedAt.Time.Add(time.Duration(i+2) * time.Microsecond)
		e.Kind = kind
		e.PayloadHashed = []byte(`{"private":"PRIVATE-PAYLOAD-404"}`)
		e.PayloadJson = []byte(`{"display":"DISPLAY-404"}`)
		if kind == audit.KindDocumentAccepted {
			e.RecipientID.Bytes = uuid.MustParse("30000000-0000-0000-0000-000000000004")
		}
		narrativeHash402(t, &e)
		rows = append(rows, &e)
	}
	metadata, err := ParticipantReportEventsV1(rows, f.cutoff)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := ParticipantReportCommentV1FromRow(comment, rows)
	if err != nil {
		t.Fatal(err)
	}
	old := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: f.scope.Root.String(), Cutoff: f.cutoff.UTC().Format(time.RFC3339Nano), Events: metadata, Comments: []ParticipantReportCommentV1{shared},
		Revisions: []ParticipantReportRevisionV1{{ID: uuid.NewString(), DocumentID: child.String(), Name: "Revision Å <1>", SourceKind: "html", At: f.request.CreatedAt.Time.Add(-time.Hour).UTC().Format(time.RFC3339Nano), Number: 1}},
		Proposals: []ParticipantReportProposalV1{{ID: uuid.NewString(), DocumentID: f.scope.Root.String(), Kind: "replace", BlockID: "payment", Text: "Proposed <text> & \u2028Unicode\u2029", Rationale: "Full reason Å 中文", Status: "pending", At: f.request.CreatedAt.Time.UTC().Format(time.RFC3339Nano), UpdatedAt: f.request.CreatedAt.Time.UTC().Format(time.RFC3339Nano)}}}
	for i, id := range []uuid.UUID{f.scope.Root, uuid.New(), uuid.New()} {
		old.Members = append(old.Members, ParticipantReportMemberV1{Position: int32(i), DocumentID: id.String(), Title: []string{"Main", "DPA", "NDA"}[i], Category: []string{"main", "dpa", "nda"}[i], PDFSHA256: strings.Repeat("a", 64), PDFVersionID: "exact-object-version-" + id.String(), PDFBytes: int64(1024 + i), PDFPages: int32(i + 1)})
	}
	for _, e := range rows {
		if e.Kind != audit.KindDocumentSigned && e.Kind != audit.KindDocumentAccepted {
			continue
		}
		kind := "signed"
		signature := uuid.NewString()
		if e.Kind == audit.KindDocumentAccepted {
			kind = "accepted"
			signature = ""
		}
		old.Responses = append(old.Responses, ParticipantReportResponseV1{RecipientID: uuid.UUID(e.RecipientID.Bytes).String(), AttemptID: uuid.NewString(), ManifestSHA256: strings.Repeat("b", 64), LegalCommitmentSHA256: strings.Repeat("c", 64), Kind: kind, SignatureID: signature, EventID: e.ID.String(), EventRowSHA256: hex.EncodeToString(e.RowHash), At: e.CreatedAt.Time.UTC().Format(time.RFC3339Nano), IncorporationVersion: "hash-package-incorporation-v1", IncorporationSHA256: strings.Repeat("d", 64)})
	}
	r, err := NewParticipantReportV2(f.scope, rows, old)
	if err != nil {
		t.Fatal(err)
	}
	return reportFixture404{f.scope, rows, old, r}
}
func cloneReport404(t *testing.T, r ParticipantReportV2) ParticipantReportV2 {
	t.Helper()
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var copy ParticipantReportV2
	if json.Unmarshal(raw, &copy) != nil {
		t.Fatal("clone")
	}
	return copy
}

func TestParticipantReportV2CompleteCanonicalAndNativeScope(t *testing.T) {
	f := newReportFixture404(t)
	raw, sum, err := f.report.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	standard, err := json.Marshal(f.report)
	if err != nil || !bytes.Equal(raw, standard) {
		t.Fatal("fixed writer differs from exact closed JSON semantics", err)
	}
	decoded, err := DecodeParticipantReportCanonicalV2(raw)
	if err != nil || decoded.SourceRowsV2() != f.report.SourceRowsV2() || ParticipantReportCanonicalSHA256V2(raw) != hex.EncodeToString(sum[:]) {
		t.Fatal("canonical round trip", err)
	}
	if len(f.report.Events) != len(f.old.Events) || f.report.SourceRowsV2() != int64(len(f.old.Events)+len(f.old.Comments)+len(f.old.Revisions)+len(f.old.Proposals)+len(f.old.Members)+len(f.old.Responses)) {
		t.Fatal("facts double counted or rows omitted")
	}
	if len(f.report.HistoryScope.DocumentIDs) != 2 || f.report.HistoryScope.DocumentIDs[1] != f.scope.Documents[0].String() {
		t.Fatal("silent native child lost or scope inferred from events")
	}
	if err := VerifyParticipantReportOriginalEventsV2(f.scope, f.rows, f.report); err != nil {
		t.Fatal("complete original association", err)
	}
	if err := VerifyParticipantReportOriginalEventsV2(f.scope, f.rows[:3], f.report); err == nil {
		t.Fatal("root/partial input passed complete event association")
	}
	for _, private := range []string{"PRIVATE-UA-402", "PRIVATE-NOTICE-402", "private-notice-schema-402", "PRIVATE-PAYLOAD-404", "DISPLAY-404", "notice_snapshot", "notice_digest"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatal("private original leaked", private)
		}
	}
}

func TestParticipantReportV2OriginalAndScopeTamperingRefuses(t *testing.T) {
	f := newReportFixture404(t)
	for _, name := range []string{"message", "resolution", "request-link", "event-row", "event-id", "actor", "recipient", "document", "omission", "duplicate", "reorder", "scope-org", "scope-root", "scope-silent-child", "scope-add-attachment", "projection-version"} {
		t.Run(name, func(t *testing.T) {
			r := cloneReport404(t, f.report)
			request, decision := -1, -1
			for i, e := range r.Events {
				if e.Request != nil {
					request = i
				}
				if e.Decision != nil {
					decision = i
				}
			}
			switch name {
			case "message":
				r.Events[request].Request.Message = "Freshly signed false request"
			case "resolution":
				r.Events[decision].Decision.Resolution = "denied"
			case "request-link":
				r.Events[decision].Decision.RequestEventID = uuid.NewString()
			case "event-row":
				r.Events[request].Event.RowSHA256 = strings.Repeat("f", 64)
			case "event-id":
				r.Events[request].Event.ID = uuid.NewString()
			case "actor":
				r.Events[decision].Event.ActorID = uuid.NewString()
			case "recipient":
				r.Events[request].Event.RecipientID = uuid.NewString()
			case "document":
				r.Events[request].Event.DocumentID = f.scope.Documents[0].String()
			case "omission":
				r.Events = r.Events[:len(r.Events)-1]
			case "duplicate":
				r.Events = append(r.Events, r.Events[0])
			case "reorder":
				r.Events[0], r.Events[1] = r.Events[1], r.Events[0]
			case "scope-org":
				r.HistoryScope.OrgID = uuid.NewString()
			case "scope-root":
				r.HistoryScope.RootDocumentID = uuid.NewString()
			case "scope-silent-child":
				r.HistoryScope.DocumentIDs = r.HistoryScope.DocumentIDs[:1]
			case "scope-add-attachment":
				r.HistoryScope.DocumentIDs = append(r.HistoryScope.DocumentIDs, r.Members[1].DocumentID)
			case "projection-version":
				r.EventProjectionVersion = "unknown"
			}
			if err := VerifyParticipantReportOriginalEventsV2(f.scope, f.rows, r); err == nil {
				t.Fatal("changed/partial claim adopted")
			}
		})
	}
	bad := *f.rows[len(f.rows)-1]
	bad.RowHash = bytes.Repeat([]byte{8}, 32)
	rows := append([]*generated.Event(nil), f.rows...)
	rows[len(rows)-1] = &bad
	if _, err := NewParticipantReportV2(f.scope, rows, f.old); err == nil {
		t.Fatal("filtered private row bypassed hash verification")
	}
	old := f.old
	old.Events = append([]ParticipantReportEventV1(nil), old.Events...)
	old.Events[0].RowSHA256 = strings.Repeat("e", 64)
	if _, err := NewParticipantReportV2(f.scope, f.rows, old); err == nil {
		t.Fatal("unverified retained metadata adopted")
	}
}

func TestParticipantReportV2ClosedUnionAndSectionValidation(t *testing.T) {
	f := newReportFixture404(t)
	for _, name := range []string{"unknown-detail", "mixed-union", "missing-request", "future-event", "foreign-comment", "comment-body-link", "comment-actor", "legacy-fake-link", "foreign-revision", "future-proposal", "duplicate-member", "noncontiguous-member", "bad-member-sha", "false-response-kind", "response-signature", "response-row", "response-recipient", "response-event", "bad-scope-order", "duplicate-scope", "bad-root", "schema-v1"} {
		t.Run(name, func(t *testing.T) {
			r := cloneReport404(t, f.report)
			request := 0
			for i, e := range r.Events {
				if e.Request != nil {
					request = i
				}
			}
			switch name {
			case "unknown-detail":
				r.Events[0].Detail = "typed-everything"
			case "mixed-union":
				r.Events[request].Decision = &ParticipantChangeDecisionDraft402{}
			case "missing-request":
				r.Events[request].Request = nil
			case "future-event":
				r.Events[0].Event.At = "2030-01-01T00:00:00Z"
			case "foreign-comment":
				r.Comments[0].DocumentID = uuid.NewString()
			case "comment-body-link":
				r.Comments[0].EventRowSHA256 = strings.Repeat("f", 64)
			case "comment-actor":
				r.Comments[0].ActorID = uuid.NewString()
			case "legacy-fake-link":
				r.Comments[0].Evidence = "legacy-text-not-verified"
			case "foreign-revision":
				r.Revisions[0].DocumentID = uuid.NewString()
			case "future-proposal":
				r.Proposals[0].UpdatedAt = "2030-01-01T00:00:00Z"
			case "duplicate-member":
				r.Members[1].DocumentID = r.Members[0].DocumentID
			case "noncontiguous-member":
				r.Members[1].Position = 7
			case "bad-member-sha":
				r.Members[0].PDFSHA256 = "wrong"
			case "false-response-kind":
				r.Responses[0].Kind = "notice-is-consent"
			case "response-signature":
				r.Responses[0].SignatureID = ""
			case "response-row":
				r.Responses[0].EventRowSHA256 = strings.Repeat("f", 64)
			case "response-recipient":
				r.Responses[0].RecipientID = uuid.NewString()
			case "response-event":
				r.Responses[0].EventID = uuid.NewString()
			case "bad-scope-order":
				r.HistoryScope.DocumentIDs[0], r.HistoryScope.DocumentIDs[1] = r.HistoryScope.DocumentIDs[1], r.HistoryScope.DocumentIDs[0]
			case "duplicate-scope":
				r.HistoryScope.DocumentIDs = append(r.HistoryScope.DocumentIDs, r.HistoryScope.DocumentIDs[0])
			case "bad-root":
				r.HistoryScope.RootDocumentID = uuid.NewString()
			case "schema-v1":
				r.Schema = ParticipantReportSchemaV1
			}
			if _, _, err := r.CanonicalV2(); err == nil {
				t.Fatal("unsupported canonical model accepted")
			}
		})
	}
}

func TestParticipantReportV2CanonicalExactDecoderRefusesAmbiguity(t *testing.T) {
	f := newReportFixture404(t)
	raw, _, err := f.report.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	for _, changed := range [][]byte{
		append(bytes.Clone(raw), []byte(` {}`)...),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schem\u0061":"duplicate","schema":`), 1),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"unknown":true,"schema":`), 1),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{ "schema":`), 1),
		bytes.Replace(raw, []byte(`"Position":0`), []byte(`"Position":0.0`), 1),
		bytes.Replace(raw, []byte(`hash-participant-event-projection-v1`), []byte(`hash-participant-event-projection-v99`), 1),
	} {
		if bytes.Equal(raw, changed) {
			t.Fatal("mutation did not change fixture")
		}
		if _, err := DecodeParticipantReportCanonicalV2(changed); err == nil {
			t.Fatal("ambiguous/noncanonical bytes accepted")
		}
	}
}

func TestParticipantReportHTMLV3CompleteEscapedBoundedAndExplicit(t *testing.T) {
	f := newReportFixture404(t)
	r := cloneReport404(t, f.report)
	r.Comments[0].Body = `<script>alert("unsafe")</script> & 'quoted' Å 中文` + strings.Repeat(" Complete long shared comment.", 2000) + " END-COMMENT-404"
	r.Proposals[0].Text = strings.Repeat("Long proposal Å. ", 2000) + " END-PROPOSAL-404"
	// Display-only formatting does not falsely recompute original comment
	// bodies. Native body association must be established before this call.
	section, digest, err := r.HTMLV3()
	if err != nil {
		t.Fatal(err)
	}
	for _, need := range []string{"END-COMMENT-404", "END-PROPOSAL-404", "&lt;script&gt;", "&#34;unsafe&#34;", "&#39;quoted&#39;", "Å 中文", "Exact native history documents", "details unavailable", "Details unavailable", "Signature recorded", "Explicit acknowledgement recorded", "Complete context", "Canonical public evidence appendix", r.Members[1].PDFVersionID, r.Events[0].Event.RowSHA256} {
		if !strings.Contains(section, need) {
			t.Fatal("complete field/explicit claim missing", need)
		}
	}
	for _, bad := range []string{"<script>", "PRIVATE-UA-402", "PRIVATE-NOTICE-402", "PRIVATE-PAYLOAD-404", "DISPLAY-404", "[truncated, full value"} {
		if strings.Contains(section, bad) {
			t.Fatal("unsafe/private/truncated participant text", bad)
		}
	}
	parsed, got, err := ParseParticipantReportHTMLV3(section)
	if err != nil || digest != got || parsed.Comments[0].Body != r.Comments[0].Body {
		t.Fatal("exact full report parse", err)
	}
	for _, mutate := range []func(string) string{
		func(s string) string {
			return strings.Replace(s, "A participant requested changes", "A participant accepted all changes", 1)
		},
		func(s string) string { return strings.Replace(s, "font-size:11px", "font-size:0px", 1) },
		func(s string) string { return strings.Replace(s, "Complete context", "Accepted contract", 1) },
		func(s string) string { return strings.Replace(s, "</pre>", "</pre><p>Uncommitted extra claim</p>", 1) },
		func(s string) string { return s + "<p>Uncommitted text</p>" },
	} {
		changed := mutate(section)
		if changed == section {
			t.Fatal("mutation unchanged")
		}
		if _, _, err := ParseParticipantReportHTMLV3(changed); err == nil {
			t.Fatal("contradictory presentation accepted")
		}
	}
	r.Comments[0].Body = strings.Repeat("&", MaxCertificatePayloadBytesV1/2)
	if output, hash, err := r.HTMLV3(); err == nil || output != "" || hash != "" {
		t.Fatal("oversized output did not fail without partial artifact", err)
	}
	r.Comments[0].Body = string([]byte{0xff})
	if _, _, err := r.CanonicalV2(); err == nil {
		t.Fatal("lossy invalid UTF8 admitted")
	}
	r.Comments[0].Body = strings.Repeat("x", MaxCertificatePayloadBytesV1+1)
	if _, _, err := r.CanonicalV2(); !errors.Is(err, ErrParticipantReportV1) || !errors.Is(err, ErrCertificatePayloadCapacityV1) {
		t.Fatal("oversized supplied scalar scanned/admitted")
	}
}

func TestParticipantReportV2PreservesArchivedV1CanonicalVector(t *testing.T) {
	r := ParticipantReportV1{Schema: ParticipantReportSchemaV1, DocumentID: "20000000-0000-0000-0000-000000000002", Cutoff: "2026-10-19T12:00:01Z"}
	want := `{"schema":"hash-participant-report-v1","document_id":"20000000-0000-0000-0000-000000000002","cutoff":"2026-10-19T12:00:01Z","events":null,"comments":null,"revisions":null,"proposals":null,"members":null,"responses":null}`
	raw, _, err := r.CanonicalV1()
	if err != nil || string(raw) != want {
		t.Fatal("archived exact V1 canonical vector changed", err)
	}
	for _, formatter := range []func() (string, string, error){r.HTMLV1, r.HTMLV2} {
		section, _, err := formatter()
		if err != nil || !strings.Contains(section, "hash-participant-report-canonical") || strings.Contains(section, "hash-participant-report-canonical-v2") {
			t.Fatal("archived formatter variant changed", err)
		}
	}
}

func TestParticipantReportV2ConstructionPreservesCapacityRefusal(t *testing.T) {
	f := newReportFixture404(t)
	f.old.Comments[0].AuthorName = strings.Repeat("n", MaxCertificatePayloadBytesV1/2+1)
	f.old.Comments[0].Body = strings.Repeat("x", MaxCertificatePayloadBytesV1/2+1)
	r, err := NewParticipantReportV2(f.scope, f.rows, f.old)
	if !errors.Is(err, ErrParticipantReportV1) || !errors.Is(err, ErrCertificatePayloadCapacityV1) || r.Schema != "" {
		t.Fatal("native report construction lost typed capacity refusal or returned partial report", err)
	}
}

// This structural gate deliberately does not replace canonical/semantic checks.
// Empty row objects make the allocation attack small without a valid report.
func TestParticipantReportV2PreflightCumulativeStructuralLimits(t *testing.T) {
	entries := func(n int, value string) string {
		if n == 0 {
			return ""
		}
		return strings.Repeat(value+",", n-1) + value
	}
	rows := func(n int) string { return entries(n, "{}") }
	ids := func(n int) string { return entries(n, `"x"`) }
	cases := []struct {
		name string
		raw  string
		pass bool
	}{
		{"source-at-limit", `{"events":[` + rows(MaxParticipantReportRowsV1) + `]}`, true},
		{"source-over-limit", `{"events":[` + rows(MaxParticipantReportRowsV1+1) + `]}`, false},
		{"all-six-source-arrays-at-limit", `{"events":[` + rows(2000) + `],"comments":[` + rows(2000) + `],"revisions":[` + rows(2000) + `],"proposals":[` + rows(2000) + `],"members":[{}],"responses":[` + rows(1999) + `]}`, true},
		{"all-six-source-arrays-over-limit", `{"events":[` + rows(2000) + `],"comments":[` + rows(2000) + `],"revisions":[` + rows(2000) + `],"proposals":[` + rows(2000) + `],"members":[{}],"responses":[` + rows(2000) + `]}`, false},
		{"duplicate-source-arrays-aggregate", `{"events":[` + rows(6000) + `],"events":[` + rows(4001) + `]}`, false},
		{"escaped-source-alias-aggregates", `{"events":[` + rows(6000) + `],"eve\u006ets":[` + rows(4001) + `]}`, false},
		{"folded-source-alias-aggregates", `{"events":[` + rows(6000) + `],"EVENTS":[` + rows(4001) + `]}`, false},
		{"unicode-folded-source-alias-aggregates", `{"events":[` + rows(6000) + `],"event\u017f":[` + rows(4001) + `]}`, false},
		{"scope-at-limit", `{"history_scope":{"document_ids":[` + ids(MaxParticipantReportRowsV1) + `]}}`, true},
		{"scope-over-limit", `{"history_scope":{"document_ids":[` + ids(MaxParticipantReportRowsV1+1) + `]}}`, false},
		{"duplicate-scope-arrays-aggregate", `{"history_scope":{"document_ids":[` + ids(6000) + `],"document_ids":[` + ids(4001) + `]}}`, false},
		{"duplicate-scope-objects-aggregate", `{"history_scope":{"document_ids":[` + ids(6000) + `]},"history_scope":{"document_ids":[` + ids(4001) + `]}}`, false},
		{"folded-escaped-scope-aliases-aggregate", `{"history_scope":{"document_ids":[` + ids(6000) + `]},"HISTORY_SCOPE":{"DOCUMENT_\u0049DS":[` + ids(4001) + `]}}`, false},
		{"members-at-limit", `{"members":[` + rows(17) + `]}`, true},
		{"members-over-limit", `{"members":[` + rows(18) + `]}`, false},
		{"duplicate-members-aggregate", `{"members":[` + rows(10) + `],"MEMBERS":[` + rows(8) + `]}`, false},
		{"unexpected-array-at-limit", `{"unknown":[` + entries(MaxParticipantReportRowsV1, "0") + `]}`, true},
		{"unexpected-array-over-limit", `{"unknown":[` + entries(MaxParticipantReportRowsV1+1, "0") + `]}`, false},
		{"nested-unexpected-arrays-aggregate", `{"unknown":[[` + entries(5000, "0") + `],[` + entries(5000, "0") + `]]}`, false},
		{"depth-at-limit", `{"unknown":` + strings.Repeat("[", participantReportJSONDepthV2-2) + "0" + strings.Repeat("]", participantReportJSONDepthV2-2) + `}`, true},
		{"depth-over-limit", `{"unknown":` + strings.Repeat("[", participantReportJSONDepthV2-1) + "0" + strings.Repeat("]", participantReportJSONDepthV2-1) + `}`, false},
		{"object-depth-over-limit", `{"unknown":` + strings.Repeat(`{"x":`, participantReportJSONDepthV2-1) + "0" + strings.Repeat("}", participantReportJSONDepthV2-1) + `}`, false},
		{"root-array", `[]`, false},
		{"root-null", `null`, false},
		{"malformed-closing", `{"events":[{]}`, false},
		{"trailing-second-object", `{} {}`, false},
		{"trailing-malformed", `{} x`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := preflightParticipantReportCanonicalV2([]byte(tc.raw))
			if (err == nil) != tc.pass {
				t.Fatalf("structural admission pass=%v, want %v: %v", err == nil, tc.pass, err)
			}
		})
	}
}

func TestParticipantReportV2PreflightPreservesExactCanonicalAdmission(t *testing.T) {
	r := newReportFixture404(t).report
	canonical, _, err := r.CanonicalV2()
	if err != nil {
		t.Fatal(err)
	}
	if preflightParticipantReportCanonicalV2(canonical) != nil {
		t.Fatal("own complete canonical report refused by structural admission")
	}
	decoded, err := DecodeParticipantReportCanonicalV2(canonical)
	if err != nil {
		t.Fatal("own exact canonical report refused", err)
	}
	got, _, err := decoded.CanonicalV2()
	if err != nil || !bytes.Equal(got, canonical) {
		t.Fatal("canonical bytes changed after structural admission", err)
	}
	// These are structurally cheap; exact decoding/regeneration must still refuse.
	for _, bad := range []string{
		strings.Replace(string(canonical), `"events":`, `"EVENTS":`, 1),
		strings.Replace(string(canonical), `"schema":`, `"unknown":null,"schema":`, 1),
		strings.TrimSuffix(string(canonical), "}") + `,"events":[]}`,
		string(canonical) + "\n",
	} {
		if preflightParticipantReportCanonicalV2([]byte(bad)) != nil {
			t.Fatal("fixture did not reach post-preflight canonical refusal")
		}
		if _, err := DecodeParticipantReportCanonicalV2([]byte(bad)); err == nil {
			t.Fatal("structurally bounded noncanonical report admitted")
		}
	}
}

func TestParticipantReportV2DecodeRejectsRowExpansionBeforeTypedAllocation(t *testing.T) {
	// Roughly 30 KiB expands to several MiB of typed row backing arrays if
	// Decode reaches the report struct before enforcing the 10,000-row limit.
	raw := []byte(`{"events":[` + strings.Repeat("{},", MaxParticipantReportRowsV1) + `{}]}`)
	if _, err := DecodeParticipantReportCanonicalV2(raw); err == nil {
		t.Fatal("oversized row cardinality admitted")
	}
	result := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			if _, err := DecodeParticipantReportCanonicalV2(raw); err == nil {
				b.Fatal("oversized row cardinality admitted")
			}
		}
	})
	// The empty-object token walk needs only decoder/stack scratch. This generous
	// ceiling excludes a typed 10,001-row slice even before its growth copies.
	if allocated := result.AllocedBytesPerOp(); allocated > 512<<10 {
		t.Fatalf("row refusal allocated %d bytes/op; typed allocation must follow structural admission", allocated)
	}
}
