// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func apiSupersessionFixtureV1() (preSignAPISourceInputV1, uuid.UUID, string, pdfadmission.PreSignSupersessionParentV1) {
	ids := make([]uuid.UUID, 10)
	for i := range ids {
		ids[i] = uuid.MustParse("00000000-0000-4000-8000-" + []string{"000000000001", "000000000002", "000000000003", "000000000004", "000000000005", "000000000006", "000000000007", "000000000008", "000000000009", "000000000010"}[i])
	}
	in := preSignAPISourceInputV1{RequestID: ids[3], ExpectedOrgID: ids[0], ExpectedUserID: ids[1], Policy: presign.Reference{ID: ids[4], Revision: 1, SHA256: strings.Repeat("a", 64)}, Grant: presign.Reference{ID: ids[5], Revision: 1, SHA256: strings.Repeat("b", 64)}, DocumentName: "Replacement contract"}
	p := pdfadmission.PreSignSupersessionParentV1{ExecutionID: ids[6], ExecutionSHA256: strings.Repeat("d", 64), DocumentID: ids[7], SourceCommitment: strings.Repeat("e", 64), MaterializationID: ids[8], MaterializationRevision: 1, Template: presign.TemplatePin{ID: ids[9], Version: 1, ContentSHA256: strings.Repeat("f", 64), ApprovedBy: ids[1], ApprovedAt: time.Date(2026, 10, 23, 12, 0, 0, 123456789, time.UTC)}}
	return in, ids[2], strings.Repeat("c", 64), p
}
func TestPreSignAPISupersessionPreservesOrdinaryCanonicalAndBindsEveryParentPinV1(t *testing.T) {
	in, key, binding, parent := apiSupersessionFixtureV1()
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"request_id":"00000000-0000-4000-8000-000000000004","expected_org_id":"00000000-0000-4000-8000-000000000001","expected_user_id":"00000000-0000-4000-8000-000000000002","policy":{"id":"00000000-0000-4000-8000-000000000005","revision":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"grant":{"id":"00000000-0000-4000-8000-000000000006","revision":1,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"document_name":"Replacement contract"}` {
		t.Fatal("ordinary no-prior canonical bytes changed")
	}
	old, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, key, binding)
	if err != nil || old != "3b367179ee3d7344ea277db7aa81153f03d4790153fede88bf3795794724936d" {
		t.Fatal("ordinary original command domain/digest changed", err)
	}
	in.Prior = &parent
	bound, err := preSignSourceInputDigestV1(in, in.ExpectedOrgID, in.ExpectedUserID, key, binding)
	if err != nil || bound == old {
		t.Fatal("exact prior did not bind original API request", err)
	}
	for name, change := range map[string]func(*pdfadmission.PreSignSupersessionParentV1){
		"execution": func(p *pdfadmission.PreSignSupersessionParentV1) { p.ExecutionID = uuid.New() }, "execution hash": func(p *pdfadmission.PreSignSupersessionParentV1) { p.ExecutionSHA256 = strings.Repeat("a", 64) },
		"document": func(p *pdfadmission.PreSignSupersessionParentV1) { p.DocumentID = uuid.New() }, "source": func(p *pdfadmission.PreSignSupersessionParentV1) { p.SourceCommitment = strings.Repeat("b", 64) },
		"materialization": func(p *pdfadmission.PreSignSupersessionParentV1) { p.MaterializationID = uuid.New() }, "materialization revision": func(p *pdfadmission.PreSignSupersessionParentV1) { p.MaterializationRevision++ },
		"template": func(p *pdfadmission.PreSignSupersessionParentV1) { p.Template.ID = uuid.New() }, "template version": func(p *pdfadmission.PreSignSupersessionParentV1) { p.Template.Version++ },
		"template hash": func(p *pdfadmission.PreSignSupersessionParentV1) { p.Template.ContentSHA256 = strings.Repeat("a", 64) }, "approver": func(p *pdfadmission.PreSignSupersessionParentV1) { p.Template.ApprovedBy = uuid.New() },
		"approval instant": func(p *pdfadmission.PreSignSupersessionParentV1) {
			p.Template.ApprovedAt = p.Template.ApprovedAt.Add(time.Nanosecond)
		},
	} {
		t.Run(name, func(t *testing.T) {
			next := in
			copy := parent
			next.Prior = &copy
			change(next.Prior)
			changed, e := preSignSourceInputDigestV1(next, next.ExpectedOrgID, next.ExpectedUserID, key, binding)
			if e != nil || changed == bound {
				t.Fatal("changed exact prior adopted original request", e)
			}
		})
	}
	for _, bad := range []pdfadmission.PreSignSupersessionParentV1{{}, func() pdfadmission.PreSignSupersessionParentV1 {
		p := parent
		p.ExecutionSHA256 = strings.Repeat("D", 64)
		return p
	}(), func() pdfadmission.PreSignSupersessionParentV1 {
		p := parent
		p.Template.ApprovedAt = time.Time{}
		return p
	}()} {
		next := in
		next.Prior = &bad
		if _, e := preSignSourceInputDigestV1(next, next.ExpectedOrgID, next.ExpectedUserID, key, binding); e == nil {
			t.Fatal("invalid explicit prior became ordinary source")
		}
	}
}
func TestPreSignAPISupersessionClosedWireCannotInjectValuesOrPartialEvidenceV1(t *testing.T) {
	in, _, _, parent := apiSupersessionFixtureV1()
	in.Prior = &parent
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var decoded preSignAPISourceInputV1
	if err = decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(string(raw))), &decoded); err != nil || decoded.Prior == nil || !decoded.Prior.Template.ApprovedAt.Equal(parent.Template.ApprovedAt) {
		t.Fatal("exact closed prior did not roundtrip", err)
	}
	priorRaw, _ := json.Marshal(parent)
	for name, bad := range map[string]string{
		"null": strings.Replace(string(raw), string(priorRaw), "null", 1), "extra": strings.Replace(string(raw), `"prior":{`, `"prior":{"source_bytes":"private",`, 1),
		"values": strings.Replace(string(raw), `"document_name":`, `"values":{"customer":"bypass"},"document_name":`, 1), "duplicate": strings.Replace(string(raw), `"execution_id":`, `"execution_id":"`+parent.ExecutionID.String()+`","execution_id":`, 1),
		"nested null": strings.Replace(string(raw), `"approved_at":"2026-10-23T12:00:00.123456789Z"`, `"approved_at":null`, 1), "trailing": string(raw) + `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			var v preSignAPISourceInputV1
			if decodeCRMTemplateJSON(httptest.NewRequest("POST", "/", strings.NewReader(bad)), &v) == nil {
				t.Fatal("ambiguous/private parent or caller values accepted")
			}
		})
	}
	missing := in
	copy := parent
	copy.MaterializationID = uuid.Nil
	missing.Prior = &copy
	if _, e := preSignSourceInputDigestV1(missing, missing.ExpectedOrgID, missing.ExpectedUserID, uuid.New(), strings.Repeat("c", 64)); e == nil {
		t.Fatal("partial explicit prior accepted")
	}
}
func TestPreSignAPISupersessionRequiresActualSameSourceLinkAndCannotUseShellSealerV1(t *testing.T) {
	in, _, _, parent := apiSupersessionFixtureV1()
	in.Prior = &parent
	digest := strings.Repeat("a", 64)
	document := uuid.New()
	sourceSHA := strings.Repeat("b", 64)
	source := pdfadmission.PreSignAPISourceViewV1{SchemaVersion: 1, RequestID: in.RequestID, State: "committed", InputSHA256: digest, Source: &pdfadmission.PreSignAPISourcePinsV1{DocumentID: document, SourceCommitment: sourceSHA}}
	linked := pdfadmission.PreSignSupersessionViewV1{SchemaVersion: 1, RequestID: in.RequestID, State: "committed", PriorExecutionID: parent.ExecutionID, PriorDocumentID: parent.DocumentID, DocumentID: document, SourceCommitment: sourceSHA}
	if err := preSignAPISupersessionResultV1(in, digest, source, linked); err != nil {
		t.Fatal("actual matched projection refused", err)
	}
	for name, change := range map[string]func(*pdfadmission.PreSignSupersessionViewV1){"missing": func(v *pdfadmission.PreSignSupersessionViewV1) { v.State = "unconfirmed" }, "request": func(v *pdfadmission.PreSignSupersessionViewV1) { v.RequestID = uuid.New() }, "parent execution": func(v *pdfadmission.PreSignSupersessionViewV1) { v.PriorExecutionID = uuid.New() }, "parent document": func(v *pdfadmission.PreSignSupersessionViewV1) { v.PriorDocumentID = uuid.New() }, "fresh source": func(v *pdfadmission.PreSignSupersessionViewV1) { v.SourceCommitment = parent.SourceCommitment }, "other source": func(v *pdfadmission.PreSignSupersessionViewV1) { v.SourceCommitment = strings.Repeat("c", 64) }, "other document": func(v *pdfadmission.PreSignSupersessionViewV1) { v.DocumentID = uuid.New() }} {
		t.Run(name, func(t *testing.T) {
			bad := linked
			change(&bad)
			if preSignAPISupersessionResultV1(in, digest, source, bad) == nil {
				t.Fatal("unbound source/link acknowledged")
			}
		})
	}
	for _, bad := range []pdfadmission.PreSignAPISourceViewV1{func() pdfadmission.PreSignAPISourceViewV1 {
		v := source
		v.InputSHA256 = strings.Repeat("c", 64)
		return v
	}(), func() pdfadmission.PreSignAPISourceViewV1 { v := source; v.Source = nil; return v }(), func() pdfadmission.PreSignAPISourceViewV1 { v := source; v.RequestID = uuid.New(); return v }()} {
		if preSignAPISupersessionResultV1(in, digest, bad, linked) == nil {
			t.Fatal("other original API receipt adopted")
		}
	}
	nilSource := source
	empty := *source.Source
	empty.DocumentID = uuid.Nil
	nilSource.Source = &empty
	nilLinked := linked
	nilLinked.DocumentID = uuid.Nil
	if preSignAPISupersessionResultV1(in, digest, nilSource, nilLinked) == nil {
		t.Fatal("nil synthetic successor accepted")
	}
	for _, server := range []*Server{nil, {}} {
		if _, ready, err := server.sealPreSignAPISupersessionV1(context.Background(), nil, nil, auth.PreSignAPIAdmissionV1{}, pdfadmission.PreSignAPISourceCommandV1{}, parent.Template, parent); err == nil || ready {
			t.Fatal("shell produced link or audit")
		}
	}
	ordinary := in
	ordinary.Prior = nil
	if err := preSignAPISupersessionResultV1(ordinary, "", pdfadmission.PreSignAPISourceViewV1{}, pdfadmission.PreSignSupersessionViewV1{}); err != nil {
		t.Fatal("ordinary source was forced into linked mode", err)
	}
}

// Exercise the real error writer and middleware correlation with private typed
// causes, rather than duplicating each implementation stage assignment.
func TestPreSignAPISourceDiagnosticPreservesMapperCauseAndPrivacyV1(t *testing.T) {
	var requestContext context.Context
	middleware.RequestID(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { requestContext = r.Context() })).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://controlled.invalid/", nil))
	if requestContext == nil || middleware.GetReqID(requestContext) == "" {
		t.Fatal("actual middleware correlation missing")
	}
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	server := &Server{}
	const secret = "private-capability-and-source-marker"
	cases := []struct {
		cause error
		kind  string
	}{{pdfadmission.ErrHTMLCreationWriterV1, "html_creation_writer"}, {pdfadmission.ErrHTMLAuthoringReadV1, "html_authoring_read"}, {pdfadmission.ErrHTMLAuditEventV1, "html_audit_event"}}
	for _, test := range cases {
		typed := &fs.PathError{Op: "open", Path: secret, Err: test.cause}
		marked := context.WithValue(requestContext, preSignAPIHTMLCreationPhaseKeyV1{}, true)
		unmarked := context.WithValue(requestContext, preSignAPIHTMLCreationPhaseKeyV1{}, false)
		if preSignAPIHTMLCreationFailureV1(requestContext, "html_prepare", typed) != typed || preSignAPIHTMLCreationFailureV1(unmarked, "html_prepare", typed) != typed || preSignAPIHTMLCreationFailureV1(nil, "html_prepare", typed) != typed || preSignAPIHTMLCreationFailureV1(marked, "html_prepare", nil) != nil {
			t.Fatal("ordinary or false marker changed original error identity or nil")
		}
		phaseOnly := preSignAPIHTMLCreationFailureV1(marked, "html_prepare", typed)
		if phaseOnly.Error() != typed.Error() || !errors.Is(phaseOnly, typed) || preSignAPISourceStageV1(phaseOnly) != "html_prepare" {
			t.Fatal("true prior marker lost original cause or fixed HTML phase")
		}
		inner := preSignAPISourceFailureV1("callback_parent_birth_read", typed)
		original := fmt.Errorf("private outer %s: %w", secret, inner)
		wrapped := preSignAPIHTMLCreationFailureV1(marked, "html_prepare", original)
		var recovered *fs.PathError
		if wrapped.Error() != original.Error() || !errors.Is(wrapped, test.cause) || !errors.Is(wrapped, typed) || !errors.As(wrapped, &recovered) || recovered != typed || preSignAPISourceStageV1(wrapped) != "callback_parent_birth_read" {
			t.Fatal("nested diagnostic changed original text, identity chain, type or first stage")
		}
		baseline := httptest.NewRecorder()
		logs.Reset()
		server.writePreSignSourceErrorV1(requestContext, baseline, typed)
		if logs.Len() != 0 {
			t.Fatal("ordinary unlabelled error emitted prior-only diagnostic")
		}
		actual := httptest.NewRecorder()
		server.writePreSignSourceErrorV1(requestContext, actual, wrapped)
		if actual.Code != http.StatusServiceUnavailable || actual.Code != baseline.Code || actual.Body.String() != baseline.Body.String() || actual.Body.String() != "{\"error\":\"HTML document creation is temporarily unavailable\"}\n" || actual.Header().Get("Content-Type") != baseline.Header().Get("Content-Type") {
			t.Fatal("closed diagnostic changed actual HTTP mapper")
		}
		var record map[string]any
		if json.Unmarshal(logs.Bytes(), &record) != nil || len(record) != 6 || record["msg"] != "pre-sign API source failed" || record["stage"] != "callback_parent_birth_read" || record["error_kind"] != test.kind || record["request_id"] != middleware.GetReqID(requestContext) || strings.Contains(logs.String(), secret) {
			t.Fatal("closed diagnostic exposed private cause or lost fixed fields/correlation")
		}
		if preSignAPISourceFailureV1(secret, typed) != typed || preSignAPISourceFailureV1("instantiate", nil) != nil {
			t.Fatal("foreign label or nil changed original error object")
		}
		forged := &preSignAPISourceDiagnosticV1{stage: secret, cause: typed}
		logs.Reset()
		foreign := httptest.NewRecorder()
		server.writePreSignSourceErrorV1(requestContext, foreign, forged)
		if preSignAPISourceStageV1(forged) != "" || logs.Len() != 0 || foreign.Code != baseline.Code || foreign.Body.String() != baseline.Body.String() {
			t.Fatal("unknown private label became emitted or changed HTTP result")
		}
	}
	// Original authority/conflict precedence must win even when a joined cause
	// also contains an internal sentinel. These responses are not internal503s.
	for _, denial := range []struct {
		cause  error
		status int
	}{{auth.ErrMutationPermissionRevoked, http.StatusForbidden}, {presignregistry.ErrConflict, http.StatusConflict}} {
		original := errors.Join(denial.cause, pdfadmission.ErrHTMLAuthoringReadV1)
		baseline := httptest.NewRecorder()
		logs.Reset()
		server.writePreSignSourceErrorV1(requestContext, baseline, original)
		actual := httptest.NewRecorder()
		server.writePreSignSourceErrorV1(requestContext, actual, preSignAPISourceFailureV1("initial_parent", original))
		if actual.Code != denial.status || actual.Code != baseline.Code || actual.Body.String() != baseline.Body.String() || logs.Len() != 0 {
			t.Fatal("joined ordinary refusal became an internal diagnostic or changed mapper precedence")
		}
	}
}
