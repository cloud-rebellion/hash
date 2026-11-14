// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/emailtemplates"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

type serviceEmailCredentialFixture struct {
	key                     *auth.MintedKey
	id, user, org, document uuid.UUID
	role                    string
	scopes                  []string
	claimErr                error
	claims                  int
}

func (v *serviceEmailCredentialFixture) LookupByPrefix(_ context.Context, prefix string) (uuid.UUID, uuid.UUID, uuid.UUID, string, string, []byte, uuid.UUID, []string, error) {
	if prefix != v.key.Prefix {
		return uuid.Nil, uuid.Nil, uuid.Nil, "", "", nil, uuid.Nil, nil, errors.New("unknown synthetic key")
	}
	return v.id, v.user, v.org, v.role, "owner@example.invalid", v.key.Hash, v.document, v.scopes, nil
}
func (v *serviceEmailCredentialFixture) Claim(context.Context, uuid.UUID, uuid.UUID) error {
	v.claims++
	return v.claimErr
}

// The production auth closure actually queries this transaction. A middleware
// fixture supplies admitted identity, while these rows model current key state.
// No test-only constructor can install the private credential receipt.
type serviceEmailAuthorizationTx struct {
	pgx.Tx
	v       *serviceEmailCredentialFixture
	hash    []byte
	scopes  []string
	expired bool
	missing bool
	queries int
}
type serviceEmailAuthorizationRow struct{ scan func(...any) error }

func (r serviceEmailAuthorizationRow) Scan(dest ...any) error { return r.scan(dest...) }
func (tx *serviceEmailAuthorizationTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	tx.queries++
	return serviceEmailAuthorizationRow{scan: func(dest ...any) error {
		if sql == "SELECT clock_timestamp()" {
			*dest[0].(*time.Time) = time.Now()
			return nil
		}
		if tx.missing {
			return pgx.ErrNoRows
		}
		if !strings.Contains(sql, "FROM api_keys") || !strings.Contains(sql, "FOR SHARE") || len(args) != 3 || args[0] != tx.v.id || args[1] != tx.v.org || args[2] != tx.v.user {
			return errors.New("unexpected authorization query")
		}
		*dest[0].(*[]byte) = tx.hash
		*dest[1].(*[]string) = tx.scopes
		if tx.expired {
			*dest[2].(*pgtype.Timestamptz) = pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}
		}
		return nil
	}}
}

type serviceEmailDelegationFixture struct {
	v     *serviceEmailCredentialFixture
	tx    *serviceEmailAuthorizationTx
	calls []string
	kind  string
	input emailtemplates.Input
	err   error
}

func (f *serviceEmailDelegationFixture) authorize(ctx context.Context, actor authoring.Actor, op string) error {
	if actor.OrgID != f.v.org || actor.UserID != f.v.user || actor.Authorize == nil {
		return errors.New("incorrect admitted actor")
	}
	if err := actor.Authorize(ctx, f.tx, &generated.User{ID: f.v.user, OrgID: f.v.org}); err != nil {
		return err
	}
	f.calls = append(f.calls, op)
	return f.err
}
func (f *serviceEmailDelegationFixture) List(ctx context.Context, a authoring.Actor) ([]emailtemplates.Template, error) {
	if err := f.authorize(ctx, a, "list"); err != nil {
		return nil, err
	}
	return []emailtemplates.Template{emailtemplates.Default("email.invite"), emailtemplates.Default("email.declined"), emailtemplates.Default("email.quota_warning_80"), emailtemplates.Default("email.voided")}, nil
}
func (f *serviceEmailDelegationFixture) Preview(ctx context.Context, a authoring.Actor, k string, in emailtemplates.Input) (emailtemplates.Preview, error) {
	f.kind, f.input = k, in
	err := f.authorize(ctx, a, "preview")
	return emailtemplates.Preview{SchemaVersion: 1, Synthetic: true, Revision: in.ExpectedRevision, MandatoryContentPreserved: true}, err
}
func (f *serviceEmailDelegationFixture) Save(ctx context.Context, a authoring.Actor, k string, in emailtemplates.Input) (emailtemplates.Template, error) {
	f.kind, f.input = k, in
	err := f.authorize(ctx, a, "save")
	out := emailtemplates.Default(k)
	out.Revision = in.ExpectedRevision + 1
	return out, err
}

func serviceEmailFixture(t *testing.T) (*Server, *serviceEmailCredentialFixture, *serviceEmailDelegationFixture) {
	t.Helper()
	key, err := auth.MintAPIKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &serviceEmailCredentialFixture{key: key, id: uuid.New(), user: uuid.New(), org: uuid.New(), role: "owner", scopes: []string{"read", "write:authoring"}}
	tx := &serviceEmailAuthorizationTx{v: v, hash: key.Hash, scopes: append([]string(nil), v.scopes...)}
	f := &serviceEmailDelegationFixture{v: v, tx: tx}
	s := NewServer()
	registerServiceEmailToolsWithService(s, f)
	return s, v, f
}
func serviceEmailCall(t *testing.T, s *Server, v *serviceEmailCredentialFixture, name string, args string) *response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", "Bearer "+v.key.Plaintext)
	w := httptest.NewRecorder()
	auth.RequireAPIKey(v)(s.Handler()).ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		return &response{Error: &rpcError{Code: w.Code, Message: w.Body.String()}}
	}
	var out response
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

const serviceEmailValidArgs = `{"kind":"email.invite","expected_revision":7,"subject_template":"Hello {{recipient_name}}","html_template":"<p>Intro</p>","text_template":"Intro"}`

func TestServiceEmailMCPRegisteredOwnerScopes(t *testing.T) {
	s := New(Deps{})
	for _, tc := range []struct {
		name, scope string
		write       bool
	}{{"list_service_email_templates", "read", false}, {"preview_service_email_template", "read", false}, {"save_service_email_template", "write:authoring", true}} {
		t.Run(tc.name, func(t *testing.T) {
			tool, ok := s.tools[tc.name]
			if !ok || tool.MinRole != auth.RoleOwner || tool.Write != tc.write || mcpToolRequiredScopes[tc.name] != tc.scope {
				t.Fatal("tool classification differs")
			}
			if tool.InputSchema["additionalProperties"] != false {
				t.Fatal("open argument schema")
			}
			if _, ok := docScopeSafeTools[tc.name]; ok {
				t.Fatal("org email tool enabled for document credentials")
			}
			if !strings.Contains(tool.Description, "introductory") || !strings.Contains(strings.ToLower(tool.Description), "send") {
				t.Fatal("missing content/synthetic boundary")
			}
		})
	}
}
func TestServiceEmailMCPDelegatesOriginalCredentialAndExactInput(t *testing.T) {
	for _, tc := range []struct{ name, op, args string }{{"list_service_email_templates", "list", "{}"}, {"preview_service_email_template", "preview", serviceEmailValidArgs}, {"save_service_email_template", "save", serviceEmailValidArgs}} {
		t.Run(tc.op, func(t *testing.T) {
			s, v, f := serviceEmailFixture(t)
			resp := serviceEmailCall(t, s, v, tc.name, tc.args)
			if resp.Error != nil {
				t.Fatal(resp.Error)
			}
			result := decodedToolResult(t, resp)
			if result.IsError {
				t.Fatal(result)
			}
			if len(f.calls) != 1 || f.calls[0] != tc.op || v.claims != 1 || f.tx.queries != 1 {
				t.Fatal("service/native credential delegation missing")
			}
			if tc.op != "list" && (f.kind != "email.invite" || f.input.ExpectedRevision != 7 || f.input.HTMLTemplate != "<p>Intro</p>" || f.input.TextTemplate != "Intro" || f.input.SubjectTemplate != "Hello {{recipient_name}}") {
				t.Fatal("input changed")
			}
			if tc.op == "list" {
				if !strings.Contains(result.Content[0].Text, `"editable":false`) || !strings.Contains(result.Content[0].Text, `"subject_bytes":256`) {
					t.Fatal("list lost capabilities/limits")
				}
				var catalog struct {
					Templates []emailtemplates.Template `json:"templates"`
				}
				if err := json.Unmarshal([]byte(result.Content[0].Text), &catalog); err != nil || len(catalog.Templates) != 4 {
					t.Fatal("native capability catalog malformed", err)
				}
				want := map[string]bool{"email.invite": true, "email.declined": true, "email.quota_warning_80": true, "email.voided": false}
				for _, row := range catalog.Templates {
					expected, exists := want[row.Kind]
					if !exists || row.Editable != expected {
						t.Fatal("native editable/builtin capability changed", row.Kind)
					}
					delete(want, row.Kind)
				}
				if len(want) != 0 {
					t.Fatal("native capability catalog omitted a kind")
				}
			} else if tc.op == "preview" && !strings.Contains(result.Content[0].Text, `"synthetic":true`) {
				t.Fatal("preview lost synthetic marker")
			}
		})
	}
}
func TestServiceEmailMCPAuthorizationRefusals(t *testing.T) {
	for _, tool := range []string{"list_service_email_templates", "preview_service_email_template", "save_service_email_template"} {
		for _, mode := range []string{"viewer", "sender", "unknown-role", "document", "missing-scope", "workflow-only", "claim-refused", "wrong-secret", "revoked-current-key", "changed-current-scope", "changed-current-hash", "expired-current-key"} {
			t.Run(tool+"/"+mode, func(t *testing.T) {
				s, v, f := serviceEmailFixture(t)
				switch mode {
				case "viewer", "sender":
					v.role = mode
				case "unknown-role":
					v.role = "root"
				case "document":
					v.document = uuid.New()
				case "missing-scope":
					v.scopes = nil
				case "workflow-only":
					v.scopes = []string{"write:workflow"}
				case "claim-refused":
					v.claimErr = errors.New("revoked")
				case "wrong-secret":
					v.key.Hash = bytes.Repeat([]byte{1}, 32)
				case "revoked-current-key":
					f.tx.missing = true
				case "changed-current-scope":
					f.tx.scopes = []string{"write:workflow"}
				case "changed-current-hash":
					f.tx.hash = bytes.Repeat([]byte{2}, 32)
				case "expired-current-key":
					f.tx.expired = true
				}
				args := serviceEmailValidArgs
				if tool == "list_service_email_templates" {
					args = "{}"
				}
				resp := serviceEmailCall(t, s, v, tool, args)
				if resp.Error == nil && !decodedToolResult(t, resp).IsError {
					t.Fatal("unauthorized tool succeeded")
				}
				if len(f.calls) != 0 {
					t.Fatal("service operation reached after authorization refusal")
				}
			})
		}
	}
}
func TestServiceEmailMCPCannotForgeTransactionReceiptWithSessionContext(t *testing.T) {
	s, v, f := serviceEmailFixture(t)
	for _, name := range []string{"list_service_email_templates", "preview_service_email_template", "save_service_email_template"} {
		args := serviceEmailValidArgs
		if name == "list_service_email_templates" {
			args = "{}"
		}
		body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		r := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)).WithContext(ctx)
		r = withSessionContext(r, v.org, v.user, "owner", "owner@example.invalid")
		r = withTokenScopes(r, "admin")
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		var resp response
		if json.Unmarshal(w.Body.Bytes(), &resp) != nil || !decodedToolResult(t, &resp).IsError {
			t.Fatal("public context forged credential")
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("service reached without private receipt")
	}
}

func TestServiceEmailMCPReadAndAuthoringScopesStaySeparate(t *testing.T) {
	for _, tc := range []struct {
		tool, scope string
		allowed     bool
	}{
		{"list_service_email_templates", "read", true},
		{"preview_service_email_template", "read", true},
		{"save_service_email_template", "read", false},
		{"list_service_email_templates", "write:authoring", false},
		{"preview_service_email_template", "write:authoring", false},
		{"save_service_email_template", "write:authoring", true},
		{"save_service_email_template", "admin", true},
	} {
		t.Run(tc.tool+"/"+tc.scope, func(t *testing.T) {
			s, v, f := serviceEmailFixture(t)
			v.scopes = []string{tc.scope}
			f.tx.scopes = append([]string(nil), v.scopes...)
			args := serviceEmailValidArgs
			if tc.tool == "list_service_email_templates" {
				args = "{}"
			}
			resp := serviceEmailCall(t, s, v, tc.tool, args)
			if resp.Error != nil {
				t.Fatal(resp.Error)
			}
			result := decodedToolResult(t, resp)
			if result.IsError == tc.allowed || (len(f.calls) == 1) != tc.allowed {
				t.Fatal("scope isolation failed", result)
			}
		})
	}
}
func TestServiceEmailMCPStrictArgumentsBeforeDelegation(t *testing.T) {
	for name, raw := range map[string]string{
		"missing": "{}", "null-field": strings.Replace(serviceEmailValidArgs, `"<p>Intro</p>"`, `null`, 1), "duplicate": strings.Replace(serviceEmailValidArgs, `"kind":`, `"kind":"email.invite","kind":`, 1), "case-alias": strings.Replace(serviceEmailValidArgs, `"kind":`, `"Kind":`, 1), "extra-org": strings.Replace(serviceEmailValidArgs, `"kind":`, `"org_id":"foreign","kind":`, 1), "wrong-type": strings.Replace(serviceEmailValidArgs, `"expected_revision":7`, `"expected_revision":"7"`, 1), "fraction": strings.Replace(serviceEmailValidArgs, `"expected_revision":7`, `"expected_revision":1.5`, 1), "overflow": strings.Replace(serviceEmailValidArgs, `"expected_revision":7`, `"expected_revision":9223372036854775808`, 1), "null": "null", "array": "[]", "missing-source": strings.Replace(serviceEmailValidArgs, `,"text_template":"Intro"`, "", 1), "unpaired-surrogate": strings.Replace(serviceEmailValidArgs, "Intro", `\ud800`, 1), "nul": strings.Replace(serviceEmailValidArgs, "Intro", `\u0000`, 1), "size": `{"kind":"` + strings.Repeat("x", 160<<10) + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			for _, tool := range []string{"preview_service_email_template", "save_service_email_template"} {
				s, v, f := serviceEmailFixture(t)
				resp := serviceEmailCall(t, s, v, tool, raw)
				if resp.Error == nil && !decodedToolResult(t, resp).IsError {
					t.Fatal("invalid arguments accepted")
				}
				if len(f.calls) != 0 {
					t.Fatal("invalid arguments reached service")
				}
			}
		})
	}
	for _, raw := range []string{`{"unexpected":1}`, `{"kind":"email.invite"}`, `null`, `[]`} {
		s, v, f := serviceEmailFixture(t)
		resp := serviceEmailCall(t, s, v, "list_service_email_templates", raw)
		if resp.Error == nil && !decodedToolResult(t, resp).IsError {
			t.Fatal("List accepted inputs")
		}
		if len(f.calls) != 0 {
			t.Fatal("List delegated invalid args")
		}
	}
	if _, err := exactServiceEmailArguments([]byte(serviceEmailValidArgs+" {}"), false); !errors.Is(err, errServiceEmailArguments) {
		t.Fatal("trailing JSON accepted")
	}
}
func TestServiceEmailMCPNativeServiceRulesRemainAuthoritative(t *testing.T) {
	s, v, _ := serviceEmailFixture(t)
	s = NewServer()
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 128 << 20, DBStagingBytes: 64 << 20}, Organisation: workguard.VectorV1{ParentBytes: 64 << 20, DBStagingBytes: 32 << 20}, MaxGrants: 64, MaxOrganisationGrants: 32})
	if err != nil {
		t.Fatal(err)
	}
	work, err := pdfadmission.NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	registerServiceEmailToolsWithService(s, emailtemplates.Service{Work: work})
	for name, args := range map[string]string{
		"builtin-save": `{"kind":"email.voided","expected_revision":0,"subject_template":"","html_template":"","text_template":""}`,
		"unknown":      strings.Replace(serviceEmailValidArgs, "email.invite", "email.unknown", 1), "negative": strings.Replace(serviceEmailValidArgs, `"expected_revision":7`, `"expected_revision":-1`, 1), "unsafe-html": strings.Replace(serviceEmailValidArgs, "<p>Intro</p>", "<a href='https://example.invalid'>x</a>", 1), "unknown-variable": strings.Replace(serviceEmailValidArgs, "recipient_name", "private_token", 1),
	} {
		t.Run(name, func(t *testing.T) {
			resp := serviceEmailCall(t, s, v, "save_service_email_template", args)
			result := decodedToolResult(t, resp)
			if !result.IsError || !strings.Contains(result.Content[0].Text, emailtemplates.ErrInput.Error()) {
				t.Fatal("native service validation not used", result)
			}
		})
	}
	// Built-in preview source restrictions likewise come from the real service.
	args := strings.Replace(serviceEmailValidArgs, "email.invite", "email.voided", 1)
	result := decodedToolResult(t, serviceEmailCall(t, s, v, "preview_service_email_template", args))
	if !result.IsError || !strings.Contains(result.Content[0].Text, emailtemplates.ErrInput.Error()) {
		t.Fatal(result)
	}
}
func TestServiceEmailMCPNativeErrorsAndEmptyResetDelegation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		message string
	}{{"stale", emailtemplates.ErrStale, emailtemplates.ErrStale.Error()}, {"input", emailtemplates.ErrInput, emailtemplates.ErrInput.Error()}, {"sql", &pgconn.PgError{Message: "secret database detail", Code: "XX000"}, "internal error"}, {"revoked", auth.ErrMutationPermissionRevoked, auth.ErrMutationPermissionRevoked.Error()}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, tool := range []string{"preview_service_email_template", "save_service_email_template"} {
				s, v, f := serviceEmailFixture(t)
				f.err = tc.err
				result := decodedToolResult(t, serviceEmailCall(t, s, v, tool, serviceEmailValidArgs))
				if !result.IsError || result.Content[0].Text != tc.message || len(f.calls) != 1 {
					t.Fatal(result)
				}
			}
		})
	}
	s, v, f := serviceEmailFixture(t)
	args := `{"kind":"email.invite","expected_revision":0,"subject_template":"","html_template":"","text_template":""}`
	result := decodedToolResult(t, serviceEmailCall(t, s, v, "save_service_email_template", args))
	if result.IsError || f.input != (emailtemplates.Input{}) {
		t.Fatal("empty reset rewritten", result)
	}
}

func TestServiceEmailMCPSyntheticLocaleIsPreviewOnlyV1(t *testing.T) {
	for _, locale := range []string{"en", "sv"} {
		s, v, f := serviceEmailFixture(t)
		args := strings.TrimSuffix(serviceEmailValidArgs, "}") + `,"preview_locale":"` + locale + `"}`
		response := serviceEmailCall(t, s, v, "preview_service_email_template", args)
		if response.Error != nil || decodedToolResult(t, response).IsError || f.input.PreviewLocale == nil || *f.input.PreviewLocale != locale || len(f.calls) != 1 {
			t.Fatal("preview locale not delegated with original owner", locale)
		}
		before := len(f.calls)
		response = serviceEmailCall(t, s, v, "save_service_email_template", args)
		if response.Error == nil && !decodedToolResult(t, response).IsError || len(f.calls) != before {
			t.Fatal("preview locale leaked into save")
		}
	}
	for _, suffix := range []string{`,"preview_locale":null}`, `,"preview_locale":""}`, `,"preview_locale":"sv-SE"}`, `,"preview_locale":"sv","preview_locale":"en"}`} {
		s, v, f := serviceEmailFixture(t)
		args := strings.TrimSuffix(serviceEmailValidArgs, "}") + suffix
		response := serviceEmailCall(t, s, v, "preview_service_email_template", args)
		if response.Error == nil && !decodedToolResult(t, response).IsError || len(f.calls) != 0 {
			t.Fatal("invalid locale reached service", suffix)
		}
	}
	s := New(Deps{})
	if _, ok := s.tools["preview_service_email_template"].InputSchema["properties"].(map[string]any)["preview_locale"]; !ok {
		t.Fatal("preview locale absent from registered schema")
	}
	if _, ok := s.tools["save_service_email_template"].InputSchema["properties"].(map[string]any)["preview_locale"]; ok {
		t.Fatal("save schema accepts preview locale")
	}
}
