// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func TestMCPRejectsInvalidUnicodeBeforeDispatch(t *testing.T) {
	invalid := map[string]string{
		"literal invalid UTF8": `{"value":"` + string([]byte{0xff}) + `"}`,
		"invalid UTF8 key":     `{"` + string([]byte{0xff}) + `":"value"}`,
		"overlong UTF8":        `{"value":"` + string([]byte{0xc0, 0xaf}) + `"}`,
		"encoded surrogate":    `{"value":"` + string([]byte{0xed, 0xa0, 0x80}) + `"}`,
		"high surrogate":       `{"value":"\ud800"}`,
		"low surrogate":        `{"value":"\udfff"}`,
		"wrong pair":           `{"value":"\ud800\u0041"}`,
		"reversed pair":        `{"value":"\udfff\ud800"}`,
		"truncated escape":     `{"value":"\ud80"}`,
		"invalid escape":       `{"value":"\uxxxx"}`,
		"nested key":           `{"value":[{"\ud800":"data"}]}`,
		"NUL value":            `{"value":"\u0000"}`,
		"NUL key":              `{"\u0000":"value"}`,
	}
	for name, arguments := range invalid {
		t.Run(name, func(t *testing.T) {
			s := NewServer()
			calls := 0
			s.RegisterTool(ToolDef{Name: "get_document", Handler: func(_ *http.Request, _ json.RawMessage) (any, error) {
				calls++
				return "must not dispatch", nil
			}})
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_document","arguments":` + arguments + `}}`
			r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			r = withSessionContext(r, uuid.New(), uuid.New(), "owner", "operator@example.test")
			r = withTokenScopes(r, "read")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var reply response
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Error == nil || reply.Error.Code != codeParseError || reply.Result != nil || calls != 0 {
				t.Fatalf("malformed input dispatched: calls=%d reply=%+v", calls, reply)
			}
		})
	}
}

func TestMCPChecksUnicodeThroughoutEnvelope(t *testing.T) {
	for name, body := range map[string]string{
		"id":            `{"jsonrpc":"2.0","id":"\ud800","method":"ping"}`,
		"method":        `{"jsonrpc":"2.0","id":1,"method":"p\ud800ing"}`,
		"resource URI":  `{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"hash://\ud800"}}`,
		"prompt args":   `{"jsonrpc":"2.0","id":1,"method":"prompts/get","params":{"name":"greet","arguments":{"name":"\ud800"}}}`,
		"extension key": `{"jsonrpc":"2.0","id":1,"method":"ping","\ud800":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newTestServer().Handler().ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body)))
			var reply response
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if reply.Error == nil || reply.Error.Code != codeParseError || len(reply.ID) != 0 {
				t.Fatalf("expected parse error without normalized ID: %+v", reply)
			}
		})
	}
}

func TestMCPValidUnicodeRoundTrips(t *testing.T) {
	for name, tc := range map[string]struct{ raw, want string }{
		"Swedish":             {`"Åäö – avtal"`, "Åäö – avtal"},
		"paired surrogates":   {`"\uD83D\uDCA1"`, "💡"},
		"pair boundaries":     {`"\uD800\uDC00\uDBFF\uDFFF"`, "\U00010000\U0010ffff"},
		"literal escapes":     {`"\\ud800 \\u0000"`, `\ud800 \u0000`},
		"replacement literal": {`"�"`, "�"},
		"replacement escape":  {`"\uFFFD"`, "�"},
		"escaped quote":       {`"\"quoted\"\\\u00e5"`, "\"quoted\"\\å"},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewServer()
			calls := 0
			s.RegisterTool(ToolDef{Name: "get_document", Handler: func(_ *http.Request, args json.RawMessage) (any, error) {
				var in struct {
					Value string `json:"value"`
				}
				if err := MustParseArgs(args, &in); err != nil {
					return nil, err
				}
				if in.Value != tc.want {
					t.Errorf("value=%q want=%q", in.Value, tc.want)
				}
				calls++
				return in.Value, nil
			}})
			body := `{"jsonrpc":"2.0","id":"avtal","method":"tools/call","params":{"name":"get_document","arguments":{"value":` + tc.raw + `}}}`
			r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBufferString(body))
			r = withSessionContext(r, uuid.New(), uuid.New(), "owner", "operator@example.test")
			r = withTokenScopes(r, "read")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			var reply response
			if err := json.Unmarshal(w.Body.Bytes(), &reply); err != nil {
				t.Fatal(err)
			}
			if calls != 1 || reply.Error != nil || string(reply.ID) != `"avtal"` {
				t.Fatalf("valid request refused: calls=%d reply=%+v", calls, reply)
			}
		})
	}
}

func TestMustParseArgsRejectsUnicodeWithoutMutatingTarget(t *testing.T) {
	for _, raw := range []string{`{"value":"\ud800"}`, `{"value":"\u0000"}`, `{"value":"` + string([]byte{0xff}) + `"}`} {
		in := struct {
			Value string `json:"value"`
		}{Value: "original"}
		if err := MustParseArgs(json.RawMessage(raw), &in); err == nil || in.Value != "original" {
			t.Fatalf("invalid arguments changed target: err=%v value=%q", err, in.Value)
		}
	}
}
