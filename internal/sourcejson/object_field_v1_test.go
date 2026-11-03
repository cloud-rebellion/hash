// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sourcejson

import (
	"context"
	"strings"
	"testing"
)

func TestLookupASCIIObjectFieldV1BoundedAndEscaped(t *testing.T) {
	for _, raw := range []string{`{"external":[{"nested":"value"}],"hash:document-purpose:v1":{"purpose":"document"}}`, `{"hash\u003adocument-purpose:v1":{"purpose":"document"}}`} {
		v, ok, err := LookupASCIIObjectFieldV1(context.Background(), []byte(raw), "hash:document-purpose:v1")
		if err != nil || !ok || string(v) != `{"purpose":"document"}` {
			t.Fatal(string(v), ok, err)
		}
	}
	for _, raw := range []string{`[]`, `{"a":}`, `{"k":1,"\u006b":2}`, `{"k":1} trailing`, `{"a":"\ud800"}`} {
		if _, _, err := LookupASCIIObjectFieldV1(context.Background(), []byte(raw), "k"); err == nil {
			t.Fatal("invalid or duplicate key accepted", raw)
		}
	}
	raw := []byte(`{"a":"` + strings.Repeat("x", 1<<20) + `","\u0062":1}`)
	if n := testing.AllocsPerRun(3, func() {
		v, ok, err := LookupASCIIObjectFieldV1(context.Background(), raw, "missing")
		if err != nil || ok || v != nil {
			panic("lookup")
		}
	}); n > 0 {
		t.Fatal("unrelated metadata allocated", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := LookupASCIIObjectFieldV1(ctx, raw, "k"); err == nil {
		t.Fatal("cancelled lookup accepted")
	}
}
