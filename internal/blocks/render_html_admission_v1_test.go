// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"errors"
	"github.com/bright-interaction/hash/internal/render"
	"testing"
)

type finalHTMLDecimalProbeV1 struct {
	count int
	deny  bool
}

func (p *finalHTMLDecimalProbeV1) BeforeDecimalV1(string) error {
	p.count++
	if p.deny {
		return errors.New("actual decimal admission denied")
	}
	return nil
}
func TestFinalHTMLNativeDecimalHookPreservesOriginalBytesV1(t *testing.T) {
	tree, err := ParseCanonicalTree([]byte(`{"version":1,"blocks":[{"id":"head","type":"heading","attrs":{"level":2},"text":"Terms & identity"},{"id":"conditional","type":"conditional","attrs":{"expression":"var(amount) > 1e5"},"content":[{"id":"paragraph","type":"paragraph","text":"{{buyer}} agrees {{amount}}"},{"id":"sig","type":"signature_field","attrs":{"recipient_role":"signer"}}]},{"id":"literal","type":"raw_html","text":"<b>Inert</b><script>bad()</script>"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"amount": "1e6", "buyer": "A&B <name>"}
	spans := map[string]render.ArchivedSignatureSpan{}
	probe := &finalHTMLDecimalProbeV1{}
	actual, err := RenderHTMLWithSignaturesForSendV1(tree, vars, spans, "Awaiting signature", probe)
	if err != nil {
		t.Fatal(err)
	}
	if expected := RenderHTMLWithSignatures(tree, vars, spans, "Awaiting signature"); actual != expected {
		t.Fatalf("formatter bytes changed\nactual=%s\nexpected=%s", actual, expected)
	}
	if probe.count < 2 {
		t.Fatal("original numeric comparison bypassed decimal hook")
	}
	denied := &finalHTMLDecimalProbeV1{deny: true}
	if body, err := RenderHTMLWithSignaturesForSendV1(tree, vars, spans, "Awaiting signature", denied); body != "" || err == nil || denied.count != 1 {
		t.Fatal("admission refusal escaped formatter", err)
	}
	if RenderHTMLWithSignatures(tree, vars, spans, "Awaiting signature") != actual {
		t.Fatal("native refusal changed legacy formatter")
	}
}
