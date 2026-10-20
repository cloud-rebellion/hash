// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blocks

import (
	"encoding/json"
	"errors"
	"golang.org/x/net/html"
	"strings"
	"testing"
)

type importConstructionProbeV1 struct {
	stages  []string
	stop    string
	failure error
	nodes   int
}

func (p *importConstructionProbeV1) stage(name string) error {
	p.stages = append(p.stages, name)
	if p.stop == name {
		return p.failure
	}
	return nil
}
func (p *importConstructionProbeV1) BeforeHTMLTokensV1(string) error { return p.stage("tokens") }
func (p *importConstructionProbeV1) BeforeHTMLDOMV1(string) error    { return p.stage("dom") }
func (p *importConstructionProbeV1) BeforeHTMLBlocksV1(root *html.Node) error {
	for range walkHTML(root) {
		p.nodes++
	}
	return p.stage("blocks")
}
func (p *importConstructionProbeV1) BeforeMarkdownBlocksV1(string) error { return p.stage("markdown") }
func importConstructionContentV1(t *testing.T, tree *Tree) string {
	t.Helper()
	var clearIDs func([]Block)
	clearIDs = func(bs []Block) {
		for i := range bs {
			bs[i].ID = ""
			clearIDs(bs[i].Content)
		}
	}
	clearIDs(tree.Blocks)
	raw, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
func TestImportConstructionPreservesOriginalGrammarAndStagesV1(t *testing.T) {
	for _, source := range []string{"<h2>Heading</h2><p>Clause <b>bold <i>mixed</b> tail</i></p>", "<svg><foreignObject><p>Foreign clause</p></foreignObject></svg><p>After</p>", "<table><tr><td>Outer<table><tr><td>Inner</td></tr></table></td></tr></table>", "<ul><li>One</li><li>Two</li></ul><pre><code class='language-go'>x &lt; y</code></pre>"} {
		want, err := ParseHTMLChecked(source)
		if err != nil {
			t.Fatal(err)
		}
		probe := &importConstructionProbeV1{}
		got, err := ParseHTMLCheckedForAuthoringV1(source, probe)
		if err != nil || got == nil {
			t.Fatal(err)
		}
		if strings.Join(probe.stages, ",") != "tokens,dom,blocks" || probe.nodes < 2 {
			t.Fatal("original real DOM was not admitted before block construction", probe)
		}
		if importConstructionContentV1(t, want) != importConstructionContentV1(t, got) {
			t.Fatal("admission changed original canonical HTML grammar")
		}
	}
	source := "# Heading\r\n\r\nClause\n\n- One\n- Two\n\n|A|B|\n|---|---|\n|C|D|"
	want, err := ParseMarkdownChecked(source)
	if err != nil {
		t.Fatal(err)
	}
	probe := &importConstructionProbeV1{}
	got, err := ParseMarkdownCheckedForAuthoringV1(source, probe)
	if err != nil || strings.Join(probe.stages, ",") != "markdown" || importConstructionContentV1(t, want) != importConstructionContentV1(t, got) {
		t.Fatal("admission changed original Markdown grammar", err)
	}
}
func TestImportConstructionRefusesBeforeEachOriginalAllocationStageV1(t *testing.T) {
	refusal := errors.New("actual construction refused")
	for _, stage := range []string{"tokens", "dom", "blocks"} {
		probe := &importConstructionProbeV1{stop: stage, failure: refusal}
		tree, err := ParseHTMLCheckedForAuthoringV1("<p>Exact clause</p>", probe)
		if tree != nil || !errors.Is(err, refusal) {
			t.Fatal("partial HTML escaped stage refusal", stage, err)
		}
		if probe.stages[len(probe.stages)-1] != stage {
			t.Fatal("later construction entered after refusal", probe)
		}
	}
	probe := &importConstructionProbeV1{stop: "markdown", failure: refusal}
	if tree, err := ParseMarkdownCheckedForAuthoringV1("# Exact clause", probe); tree != nil || !errors.Is(err, refusal) {
		t.Fatal("partial Markdown escaped pre-AST refusal", err)
	}
	for _, markdown := range []bool{false, true} {
		probe := &importConstructionProbeV1{}
		source := strings.Repeat("x", MaxImportSourceBytes+1)
		var tree *Tree
		var err error
		if markdown {
			tree, err = ParseMarkdownCheckedForAuthoringV1(source, probe)
		} else {
			tree, err = ParseHTMLCheckedForAuthoringV1(source, probe)
		}
		if tree != nil || !errors.Is(err, ErrInvalidBlock) || len(probe.stages) != 0 {
			t.Fatal("original source limit moved behind construction", err, probe)
		}
	}
	probe = &importConstructionProbeV1{}
	if tree, err := ParseHTMLCheckedForAuthoringV1(strings.Repeat("<hr>", MaxHTMLImportTokens+1), probe); tree != nil || !errors.Is(err, ErrInvalidBlock) || !strings.Contains(err.Error(), "20000 tokens") || strings.Join(probe.stages, ",") != "tokens" {
		t.Fatal("original token limit did not precede DOM", err, probe)
	}
}
