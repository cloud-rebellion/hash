// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/blocks"
	"golang.org/x/net/html"
	"io"
	"strings"
	"unsafe"
)

// Only the fixed original MCP imports use this active borrower. The actual
// input factory/raw argument registration remains the authority; source counts
// and construction costs are derived privately, never supplied by callers.
func (h *ApplicationBlocksInputV1) beginMCPImportV1(ctx context.Context) error {
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return ErrBlocksInputV1
	}
	s := h.state
	p := s.factory
	if p == nil {
		return ErrBlocksInputV1
	}
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if _, ok := p.htmlInputProducers[s]; !ok || p.closing || s.consumerClosed || s.retired || !s.ready || !s.readStarted || s.active != 0 || s.profile != blocksAuthoringMCPProfileV1 {
		return ErrBlocksInputV1
	}
	s.active++
	return nil
}
func (h *ApplicationBlocksInputV1) ParseMCPHTMLImportV1(ctx context.Context, source string) (*blocks.Tree, error) {
	if err := h.beginMCPImportV1(ctx); err != nil {
		return nil, err
	}
	defer h.state.finishV1()
	return blocks.ParseHTMLCheckedForAuthoringV1(source, blocksHTMLImportConstructionV1{input: h, ctx: ctx})
}
func (h *ApplicationBlocksInputV1) ParseMCPMarkdownImportV1(ctx context.Context, source string) (*blocks.Tree, error) {
	if err := h.beginMCPImportV1(ctx); err != nil {
		return nil, err
	}
	defer h.state.finishV1()
	return blocks.ParseMarkdownCheckedForAuthoringV1(source, blocksMarkdownImportConstructionV1{input: h, ctx: ctx})
}

type blocksHTMLImportConstructionV1 struct {
	input *ApplicationBlocksInputV1
	ctx   context.Context
}
type blocksMarkdownImportConstructionV1 struct {
	input *ApplicationBlocksInputV1
	ctx   context.Context
}

// Concrete x/net/html v0.60.0 token.go inventory: each raw attribute has two
// spans/four ints; attrNames and the finite source-tag inventory are string
// maps. Source bytes prepay their maximum syntax slots BEFORE Next allocates.
// Two simultaneous tokenizers, append capacity, raw/UTF8/reader/control storage
// are included. This is logical source work, not measured heap/RSS.
func blocksHTMLImportTokenWorkV1(source string) (int64, error) {
	n := int64(len(source))
	entries := n/2 + 1
	needed := int64(0)
	if !htmlInputAddV1(&needed, entries, 8) || !htmlInputAddV1(&needed, 1, 6) {
		return 0, ErrBlocksInputV1
	}
	slots := htmlInputPowerV1(max(8, needed/7))
	cost := 4*int64(unsafe.Sizeof(html.Tokenizer{})) + 4*int64(unsafe.Sizeof(html.Token{})) + 4*int64(unsafe.Sizeof(strings.Reader{})) + 2*int64(unsafe.Sizeof(blocks.Tree{})) + 8*int64(unsafe.Sizeof((func())(nil)))
	if !htmlInputAddV1(&cost, n+4096, 8) || !htmlInputAddV1(&cost, entries, 4*int64(unsafe.Sizeof([4]int{}))) || !htmlInputAddV1(&cost, slots, 3*(int64(unsafe.Sizeof(""))+2*int64(unsafe.Sizeof(int64(0)))+1)) || !htmlInputAddV1(&cost, 1, 3*2*16*256) {
		return 0, ErrBlocksInputV1
	}
	return cost, nil
}
func (a blocksHTMLImportConstructionV1) BeforeHTMLTokensV1(source string) error {
	cost, err := blocksHTMLImportTokenWorkV1(source)
	if err != nil {
		return err
	}
	return a.input.retainWorkV1(a.ctx, cost)
}

// HTML parser control layout from exact v0.60.0 parse.go (not a parser): two
// node stacks, two insertion-mode functions, template-mode slice, token,
// tokenizer/root/head/form/context pointers and six flags.
type blocksHTMLParserControlV1 struct {
	tokenizer                *html.Tokenizer
	token                    html.Token
	selfClosing              bool
	document                 *html.Node
	open, formatting         []*html.Node
	head, form               *html.Node
	scripting, frameset      bool
	templates                []func()
	mode, original           func()
	foster, quirks, fragment bool
	context                  *html.Node
}
type blocksHTMLFormattingShapeV1 struct{ attributes int64 }

func blocksHTMLImportDOMWorkV1(ctx context.Context, source string) (int64, error) {
	// The actual DOM changes raw-text/foreign-content tokenizer context. This
	// separate lexical size inventory clears raw-text mode for every start tag,
	// so it sees a superset of possible formatting starts; it decides no grammar.
	// Literal '<' bounds DOM token boundaries even when the checked prepass and
	// DOM context tokenize differently. No new token or declaration cap is used.
	tokenizer := html.NewTokenizer(strings.NewReader(source))
	distinct := make(map[string]blocksHTMLFormattingShapeV1)
	var allAttributes, formatTouches, maxFormatAttributes int64
	for {
		if err := ctx.Err(); err != nil {
			return 0, errors.Join(ErrBlocksInputV1, err)
		}
		kind := tokenizer.Next()
		if kind == html.ErrorToken {
			if tokenizer.Err() != io.EOF {
				return 0, ErrBlocksInputV1
			}
			break
		}
		if kind != html.StartTagToken && kind != html.SelfClosingTagToken && kind != html.EndTagToken {
			continue
		}
		raw := tokenizer.Raw()
		name, more := tokenizer.TagName()
		formatting := false
		// This is the exact finite addFormattingElement/adoption source-type
		// inventory, not acceptance or a replacement parsing implementation.
		switch string(name) {
		case "a", "b", "big", "code", "em", "font", "i", "s", "small", "strike", "strong", "tt", "u", "nobr":
			formatting = true
		}
		key := ""
		if formatting && kind != html.EndTagToken {
			key = string(raw)
		}
		attributes := int64(0)
		for more {
			_, _, more = tokenizer.TagAttr()
			attributes++
			allAttributes++
		}
		if formatting {
			formatTouches++
			if key != "" {
				distinct[key] = blocksHTMLFormattingShapeV1{attributes: attributes}
				if attributes > maxFormatAttributes {
					maxFormatAttributes = attributes
				}
			}
		}
		if kind != html.EndTagToken {
			tokenizer.NextIsNotRawText()
		}
	}
	uniqueAttributes := int64(0)
	for _, shape := range distinct {
		if !htmlInputAddV1(&uniqueAttributes, shape.attributes, 1) {
			return 0, ErrBlocksInputV1
		}
	}
	tokenBound := int64(8)
	if !htmlInputAddV1(&tokenBound, int64(strings.Count(source, "<")), 2) {
		return 0, ErrBlocksInputV1
	}
	// parse.go: at most two reconstruct calls per consumed source token; the
	// Noah's Ark rule retains three per distinct raw formatting family since
	// the most recent marker. Reconstruction inserts through the existing512
	// open-element ceiling (including the one attempted513th node). Adoption
	// has eight outer iterations, at most three inner clones plus one final.
	formatting := min(3*int64(len(distinct)), 513)
	formatAttrs := min(3*uniqueAttributes, 513*maxFormatAttributes)
	nodes := int64(8)
	cloneAttrs := int64(0)
	if !htmlInputAddV1(&nodes, tokenBound, 8+2*formatting) || !htmlInputAddV1(&nodes, formatTouches, 32) || !htmlInputAddV1(&cloneAttrs, tokenBound, 2*formatAttrs) || !htmlInputAddV1(&cloneAttrs, formatTouches, 32*maxFormatAttributes) {
		return 0, ErrBlocksInputV1
	}
	cost := 4*int64(unsafe.Sizeof(blocksHTMLParserControlV1{})) + 4*int64(unsafe.Sizeof(html.Node{}))
	if !htmlInputAddV1(&cost, int64(len(source))+26, 16) || !htmlInputAddV1(&cost, nodes, 2*int64(unsafe.Sizeof(html.Node{}))) || !htmlInputAddV1(&cost, allAttributes, 4*int64(unsafe.Sizeof(html.Attribute{}))+4*(2*int64(unsafe.Sizeof(""))+1)) || !htmlInputAddV1(&cost, cloneAttrs, 2*int64(unsafe.Sizeof(html.Attribute{}))) || !htmlInputAddV1(&cost, tokenBound, 4*(int64(unsafe.Sizeof((*html.Node)(nil)))+int64(unsafe.Sizeof((func())(nil))))) {
		return 0, ErrBlocksInputV1
	}
	return cost, nil
}
func (a blocksHTMLImportConstructionV1) BeforeHTMLDOMV1(source string) error {
	cost, err := blocksHTMLImportDOMWorkV1(a.ctx, source)
	if err != nil {
		return err
	}
	return a.input.retainWorkV1(a.ctx, cost)
}
func blocksHTMLImportTreeWorkV1(ctx context.Context, body *html.Node) (int64, error) {
	if body == nil {
		return 0, ErrBlocksInputV1
	}
	var nodes, textWork int64
	// Same parent-linked iterative traversal as original walkHTML. Before any
	// canonical block/map/list/table/text builder is allocated, actual text
	// counts every ancestor cell whose original rowCells may copy that subtree.
	// This covers nested table text without a guessed flat source multiplier.
	for node := body; node != nil; {
		if err := ctx.Err(); err != nil {
			return 0, errors.Join(ErrBlocksInputV1, err)
		}
		nodes++
		if node.Type == html.TextNode {
			copies := int64(1)
			for parent := node.Parent; parent != nil; parent = parent.Parent {
				if err := ctx.Err(); err != nil {
					return 0, errors.Join(ErrBlocksInputV1, err)
				}
				if parent.Type == html.ElementNode && (strings.EqualFold(parent.Data, "td") || strings.EqualFold(parent.Data, "th")) {
					copies++
				}
				if parent == body {
					break
				}
			}
			if !htmlInputAddV1(&textWork, int64(len(node.Data)), copies) {
				return 0, ErrBlocksInputV1
			}
		}
		if node.FirstChild != nil {
			node = node.FirstChild
			continue
		}
		for node != body && node.NextSibling == nil {
			node = node.Parent
		}
		if node == body {
			break
		}
		node = node.NextSibling
	}
	// Original Block/slice/ID allocations, fixed at-most-two-key attr maps,
	// rows/cell/columns interfaces and Validate ID-map slots. textContent's
	// Builder/Fields/string-slice/Join use actual aggregate copied text above.
	cost := 4*int64(unsafe.Sizeof(blocks.Tree{})) + 16*int64(unsafe.Sizeof((func())(nil)))
	fixedNode := 4*(int64(unsafe.Sizeof(blocks.Block{}))+64) + 2*8*(int64(unsafe.Sizeof(""))+int64(unsafe.Sizeof(any(nil)))+1) + 2*64 + 4*(int64(unsafe.Sizeof(""))+int64(unsafe.Sizeof([]string(nil)))+int64(unsafe.Sizeof(any(nil)))) + 2*(int64(unsafe.Sizeof(""))+1+16)
	if !htmlInputAddV1(&cost, nodes, fixedNode) || !htmlInputAddV1(&cost, textWork, 16+4*int64(unsafe.Sizeof(""))) {
		return 0, ErrBlocksInputV1
	}
	return cost, nil
}
func (a blocksHTMLImportConstructionV1) BeforeHTMLBlocksV1(body *html.Node) error {
	cost, err := blocksHTMLImportTreeWorkV1(a.ctx, body)
	if err != nil {
		return err
	}
	return a.input.retainWorkV1(a.ctx, cost)
}
func blocksMarkdownImportWorkV1(ctx context.Context, source string) (int64, error) {
	lines, nonblank := int64(1), int64(0)
	for rest := source; ; {
		if err := ctx.Err(); err != nil {
			return 0, errors.Join(ErrBlocksInputV1, err)
		}
		end := strings.IndexByte(rest, '\n')
		line := rest
		if end >= 0 {
			line = rest[:end]
		}
		if strings.TrimSpace(line) != "" {
			nonblank++
		}
		if end < 0 {
			break
		}
		lines++
		rest = rest[end+1:]
	}
	cells := int64(strings.Count(source, "|")) + lines
	// Original CRLF replacement, Split/body/header/cell slices, per-line prefix
	// trials, exact small attrs/IDs/Block model and Validate map. All source
	// counts are local observations; no parser or count/depth policy is added.
	cost := 4*int64(unsafe.Sizeof(blocks.Tree{})) + 16*int64(unsafe.Sizeof((func())(nil)))
	block := 4*(int64(unsafe.Sizeof(blocks.Block{}))+64) + 2*8*(int64(unsafe.Sizeof(""))+int64(unsafe.Sizeof(any(nil)))+1) + 2*64 + 128 + 2*(int64(unsafe.Sizeof(""))+1+16)
	if !htmlInputAddV1(&cost, int64(len(source)), 8) || !htmlInputAddV1(&cost, lines, 6*int64(unsafe.Sizeof(""))) || !htmlInputAddV1(&cost, cells, 4*(int64(unsafe.Sizeof(""))+int64(unsafe.Sizeof(any(nil)))+int64(unsafe.Sizeof([]string(nil))))) || !htmlInputAddV1(&cost, nonblank, block) {
		return 0, ErrBlocksInputV1
	}
	return cost, nil
}
func (a blocksMarkdownImportConstructionV1) BeforeMarkdownBlocksV1(source string) error {
	cost, err := blocksMarkdownImportWorkV1(a.ctx, source)
	if err != nil {
		return err
	}
	return a.input.retainWorkV1(a.ctx, cost)
}
