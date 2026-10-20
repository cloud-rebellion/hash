// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package pdfadmission

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"io"
	"strings"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/imageguard"
	"github.com/bright-interaction/hash/internal/workguard"
	"golang.org/x/net/html"
)

func htmlInputCanonicalInvalidV1() error {
	return fmt.Errorf("%w: source or asset structure", htmlmaster.ErrInvalid)
}

// Only real request bytes select this work. The legacy strict parser has
// already validated the route; no callback, caller cost, replacement RawMessage
// or caller-supplied image geometry becomes admission authority.
func (h *ApplicationHTMLAuthoringInputV1) CanonicalTemplateV1(ctx context.Context) (htmlmaster.TemplateCommitment, error) {
	var result htmlmaster.TemplateCommitment
	if h == nil || h.state == nil || !applicationContextV1(ctx) {
		return result, ErrHTMLAuthoringInputV1
	}
	s := h.state
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	_, registered := p.htmlInputProducers[s]
	if !registered || p.closing || s.consumerClosed || s.retired || !s.ready || s.canonicalStarted || s.profile != HTMLTemplateMasterInputV1 {
		s.mu.Unlock()
		p.mu.Unlock()
		return result, ErrHTMLAuthoringInputV1
	}
	s.canonicalStarted = true
	s.active++
	// Pin the original raw slices under the same active owner; the potentially
	// large clones execute after releasing the process factory mutex.
	masterSource := s.raw[s.shape.masterStart:s.shape.masterEnd]
	var defaultsSource []byte
	if s.shape.defaultsEnd != 0 {
		defaultsSource = s.raw[s.shape.defaultsStart:s.shape.defaultsEnd]
	}
	s.mu.Unlock()
	p.mu.Unlock()
	defer s.finishV1()
	// Copies are included in the already-held actual request parser arena.
	masterRaw := bytes.Clone(masterSource)
	defaultsRaw := []byte("{}")
	if defaultsSource != nil {
		defaultsRaw = bytes.Clone(defaultsSource)
	}
	master, err := htmlmaster.Decode(masterRaw)
	if err != nil {
		return result, err
	}
	if len(master.HTML) == 0 || len(master.HTML) > htmlmaster.MaxHTMLBytes || len(master.CSS) > htmlmaster.MaxCSSBytes || len(master.Assets) > htmlmaster.MaxAssets {
		return result, htmlInputCanonicalInvalidV1()
	}
	inspection, err := htmlInputCanonicalInspectionResourcesV1(master)
	if err != nil {
		return result, err
	}
	if err = s.holdCanonicalResourcesV1(ctx, inspection); err != nil {
		return result, err
	}
	stats, err := htmlInputCanonicalInspectV1(ctx, master)
	if err != nil {
		return result, err
	}
	cost, err := htmlInputCanonicalResourcesV1(masterRaw, defaultsRaw, master, stats)
	if err != nil {
		return result, err
	}
	if err = s.holdCanonicalResourcesV1(ctx, cost); err != nil {
		return result, err
	}
	// Preserve the exact current canonicalizer, approved contract provenance,
	// SHA domains, declared values/sections and all unchanged legacy checks.
	result, err = htmlmaster.CanonicalTemplate(masterRaw, defaultsRaw)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	// scanHTMLMaster later strictly decodes the ACTUAL canonical output, whose
	// escaped section/HTML strings may be larger than authored request bytes.
	// Price that exact fixed-shape output before returning it to the handler.
	outputShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputMasterV1, result.MasterJSON)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, ErrHTMLAuthoringInputV1
	}
	// Three Decode calls consume produced master bytes: inspection below,
	// later malware scan, and the fixed fresh writer canonical revalidation.
	outputCost, err := htmlAuthoringInputParserArenaV1(outputShape, 15)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	defaultsShape, err := htmlAuthoringInputRootShapeV1(ctx, htmlInputStringMapV1, result.DefaultsJSON)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, ErrHTMLAuthoringInputV1
	}
	defaultsCost, err := htmlAuthoringInputParserArenaV1(defaultsShape, 2)
	if err != nil || !htmlInputAddV1(&outputCost, defaultsCost, 1) {
		return htmlmaster.TemplateCommitment{}, ErrHTMLAuthoringInputV1
	}
	if err = s.holdCanonicalResourcesV1(ctx, outputCost); err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	// The actual fixed fresh writer calls CanonicalTemplate again. Its generic
	// SQL body loan does not price pixels/DOM/CSS. Derive a SEPARATE second
	// component grant from this same actual immutable output before exposure.
	futureMaster, err := htmlmaster.Decode(result.MasterJSON)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, ErrHTMLAuthoringInputV1
	}
	futureInspection, err := htmlInputCanonicalInspectionResourcesV1(futureMaster)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	if err = s.holdCanonicalResourcesV1(ctx, futureInspection); err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	futureStats, err := htmlInputCanonicalInspectV1(ctx, futureMaster)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	futureCost, err := htmlInputCanonicalResourcesV1(result.MasterJSON, result.DefaultsJSON, futureMaster, futureStats)
	if err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	if err = s.holdCanonicalResourcesV1(ctx, futureCost); err != nil {
		return htmlmaster.TemplateCommitment{}, err
	}
	return result, nil
}
func (s *applicationHTMLAuthoringInputStateV1) holdCanonicalResourcesV1(ctx context.Context, n int64) error {
	p := s.factory
	p.mu.Lock()
	s.mu.Lock()
	defer p.mu.Unlock()
	defer s.mu.Unlock()
	if p.closing || s.consumerClosed || s.retired || ctx.Err() != nil {
		return ErrHTMLAuthoringInputV1
	}
	release, err := p.work.acquire(ctx, s.org, workguard.VectorV1{ParentBytes: n})
	if err != nil {
		return fmt.Errorf("%w: %w", ErrHTMLAuthoringInputV1, err)
	}
	s.releases = append(s.releases, release)
	return nil
}

type htmlInputCanonicalStatsV1 struct{ tokens, formatStarts, formatEnds, cssTokens, cssURIs, maxAssetURL, maxTagOutput, pixels int64 }

func htmlInputCanonicalInspectionResourcesV1(m htmlmaster.Master) (int64, error) {
	n := int64(0)
	// HTML tokenizer raw/key/attribute arenas and both token preflights have
	// at most one token per source byte. Names are filtered before its map.
	for _, p := range [][2]int64{{int64(len(m.HTML)), 512}, {int64(len(m.Assets)), (1 << 20) + 4096}} {
		if !htmlInputAddV1(&n, p[0], p[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, a := range m.Assets {
		if len(a.DataBase64) > base64.StdEncoding.EncodedLen(htmlmaster.MaxAssetBytes) {
			return 0, htmlInputCanonicalInvalidV1()
		}
		if !htmlInputAddV1(&n, int64(base64.StdEncoding.DecodedLen(len(a.DataBase64))), 2) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return n, nil
}
func htmlInputCanonicalInspectV1(ctx context.Context, m htmlmaster.Master) (htmlInputCanonicalStatsV1, error) {
	var s htmlInputCanonicalStatsV1
	if err := htmlInputHTMLNamesV1(ctx, m.HTML); err != nil {
		return s, err
	}
	z := html.NewTokenizer(strings.NewReader(m.HTML))
	for {
		if ctx.Err() != nil {
			return s, ErrHTMLAuthoringInputV1
		}
		kind := z.Next()
		if kind == html.ErrorToken {
			if z.Err() != io.EOF {
				return s, htmlInputCanonicalInvalidV1()
			}
			break
		}
		s.tokens++
		if s.tokens > 20000 {
			return s, htmlInputCanonicalInvalidV1()
		}
		if kind == html.StartTagToken || kind == html.SelfClosingTagToken || kind == html.EndTagToken {
			name, more := z.TagName()
			tagOutput := int64(32)
			for more {
				var key, value []byte
				key, value, more = z.TagAttr()
				tagOutput += int64(len(key)+4) + 6*int64(len(value))
			}
			s.maxTagOutput = max(s.maxTagOutput, tagOutput)
			switch string(name) {
			case "b", "code", "em", "i", "s", "small", "strong", "u":
				if kind == html.EndTagToken {
					s.formatEnds++
				} else {
					s.formatStarts++
				}
			}
		}
	}
	// One token consumes at least one source byte. The unchanged CSS scanner
	// refuses after20001tokens. Counting literalURI prefixes overestimates real
	// URI tokens without invoking regex engines before their component grant.
	s.cssTokens = min(int64(len(m.CSS))+1, int64(20001))
	s.cssURIs = int64(strings.Count(m.CSS, "url("))
	total := 0
	for _, a := range m.Assets {
		if ctx.Err() != nil {
			return s, ErrHTMLAuthoringInputV1
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(a.DataBase64)
		if err != nil || len(raw) == 0 || len(raw) > htmlmaster.MaxAssetBytes || len(raw) > htmlmaster.MaxTotalAssetBytes-total {
			return s, htmlInputCanonicalInvalidV1()
		}
		total += len(raw)
		urlBytes := int64(len("data:") + len(a.MediaType) + len(";base64,") + base64.StdEncoding.EncodedLen(len(raw)))
		s.maxAssetURL = max(s.maxAssetURL, urlBytes)
		switch a.MediaType {
		case "image/png", "image/jpeg":
			var cfg image.Config
			if a.MediaType == "image/jpeg" {
				cfg, err = jpeg.DecodeConfig(bytes.NewReader(raw))
			} else {
				cfg, err = png.DecodeConfig(bytes.NewReader(raw))
			}
			if err != nil || cfg.Width <= 0 || cfg.Height <= 0 || cfg.Width > imageguard.MaxDimension || cfg.Height > imageguard.MaxDimension || cfg.Width > imageguard.MaxPixels/cfg.Height {
				return s, htmlInputCanonicalInvalidV1()
			}
			w, h := int64(cfg.Width), int64(cfg.Height)
			component := int64(0)
			if a.MediaType == "image/jpeg" {
				component = 24 * ((w + 31) / 32 * 32) * ((h + 15) / 16 * 16)
			} else {
				component = 16*w*h + 14*(1+8*w)
			}
			// Sum real geometries: do not assume collection between sequential assets.
			if !htmlInputAddV1(&s.pixels, component, 2) || !htmlInputAddV1(&s.pixels, 1, 1<<20) {
				return s, ErrHTMLAuthoringInputV1
			}
		case "font/woff", "font/woff2": // Header-only in unchanged Compile, no font decode.
		default:
			return s, htmlInputCanonicalInvalidV1()
		}
	}
	return s, nil
}

// Lowercase ASCII names match the pinned tokenizer. Repeated known attributes
// remain accepted by this filter: tokenizer deduplicates them before the legacy
// validator. End-tag attributes never enter attrNames and remain legacy-owned.
func htmlInputHTMLSpaceV1(c byte) bool {
	return c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == '\f'
}
func htmlInputHTMLNameEqualV1(s, want string) bool {
	if len(s) != len(want) {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != want[i] {
			return false
		}
	}
	return true
}
func htmlInputHTMLNamesV1(ctx context.Context, s string) error {
	for i := 0; i < len(s); {
		if i&4095 == 0 && ctx.Err() != nil {
			return ErrHTMLAuthoringInputV1
		}
		if s[i] != '<' {
			i++
			continue
		}
		i++
		if i == len(s) {
			break
		}
		end := false
		if s[i] == '/' {
			end = true
			i++
			if i == len(s) {
				break
			}
		}
		if !(s[i] >= 'a' && s[i] <= 'z' || s[i] >= 'A' && s[i] <= 'Z') {
			if s[i] == '!' || s[i] == '?' {
				return htmlInputCanonicalInvalidV1()
			}
			continue
		}
		start := i
		i++
		for i < len(s) && !htmlInputHTMLSpaceV1(s[i]) && s[i] != '/' && s[i] != '>' {
			i++
		}
		if !end {
			allowed := false
			for _, name := range [...]string{"main", "article", "section", "header", "footer", "div", "span", "p", "h1", "h2", "h3", "h4", "h5", "h6", "br", "hr", "strong", "b", "em", "i", "u", "s", "small", "sup", "sub", "blockquote", "pre", "code", "ul", "ol", "li", "dl", "dt", "dd", "table", "thead", "tbody", "tfoot", "tr", "th", "td", "caption", "colgroup", "col", "img", "figure", "figcaption"} {
				if htmlInputHTMLNameEqualV1(s[start:i], name) {
					allowed = true
					break
				}
			}
			if !allowed {
				return htmlInputCanonicalInvalidV1()
			}
		}
		for i < len(s) {
			for i < len(s) && htmlInputHTMLSpaceV1(s[i]) {
				i++
			}
			if i == len(s) {
				break
			}
			if s[i] == '>' {
				i++
				break
			}
			start = i
			// readTagAttrKey: a leading '=' is part of the key, while '/' is empty.
			for i < len(s) {
				c := s[i]
				if htmlInputHTMLSpaceV1(c) || c == '/' || c == '>' || c == '=' && i != start {
					break
				}
				i++
			}
			if !end && i != start {
				allowed := false
				for _, name := range [...]string{"class", "id", "title", "lang", "dir", "data-hash-value", "data-hash-section", "src", "alt", "width", "height", "colspan", "rowspan", "scope"} {
					if htmlInputHTMLNameEqualV1(s[start:i], name) {
						allowed = true
						break
					}
				}
				if !allowed {
					return htmlInputCanonicalInvalidV1()
				}
			}
			for i < len(s) && htmlInputHTMLSpaceV1(s[i]) {
				i++
			}
			if i == len(s) {
				break
			}
			if s[i] == '/' {
				i++
				continue
			}
			if s[i] != '=' {
				continue
			}
			i++
			for i < len(s) && htmlInputHTMLSpaceV1(s[i]) {
				i++
			}
			if i == len(s) {
				break
			}
			if s[i] == '>' {
				continue
			}
			quote := s[i]
			if quote == '\'' || quote == '"' {
				i++
				for i < len(s) && s[i] != quote {
					i++
				}
				if i < len(s) {
					i++
				}
			} else {
				for i < len(s) && !htmlInputHTMLSpaceV1(s[i]) && s[i] != '>' {
					i++
				}
			}
		}
	}
	return nil
}

// Component arenas for the pinned 64-bit Go1.26.9 / x/net0.60 producers.
// No unrestricted raw JSON, exponent, pixel or accepted-node multiplier.
func htmlInputCanonicalResourcesV1(master, defaults []byte, m htmlmaster.Master, s htmlInputCanonicalStatsV1) (int64, error) {
	n := int64(0)
	// Pinned backtrack limit262144bits +up-to500 program states forend+1.
	// Each state pushes at mostone false andone continuation16Bjob.256/state
	// prices slice growth/old-new/rounding plus visitedbits. Trusted regex
	// programs<8192Inst round NFAqueues to16384;1024/classslot separately
	// prices both queues, live/pool threads,captures andgrowth. Include fixed
	// name/selector checks even for emptyCSS; pools remainprocessbaseline.
	regexStates := min(int64(262144+500), 500*(int64(len(master))+1))
	if !htmlInputAddV1(&n, regexStates, 256) || !htmlInputAddV1(&n, 16384, 1024) {
		return 0, ErrHTMLAuthoringInputV1
	}
	// AFE list grows only at original formatting starts. Each permitted token
	// reconstructs at most once; open-element cap bounds one call at513clones.
	// Adoption clones<=32 per formatting end; four implied+one explicit nodes.
	clones := (s.tokens+1)*min(s.formatStarts, int64(513)) + 32*s.formatEnds
	nodes := clones + 5*(s.tokens+1) + 8
	// Node<=112B, Attribute48B; every clone copies<=14 attributes. Doubling
	// covers allocator-class rounding. Original+token-tree explicit DOM included.
	for _, p := range [][2]int64{{nodes, 2 * (112 + 14*48)}, {s.tokens + 1, 2 * (112 + 14*48)}, {s.tokens + 1, 128}, {int64(len(m.HTML)), 32}, {s.pixels, 1}} {
		if !htmlInputAddV1(&n, p[0], p[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	// Repair clones share original character backing but render/escape their
	// attributes again before the existing repair comparison can refuse them.
	htmlOut := min(int64(htmlmaster.MaxMaterializedBytes), 6*int64(len(m.HTML))+32*(s.tokens+1)+clones*s.maxTagOutput+512)
	cssBase := 12*int64(len(m.CSS)) + 32*(s.cssTokens+1)
	cssOut := cssBase + s.cssURIs*(s.maxAssetURL+7)
	cssOut = min(cssOut, int64(htmlmaster.MaxMaterializedBytes)+4096+cssBase)
	// Two CSS scanners, bounded rawTokens growth, parser Rule/Declaration/
	// selector slices and scratch. Source and both formatted outputs coexist;
	// formatter recursion<=4 plus old/new concatenation and fmt copies.
	for _, p := range [][2]int64{{s.cssTokens + 1, 2048}, {int64(len(m.CSS)), 128}, {cssOut, 64}, {htmlOut, 16}} {
		if !htmlInputAddV1(&n, p[0], p[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	// Typed strings alone may HTML-escape sixfold. Price master/default JSON,
	// cloned canonical bytes and envelope marshaling buffers/results separately.
	jsonOut := 6*(int64(len(master)+len(defaults))+htmlOut+cssBase) + 4096
	for _, a := range m.Assets {
		// FullCompile raw/base64/dataURL +imageguard.ReadAll +later malware-scan
		// raw staging, independently from imagepixels andcanonicalJSON outputs.
		if !htmlInputAddV1(&n, int64(base64.StdEncoding.DecodedLen(len(a.DataBase64))), 14) || !htmlInputAddV1(&n, int64(len(a.DataBase64)), 8) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	for _, p := range [][2]int64{{jsonOut, 18}, {int64(len(master) + len(defaults)), 4}, {int64(len(m.Assets)), 2 * 256 * 128}, {1, 4 * 4096}} {
		if !htmlInputAddV1(&n, p[0], p[1]) {
			return 0, ErrHTMLAuthoringInputV1
		}
	}
	return n, nil
}
