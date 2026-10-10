// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"regexp"
	"strings"

	"github.com/aymerick/douceur/css"
	"github.com/aymerick/douceur/parser"
	"github.com/gorilla/css/scanner"
)

var selectorPattern = regexp.MustCompile(`^[a-zA-Z0-9_#., :>+~\[\]="'|*-]+$`)

var safeProperties = func() map[string]bool {
	result := map[string]bool{}
	for _, name := range strings.Fields(`color background background-color background-image background-size background-position background-repeat border border-top border-right border-bottom border-left border-color border-width border-style border-radius box-sizing box-shadow display position top right bottom left float clear width min-width max-width height min-height max-height margin margin-top margin-right margin-bottom margin-left padding padding-top padding-right padding-bottom padding-left font font-family font-size font-weight font-style font-variant line-height letter-spacing word-spacing text-align text-indent text-transform text-decoration text-decoration-color white-space word-break overflow-wrap vertical-align list-style-type list-style-position border-collapse border-spacing table-layout opacity overflow overflow-x overflow-y object-fit object-position flex flex-basis flex-grow flex-shrink flex-direction flex-wrap align-items align-content align-self justify-content gap row-gap column-gap grid-template-columns grid-template-rows grid-column grid-row order page-break-before page-break-after page-break-inside break-before break-after break-inside orphans widows counter-reset counter-increment content size`) {
		result[name] = true
	}
	return result
}()
var safeFunctions = map[string]bool{"rgb": true, "rgba": true, "hsl": true, "hsla": true, "calc": true, "min": true, "max": true, "clamp": true, "linear-gradient": true, "radial-gradient": true, "repeating-linear-gradient": true, "repeating-radial-gradient": true, "counter": true, "counters": true, "format": true}

func compileCSS(source string, assets map[string]resolvedAsset) (string, string, error) {
	if strings.ContainsAny(source, "\\<>") || strings.Contains(source, "/*") || strings.Contains(source, "*/") {
		return "", "", invalid("CSS escapes, HTML delimiters or comments are unsupported")
	}
	if strings.TrimSpace(source) == "" {
		return "", "", nil
	}
	// Token limits and explicit brace depth precede the recursive third-party
	// parser. Escapes/comments are refused, not normalized around URL checks.
	scan := scanner.New(source)
	depth, tokens := 0, 0
	var rawTokens []scanner.Token
	for {
		token := scan.Next()
		if token.Type == scanner.TokenEOF {
			break
		}
		tokens++
		if token.Type == scanner.TokenError || token.Type == scanner.TokenCDO || token.Type == scanner.TokenCDC || token.Type == scanner.TokenBOM {
			return "", "", invalid("CSS tokens")
		}
		if tokens > 20000 {
			return "", "", limited("CSS tokens")
		}
		rawTokens = append(rawTokens, *token)
		if token.Type == scanner.TokenChar && token.Value == "{" {
			depth++
			if depth > 4 {
				return "", "", limited("CSS nesting")
			}
		}
		if token.Type == scanner.TokenChar && token.Value == "}" {
			depth--
			if depth < 0 {
				return "", "", invalid("CSS braces")
			}
		}
	}
	if depth != 0 {
		return "", "", invalid("CSS braces")
	}
	// The formatter's parser repairs malformed declarations (including resetting
	// a property at every colon). Independently require one unambiguous source
	// declaration and validate its whole original value before formatting it.
	raw := cssSource{tokens: rawTokens, assets: assets}
	if err := raw.rules(false); err != nil {
		return "", "", err
	}
	sheet, err := parser.Parse(source)
	if err != nil {
		return "", "", invalid("CSS grammar")
	}
	count := 0
	bytes := 0
	if err = validateRules(sheet.Rules, assets, false, &count, &bytes); err != nil {
		return "", "", err
	}
	canonical := sheet.String()
	// Resolve only already-validated URI tokens in declarations, preserving
	// rule/declaration order (the CSS cascade is part of the approved design).
	count, bytes = 0, 0
	if err = validateRules(sheet.Rules, assets, true, &count, &bytes); err != nil {
		return "", "", err
	}
	rendered := sheet.String()
	if len(rendered) > MaxMaterializedBytes/2 {
		return "", "", limited("embedded CSS bytes")
	}
	return canonical, rendered, nil
}

type cssSource struct {
	tokens []scanner.Token
	assets map[string]resolvedAsset
	index  int
	rulesN int
}

func (s *cssSource) whitespace() {
	for s.index < len(s.tokens) && s.tokens[s.index].Type == scanner.TokenS {
		s.index++
	}
}

func (s *cssSource) char(value string) bool {
	return s.index < len(s.tokens) && s.tokens[s.index].Type == scanner.TokenChar && s.tokens[s.index].Value == value
}

func (s *cssSource) rules(nested bool) error {
	startCount := s.rulesN
	for {
		s.whitespace()
		if s.index == len(s.tokens) {
			if nested {
				return invalid("CSS rule closing")
			}
			return nil
		}
		if s.char("}") {
			if !nested || startCount == s.rulesN {
				return invalid("CSS empty or unexpected rule block")
			}
			s.index++
			return nil
		}
		s.rulesN++
		if s.rulesN > 512 {
			return limited("CSS rules")
		}
		name := ""
		if s.tokens[s.index].Type == scanner.TokenAtKeyword {
			name = s.tokens[s.index].Value
			s.index++
		}
		var prelude strings.Builder
		for s.index < len(s.tokens) && !s.char("{") {
			if s.char("}") || s.char(";") {
				return invalid("CSS rule requires a block")
			}
			prelude.WriteString(s.tokens[s.index].Value)
			s.index++
		}
		if s.index == len(s.tokens) {
			return invalid("CSS rule requires a block")
		}
		p := strings.TrimSpace(prelude.String())
		switch name {
		case "":
			for _, selector := range strings.Split(p, ",") {
				if !selectorPattern.MatchString(strings.TrimSpace(selector)) {
					return invalid("CSS selector syntax")
				}
			}
		case "@media":
			if p != "print" && p != "screen" {
				return invalid("CSS media rule")
			}
		case "@page":
			if p != "" && p != ":first" && p != ":left" && p != ":right" {
				return invalid("CSS page rule")
			}
		case "@font-face":
			if p != "" {
				return invalid("CSS font rule")
			}
		default:
			return invalid("unsupported CSS at-rule")
		}
		s.index++ // opening brace
		if name == "@media" {
			if err := s.rules(true); err != nil {
				return err
			}
		} else if err := s.declarations(name == "@font-face"); err != nil {
			return err
		}
	}
}

func (s *cssSource) declarations(font bool) error {
	count := 0
	for {
		s.whitespace()
		if s.index == len(s.tokens) {
			return invalid("CSS declaration closing")
		}
		if s.char("}") {
			if count == 0 {
				return invalid("CSS empty declaration block")
			}
			s.index++
			return nil
		}
		if s.tokens[s.index].Type != scanner.TokenIdent {
			return invalid("CSS declaration property")
		}
		property := s.tokens[s.index].Value
		s.index++
		s.whitespace()
		if !s.char(":") {
			return invalid("CSS declaration colon")
		}
		s.index++
		var value strings.Builder
		for s.index < len(s.tokens) && !s.char(";") && !s.char("}") {
			if s.char(":") || s.char("{") {
				return invalid("ambiguous CSS declaration")
			}
			value.WriteString(s.tokens[s.index].Value)
			s.index++
		}
		v := strings.TrimSpace(value.String())
		// The formatter recognizes this exact, case-insensitive suffix. All other
		// exclamation syntax is rejected by whole-value validation below.
		if strings.HasSuffix(strings.ToLower(v), "!important") {
			v = strings.TrimSpace(v[:len(v)-len("!important")])
		}
		if v == "" {
			return invalid("CSS empty declaration value")
		}
		if _, err := validateCSSValue(v, s.assets, font && property == "src", false); err != nil {
			return err
		}
		count++
		if count > 128 {
			return limited("CSS declarations")
		}
		if s.char(";") {
			s.index++
		}
	}
}

func validateRules(rules []*css.Rule, assets map[string]resolvedAsset, resolve bool, count, bytes *int) error {
	for _, rule := range rules {
		*count++
		*bytes += len(rule.Prelude) + len(rule.Name) + 32
		if *count > 512 {
			return limited("CSS rules")
		}
		font := false
		if rule.Kind == css.QualifiedRule {
			if len(rule.Selectors) == 0 {
				return invalid("CSS selector")
			}
			for _, selector := range rule.Selectors {
				if !selectorPattern.MatchString(selector) {
					return invalid("CSS selector syntax")
				}
			}
		} else {
			switch rule.Name {
			case "@media":
				if rule.Prelude != "print" && rule.Prelude != "screen" {
					return invalid("CSS media rule")
				}
			case "@page":
				if rule.Prelude != "" && rule.Prelude != ":first" && rule.Prelude != ":left" && rule.Prelude != ":right" {
					return invalid("CSS page rule")
				}
			case "@font-face":
				font = true
				if rule.Prelude != "" {
					return invalid("CSS font rule")
				}
			default:
				return invalid("unsupported CSS at-rule")
			}
		}
		if len(rule.Declarations) > 128 {
			return limited("CSS declarations")
		}
		fontSource, fontFamily := false, false
		for _, declaration := range rule.Declarations {
			property := declaration.Property
			if font {
				if property != "font-family" && property != "font-style" && property != "font-weight" && property != "font-display" && property != "src" {
					return invalid("CSS font property")
				}
				fontSource = fontSource || property == "src"
				fontFamily = fontFamily || property == "font-family"
			} else if !safeProperties[property] {
				return invalid("unsupported CSS property")
			}
			value, err := validateCSSValue(declaration.Value, assets, font && property == "src", resolve)
			if err != nil {
				return err
			}
			*bytes += len(property) + len(value) + 32
			if *bytes > MaxMaterializedBytes/2 {
				return limited("embedded CSS bytes")
			}
			if resolve {
				declaration.Value = value
			}
		}
		if font && (!fontSource || !fontFamily) {
			return invalid("font source and family are required")
		}
		if err := validateRules(rule.Rules, assets, resolve, count, bytes); err != nil {
			return err
		}
	}
	return nil
}

func validateCSSValue(value string, assets map[string]resolvedAsset, fontSource, resolve bool) (string, error) {
	if len(value) > 4096 {
		return "", limited("CSS declaration bytes")
	}
	scan := scanner.New(value)
	var out strings.Builder
	urls := 0
	depth := 0
	for {
		token := scan.Next()
		if token.Type == scanner.TokenEOF {
			break
		}
		switch token.Type {
		case scanner.TokenError, scanner.TokenComment, scanner.TokenAtKeyword, scanner.TokenCDO, scanner.TokenCDC, scanner.TokenBOM:
			return "", invalid("CSS value tokens")
		case scanner.TokenURI:
			urls++
			url := strings.TrimSpace(token.Value[4 : len(token.Value)-1])
			if len(url) > 1 && ((url[0] == '"' && url[len(url)-1] == '"') || (url[0] == '\'' && url[len(url)-1] == '\'')) {
				url = url[1 : len(url)-1]
			}
			resolved, err := assetURL(url, assets, !fontSource)
			if err != nil {
				return "", err
			}
			if resolve {
				if len(resolved)+7 > MaxMaterializedBytes/2-out.Len() {
					return "", limited("embedded CSS declaration bytes")
				}
				out.WriteString(`url("` + resolved + `")`)
			} else {
				out.WriteString(token.Value)
			}
		case scanner.TokenFunction:
			function := strings.ToLower(strings.TrimSuffix(token.Value, "("))
			if !safeFunctions[function] || (function == "format" && !fontSource) {
				return "", invalid("unsupported CSS function")
			}
			depth++
			if depth > 8 {
				return "", limited("CSS function depth")
			}
			out.WriteString(token.Value)
		case scanner.TokenChar:
			if token.Value == ")" {
				depth--
				if depth < 0 {
					return "", invalid("CSS function closing")
				}
			}
			if strings.ContainsAny(token.Value, "{};@!:") {
				return "", invalid("CSS value punctuation")
			}
			out.WriteString(token.Value)
		default:
			out.WriteString(token.Value)
		}
	}
	if depth != 0 || (fontSource && urls != 1) {
		return "", invalid("CSS font source or function balance")
	}
	return out.String(), nil
}
