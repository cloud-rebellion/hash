// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package htmlmaster

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Compiled owns a private validated snapshot. Its methods never modify shared
// source nodes, declarations or asset bytes, so it can be reused concurrently.
type Compiled struct {
	master       Master
	canonical    []byte
	masterDigest string
	values       map[string]Value
	sections     map[string]Section
	assets       map[string]resolvedAsset
	renderCSS    string
}

func (c *Compiled) CanonicalJSON() []byte { return bytes.Clone(c.canonical) }
func (c *Compiled) Digest() string        { return c.masterDigest }

func Compile(master Master) (*Compiled, error) {
	if master.SchemaVersion != SchemaVersion && master.SchemaVersion != ContractSchemaVersion {
		return nil, invalid("unsupported schema version")
	}
	if len(master.HTML) == 0 || len(master.HTML) > MaxHTMLBytes || len(master.CSS) > MaxCSSBytes {
		return nil, limited("HTML or CSS bytes")
	}
	if !validText(master.HTML, MaxHTMLBytes) || !validText(master.CSS, MaxCSSBytes) {
		return nil, invalid("source text")
	}
	if len(master.Values) > MaxDefinitions || len(master.Sections) > MaxDefinitions {
		return nil, limited("definitions")
	}
	c := &Compiled{values: map[string]Value{}, sections: map[string]Section{}}
	master.Values = append([]Value{}, master.Values...)
	master.Sections = append([]Section{}, master.Sections...)
	master.Assets = append([]Asset{}, master.Assets...)
	for _, value := range master.Values {
		if !namePattern.MatchString(value.Name) || value.MaxChars < 1 || value.MaxChars > MaxValueChars || c.values[value.Name].Name != "" {
			return nil, invalid("value definition")
		}
		c.values[value.Name] = value
	}
	for _, section := range master.Sections {
		if !namePattern.MatchString(section.Name) || section.MaxChars < 1 || section.MaxChars > MaxSectionChars || c.sections[section.Name].Name != "" || !validText(section.DefaultText, section.MaxChars) {
			return nil, invalid("section definition")
		}
		c.sections[section.Name] = section
	}
	if err := c.compileContractProfile(&master); err != nil {
		return nil, err
	}
	assets, err := compileAssets(master.Assets)
	if err != nil {
		return nil, err
	}
	c.assets = assets
	if err := validateHTMLTokens(master.HTML); err != nil {
		return nil, err
	}
	nodes, err := parseFragment(master.HTML)
	if err != nil {
		return nil, err
	}
	valueUses, sectionUses := map[string]int{}, map[string]int{}
	count := 0
	for _, node := range nodes {
		if err := c.validateNode(node, 0, &count, valueUses, sectionUses); err != nil {
			return nil, err
		}
	}
	for name := range c.values {
		if valueUses[name] == 0 {
			return nil, invalid("unused value declaration: " + name)
		}
	}
	for name := range c.sections {
		if sectionUses[name] != 1 {
			return nil, invalid("section must have exactly one marker: " + name)
		}
	}
	canonicalHTML, err := renderFragment(nodes)
	if err != nil {
		return nil, err
	}
	if rawCanonical, err := tokenTreeCanonical(master.HTML); err != nil || rawCanonical != canonicalHTML {
		return nil, invalid("HTML parser would repair the declared structure")
	}
	if len(canonicalHTML) > MaxHTMLBytes {
		return nil, limited("canonical HTML bytes")
	}
	master.HTML = canonicalHTML
	canonicalCSS, renderedCSS, err := compileCSS(master.CSS, assets)
	if err != nil {
		return nil, err
	}
	if len(canonicalCSS) > MaxCSSBytes {
		return nil, limited("canonical CSS bytes")
	}
	master.CSS = canonicalCSS
	c.renderCSS = renderedCSS
	sort.Slice(master.Values, func(i, j int) bool { return master.Values[i].Name < master.Values[j].Name })
	sort.Slice(master.Sections, func(i, j int) bool { return master.Sections[i].Name < master.Sections[j].Name })
	sort.Slice(master.Assets, func(i, j int) bool { return master.Assets[i].Name < master.Assets[j].Name })
	c.master = master
	c.canonical, err = json.Marshal(master)
	if err != nil {
		return nil, invalid("cannot encode master")
	}
	if len(c.canonical) > MaxMasterJSONBytes {
		return nil, limited("canonical master bytes")
	}
	c.masterDigest = digest(versionedDomain("hash.html-master", master.SchemaVersion), c.canonical)
	return c, nil
}

func (c *Compiled) validateValues(values map[string]string, requireComplete bool) error {
	if len(values) > MaxDefinitions {
		return limited("input values")
	}
	for name, text := range values {
		definition, found := c.values[name]
		if !found {
			return invalid("unknown value name")
		}
		if !validText(text, definition.MaxChars) {
			return limited("value text: " + name)
		}
	}
	if requireComplete {
		missing := []string{}
		for name, definition := range c.values {
			if definition.Required && isBlank(values[name]) {
				missing = append(missing, name)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			return fmt.Errorf("%w: %s", ErrMissingValues, strings.Join(missing, ", "))
		}
	}
	return nil
}

func (c *Compiled) validateSections(sections map[string]string) error {
	if len(sections) > MaxDefinitions {
		return limited("input sections")
	}
	for name, text := range sections {
		definition, found := c.sections[name]
		if !found {
			return invalid("unknown section name")
		}
		if !validText(text, definition.MaxChars) {
			return limited("section text: " + name)
		}
	}
	return nil
}

func (c *Compiled) Materialize(input Input) (Result, error) {
	var result Result
	if c == nil {
		return result, invalid("missing compiled master")
	}
	// Profile readiness supplies semantic issue paths before generic required
	// value checks; both still apply to the same immutable input snapshot.
	if err := c.requireContractComplete(input); err != nil {
		return result, err
	}
	if err := c.validateValues(input.Values, true); err != nil {
		return result, err
	}
	if err := c.validateSections(input.Sections); err != nil {
		return result, err
	}
	values, sections := map[string]string{}, map[string]string{}
	for name := range c.values {
		values[name] = input.Values[name]
	}
	result.ChangedSections = []string{}
	for name, definition := range c.sections {
		text, overridden := input.Sections[name]
		if !overridden {
			text = definition.DefaultText
		}
		sections[name] = text
		if text != definition.DefaultText {
			result.ChangedSections = append(result.ChangedSections, name)
		}
	}
	sort.Strings(result.ChangedSections)
	nodes, err := parseFragment(c.master.HTML)
	if err != nil {
		return result, err
	}
	for _, node := range nodes {
		c.fillNode(node, values, sections)
	}
	var out boundedBuffer
	_, _ = out.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; font-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\"><style>"))
	if _, err = out.Write([]byte(c.renderCSS)); err != nil {
		return Result{}, err
	}
	_, _ = out.Write([]byte("</style></head><body>"))
	for _, node := range nodes {
		if err = html.Render(&out, node); err != nil {
			return Result{}, err
		}
	}
	if _, err = out.Write([]byte("</body></html>")); err != nil {
		return Result{}, err
	}
	result.HTML = out.String()
	result.MasterDigest = c.masterDigest
	envelope := struct {
		Master     string            `json:"master_digest"`
		Values     map[string]string `json:"values"`
		Sections   map[string]string `json:"sections"`
		HTMLDigest string            `json:"html_digest"`
	}{c.masterDigest, values, sections, digest(versionedDomain("hash.html-output", c.master.SchemaVersion), out.Bytes())}
	canonical, _ := json.Marshal(envelope)
	result.ContentDigest = digest(versionedDomain("hash.html-materialization", c.master.SchemaVersion), canonical)
	return result, nil
}

var allowedElements = map[string]bool{
	"main": true, "article": true, "section": true, "header": true, "footer": true, "div": true, "span": true,
	"p": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "br": true, "hr": true,
	"strong": true, "b": true, "em": true, "i": true, "u": true, "s": true, "small": true, "sup": true, "sub": true,
	"blockquote": true, "pre": true, "code": true, "ul": true, "ol": true, "li": true, "dl": true, "dt": true, "dd": true,
	"table": true, "thead": true, "tbody": true, "tfoot": true, "tr": true, "th": true, "td": true, "caption": true,
	"colgroup": true, "col": true, "img": true, "figure": true, "figcaption": true,
}
var voidElements = map[string]bool{"br": true, "hr": true, "img": true, "col": true}

// Validate the raw token stream before the HTML parser can repair or discard
// dangerous source. Requiring balanced explicit tags also avoids hidden marker
// movement through foster parenting or implicitly closed paragraph elements.
func validateHTMLTokens(source string) error {
	z := html.NewTokenizer(strings.NewReader(source))
	stack := []string{}
	count := 0
	for {
		typeID := z.Next()
		if typeID == html.ErrorToken {
			if z.Err() == io.EOF && len(z.Raw()) == 0 && len(stack) == 0 {
				return nil
			}
			return invalid("unbalanced HTML")
		}
		count++
		if count > 20000 {
			return limited("HTML tokens")
		}
		switch typeID {
		case html.TextToken:
			if !validText(string(z.Text()), MaxHTMLBytes) {
				return invalid("HTML text")
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			if !allowedElements[token.Data] || (typeID == html.SelfClosingTagToken && !voidElements[token.Data]) {
				return invalid("unsupported HTML element")
			}
			if err := validateAttrs(token.Data, token.Attr); err != nil {
				return err
			}
			if !voidElements[token.Data] {
				stack = append(stack, token.Data)
				if len(stack) > 64 {
					return limited("HTML depth")
				}
			}
		case html.EndTagToken:
			name := z.Token().Data
			if len(stack) == 0 || stack[len(stack)-1] != name {
				return invalid("unbalanced HTML tags")
			}
			stack = stack[:len(stack)-1]
		default:
			return invalid("comments, doctypes and processing instructions are unsupported")
		}
	}
}

func validateAttrs(element string, attrs []html.Attribute) error {
	seen := map[string]bool{}
	for _, attr := range attrs {
		if attr.Namespace != "" || seen[attr.Key] || len(attr.Val) > 1024 || !validText(attr.Val, 1024) {
			return invalid("HTML attribute")
		}
		seen[attr.Key] = true
		switch attr.Key {
		case "class", "id", "title", "lang", "dir":
			if (attr.Key == "dir" && attr.Val != "ltr" && attr.Val != "rtl" && attr.Val != "auto") || strings.ContainsAny(attr.Val, "{}") {
				return invalid("HTML attribute value")
			}
		case "data-hash-value", "data-hash-section":
			if !namePattern.MatchString(attr.Val) || voidElements[element] {
				return invalid("text marker attribute")
			}
		case "src":
			if element != "img" || !strings.HasPrefix(attr.Val, "hash-asset:") || !namePattern.MatchString(strings.TrimPrefix(attr.Val, "hash-asset:")) {
				return invalid("image source")
			}
		case "alt", "width", "height":
			if element != "img" {
				return invalid("image attribute")
			}
		case "colspan", "rowspan":
			if element != "td" && element != "th" {
				return invalid("table attribute")
			}
		case "scope":
			if element != "th" {
				return invalid("table attribute")
			}
		default:
			return invalid("unsupported HTML attribute")
		}
	}
	return nil
}

func parseFragment(source string) ([]*html.Node, error) {
	nodes, err := html.ParseFragment(strings.NewReader(source), &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div})
	if err != nil {
		return nil, invalid("HTML parse")
	}
	return nodes, nil
}

func (c *Compiled) validateNode(node *html.Node, depth int, count *int, values, sections map[string]int) error {
	*count++
	if depth > 64 || *count > 20000 {
		return limited("HTML tree")
	}
	if node.Type == html.TextNode {
		return nil
	}
	if node.Type != html.ElementNode || !allowedElements[node.Data] || node.Namespace != "" {
		return invalid("HTML tree element")
	}
	if err := validateAttrs(node.Data, node.Attr); err != nil {
		return err
	}
	markers := 0
	for _, attr := range node.Attr {
		switch attr.Key {
		case "data-hash-value":
			markers++
			if c.values[attr.Val].Name == "" {
				return invalid("undeclared value marker")
			}
			values[attr.Val]++
		case "data-hash-section":
			markers++
			if c.sections[attr.Val].Name == "" {
				return invalid("undeclared section marker")
			}
			sections[attr.Val]++
		case "src":
			asset, found := c.assets[strings.TrimPrefix(attr.Val, "hash-asset:")]
			if !found || !asset.image {
				return invalid("unknown or non-image HTML asset")
			}
		}
	}
	if markers > 1 || (markers > 0 && node.FirstChild != nil) {
		return invalid("markers must be distinct empty elements")
	}
	sort.Slice(node.Attr, func(i, j int) bool { return node.Attr[i].Key < node.Attr[j].Key })
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		if err := c.validateNode(child, depth+1, count, values, sections); err != nil {
			return err
		}
	}
	return nil
}

func (c *Compiled) fillNode(node *html.Node, values, sections map[string]string) {
	if node.Type != html.ElementNode {
		return
	}
	attrs := node.Attr[:0]
	for _, attr := range node.Attr {
		switch attr.Key {
		case "data-hash-value":
			node.AppendChild(&html.Node{Type: html.TextNode, Data: values[attr.Val]})
			continue
		case "data-hash-section":
			node.AppendChild(&html.Node{Type: html.TextNode, Data: sections[attr.Val]})
			continue
		case "src":
			attr.Val = c.assets[strings.TrimPrefix(attr.Val, "hash-asset:")].dataURL
		}
		attrs = append(attrs, attr)
	}
	node.Attr = attrs
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		c.fillNode(child, values, sections)
	}
}

func renderFragment(nodes []*html.Node) (string, error) {
	var out boundedBuffer
	for _, node := range nodes {
		if err := html.Render(&out, node); err != nil {
			return "", err
		}
	}
	return out.String(), nil
}

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(raw []byte) (int, error) {
	if len(raw) > MaxMaterializedBytes-b.Len() {
		return 0, limited("materialized HTML bytes")
	}
	return b.Buffer.Write(raw)
}
func (b *boundedBuffer) WriteString(raw string) (int, error) {
	if len(raw) > MaxMaterializedBytes-b.Len() {
		return 0, limited("materialized HTML bytes")
	}
	return b.Buffer.WriteString(raw)
}

func tokenTreeCanonical(source string) (string, error) {
	root := &html.Node{Type: html.ElementNode, Data: "div", DataAtom: atom.Div}
	stack := []*html.Node{root}
	z := html.NewTokenizer(strings.NewReader(source))
	for {
		switch z.Next() {
		case html.ErrorToken:
			if z.Err() != io.EOF || len(z.Raw()) != 0 || len(stack) != 1 {
				return "", invalid("HTML token tree")
			}
			nodes := []*html.Node{}
			for n := root.FirstChild; n != nil; n = n.NextSibling {
				nodes = append(nodes, n)
			}
			return renderFragment(nodes)
		case html.TextToken:
			stack[len(stack)-1].AppendChild(&html.Node{Type: html.TextNode, Data: string(z.Text())})
		case html.StartTagToken, html.SelfClosingTagToken:
			token := z.Token()
			sort.Slice(token.Attr, func(i, j int) bool { return token.Attr[i].Key < token.Attr[j].Key })
			node := &html.Node{Type: html.ElementNode, Data: token.Data, DataAtom: atom.Lookup([]byte(token.Data)), Attr: token.Attr}
			stack[len(stack)-1].AppendChild(node)
			if !voidElements[token.Data] {
				stack = append(stack, node)
			}
		case html.EndTagToken:
			if len(stack) <= 1 {
				return "", invalid("HTML token tree")
			}
			stack = stack[:len(stack)-1]
		default:
			return "", invalid("HTML token tree")
		}
	}
}
