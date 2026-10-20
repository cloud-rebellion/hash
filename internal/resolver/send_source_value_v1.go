// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// Generic source objects retain sorted key slices rather than hash maps. This
// preserves decoded-key/path/UseNumber/stringify decisions without inheriting
// an unbounded Swiss-map directory from a256KiB response with many keys.
// Native work prices actual nodes/edges/strings before invoking this parser;
// this pure helper grants no resources, SQL scope or source provenance.
var errSendJSONPathV1 = errors.New("resolver source path unavailable")
var errSendJSONNullV1 = errors.New("resolver source value is null")

type sendJSONNodeV1 struct {
	kind  byte
	text  string
	edges []sendJSONEdgeV1
}
type sendJSONEdgeV1 struct {
	key   string
	index int
}
type sendJSONTreeV1 struct {
	nodes   []sendJSONNodeV1
	decoder *json.Decoder
}

func sendJSONSourceValueV1(raw []byte, path string) (string, error) {
	if !utf8.Valid(raw) {
		return "", errAmbiguousResponse
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", errAmbiguousResponse
	}
	tree := sendJSONTreeV1{decoder: json.NewDecoder(bytes.NewReader(raw))}
	tree.decoder.UseNumber()
	root, err := tree.readV1(0)
	if err != nil {
		return "", errAmbiguousResponse
	}
	if _, err = tree.decoder.Token(); err != io.EOF {
		return "", errAmbiguousResponse
	}
	selected, ok := tree.lookupV1(root, path)
	if !ok {
		return "", errSendJSONPathV1
	}
	node := tree.nodes[selected]
	switch node.kind {
	case 's', 'n', 'b':
		return node.text, nil
	case '0':
		return "", errSendJSONNullV1
	}
	var output bytes.Buffer
	if err = tree.emitV1(&output, selected); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (t *sendJSONTreeV1) readV1(depth int) (int, error) {
	if depth > 64 {
		return 0, errAmbiguousResponse
	}
	token, err := t.decoder.Token()
	if err != nil {
		return 0, errAmbiguousResponse
	}
	index := len(t.nodes)
	t.nodes = append(t.nodes, sendJSONNodeV1{})
	switch value := token.(type) {
	case string:
		t.nodes[index].kind = 's'
		t.nodes[index].text = value
	case json.Number:
		t.nodes[index].kind = 'n'
		t.nodes[index].text = value.String()
	case bool:
		t.nodes[index].kind = 'b'
		if value {
			t.nodes[index].text = "true"
		} else {
			t.nodes[index].text = "false"
		}
	case nil:
		t.nodes[index].kind = '0'
	case json.Delim:
		if value != '{' && value != '[' {
			return 0, errAmbiguousResponse
		}
		t.nodes[index].kind = byte(value)
		for t.decoder.More() {
			key := ""
			if value == '{' {
				rawKey, err := t.decoder.Token()
				if err != nil {
					return 0, errAmbiguousResponse
				}
				var ok bool
				key, ok = rawKey.(string)
				if !ok {
					return 0, errAmbiguousResponse
				}
			}
			child, err := t.readV1(depth + 1)
			if err != nil {
				return 0, err
			}
			t.nodes[index].edges = append(t.nodes[index].edges, sendJSONEdgeV1{key: key, index: child})
		}
		end, err := t.decoder.Token()
		if err != nil || value == '{' && end != json.Delim('}') || value == '[' && end != json.Delim(']') {
			return 0, errAmbiguousResponse
		}
		if value == '{' {
			edges := t.nodes[index].edges
			sort.Slice(edges, func(i, j int) bool { return edges[i].key < edges[j].key })
			for i := 1; i < len(edges); i++ {
				if edges[i-1].key == edges[i].key {
					return 0, errAmbiguousResponse
				}
			}
		}
	default:
		return 0, errAmbiguousResponse
	}
	return index, nil
}
func (t *sendJSONTreeV1) lookupV1(root int, path string) (int, bool) {
	current := root
	if path == "" {
		return current, true
	}
	for start := 0; ; {
		end := len(path)
		if dot := strings.IndexByte(path[start:], '.'); dot >= 0 {
			end = start + dot
		}
		segment := path[start:end]
		node := t.nodes[current]
		switch node.kind {
		case '{':
			at := sort.Search(len(node.edges), func(i int) bool { return node.edges[i].key >= segment })
			if at == len(node.edges) || node.edges[at].key != segment {
				return 0, false
			}
			current = node.edges[at].index
		case '[':
			at, err := parseArrayIndex(segment)
			if err != nil || at < 0 || at >= len(node.edges) {
				return 0, false
			}
			current = node.edges[at].index
		default:
			return 0, false
		}
		if end == len(path) {
			return current, true
		}
		start = end + 1
	}
}
func (t *sendJSONTreeV1) emitV1(out *bytes.Buffer, index int) error {
	node := t.nodes[index]
	switch node.kind {
	case 's':
		encoded, err := json.Marshal(node.text)
		if err != nil {
			return err
		}
		out.Write(encoded)
	case 'n', 'b':
		out.WriteString(node.text)
	case '0':
		out.WriteString("null")
	case '{', '[':
		out.WriteByte(node.kind)
		for i, edge := range node.edges {
			if i != 0 {
				out.WriteByte(',')
			}
			if node.kind == '{' {
				encoded, err := json.Marshal(edge.key)
				if err != nil {
					return err
				}
				out.Write(encoded)
				out.WriteByte(':')
			}
			if err := t.emitV1(out, edge.index); err != nil {
				return err
			}
		}
		if node.kind == '{' {
			out.WriteByte('}')
		} else {
			out.WriteByte(']')
		}
	}
	return nil
}
