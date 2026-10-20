// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"errors"
	"unsafe"
)

var errCatalogRulePredicateComponentsV1 = errors.New("pdfadmission: rule predicate components unavailable")

// These are logical allocation-expression masses for ONE unchanged
// eidas.ValidateRule invocation on the actual owned predicate. They are not a
// general JSON parser/allocator arena or a process/PostgreSQL RSS bound. The
// fixed process header separately owns this no-allocation scanner's stack.
type catalogRulePredicateComponentsV1 struct {
	rawBytes, rawMessageCopies, pathCopies, typedExpressions, parentBytes int64
	containers, strings, scalars                                          int64
}

// Every predicate-map decode copies its direct values as RawMessage; every
// composite/in-array decode copies its direct children. Summing spans of ALL
// actual containers safely includes both, including containers under a leaf
// later rejected by validateComparableScalar. A leaf's field/op/scalar string
// and map keys are covered separately by six source-byte copies. Recursive
// fmt paths are accounted for every actual object at its concrete depth.
// No result grants work or changes ValidateRule's accepted shapes or errors.
func catalogRulePredicateComponentsForV1(raw json.RawMessage) (catalogRulePredicateComponentsV1, error) {
	var out catalogRulePredicateComponentsV1
	n := int64(len(raw))
	if n == 0 {
		return out, errCatalogRulePredicateComponentsV1
	}
	out.rawBytes = n
	// encoding/json's existing maximum nesting is 10000. This scanner refuses
	// only beyond that existing parser limit; it does not add a predicate limit.
	var starts [10000]int64
	var kinds [10000]byte
	depth := 0
	digits := int64(1)
	for v := n; v >= 10; v /= 10 {
		digits++
	}
	var spans, paths int64
	add := func(dst *int64, v int64) bool {
		if v < 0 || *dst > int64(1<<40)-v {
			return false
		}
		*dst += v
		return true
	}
	for i := 0; i < len(raw); {
		c := raw[i]
		switch c {
		case ' ', '\t', '\r', '\n', ':', ',':
			i++
		case '{', '[':
			if depth == len(starts) {
				return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
			}
			starts[depth] = int64(i)
			kinds[depth] = c
			depth++
			out.containers++
			if c == '{' {
				p := int64(9) + (6+digits)*int64(depth)
				if !add(&paths, p) {
					return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
				}
			}
			i++
		case '}', ']':
			if depth == 0 || (c == '}' && kinds[depth-1] != '{') || (c == ']' && kinds[depth-1] != '[') {
				return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
			}
			depth--
			if !add(&spans, int64(i)+1-starts[depth]) {
				return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
			}
			i++
		case '"':
			out.strings++
			i++
			closed := false
			for i < len(raw) {
				if raw[i] == '"' {
					i++
					closed = true
					break
				}
				if raw[i] == '\\' {
					i++
					if i == len(raw) {
						break
					}
				}
				i++
			}
			if !closed {
				return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
			}
		default:
			// The actual fixed input decoder or stored JSONB already establishes JSON
			// syntax. Count every primitive conservatively without decoding numbers,
			// strings, keys, or schema; unchanged ValidateRule owns those decisions.
			start := i
			for i < len(raw) && raw[i] != ' ' && raw[i] != '\t' && raw[i] != '\r' && raw[i] != '\n' && raw[i] != ',' && raw[i] != ']' && raw[i] != '}' && raw[i] != ':' {
				i++
			}
			if i == start {
				return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
			}
			out.scalars++
		}
	}
	if depth != 0 {
		return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
	}
	const max int64 = 1 << 40
	if spans > max/2 || n > max/6 || paths > max/4 {
		return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
	}
	out.rawMessageCopies = 2*spans + 6*n
	out.pathCopies = 4 * paths
	// Positive logical typed containers cover map[string]RawMessage, child
	// []RawMessage, scalar-any decoder values and returned validation errors.
	// Counting every string as a possible map key only overstates the fixed
	// validator's actual expressions; empty objects/arrays still pay headers.
	container := int64(unsafe.Sizeof(map[string]json.RawMessage{})) + int64(unsafe.Sizeof([]json.RawMessage{})) + int64(unsafe.Sizeof(any(nil)))
	entry := int64(unsafe.Sizeof("")) + int64(unsafe.Sizeof(json.RawMessage{})) + int64(unsafe.Sizeof(any(nil)))
	totalNodes := out.containers + out.strings + out.scalars
	if out.containers > max/container || totalNodes > max/entry {
		return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
	}
	out.typedExpressions = out.containers*container + totalNodes*entry
	for _, v := range []int64{out.rawMessageCopies, out.pathCopies, out.typedExpressions} {
		if !add(&out.parentBytes, v) {
			return catalogRulePredicateComponentsV1{}, errCatalogRulePredicateComponentsV1
		}
	}
	return out, nil
}
