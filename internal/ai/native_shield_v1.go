// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package ai

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Regex discovery's real match-index backing is paid before FindAll. Each
// unchanged replacement/token/HMAC/map producer is then funded from the actual
// current input and actual match count, before it can expand or allocate.
func nativeShieldReplaceV1(ctx context.Context, re *regexp.Regexp, in, kind string, replace func(string) string) (string, error) {
	cost, err := NativeCostV1(4096, int64(len(in)), 64)
	if err != nil {
		return "", err
	}
	if err = RetainNativeV1(ctx, cost); err != nil {
		return "", err
	}
	matches := re.FindAllStringIndex(in, -1)
	// All fixed token strings have the same original recipe; phone's rejected
	// short-number matches are conservatively included in its real count.
	tokenBytes := int64(len("[shield:"+kind+":tok_") + 16 + 1)
	upper, err := NativeCostV1(int64(len(in)), int64(len(matches)), tokenBytes)
	if err != nil {
		return "", err
	}
	cost, err = NativeCostV1(4096, upper, 8)
	if err != nil {
		return "", err
	}
	cost, err = NativeCostV1(cost, int64(len(matches)), 4096)
	if err != nil {
		return "", err
	}
	if err = RetainNativeV1(ctx, cost); err != nil {
		return "", err
	}
	return re.ReplaceAllStringFunc(in, replace), nil
}
func tokenizeForNativeV1(ctx context.Context, shield Shield, in string, known ...string) (string, Handle, error) {
	if NativeWorkflowFromContextV1(ctx) == nil {
		return shield.Tokenize(ctx, in, known...)
	}
	switch s := shield.(type) {
	case NoopShield:
		return s.Tokenize(ctx, in, known...)
	case *LocalShield:
		if err := RetainNativeV1(ctx, 4096); err != nil {
			return "", nil, err
		}
		if in == "" {
			return in, &localHandle{shield: s, ids: nil}, nil
		}
		h := &localHandle{shield: s, ids: []string{}, plain: map[string]string{}, ts: time.Now()}
		out := in
		var err error
		for _, stage := range []struct {
			re   *regexp.Regexp
			kind string
		}{{reEmail, "email"}, {reIBAN, "iban"}, {rePersonnummer, "personnummer"}, {rePhone, "phone"}} {
			kind := stage.kind
			out, err = nativeShieldReplaceV1(ctx, stage.re, out, kind, func(match string) string {
				if kind == "phone" {
					stripped := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", "+", "").Replace(match)
					if len(stripped) < 7 {
						return match
					}
				}
				return s.token(kind, match, h)
			})
			if err != nil {
				return "", nil, err
			}
		}
		var termBytes int64
		for _, term := range known {
			termBytes, err = NativeCostV1(termBytes, int64(len(term)), 4)
			if err != nil {
				return "", nil, err
			}
		}
		cost, err := NativeCostV1(termBytes, int64(len(known)), 512)
		if err != nil {
			return "", nil, err
		}
		if err = RetainNativeV1(ctx, cost); err != nil {
			return "", nil, err
		}
		for _, term := range sortedDistinctByLenDesc(known) {
			cost, err := NativeCostV1(65536, int64(len(term)), 2048)
			if err != nil {
				return "", nil, err
			}
			if err = RetainNativeV1(ctx, cost); err != nil {
				return "", nil, err
			}
			re, e := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(term) + `\b`)
			if e != nil {
				continue
			}
			out, err = nativeShieldReplaceV1(ctx, re, out, "name", func(string) string { return s.token("name", term, h) })
			if err != nil {
				return "", nil, err
			}
		}
		return out, h, nil
	default:
		return "", nil, ErrNativeWorkflowV1
	}
}
func untokenizeForNativeV1(ctx context.Context, shield Shield, in string, raw Handle) (string, error) {
	if NativeWorkflowFromContextV1(ctx) == nil {
		return shield.Untokenize(ctx, in, raw)
	}
	switch s := shield.(type) {
	case NoopShield:
		return s.Untokenize(ctx, in, raw)
	case *LocalShield:
		h, ok := raw.(*localHandle)
		if !ok || h.shield != s {
			return in, nil
		}
		out := in
		for _, id := range h.ids {
			if err := ctx.Err(); err != nil {
				return "", err
			}
			plain, ok := h.plain[id]
			if !ok {
				continue
			}
			count := int64(strings.Count(out, id))
			if count == 0 {
				continue
			}
			current := int64(len(out))
			removed := count * int64(len(id))
			if removed > current {
				return "", ErrNativeWorkflowV1
			}
			next, err := NativeCostV1(current-removed, count, int64(len(plain)))
			if err != nil {
				return "", err
			}
			cost, err := NativeCostV1(4096, next, 4)
			if err != nil {
				return "", err
			}
			if err = RetainNativeV1(ctx, cost); err != nil {
				return "", err
			}
			out = strings.ReplaceAll(out, id, plain)
		}
		return out, nil
	default:
		return "", ErrNativeWorkflowV1
	}
}
