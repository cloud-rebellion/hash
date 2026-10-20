// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sourcejson

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestPostgreSQLJSONBWireUpperBoundV1(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cases := []struct {
		raw  string
		want int64
	}{
		{"{}", 2}, {"[]", 2}, {"null", 4}, {"true", 4}, {"false", 5},
		{"123", 3}, {"-123", 4}, {"1e6", 7}, {"1e-6", 8}, {"1.23e4", 5},
		{"1.23e-4", 8}, {"-0.00100e-2", 10}, {"0e-2", 4},
		{"{\"a\":1,\"b\":[true,2]}", 24},
		{"[1,2,3]", 9},
		{"\"é😀\"", 8},
		{"\"\\u00e9\\ud83d\\ude00\"", 20},
		{"\"a\\n\\t\\\\\\\"b\"", 12},
		{"  { \"a\" : 1 } \n", 8},
		{"1e131071", 131072}, {"1e-16383", 16385},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			raw := []byte(tc.raw)
			original := string(raw)
			got, err := PostgreSQLJSONBWireUpperBoundV1(ctx, raw)
			if err != nil || got != tc.want {
				t.Fatalf("bound=%d error=%v want=%d", got, err, tc.want)
			}
			if string(raw) != original {
				t.Fatal("input changed")
			}
		})
	}
}
func TestPostgreSQLJSONBWireUpperBoundV1Refusals(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, raw := range []string{"", " ", "01", "-.1", "1.", "1e", "1e+", "NaN", "Infinity", "truex", "[1,]", "{\"a\":}", "{\"a\":1,}", "\"\\u0000\"", "\"\\ud800\"", "\"\\udc00\"", "\"\\ud800\\u0041\"", "\"\\x\"", "\"a\nb\"", "\"", "1e9223372036854775807", "1e-9223372036854775807", "1e999999999999999999999"} {
		if got, err := PostgreSQLJSONBWireUpperBoundV1(ctx, []byte(raw)); got != 0 || !errors.Is(err, ErrPostgreSQLWireV1) {
			t.Fatalf("accepted invalid or overflow JSON %q: %d %v", raw, got, err)
		}
	}
	if got, err := PostgreSQLJSONBWireUpperBoundV1(ctx, []byte{'"', 0xff, '"'}); got != 0 || !errors.Is(err, ErrPostgreSQLWireV1) {
		t.Fatal("accepted malformed UTF8")
	}
	raw := []byte(strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66))
	if got, err := PostgreSQLJSONBWireUpperBoundV1(ctx, raw); got != 0 || !errors.Is(err, ErrPostgreSQLWireV1) {
		t.Fatal("accepted excess depth")
	}
	if _, err := wireAddV1(math.MaxInt64, 1); err == nil {
		t.Fatal("overflow accepted")
	}
}
func TestPostgreSQLJSONBWireUpperBoundV1Cancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	cancel()
	if got, err := PostgreSQLJSONBWireUpperBoundV1(ctx, []byte("{}")); got != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %d %v", got, err)
	}
	if got, err := PostgreSQLJSONBWireUpperBoundV1(context.Background(), []byte("{}")); got != 0 || !errors.Is(err, ErrPostgreSQLWireV1) {
		t.Fatal("unbounded context accepted")
	}
}
func TestPostgreSQLJSONBWireUpperBoundV1NoBodyAllocation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// This is a body-growth witness, not a compiler-specific zero-allocation
	// assertion: scanning a retained1MiB string does not decode/copy it.
	raw := []byte("{\"asset\":\"" + strings.Repeat("a", 1<<20) + "\",\"n\":1e1000}")
	allocated := testing.AllocsPerRun(5, func() {
		if _, err := PostgreSQLJSONBWireUpperBoundV1(ctx, raw); err != nil {
			panic(err)
		}
	})
	if allocated > 2 {
		t.Fatalf("scan allocated body objects: %f", allocated)
	}
}
