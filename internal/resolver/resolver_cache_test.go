// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package resolver

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestInvalidateForSourceOrgsIsTenantScoped(t *testing.T) {
	resolver := New(nil)
	orgA := uuid.New()
	orgB := uuid.New()
	key := func(orgID uuid.UUID, kind, ref, path string) string {
		return sourceCacheKey(orgID, kind, ref, path)
	}
	for cacheKey, value := range map[string]string{
		key(orgA, "crm.deal", "shared-ref", "amount"):  "a-amount",
		key(orgA, "crm.deal", "shared-ref", "stage"):   "a-stage",
		key(orgB, "crm.deal", "shared-ref", "amount"):  "b-amount",
		key(orgA, "crm.deal", "other-ref", "amount"):   "a-other",
		key(orgA, "crm.contact", "shared-ref", "name"): "a-contact",
	} {
		resolver.Cache.put(cacheKey, value)
	}

	if got := resolver.InvalidateForSourceOrgs("crm.deal", "shared-ref", []uuid.UUID{orgA}); got != 2 {
		t.Fatalf("invalidated entries = %d, want 2", got)
	}
	if _, ok := resolver.Cache.get(key(orgA, "crm.deal", "shared-ref", "amount")); ok {
		t.Fatal("authorized org cache entry survived invalidation")
	}
	for _, untouched := range []string{
		key(orgB, "crm.deal", "shared-ref", "amount"),
		key(orgA, "crm.deal", "other-ref", "amount"),
		key(orgA, "crm.contact", "shared-ref", "name"),
	} {
		if _, ok := resolver.Cache.get(untouched); !ok {
			t.Fatalf("unrelated or unaudited cache entry %q was removed", untouched)
		}
	}
	if got := resolver.InvalidateForSourceOrgs("crm.deal", "shared-ref", nil); got != 0 {
		t.Fatalf("empty tenant authorization invalidated %d entries", got)
	}
}

func TestCacheBoundsAndPrunesUnaccessedExpiredEntries(t *testing.T) {
	c := newCache(time.Hour)
	for i := 0; i < maxCacheEntries+10; i++ {
		c.put(fmt.Sprintf("k%d", i), "value")
	}
	if len(c.m) != maxCacheEntries {
		t.Fatalf("cache count %d", len(c.m))
	}
	c.m["expired-unread"] = cacheEntry{value: "private", at: time.Now().Add(-2 * time.Hour)}
	c.put("new", "value")
	if _, ok := c.m["expired-unread"]; ok {
		t.Fatal("unread expired entry retained")
	}
	// Byte budget must apply independently of cardinality.
	for i := 0; i < 40; i++ {
		c.put(fmt.Sprintf("large%d", i), strings.Repeat("x", 256<<10))
	}
	bytes := 0
	for k, e := range c.m {
		bytes += len(k) + len(e.value)
	}
	if bytes > maxCacheBytes {
		t.Fatalf("cache retained %d bytes", bytes)
	}
	c.put("too-large", strings.Repeat("x", maxCacheBytes+1))
	if _, ok := c.m["too-large"]; ok {
		t.Fatal("oversized value cached")
	}
	c.put("new", "replacement")
	if v, ok := c.get("new"); !ok || v != "replacement" {
		t.Fatal("replacement not retained")
	}
}

func TestInvalidationFencesInflightCacheMiss(t *testing.T) {
	org := uuid.New()
	resolver := New(nil)
	key := sourceCacheKey(org, "crm.deal", "42", "name")
	_, hit, generation := resolver.Cache.getWithGeneration(key)
	if hit {
		t.Fatal("unexpected cached value")
	}
	if dropped := resolver.InvalidateForSourceOrgs("crm.deal", "42", []uuid.UUID{org}); dropped != 0 {
		t.Fatalf("dropped=%d", dropped)
	}
	if resolver.Cache.putIfGeneration(key, "old upstream response", generation) {
		t.Fatal("pre-invalidation response repopulated cache")
	}
	if _, hit := resolver.Cache.get(key); hit {
		t.Fatal("old value cached")
	}
	_, _, freshGeneration := resolver.Cache.getWithGeneration(key)
	if !resolver.Cache.putIfGeneration(key, "new upstream response", freshGeneration) {
		t.Fatal("fresh generation refused")
	}
	if value, hit := resolver.Cache.get(key); !hit || value != "new upstream response" {
		t.Fatalf("value=%q hit=%v", value, hit)
	}
}

func TestUnauthorizedInvalidationDoesNotFenceInflightMiss(t *testing.T) {
	resolver := New(nil)
	_, _, generation := resolver.Cache.getWithGeneration("key")
	resolver.InvalidateForSourceOrgs("crm.deal", "42", nil)
	if !resolver.Cache.putIfGeneration("key", "value", generation) {
		t.Fatal("unauthorized invalidation changed generation")
	}
}

func TestSourceCacheKeysSeparateDelimiterBearingFields(t *testing.T) {
	resolver := New(nil)
	org := uuid.New()
	first := sourceCacheKey(org, "crm.deal", "a|b", "c")
	second := sourceCacheKey(org, "crm.deal", "a", "b|c")
	if first == second {
		t.Fatal("distinct source tuples collide")
	}
	resolver.Cache.put(first, "first record")
	resolver.Cache.put(second, "second record")
	if value, ok := resolver.Cache.get(first); !ok || value != "first record" {
		t.Fatalf("first=%q", value)
	}
	if value, ok := resolver.Cache.get(second); !ok || value != "second record" {
		t.Fatalf("second=%q", value)
	}
	if dropped := resolver.InvalidateForSourceOrgs("crm.deal", "a", []uuid.UUID{org}); dropped != 1 {
		t.Fatalf("dropped=%d", dropped)
	}
	if _, ok := resolver.Cache.get(first); !ok {
		t.Fatal("prefix-matching different source invalidated")
	}
	if _, ok := resolver.Cache.get(second); ok {
		t.Fatal("exact source survived invalidation")
	}
}
