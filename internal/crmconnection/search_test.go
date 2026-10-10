// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func searchFixturePage(kind RecordKind, team string, count int, total int64, offset int) string {
	rows := make([]json.RawMessage, 0, count)
	for i := range count {
		rows = append(rows, json.RawMessage(syntheticBody(kind, fmt.Sprintf("native_cuid_%d", i), team)))
	}
	raw, _ := json.Marshal(map[string]any{"data": rows, "total": total, "limit": SearchPageSize, "offset": offset})
	return string(raw)
}

func searchFixtureClient(t *testing.T, conn Connection, body string) *Client {
	t.Helper()
	return testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/auth/me" {
			return jsonResponse(meBody(conn.Identity)), nil
		}
		return jsonResponse(body), nil
	})
}

func TestCRMSearchInputRefusesNormalizationAndUnboundedDiscovery(t *testing.T) {
	for _, in := range []SearchInput{
		{Kind: Deal}, {Kind: Contact, Query: "Åsa Öberg", Offset: 20},
		{Kind: Company, Query: strings.Repeat("😀", MaxSearchQueryRunes), Offset: MaxSearchOffset},
		{Kind: Deal, Query: "Åsa & co?=+/"},
	} {
		if err := ValidateSearchInput(in); err != nil {
			t.Fatal("supported bounded query refused", err)
		}
	}
	for _, in := range []SearchInput{
		{Kind: "crm.lead"}, {Kind: Deal, Offset: -20}, {Kind: Deal, Offset: 1},
		{Kind: Deal, Offset: MaxSearchOffset + SearchPageSize},
		{Kind: Deal, Query: "a"}, {Kind: Deal, Query: " ab"}, {Kind: Deal, Query: "ab "},
		{Kind: Deal, Query: " ab "}, {Kind: Deal, Query: "ab\tcd"},
		{Kind: Deal, Query: "ab\x00cd"}, {Kind: Deal, Query: "ab\u0085cd"},
		{Kind: Deal, Query: "ab\u202ecd"}, {Kind: Deal, Query: "ab\u200bcd"},
		{Kind: Deal, Query: "ab\u00a0"}, {Kind: Deal, Query: string([]byte{0xff, 'a'})},
		{Kind: Deal, Query: strings.Repeat("x", MaxSearchQueryRunes+1)},
		{Kind: Deal, Query: strings.Repeat("😀", MaxSearchQueryRunes+1)},
	} {
		if err := ValidateSearchInput(in); !errors.Is(err, ErrSearchInput) {
			t.Fatal("unsafe search input accepted")
		}
	}
}

func TestCRMSearchUsesTypedListAndOriginalAccountBookends(t *testing.T) {
	for _, kind := range []RecordKind{Deal, Contact, Company} {
		t.Run(string(kind), func(t *testing.T) {
			conn := testConnection(t)
			var calls []string
			query := "Åsa & co?=+/"
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet || r.URL.Host != "crm.example.test" || r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Cache-Control") != "no-cache" {
					t.Fatal("search route or original credential changed")
				}
				deadline, ok := r.Context().Deadline()
				if !ok || time.Until(deadline) > BatchTimeout {
					t.Fatal("search batch deadline missing")
				}
				calls = append(calls, r.URL.Path)
				if r.URL.Path == "/api/v1/auth/me" {
					return jsonResponse(meBody(conn.Identity)), nil
				}
				path := map[RecordKind]string{Deal: "deals", Contact: "contacts", Company: "companies"}[kind]
				if r.URL.Path != "/api/v1/"+path+"/" || len(r.URL.Query()) != 3 || r.URL.Query().Get("search") != query || r.URL.Query().Get("limit") != "20" || r.URL.Query().Get("offset") != "20" {
					t.Fatal("provider list parameters changed")
				}
				return jsonResponse(searchFixturePage(kind, conn.CRMTeamID, 1, 21, 20)), nil
			})
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: kind, Query: query, Offset: 20})
			if err != nil || len(s.Choices) != 1 || len(calls) != 3 || calls[0] != "/api/v1/auth/me" || calls[2] != "/api/v1/auth/me" || s.Identity != conn.Identity || s.StartedAt.IsZero() || s.CompletedAt.Before(s.StartedAt) {
				t.Fatal("typed search lacked complete original-account observation", err)
			}
			choice := s.Choices[0]
			want := map[RecordKind]string{Deal: "Synthetic deal", Contact: "Åsa Öberg", Company: "Synthetic company"}[kind]
			if choice.ID != "native_cuid_0" || choice.Kind != kind || choice.Label != want || choice.RecordUpdatedAt.IsZero() || s.CredentialBefore.CRMUserID != conn.CRMUserID || s.CredentialAfter.CRMTeamID != conn.CRMTeamID {
				t.Fatal("source-native choice/account identity missing")
			}
			if kind == Deal && choice.Secondary != "PROPOSAL" || kind != Deal && choice.Secondary != "" {
				t.Fatal("extra personal or contractual fields disclosed")
			}
			encoded, err := json.Marshal(choice)
			if err != nil || strings.Contains(string(encoded), "example.test") || strings.Contains(string(encoded), "9007199254740993") || strings.Contains(string(encoded), "Sales director") || strings.Contains(string(encoded), "Synthetic-registration") {
				t.Fatal("discovery choice disclosed unrequested record values")
			}
		})
	}
}

func TestCRMSearchPaginationIsBoundedMutableDiscovery(t *testing.T) {
	conn := testConnection(t)
	for _, tc := range []struct {
		name       string
		count      int
		total      int64
		offset     int
		hasMore    bool
		nextOffset int
	}{
		{"empty_recent", 0, 0, 0, false, 0},
		{"complete", 20, 20, 0, false, 0},
		{"next_page", 20, 21, 0, true, 20},
		{"offset", 20, 41, 20, true, 40},
		{"short_page_count_race", 1, 100, 0, false, 0},
		{"lower_count_race", 20, 0, 0, false, 0},
		{"max_offset", 20, 2000, MaxSearchOffset, false, 0},
		{"int64_count", 20, 9223372036854775807, 0, true, 20},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := searchFixtureClient(t, conn, searchFixturePage(Deal, conn.CRMTeamID, tc.count, tc.total, tc.offset))
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal, Offset: tc.offset})
			if err != nil || s.Choices == nil || len(s.Choices) != tc.count || s.HasMore != tc.hasMore || s.NextOffset != tc.nextOffset {
				t.Fatal("pagination exceeded discovery contract", err)
			}
		})
	}
}

func TestCRMSearchRejectsAmbiguousOrWrongPagination(t *testing.T) {
	conn := testConnection(t)
	base := searchFixturePage(Deal, conn.CRMTeamID, 1, 1, 0)
	mutate := func(key string, value any) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(base), &m); err != nil {
			t.Fatal(err)
		}
		m[key] = value
		raw, _ := json.Marshal(m)
		return string(raw)
	}
	for name, body := range map[string]string{
		"null_data":       mutate("data", nil),
		"object_data":     mutate("data", map[string]any{}),
		"missing_data":    strings.Replace(base, `"data":`, `"wrong":`, 1),
		"unknown_key":     mutate("extra", "private"),
		"duplicate":       strings.Replace(base, `"limit":20`, `"limit":20,"limit":20`, 1),
		"escaped_alias":   strings.Replace(base, `"limit":20`, `"limit":20,"li\u006dit":20`, 1),
		"case_alias":      mutate("Limit", 20),
		"case_only":       strings.Replace(base, `"limit":20`, `"Limit":20`, 1),
		"wrong_limit":     mutate("limit", 100),
		"wrong_offset":    mutate("offset", 20),
		"negative_total":  mutate("total", -1),
		"null_total":      mutate("total", nil),
		"string_total":    mutate("total", "1"),
		"fraction_total":  strings.Replace(base, `"total":1`, `"total":1.0`, 1),
		"exponent_total":  strings.Replace(base, `"total":1`, `"total":1e0`, 1),
		"overflow_total":  strings.Replace(base, `"total":1`, `"total":9223372036854775808`, 1),
		"trailing_object": base + `{}`,
		"too_many_rows":   searchFixturePage(Deal, conn.CRMTeamID, SearchPageSize+1, 21, 0),
	} {
		t.Run(name, func(t *testing.T) {
			c := searchFixtureClient(t, conn, body)
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal})
			if err == nil || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("malformed page returned partial discovery")
			}
		})
	}
}

func TestCRMSearchRejectsUntrustedRowsWithoutPartialChoices(t *testing.T) {
	conn := testConnection(t)
	for _, fault := range []string{"duplicate_id", "foreign_team", "missing_team", "null_team", "missing_id", "null_id", "unsafe_id", "missing_updated", "null_updated", "future_updated", "case_id", "label_control", "label_format", "label_oversize", "secondary_control"} {
		t.Run(fault, func(t *testing.T) {
			var page map[string]any
			if err := json.Unmarshal([]byte(searchFixturePage(Deal, conn.CRMTeamID, 2, 2, 0)), &page); err != nil {
				t.Fatal(err)
			}
			rows := page["data"].([]any)
			bad := rows[1].(map[string]any)
			switch fault {
			case "duplicate_id":
				bad["id"] = "native_cuid_0"
			case "foreign_team":
				bad["team_id"] = "another_team"
			case "missing_team":
				delete(bad, "team_id")
			case "null_team":
				bad["team_id"] = nil
			case "missing_id":
				delete(bad, "id")
			case "null_id":
				bad["id"] = nil
			case "unsafe_id":
				bad["id"] = "../another"
			case "missing_updated":
				delete(bad, "updated_at")
			case "null_updated":
				bad["updated_at"] = nil
			case "future_updated":
				bad["updated_at"] = "2026-10-11T00:00:00Z"
			case "case_id":
				bad["ID"] = bad["id"]
			case "label_control":
				bad["title"] = "unsafe\nlabel"
			case "label_format":
				bad["title"] = "unsafe\u202elabel"
			case "label_oversize":
				bad["title"] = strings.Repeat("Å", MaxSearchLabelBytes/2+1)
			case "secondary_control":
				bad["stage"] = "PROPOSAL\t"
			}
			raw, _ := json.Marshal(page)
			c := searchFixtureClient(t, conn, string(raw))
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal})
			if err == nil || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("untrusted later row leaked an earlier choice")
			}
		})
	}
}

func TestCRMSearchRefusesErasedOrPermissionFilteredContacts(t *testing.T) {
	conn := testConnection(t)
	for _, fault := range []string{"anonymized_at", "missing_anonymized", "anonymized_name", "anonymized_email", "missing_first", "null_email"} {
		t.Run(fault, func(t *testing.T) {
			var page map[string]any
			if err := json.Unmarshal([]byte(searchFixturePage(Contact, conn.CRMTeamID, 1, 1, 0)), &page); err != nil {
				t.Fatal(err)
			}
			row := page["data"].([]any)[0].(map[string]any)
			switch fault {
			case "anonymized_at":
				row["anonymized_at"] = "2026-10-10T00:00:00Z"
			case "missing_anonymized":
				delete(row, "anonymized_at")
			case "anonymized_name":
				row["first_name"] = "(anonymized)"
			case "anonymized_email":
				row["email"] = "anon-private@example.invalid"
			case "missing_first":
				delete(row, "first_name")
			case "null_email":
				row["email"] = nil
			}
			raw, _ := json.Marshal(page)
			c := searchFixtureClient(t, conn, string(raw))
			if s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Contact}); err == nil || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("erased or unavailable contact was selectable")
			}
		})
	}
}

func TestCRMSearchFallbackNeverGuessesPrintedValues(t *testing.T) {
	conn := testConnection(t)
	for _, kind := range []RecordKind{Deal, Company} {
		for _, state := range []string{"missing", "null", "empty"} {
			t.Run(string(kind)+"/"+state, func(t *testing.T) {
				var page map[string]any
				if err := json.Unmarshal([]byte(searchFixturePage(kind, conn.CRMTeamID, 1, 1, 0)), &page); err != nil {
					t.Fatal(err)
				}
				row := page["data"].([]any)[0].(map[string]any)
				key := map[RecordKind]string{Deal: "title", Company: "name"}[kind]
				switch state {
				case "missing":
					delete(row, key)
				case "null":
					row[key] = nil
				case "empty":
					row[key] = ""
				}
				raw, _ := json.Marshal(page)
				c := searchFixtureClient(t, conn, string(raw))
				s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: kind})
				want := "native_cuid_0"
				if state == "empty" {
					want = ""
				}
				if err != nil || len(s.Choices) != 1 || s.Choices[0].Label != want {
					t.Fatal("discovery missing/null/empty semantics changed", err)
				}
			})
		}
	}
}

func TestCRMSearchRejectsPrincipalChangesAtBothAccountChecks(t *testing.T) {
	for _, fault := range []string{"before_user", "before_team", "after_user", "after_team", "after_inactive"} {
		t.Run(fault, func(t *testing.T) {
			conn := testConnection(t)
			accountCalls, listCalls := 0, 0
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer "+testToken {
					t.Fatal("account recheck replaced the credential")
				}
				if r.URL.Path != "/api/v1/auth/me" {
					listCalls++
					return jsonResponse(searchFixturePage(Deal, conn.CRMTeamID, 1, 1, 0)), nil
				}
				accountCalls++
				id := conn.Identity
				if fault == "before_user" || fault == "after_user" && accountCalls == 2 {
					id.CRMUserID = "other_user"
				}
				if fault == "before_team" || fault == "after_team" && accountCalls == 2 {
					id.CRMTeamID = "other_team"
				}
				body := meBody(id)
				if fault == "after_inactive" && accountCalls == 2 {
					body = strings.Replace(body, `"is_active":true`, `"is_active":false`, 1)
				}
				return jsonResponse(body), nil
			})
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal})
			if !errors.Is(err, ErrIdentity) || !reflect.DeepEqual(s, SearchResult{}) || strings.HasPrefix(fault, "before_") && listCalls != 0 || strings.HasPrefix(fault, "after_") && listCalls != 1 {
				t.Fatal("changed principal admitted discovery")
			}
		})
	}
}

func TestCRMSearchRefusesUnusableConnectionBeforeRemoteReads(t *testing.T) {
	for _, fault := range []string{"disabled", "unverified", "future_verified", "different_org", "generation", "origin", "ciphertext", "missing_keyring", "invalid_input", "canceled"} {
		t.Run(fault, func(t *testing.T) {
			conn := testConnection(t)
			keyring := testKeyring(t)
			calls := 0
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(meBody(conn.Identity)), nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input := SearchInput{Kind: Deal}
			switch fault {
			case "disabled":
				conn.Enabled = false
			case "unverified":
				conn.VerifiedAt = time.Time{}
			case "future_verified":
				conn.VerifiedAt = c.now().Add(MaxClockSkew + time.Second)
			case "different_org":
				conn.OrgID = uuid.New()
			case "generation":
				conn.Generation++
			case "origin":
				conn.Origin = "https://other.example.test"
			case "ciphertext":
				conn.Ciphertext = nil
			case "missing_keyring":
				keyring = nil
			case "invalid_input":
				input.Query = " a"
			case "canceled":
				cancel()
			}
			s, err := c.SearchRecords(ctx, conn, keyring, input)
			if err == nil || calls != 0 || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("unusable authority performed discovery")
			}
		})
	}
}

func TestCRMSearchBoundedUpstreamFailuresAreRedacted(t *testing.T) {
	conn := testConnection(t)
	for _, status := range []int{301, 401, 403, 404, 429, 503} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			calls := 0
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return jsonResponse(meBody(conn.Identity)), nil
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"5"}}, Body: io.NopCloser(strings.NewReader("private " + testToken))}, nil
			})
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal})
			var upstream *HTTPError
			if !errors.As(err, &upstream) || upstream.Status != status || upstream.RetryAfter != 5*time.Second || strings.Contains(err.Error(), testToken) || calls != 2 || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("upstream failure retried or disclosed private data")
			}
		})
	}
	for _, fault := range []string{"length", "chunked", "content_type", "transport"} {
		t.Run(fault, func(t *testing.T) {
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/auth/me" {
					return jsonResponse(meBody(conn.Identity)), nil
				}
				if fault == "transport" {
					return nil, fmt.Errorf("private URL %s", testToken)
				}
				resp := jsonResponse(strings.Repeat(" ", MaxResponseBytes+1))
				if fault == "chunked" {
					resp.ContentLength = -1
				}
				if fault == "content_type" {
					resp = jsonResponse(searchFixturePage(Deal, conn.CRMTeamID, 1, 1, 0))
					resp.Header.Set("Content-Type", "text/html")
				}
				return resp, nil
			})
			s, err := c.SearchRecords(context.Background(), conn, testKeyring(t), SearchInput{Kind: Deal})
			if err == nil || strings.Contains(err.Error(), testToken) || !reflect.DeepEqual(s, SearchResult{}) {
				t.Fatal("unbounded or private discovery response accepted")
			}
		})
	}
}

func TestCRMSearchCancellationAfterListReturnsNoChoices(t *testing.T) {
	conn := testConnection(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.URL.Path == "/api/v1/auth/me" {
			return jsonResponse(meBody(conn.Identity)), nil
		}
		cancel()
		return jsonResponse(searchFixturePage(Deal, conn.CRMTeamID, 1, 1, 0)), nil
	})
	s, err := c.SearchRecords(ctx, conn, testKeyring(t), SearchInput{Kind: Deal})
	if !errors.Is(err, context.Canceled) || calls != 2 || !reflect.DeepEqual(s, SearchResult{}) {
		t.Fatal("cancellation exposed a partial selection")
	}
}

func TestCRMConcurrentSearchesDoNotShareChoiceState(t *testing.T) {
	conn := testConnection(t)
	c := searchFixtureClient(t, conn, searchFixturePage(Deal, conn.CRMTeamID, 1, 1, 0))
	k := testKeyring(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.SearchRecords(context.Background(), conn, k, SearchInput{Kind: Deal})
			if err != nil || len(s.Choices) != 1 {
				t.Error("concurrent search failed", err)
				return
			}
			s.Choices[0].Label = "mutated client choice"
			next, err := c.SearchRecords(context.Background(), conn, k, SearchInput{Kind: Deal})
			if err != nil || len(next.Choices) != 1 || next.Choices[0].Label != "Synthetic deal" {
				t.Error("choice state leaked between searches", err)
			}
		}()
	}
	wg.Wait()
}
