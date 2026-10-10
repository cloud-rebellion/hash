// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bright-interaction/hash/internal/sourcejson"
)

const (
	SearchPageSize      = 20
	MaxSearchOffset     = 1000
	MaxSearchQueryRunes = 100
	MaxSearchQueryBytes = 400
	MaxSearchLabelBytes = 1024
)

var ErrSearchInput = errors.New("CRM search input invalid")

// SearchInput selects a fixed source-native list, never a URL or arbitrary
// provider filter. Empty Query requests recent records. Offset pagination is
// bounded discovery: concurrent provider edits can move records between pages.
type SearchInput struct {
	Kind   RecordKind
	Query  string
	Offset int
}

// RecordChoice contains discovery labels only. It is not a contract-value
// observation; selected IDs must be read again using ReadRecords before Apply.
// Secondary is an optional deal stage, never extra contact identity or notes.
type RecordChoice struct {
	Kind            RecordKind
	ID              string
	Label           string
	Secondary       string
	RecordUpdatedAt time.Time
}

// SearchResult retains the original account and read times for the caller's
// final authorized document/connection check. No raw provider record or body
// is exposed. NextOffset is zero when HasMore is false, including at the cap.
type SearchResult struct {
	Identity         Identity
	StartedAt        time.Time
	CompletedAt      time.Time
	CredentialBefore CredentialObservation
	CredentialAfter  CredentialObservation
	Choices          []RecordChoice
	HasMore          bool
	NextOffset       int
}

func ValidateSearchInput(in SearchInput) error {
	if in.Kind != Deal && in.Kind != Contact && in.Kind != Company || in.Offset < 0 || in.Offset > MaxSearchOffset || in.Offset%SearchPageSize != 0 {
		return ErrSearchInput
	}
	if !utf8.ValidString(in.Query) || len(in.Query) > MaxSearchQueryBytes || strings.TrimSpace(in.Query) != in.Query || hasSearchControls(in.Query) {
		return ErrSearchInput
	}
	if n := utf8.RuneCountInString(in.Query); n > MaxSearchQueryRunes || n == 1 {
		return ErrSearchInput
	}
	return nil
}

func hasSearchControls(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return true
		}
	}
	return false
}

// SearchRecords reads one bounded typed list between account checks using the
// same original encrypted credential. It never falls back to global search,
// holds database locks, or authorizes a mutation. Trust failures return no
// partial choices; callers must recheck actor/document/connection after waits.
func (c *Client) SearchRecords(ctx context.Context, conn Connection, keyring *Keyring, in SearchInput) (SearchResult, error) {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return SearchResult{}, err
	}
	if err := ValidateSearchInput(in); err != nil {
		return SearchResult{}, err
	}
	if err := c.validIdentity(conn.Identity, false); err != nil {
		return SearchResult{}, err
	}
	if !conn.Enabled || conn.VerifiedAt.IsZero() || conn.VerifiedAt.After(c.now().Add(MaxClockSkew)) {
		return SearchResult{}, ErrNotConfigured
	}
	token, _, err := keyring.Open(conn.Identity, conn.Ciphertext)
	if err != nil {
		return SearchResult{}, err
	}
	budget := 3 * MaxResponseBytes
	s := SearchResult{Identity: conn.Identity, StartedAt: c.now().UTC()}
	s.CredentialBefore, err = c.verify(ctx, conn.Identity, token, &budget)
	if err != nil {
		return SearchResult{}, err
	}
	query := url.Values{"search": {in.Query}, "limit": {strconv.Itoa(SearchPageSize)}, "offset": {strconv.Itoa(in.Offset)}}
	resource := map[RecordKind]string{Deal: "deals", Contact: "contacts", Company: "companies"}[in.Kind]
	raw, at, err := c.get(ctx, "/api/v1/"+resource+"/?"+query.Encode(), token, &budget)
	if err != nil {
		return SearchResult{}, err
	}
	s.Choices, s.HasMore, s.NextOffset, err = decodeSearchPage(raw, in, conn.CRMTeamID, at)
	if err != nil {
		return SearchResult{}, err
	}
	s.CredentialAfter, err = c.verify(ctx, conn.Identity, token, &budget)
	if err != nil {
		return SearchResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return SearchResult{}, err
	}
	s.CompletedAt = c.now().UTC()
	return s, nil
}

func searchInteger(raw json.RawMessage) (int64, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || len(value) > 19 || value[0] < '0' || value[0] > '9' || len(value) > 1 && value[0] == '0' {
		return 0, ErrResponse
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, ErrResponse
		}
	}
	n, err := strconv.ParseInt(string(value), 10, 64)
	if err != nil {
		return 0, ErrResponse
	}
	return n, nil
}

func decodeSearchPage(raw []byte, in SearchInput, team string, at time.Time) ([]RecordChoice, bool, int, error) {
	if len(raw) > MaxResponseBytes {
		return nil, false, 0, ErrLimit
	}
	if err := sourcejson.Validate(raw); err != nil {
		return nil, false, 0, ErrResponse
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil || len(envelope) != 4 {
		return nil, false, 0, ErrResponse
	}
	for key := range envelope {
		if key != "data" && key != "total" && key != "limit" && key != "offset" {
			return nil, false, 0, ErrResponse
		}
	}
	total, totalErr := searchInteger(envelope["total"])
	limit, limitErr := searchInteger(envelope["limit"])
	offset, offsetErr := searchInteger(envelope["offset"])
	if totalErr != nil || limitErr != nil || offsetErr != nil || limit != SearchPageSize || offset != int64(in.Offset) {
		return nil, false, 0, ErrResponse
	}
	data := bytes.TrimSpace(envelope["data"])
	if len(data) == 0 || data[0] != '[' {
		return nil, false, 0, ErrResponse
	}
	var rows []json.RawMessage
	if json.Unmarshal(data, &rows) != nil || len(rows) > SearchPageSize {
		return nil, false, 0, ErrResponse
	}
	choices := make([]RecordChoice, 0, len(rows))
	seen := make(map[string]bool, len(rows))
	for _, row := range rows {
		fields, err := object(row, map[string]bool{"id": true})
		if err != nil {
			return nil, false, 0, err
		}
		id, err := requiredString(fields, "id")
		if err != nil || validateOpaqueID(id) != nil || seen[id] {
			return nil, false, 0, ErrIdentity
		}
		seen[id] = true
		record, err := decodeRecord(row, RecordRef{Kind: in.Kind, ID: id}, team, at)
		if err != nil {
			return nil, false, 0, err
		}
		labelPath := map[RecordKind]string{Deal: "title", Contact: "full_name", Company: "name"}[in.Kind]
		label := record.Fields[labelPath]
		choice := RecordChoice{Kind: in.Kind, ID: id, Label: id, RecordUpdatedAt: record.RecordUpdatedAt}
		if label.Present && !label.Null {
			choice.Label = label.Value
		}
		if in.Kind == Deal {
			if stage := record.Fields["stage"]; stage.Present && !stage.Null {
				choice.Secondary = stage.Value
			}
		}
		for _, display := range []string{choice.Label, choice.Secondary} {
			if len(display) > MaxSearchLabelBytes || !utf8.ValidString(display) || hasSearchControls(display) {
				return nil, false, 0, ErrResponse
			}
		}
		choices = append(choices, choice)
	}
	// Provider count and page reads are separate and mutable. This is a hint
	// for the next bounded page, not a stable cursor or enumeration guarantee.
	next := in.Offset + SearchPageSize
	hasMore := len(choices) == SearchPageSize && total > int64(in.Offset+len(choices)) && next <= MaxSearchOffset
	if !hasMore {
		next = 0
	}
	return choices, hasMore, next, nil
}
