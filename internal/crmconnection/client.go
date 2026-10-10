// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bright-interaction/hash/internal/nethard"
	"github.com/bright-interaction/hash/internal/sourcejson"
)

type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	origin string
	doer   httpDoer
	now    func() time.Time
}

// NewClient accepts server configuration only. Its production path refuses
// redirects and private destination IPs, including a DNS rebinding at dial time.
// A transport override is deliberately unexported and available only to tests
// inside this package. No request/ref/account value can choose a destination.
func NewClient(serverOrigin string, allowPrivateDevelopment bool) (*Client, error) {
	origin, err := CanonicalOrigin(serverOrigin, allowPrivateDevelopment)
	if err != nil {
		return nil, err
	}
	return &Client{origin: origin, doer: nethard.Client(RequestTimeout, func() bool { return allowPrivateDevelopment }), now: time.Now}, nil
}

type HTTPError struct {
	Status     int
	RetryAfter time.Duration
	cause      error
}

func (e *HTTPError) Error() string { return fmt.Sprintf("CRM upstream HTTP %d", e.Status) }
func (e *HTTPError) Unwrap() error { return e.cause }

func (c *Client) validIdentity(id Identity, allowUnmapped bool) error {
	if c == nil || c.doer == nil || c.now == nil {
		return ErrNotConfigured
	}
	if err := validateIdentity(id, allowUnmapped); err != nil {
		return err
	}
	if id.Origin != c.origin {
		return ErrIdentity
	}
	return nil
}

func (c *Client) get(ctx context.Context, path, token string, budget *int) ([]byte, time.Time, error) {
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.origin+path, nil)
	if err != nil {
		return nil, time.Time{}, ErrIdentity
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := c.doer.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return nil, time.Time{}, ErrUpstream
	}
	if resp == nil || resp.Body == nil {
		return nil, time.Time{}, ErrResponse
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cause := ErrUpstream
		switch resp.StatusCode {
		case 401, 403:
			cause = ErrCredential
		case 404:
			cause = ErrRecordUnavailable
		case 429:
			cause = ErrRateLimited
		}
		return nil, time.Time{}, &HTTPError{Status: resp.StatusCode, RetryAfter: safeRetryAfter(resp.Header.Get("Retry-After")), cause: cause}
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || strings.ToLower(media) != "application/json" {
		return nil, time.Time{}, ErrResponse
	}
	if resp.ContentLength > MaxResponseBytes {
		return nil, time.Time{}, ErrLimit
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return nil, time.Time{}, ctx.Err()
		}
		return nil, time.Time{}, ErrResponse
	}
	if len(raw) > MaxResponseBytes {
		return nil, time.Time{}, ErrLimit
	}
	if budget != nil {
		*budget -= len(raw)
		if *budget < 0 {
			return nil, time.Time{}, ErrLimit
		}
	}
	if err := sourcejson.Validate(raw); err != nil {
		return nil, time.Time{}, ErrResponse
	}
	if err := ctx.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return raw, c.now().UTC(), nil
}

func safeRetryAfter(raw string) time.Duration {
	seconds, err := strconv.Atoi(raw)
	if err != nil || seconds < 0 || seconds > 30 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

func bodySHA(raw []byte) string { s := sha256.Sum256(raw); return hex.EncodeToString(s[:]) }

func object(raw []byte, recognized map[string]bool) (map[string]json.RawMessage, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, ErrResponse
	}
	for key := range fields {
		if recognized[strings.ToLower(key)] && !recognized[key] {
			return nil, ErrResponse
		}
	}
	return fields, nil
}

func requiredString(fields map[string]json.RawMessage, key string) (string, error) {
	raw, ok := fields[key]
	if !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", ErrResponse
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || len(value) > MaxScalarBytes || strings.ContainsRune(value, 0) {
		return "", ErrResponse
	}
	return value, nil
}

// VerifyCredential may discover the actual account only when BOTH expected
// remote IDs are empty. It does not enable a connection or prove key scopes,
// expiry, remote service identity, consent, or signing authority.
func (c *Client) VerifyCredential(ctx context.Context, id Identity, token string) (CredentialObservation, error) {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return CredentialObservation{}, err
	}
	if err := c.validIdentity(id, true); err != nil {
		return CredentialObservation{}, err
	}
	if err := ValidateToken(token); err != nil {
		return CredentialObservation{}, err
	}
	budget := MaxResponseBytes
	return c.verify(ctx, id, token, &budget)
}

func (c *Client) verify(ctx context.Context, id Identity, token string, budget *int) (CredentialObservation, error) {
	raw, at, err := c.get(ctx, "/api/v1/auth/me", token, budget)
	if err != nil {
		return CredentialObservation{}, err
	}
	fields, err := object(raw, map[string]bool{"id": true, "team_id": true, "is_active": true, "name": true, "email": true})
	if err != nil {
		return CredentialObservation{}, err
	}
	user, err := requiredString(fields, "id")
	if err != nil || validateOpaqueID(user) != nil {
		return CredentialObservation{}, ErrIdentity
	}
	team, err := requiredString(fields, "team_id")
	if err != nil || validateOpaqueID(team) != nil {
		return CredentialObservation{}, ErrIdentity
	}
	var active bool
	activeRaw, ok := fields["is_active"]
	if !ok || bytes.Equal(bytes.TrimSpace(activeRaw), []byte("null")) || json.Unmarshal(activeRaw, &active) != nil || !active {
		return CredentialObservation{}, ErrIdentity
	}
	if id.CRMUserID != "" && (user != id.CRMUserID || team != id.CRMTeamID) {
		return CredentialObservation{}, ErrIdentity
	}
	o := CredentialObservation{CRMUserID: user, CRMTeamID: team, IsActive: true, ObservedAt: at, BodySHA256: bodySHA(raw)}
	for key := range map[string]bool{"name": true, "email": true} {
		if value, ok := fields[key]; ok && !bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			s, err := requiredString(fields, key)
			if err != nil {
				return CredentialObservation{}, err
			}
			if key == "name" {
				o.Name = s
			} else {
				o.Email = s
			}
		}
	}
	return o, nil
}

// ReadRecords makes one read per unique record under the same original token.
// The before/after account checks narrow the remote race window; they do not
// turn ordinary HTTP reads into an atomic CRM transaction. Failed batches never
// expose partial results or silently reuse an old credential/value.
func (c *Client) ReadRecords(ctx context.Context, conn Connection, keyring *Keyring, refs []RecordRef) (Snapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, BatchTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if err := c.validIdentity(conn.Identity, false); err != nil {
		return Snapshot{}, err
	}
	if !conn.Enabled || conn.VerifiedAt.IsZero() || conn.VerifiedAt.After(c.now().Add(MaxClockSkew)) {
		return Snapshot{}, ErrNotConfigured
	}
	if len(refs) == 0 || len(refs) > MaxRecordReferences {
		return Snapshot{}, ErrLimit
	}
	unique := make(map[RecordRef]bool, len(refs))
	for _, ref := range refs {
		if err := ValidateRecordRef(ref); err != nil {
			return Snapshot{}, err
		}
		unique[ref] = true
	}
	if len(unique) > MaxUniqueRecords {
		return Snapshot{}, ErrLimit
	}
	token, _, err := keyring.Open(conn.Identity, conn.Ciphertext)
	if err != nil {
		return Snapshot{}, err
	}
	ordered := make([]RecordRef, 0, len(unique))
	for ref := range unique {
		ordered = append(ordered, ref)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Kind != ordered[j].Kind {
			return ordered[i].Kind < ordered[j].Kind
		}
		return ordered[i].ID < ordered[j].ID
	})
	budget := MaxSnapshotResponseBytes
	s := Snapshot{Identity: conn.Identity, StartedAt: c.now().UTC(), Records: make([]RecordObservation, 0, len(ordered))}
	s.CredentialBefore, err = c.verify(ctx, conn.Identity, token, &budget)
	if err != nil {
		return Snapshot{}, err
	}
	for _, ref := range ordered {
		path := map[RecordKind]string{Deal: "deals", Contact: "contacts", Company: "companies"}[ref.Kind]
		raw, at, err := c.get(ctx, "/api/v1/"+path+"/"+ref.ID, token, &budget)
		if err != nil {
			return Snapshot{}, err
		}
		r, err := decodeRecord(raw, ref, conn.CRMTeamID, at)
		if err != nil {
			return Snapshot{}, err
		}
		s.Records = append(s.Records, r)
	}
	s.CredentialAfter, err = c.verify(ctx, conn.Identity, token, &budget)
	if err != nil {
		return Snapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	s.CompletedAt = c.now().UTC()
	return s, nil
}

var timestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})$`)

func parseTimestamp(value string) (time.Time, error) {
	if len(value) > 64 || !timestampPattern.MatchString(value) {
		return time.Time{}, ErrResponse
	}
	if value[len(value)-1] != 'Z' {
		h, _ := strconv.Atoi(value[len(value)-5 : len(value)-3])
		m, _ := strconv.Atoi(value[len(value)-2:])
		if h > 23 || m > 59 {
			return time.Time{}, ErrResponse
		}
	}
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || t.IsZero() {
		return time.Time{}, ErrResponse
	}
	return t.UTC(), nil
}

func decodeRecord(raw []byte, ref RecordRef, team string, at time.Time) (RecordObservation, error) {
	rules := fieldCatalog(ref.Kind)
	known := map[string]bool{"id": true, "team_id": true, "updated_at": true, "anonymized_at": true}
	for key := range rules {
		known[key] = true
	}
	fields, err := object(raw, known)
	if err != nil {
		return RecordObservation{}, err
	}
	id, err := requiredString(fields, "id")
	if err != nil || id != ref.ID {
		return RecordObservation{}, ErrIdentity
	}
	actualTeam, err := requiredString(fields, "team_id")
	if err != nil || actualTeam != team {
		return RecordObservation{}, ErrIdentity
	}
	updated, err := requiredString(fields, "updated_at")
	if err != nil {
		return RecordObservation{}, err
	}
	stamp, err := parseTimestamp(updated)
	if err != nil || stamp.After(at.Add(MaxClockSkew)) {
		return RecordObservation{}, ErrResponse
	}
	r := RecordObservation{Kind: ref.Kind, ID: id, CRMTeamID: team, ObservedAt: at, RecordUpdatedAt: stamp, BodySHA256: bodySHA(raw), Fields: make(map[string]Scalar, len(rules)), Relationships: map[string]Scalar{}}
	for path, rule := range rules {
		if rule.derived {
			continue
		}
		value, ok := fields[path]
		if !ok {
			r.Fields[path] = Scalar{}
			continue
		}
		scalar := Scalar{Present: true}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			// A permission-filtered property may be null even when the storage
			// column is NOT NULL. Preserve that observation, never coerce it to an
			// empty value; Value refuses it if a mapping selects this property.
			scalar.Null = true
		} else {
			switch rule.typ {
			case "string", "reference", "timestamp":
				if json.Unmarshal(value, &scalar.Value) != nil || len(scalar.Value) > MaxScalarBytes || strings.ContainsRune(scalar.Value, 0) {
					return RecordObservation{}, ErrResponse
				}
				if rule.typ == "reference" && validateOpaqueID(scalar.Value) != nil {
					return RecordObservation{}, ErrIdentity
				}
				if rule.typ == "timestamp" {
					if _, err := parseTimestamp(scalar.Value); err != nil {
						return RecordObservation{}, err
					}
				}
			case "decimal":
				var number any
				decoder := json.NewDecoder(bytes.NewReader(value))
				decoder.UseNumber()
				if decoder.Decode(&number) != nil {
					return RecordObservation{}, ErrResponse
				}
				n, ok := number.(json.Number)
				if !ok || len(n.String()) > MaxScalarBytes {
					return RecordObservation{}, ErrResponse
				}
				scalar.Value = n.String()
			case "boolean":
				var v bool
				if json.Unmarshal(value, &v) != nil {
					return RecordObservation{}, ErrResponse
				}
				scalar.Value = strconv.FormatBool(v)
			default:
				return RecordObservation{}, ErrResponse
			}
		}
		r.Fields[path] = scalar
		if rule.typ == "reference" {
			r.Relationships[path] = scalar
		}
	}
	if ref.Kind == Contact {
		anon, ok := fields["anonymized_at"]
		if !ok || !bytes.Equal(bytes.TrimSpace(anon), []byte("null")) {
			return RecordObservation{}, ErrRecordUnavailable
		}
		first, last, email := r.Fields["first_name"], r.Fields["last_name"], r.Fields["email"]
		if !first.Present || !last.Present || !email.Present || first.Null || last.Null || email.Null {
			return RecordObservation{}, ErrFieldUnavailable
		}
		if strings.EqualFold(strings.TrimSpace(first.Value), "(anonymized)") || strings.HasPrefix(strings.ToLower(email.Value), "anon-") && strings.HasSuffix(strings.ToLower(email.Value), "@example.invalid") {
			return RecordObservation{}, ErrRecordUnavailable
		}
		full := strings.TrimSpace(first.Value) + " " + strings.TrimSpace(last.Value)
		if strings.TrimSpace(first.Value) == "" || strings.TrimSpace(last.Value) == "" {
			r.Fields["full_name"] = Scalar{}
		} else if len(full) > MaxScalarBytes {
			return RecordObservation{}, ErrLimit
		} else {
			r.Fields["full_name"] = Scalar{Present: true, Value: full}
		}
	}
	return r, nil
}
