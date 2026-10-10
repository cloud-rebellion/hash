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
	"strings"
	"sync"
	"testing"
	"time"
)

type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }

func jsonResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

func testConnection(t *testing.T) Connection {
	t.Helper()
	id := testIdentity()
	blob, err := testKeyring(t).Seal(id, testToken)
	if err != nil {
		t.Fatal(err)
	}
	return Connection{Identity: id, Enabled: true, VerifiedAt: time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC), Ciphertext: blob}
}

func syntheticBody(kind RecordKind, id, team string) string {
	d := map[string]any{"id": id, "team_id": team, "updated_at": "2026-10-10T00:00:00Z"}
	switch kind {
	case Deal:
		d["title"] = "Synthetic deal"
		d["value"] = json.Number("9007199254740993.2300")
		d["currency"] = "SEK"
		d["stage"] = "PROPOSAL"
		d["contact_id"] = "contact_cuid"
		d["company_id"] = "company_cuid"
	case Contact:
		d["first_name"] = "  Åsa "
		d["last_name"] = " Öberg  "
		d["email"] = "Asa@example.test"
		d["anonymized_at"] = nil
		d["company_id"] = "company_cuid"
		d["do_not_contact"] = false
		d["is_primary"] = true
		d["role"] = "Sales director"
	case Company:
		d["name"] = "Synthetic company"
		d["legal_name"] = "Synthetic Company AB"
		d["orgnr"] = "Synthetic-registration"
		d["tax_id"] = nil
		d["email"] = ""
		d["payment_terms"] = "30 days"
	}
	raw, _ := json.Marshal(d)
	return string(raw)
}

func meBody(id Identity) string {
	raw, _ := json.Marshal(map[string]any{"id": id.CRMUserID, "team_id": id.CRMTeamID, "is_active": true, "name": "Synthetic member", "email": "member@example.test"})
	return string(raw)
}

func testClient(t *testing.T, conn Connection, handler func(*http.Request) (*http.Response, error)) *Client {
	t.Helper()
	c, err := NewClient(conn.Origin, false)
	if err != nil {
		t.Fatal(err)
	}
	c.now = func() time.Time { return time.Date(2026, 10, 10, 0, 1, 0, 0, time.UTC) }
	c.doer = doerFunc(handler)
	return c
}

func TestCRMVerifyDiscoversAccountButNeverEnablesIt(t *testing.T) {
	conn := testConnection(t)
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) { return jsonResponse(meBody(conn.Identity)), nil })
	unmapped := conn.Identity
	unmapped.CRMTeamID, unmapped.CRMUserID = "", ""
	o, err := c.VerifyCredential(context.Background(), unmapped, testToken)
	if err != nil || o.CRMTeamID != conn.CRMTeamID || o.CRMUserID != conn.CRMUserID || !o.IsActive || o.Name != "Synthetic member" || o.Email != "member@example.test" || len(o.BodySHA256) != 64 {
		t.Fatal("actual enrollment account not returned")
	}
	partial := unmapped
	partial.CRMTeamID = conn.CRMTeamID
	if _, err := c.VerifyCredential(context.Background(), partial, testToken); !errors.Is(err, ErrIdentity) {
		t.Fatal("partial account mapping accepted")
	}
	if _, err := c.ReadRecords(context.Background(), Connection{Identity: unmapped, Enabled: true, VerifiedAt: conn.VerifiedAt, Ciphertext: conn.Ciphertext}, testKeyring(t), []RecordRef{{Kind: Deal, ID: "deal_cuid"}}); !errors.Is(err, ErrIdentity) {
		t.Fatal("unreviewed enrollment admitted for records")
	}
}

func TestCRMGroupedReadPreservesValuesAndSourceNativeRelationships(t *testing.T) {
	conn := testConnection(t)
	calls := map[string]int{}
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		if r.URL.Host != "crm.example.test" || r.Header.Get("Authorization") != "Bearer "+testToken {
			t.Fatal("unexpected route or credential")
		}
		calls[r.URL.Path]++
		if r.URL.Path == "/api/v1/auth/me" {
			return jsonResponse(meBody(conn.Identity)), nil
		}
		parts := strings.Split(r.URL.Path, "/")
		kind := map[string]RecordKind{"deals": Deal, "contacts": Contact, "companies": Company}[parts[3]]
		return jsonResponse(syntheticBody(kind, parts[4], conn.CRMTeamID)), nil
	})
	refs := []RecordRef{{Kind: Deal, ID: "deal_cuid"}, {Kind: Contact, ID: "contact_cuid"}, {Kind: Company, ID: "company_cuid"}, {Kind: Deal, ID: "deal_cuid"}}
	s, err := c.ReadRecords(context.Background(), conn, testKeyring(t), refs)
	if err != nil || len(s.Records) != 3 || s.Identity != conn.Identity || s.StartedAt.IsZero() || s.CompletedAt.Before(s.StartedAt) {
		t.Fatal("grouped snapshot failed")
	}
	if calls["/api/v1/auth/me"] != 2 || calls["/api/v1/deals/deal_cuid"] != 1 {
		t.Fatal("record fetched more than once or account not rechecked")
	}
	d, _ := s.Record(Deal, "deal_cuid")
	if v, err := d.Value("value"); err != nil || v != "9007199254740993.2300" {
		t.Fatal("decimal precision changed")
	}
	if d.Relationships["contact_id"].Value != "contact_cuid" || d.Relationships["company_id"].Value != "company_cuid" || len(d.BodySHA256) != 64 || !d.RecordUpdatedAt.Before(d.ObservedAt) {
		t.Fatal("record provenance/relations missing")
	}
	person, _ := s.Record(Contact, "contact_cuid")
	if v, err := person.Value("full_name"); err != nil || v != "Åsa Öberg" {
		t.Fatal("explicit deterministic full name mismatch")
	}
	company, _ := s.Record(Company, "company_cuid")
	if !company.Fields["tax_id"].Null || !company.Fields["tax_id"].Present {
		t.Fatal("null tax field was guessed")
	}
	if v, err := company.Value("email"); err != nil || v != "" {
		t.Fatal("successful empty scalar lost")
	}
	if _, err := company.Value("tax_id"); !errors.Is(err, ErrFieldUnavailable) {
		t.Fatal("null treated as empty")
	}
	if _, err := company.Value("vat_number"); !errors.Is(err, ErrFieldUnavailable) {
		t.Fatal("invented VAT mapping accepted")
	}
	if _, err := d.Value(""); !errors.Is(err, ErrFieldUnavailable) {
		t.Fatal("whole record returned")
	}
	if _, err := d.Value("company_id.name"); !errors.Is(err, ErrFieldUnavailable) {
		t.Fatal("arbitrary nested mapping accepted")
	}
	d.Fields["value"] = Scalar{Present: true, Value: "tampered"}
	again, _ := s.Record(Deal, "deal_cuid")
	if again.Fields["value"].Value == "tampered" {
		t.Fatal("snapshot lookup shared maps")
	}
	defs := Catalog(Company)
	defs[0].Path = "tampered"
	if Catalog(Company)[0].Path == "tampered" {
		t.Fatal("catalog shared definition state")
	}
}

func TestCRMReadRefusesWrongRecordTenantAndOriginalPrincipal(t *testing.T) {
	for _, fault := range []string{"record_id", "record_team", "before_user", "after_user", "after_team", "inactive"} {
		t.Run(fault, func(t *testing.T) {
			conn := testConnection(t)
			authCalls := 0
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.Header.Get("Authorization") != "Bearer "+testToken {
					t.Fatal("adopted new credential")
				}
				if r.URL.Path == "/api/v1/auth/me" {
					authCalls++
					id := conn.Identity
					if fault == "before_user" || fault == "after_user" && authCalls == 2 {
						id.CRMUserID = "another_user"
					}
					if fault == "after_team" && authCalls == 2 {
						id.CRMTeamID = "another_team"
					}
					body := meBody(id)
					if fault == "inactive" {
						body = strings.Replace(body, `"is_active":true`, `"is_active":false`, 1)
					}
					return jsonResponse(body), nil
				}
				id, team := "deal_cuid", conn.CRMTeamID
				if fault == "record_id" {
					id = "other_deal"
				}
				if fault == "record_team" {
					team = "other_team"
				}
				return jsonResponse(syntheticBody(Deal, id, team)), nil
			})
			s, err := c.ReadRecords(context.Background(), conn, testKeyring(t), []RecordRef{{Kind: Deal, ID: "deal_cuid"}})
			if !errors.Is(err, ErrIdentity) || len(s.Records) != 0 {
				t.Fatal("identity fault leaked partial snapshot")
			}
		})
	}
}

func TestCRMReadRejectsAmbiguousOrUnavailableProof(t *testing.T) {
	conn := testConnection(t)
	valid := syntheticBody(Deal, "deal_cuid", conn.CRMTeamID)
	var base map[string]any
	if err := json.Unmarshal([]byte(valid), &base); err != nil {
		t.Fatal(err)
	}
	mutated := func(key string, value any) string {
		m := map[string]any{}
		for k, v := range base {
			m[k] = v
		}
		m[key] = value
		raw, _ := json.Marshal(m)
		return string(raw)
	}
	missing := map[string]any{}
	for k, v := range base {
		if k != "updated_at" {
			missing[k] = v
		}
	}
	missingRaw, _ := json.Marshal(missing)
	cases := map[string]string{
		"null_id": mutated("id", nil), "null_team": mutated("team_id", nil), "null_version": mutated("updated_at", nil), "missing_version": string(missingRaw),
		"case_alias":        strings.TrimSuffix(valid, "}") + `,"ID":"deal_cuid"}`,
		"duplicate":         strings.TrimSuffix(valid, "}") + `,"id":"deal_cuid"}`,
		"escaped_duplicate": strings.TrimSuffix(valid, "}") + `,"\u0069d":"deal_cuid"}`,
		"trailing":          valid + `{}`, "not_object": `[]`, "invalid_utf8": strings.TrimSuffix(valid, "}") + string([]byte{0xff}) + `}`,
		"future_version": mutated("updated_at", "2027-10-10T00:00:00Z"), "bad_version": mutated("updated_at", "infinity"), "offset24": mutated("updated_at", "2026-10-10T00:00:00+24:00"),
		"decimal_string": mutated("value", "2.00"), "object_value": mutated("title", map[string]any{"text": "foo"}), "bad_relation": mutated("company_id", "../../company"),
		"too_big": mutated("notes", strings.Repeat("x", MaxResponseBytes)), "scalar_too_big": mutated("title", strings.Repeat("x", MaxScalarBytes+1)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/auth/me" {
					return jsonResponse(meBody(conn.Identity)), nil
				}
				return jsonResponse(body), nil
			})
			if s, err := c.ReadRecords(context.Background(), conn, testKeyring(t), []RecordRef{{Kind: Deal, ID: "deal_cuid"}}); err == nil || len(s.Records) != 0 {
				t.Fatal("malformed observation admitted")
			}
		})
	}
}

func TestCRMContactErasureAndPermissionNullCannotSupplySignerIdentity(t *testing.T) {
	conn := testConnection(t)
	for _, fault := range []string{"erasure_time", "tombstone_name", "tombstone_email", "null_email", "missing_guard", "forged_full_name"} {
		t.Run(fault, func(t *testing.T) {
			var m map[string]any
			_ = json.Unmarshal([]byte(syntheticBody(Contact, "contact_cuid", conn.CRMTeamID)), &m)
			switch fault {
			case "erasure_time":
				m["anonymized_at"] = "2026-10-10T00:00:00Z"
			case "tombstone_name":
				m["first_name"] = "(anonymized)"
			case "tombstone_email":
				m["email"] = "anon-contact@example.invalid"
			case "null_email":
				m["email"] = nil
			case "missing_guard":
				delete(m, "anonymized_at")
			case "forged_full_name":
				m["full_name"] = "Forged signer"
			}
			raw, _ := json.Marshal(m)
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				if r.URL.Path == "/api/v1/auth/me" {
					return jsonResponse(meBody(conn.Identity)), nil
				}
				return jsonResponse(string(raw)), nil
			})
			s, err := c.ReadRecords(context.Background(), conn, testKeyring(t), []RecordRef{{Kind: Contact, ID: "contact_cuid"}})
			if fault == "forged_full_name" {
				r, _ := s.Record(Contact, "contact_cuid")
				if v, valueErr := r.Value("full_name"); err != nil || valueErr != nil || v != "Åsa Öberg" {
					t.Fatal("upstream forged derived value adopted")
				}
			} else if err == nil || len(s.Records) != 0 {
				t.Fatal("erased or unknown identity admitted")
			}
		})
	}
}

func TestCRMRecordReadHonorsCancellationAndRecordLimits(t *testing.T) {
	conn := testConnection(t)
	calls := 0
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		calls++
		return jsonResponse(meBody(conn.Identity)), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ReadRecords(ctx, conn, testKeyring(t), []RecordRef{{Kind: Deal, ID: "deal_cuid"}}); !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatal("canceled batch made a request")
	}
	refs := make([]RecordRef, MaxUniqueRecords+1)
	for i := range refs {
		refs[i] = RecordRef{Kind: Deal, ID: fmt.Sprintf("deal_%d", i)}
	}
	if _, err := c.ReadRecords(context.Background(), conn, testKeyring(t), refs); !errors.Is(err, ErrLimit) || calls != 0 {
		t.Fatal("unique-record limit failed before I/O")
	}
	refs = make([]RecordRef, MaxRecordReferences+1)
	for i := range refs {
		refs[i] = RecordRef{Kind: Deal, ID: "deal_cuid"}
	}
	if _, err := c.ReadRecords(context.Background(), conn, testKeyring(t), refs); !errors.Is(err, ErrLimit) || calls != 0 {
		t.Fatal("reference cardinality unbounded")
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	c.doer = doerFunc(func(r *http.Request) (*http.Response, error) { cancel(); return nil, r.Context().Err() })
	if _, err := c.ReadRecords(ctx, conn, testKeyring(t), []RecordRef{{Kind: Deal, ID: "deal_cuid"}}); !errors.Is(err, context.Canceled) {
		t.Fatal("in-flight cancellation lost")
	}
}

func TestCRMUpstreamErrorsDoNotDiscloseDiagnosticBodiesOrCredentials(t *testing.T) {
	conn := testConnection(t)
	for _, status := range []int{301, 302, 400, 401, 403, 404, 429, 500, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"5"}}, Body: io.NopCloser(strings.NewReader("private " + testToken + conn.CRMUserID))}, nil
			})
			_, err := c.VerifyCredential(context.Background(), conn.Identity, testToken)
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Status != status || httpErr.RetryAfter != 5*time.Second || strings.Contains(err.Error(), testToken) || strings.Contains(err.Error(), conn.CRMUserID) {
				t.Fatal("HTTP diagnostics not safely bounded")
			}
		})
	}
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("private URI/credential %s", testToken)
	})
	if _, err := c.VerifyCredential(context.Background(), conn.Identity, testToken); !errors.Is(err, ErrUpstream) || strings.Contains(err.Error(), testToken) {
		t.Fatal("transport error leaked secret")
	}
}

func TestCRMConcurrentBatchesDoNotShareRecordState(t *testing.T) {
	conn := testConnection(t)
	c := testClient(t, conn, func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/api/v1/auth/me" {
			return jsonResponse(meBody(conn.Identity)), nil
		}
		return jsonResponse(syntheticBody(Deal, "deal_cuid", conn.CRMTeamID)), nil
	})
	k := testKeyring(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.ReadRecords(context.Background(), conn, k, []RecordRef{{Kind: Deal, ID: "deal_cuid"}})
			if err != nil {
				t.Error(err)
				return
			}
			r, _ := s.Record(Deal, "deal_cuid")
			r.Fields["value"] = Scalar{Present: true, Value: "edited"}
			again, _ := s.Record(Deal, "deal_cuid")
			if again.Fields["value"].Value == "edited" {
				t.Error("record lookup was not isolated")
			}
		}()
	}
	wg.Wait()
}
