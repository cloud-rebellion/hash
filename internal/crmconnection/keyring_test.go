// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package crmconnection

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

const testToken = "abababababababababababababababababababababababababababababababab"

func testIdentity() Identity {
	return Identity{ID: uuid.New(), OrgID: uuid.New(), Generation: 1, Origin: "https://crm.example.test", CRMTeamID: "m0t67xo16lyka94bnzd44rxj", CRMUserID: "vxtknzsrrsndvnojqcwb95bv"}
}

func testKeyring(t *testing.T) *Keyring {
	t.Helper()
	k, err := NewKeyring(strings.Repeat("01", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCRMKeyringAuthenticatesAllConnectionAuthority(t *testing.T) {
	k, id := testKeyring(t), testIdentity()
	blob, err := k.Seal(id, testToken)
	if err != nil {
		t.Fatal(err)
	}
	second, err := k.Seal(id, testToken)
	if err != nil || bytes.Equal(blob, second) {
		t.Fatal("envelopes must use fresh nonces")
	}
	if token, previous, err := k.Open(id, blob); err != nil || previous || token != testToken {
		t.Fatal("exact authority did not open")
	}
	for name, mutate := range map[string]func(*Identity){
		"organization": func(i *Identity) { i.OrgID = uuid.New() },
		"connection":   func(i *Identity) { i.ID = uuid.New() },
		"generation":   func(i *Identity) { i.Generation++ },
		"origin":       func(i *Identity) { i.Origin = "https://other.example.test" },
		"crm_team":     func(i *Identity) { i.CRMTeamID += "x" },
		"crm_user":     func(i *Identity) { i.CRMUserID += "x" },
	} {
		t.Run(name, func(t *testing.T) {
			other := id
			mutate(&other)
			if token, _, err := k.Open(other, blob); !errors.Is(err, ErrCredential) || token != "" {
				t.Fatal("altered authority opened ciphertext")
			}
		})
	}
	for _, bad := range [][]byte{nil, blob[:len(blob)-1], append(bytes.Clone(blob), 0), bytes.Repeat([]byte{1}, CredentialCiphertextBytes)} {
		if token, _, err := k.Open(id, bad); err == nil || token != "" {
			t.Fatal("corrupt envelope opened")
		}
	}
}

func TestCRMKeyringRotationRequiresExactOriginalAuthority(t *testing.T) {
	old, id := testKeyring(t), testIdentity()
	blob, err := old.Seal(id, testToken)
	if err != nil {
		t.Fatal(err)
	}
	next, err := NewKeyring(strings.Repeat("02", 32), strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	token, previous, err := next.Open(id, blob)
	if err != nil || !previous || token != testToken {
		t.Fatal("previous-key envelope did not open")
	}
	rewrapped, err := next.Seal(id, token)
	if err != nil {
		t.Fatal(err)
	}
	current, err := NewKeyring(strings.Repeat("02", 32), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, previous, err := current.Open(id, rewrapped); err != nil || previous {
		t.Fatal("rewrapped envelope is not current")
	}
	if _, _, err := current.Open(id, blob); !errors.Is(err, ErrCredential) {
		t.Fatal("retired encryption key still accepted")
	}
	rotated := id
	rotated.Generation++
	if _, _, err := next.Open(rotated, blob); !errors.Is(err, ErrCredential) {
		t.Fatal("new semantic generation adopted old envelope")
	}
	if _, err := NewKeyring(strings.Repeat("02", 32), strings.Repeat("02", 32)); err == nil {
		t.Fatal("duplicate encryption keys accepted")
	}
}

func TestCRMCanonicalEnrollmentAndUnmappedSealRefuse(t *testing.T) {
	for _, token := range []string{"", strings.Repeat("a", 63), strings.Repeat("a", 65), strings.Repeat("A", 64), " " + testToken, "crm_" + testToken, strings.Repeat("g", 64)} {
		if err := ValidateToken(token); !errors.Is(err, ErrCredential) {
			t.Fatal("noncanonical token accepted")
		}
	}
	if err := ValidateToken(testToken); err != nil {
		t.Fatal(err)
	}
	id := testIdentity()
	id.CRMTeamID, id.CRMUserID = "", ""
	if _, err := testKeyring(t).Seal(id, testToken); !errors.Is(err, ErrIdentity) {
		t.Fatal("unreviewed account sealed")
	}
	if _, err := NewKeyring("", ""); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("missing encryption key was not disabled")
	}
}

func TestCRMOpaqueIdentifiersAndCanonicalOriginBoundaries(t *testing.T) {
	for _, id := range []string{"", ".", "..", "../../deals", " id", "id ", "id?x=1", "id#f", "id/name", "公司", strings.Repeat("a", 257)} {
		if ValidateRecordRef(RecordRef{Kind: Deal, ID: id}) == nil {
			t.Fatal("unsafe opaque ID accepted")
		}
	}
	if ValidateRecordRef(RecordRef{Kind: Contact, ID: "m0t67xo16lyka94bnzd44rxj"}) != nil {
		t.Fatal("actual CUID-style ID refused")
	}
	if ValidateRecordRef(RecordRef{Kind: Company, ID: "old_uuid-compatible_123"}) != nil {
		t.Fatal("supported opaque ID refused")
	}
	if ValidateRecordRef(RecordRef{Kind: "crm.lead", ID: "ok"}) == nil {
		t.Fatal("unknown kind accepted")
	}
	for _, raw := range []string{"http://crm.example.test", "https://crm.example.test/api", "https://crm.example.test?", "https://crm.example.test?x=1", "https://a:b@crm.example.test", "https://crm.example.test#x", "https://crm.example.test:0", "https://crm.example.test:99999", "https://crm.example.test:", "https://crm.example.test./", " https://crm.example.test", "https://crm_example.test", "https://-crm.example.test"} {
		if _, err := NewClient(raw, false); err == nil {
			t.Fatal("unsafe production origin accepted")
		}
	}
	for raw, want := range map[string]string{"https://CRM.example.test:443/": "https://crm.example.test", "https://crm.example.test:8443": "https://crm.example.test:8443", "https://[2001:db8::1]": "https://[2001:db8::1]"} {
		if got, err := CanonicalOrigin(raw, false); err != nil || got != want {
			t.Fatal("canonical origin mismatch")
		}
	}
	if _, err := NewClient("http://127.0.0.1:1234", true); err != nil {
		t.Fatal("explicit development origin refused")
	}
}
