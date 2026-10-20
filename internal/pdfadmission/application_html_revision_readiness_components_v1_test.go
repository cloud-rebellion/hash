// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"encoding/json"
	"math"
	"net/mail"
	"strings"
	"testing"
	"unsafe"

	"github.com/bright-interaction/hash/internal/htmlmaster"
	"github.com/bright-interaction/hash/internal/testfixture"
)

func TestHTMLRevisionReadinessPinnedLayoutsV1(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want uintptr
	}{
		{"Readiness", unsafe.Sizeof(htmlmaster.ContractReadiness{}), 112},
		{"PartyValues", unsafe.Sizeof(htmlmaster.ContractPartyValues{}), 96},
		{"Issue", unsafe.Sizeof(htmlmaster.ContractIssue{}), 48},
		{"mailAddress", unsafe.Sizeof(mail.Address{}), 32},
		{"fmtMirror", unsafe.Sizeof(htmlRevisionReadinessFmtV1{}), 112},
		{"printerMirror", unsafe.Sizeof(htmlRevisionReadinessPrinterV1{}), 208},
	} {
		if c.got != c.want {
			t.Errorf("%s shape changed: %d !=%d", c.name, c.got, c.want)
		}
	}
}

func TestHTMLRevisionReadinessTypedProfileCeilingV1(t *testing.T) {
	name := strings.Repeat("a", 64)
	p := htmlmaster.ContractProfile{ID: name, Version: 1000000, Kind: "b2b_services"}
	for _, slot := range []string{"provider", "customer"} {
		p.Parties = append(p.Parties, htmlmaster.ContractParty{Slot: slot, CompanyName: name, CompanyID: name, RepresentativeName: name, RepresentativeEmail: name, RepresentativeAuthority: name})
	}
	for range 16 {
		p.Terms = append(p.Terms, htmlmaster.ContractTerm{Name: name, Section: name})
	}
	// This is the exact typed-shape extremum, not a valid unique-name design.
	// It checks the original typed encoder's tags/omission/ASCII output directly.
	encoded, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) != 3493 {
		t.Fatalf("typed profile ceiling changed: %d", len(encoded))
	}
	components, err := htmlRevisionContractReadinessComponentsForV1(htmlmaster.Master{ContractProfile: &p}, htmlmaster.Input{})
	if err != nil {
		t.Fatal(err)
	}
	if components.profileJSONBytes < int64(len(encoded)) || components.parentBytes < 5*int64(len(encoded)) {
		t.Fatal("typed profile buffers omitted")
	}
	p.Parties[0].CompanyName = strings.Repeat("a", 65)
	if _, err = htmlRevisionContractReadinessComponentsForV1(htmlmaster.Master{ContractProfile: &p}, htmlmaster.Input{}); err == nil {
		t.Fatal("unproved profile topology accepted")
	}
}

func readinessActualOwnedResultBytesV1(r htmlmaster.ContractReadiness) int64 {
	n := int64(unsafe.Sizeof(r)) + int64(cap(r.Parties))*int64(unsafe.Sizeof(htmlmaster.ContractPartyValues{})) + int64(cap(r.Issues))*int64(unsafe.Sizeof(htmlmaster.ContractIssue{})) + int64(len(r.ProfileDigest))
	for _, issue := range r.Issues {
		n += int64(len(issue.Path) + len(issue.Message))
	}
	// Party text and profile identity are original immutable model/input aliases.
	return n
}

func TestHTMLRevisionReadinessActualDecisionAndResultOracleV1(t *testing.T) {
	source, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(source.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{
		"provider@example.test", "display <provider@example.test>",
		"\"quoted local\"@example.test", "group:a@example.test,b@example.test;",
		"a@example.test (=?ISO-8859-1?Q?Andr=E9?=)",
		"a@example.test (=?us-ascii?Q?=FF?=)",
		"=?unknown?Q?word?= <a@example.test>",
		"=?UTF-8?Q?=ZZ?= <a@example.test>",
		"a@[2001:db8::1%zone]", "a@[2001:db8::1]", "a@[127.0.0.1]",
		strings.Repeat("a", 254), strings.Repeat("a", 255), "",
	}
	for _, email := range cases {
		t.Run(email[:min(len(email), 40)], func(t *testing.T) {
			values := make(map[string]string, len(source.Values))
			for key, value := range source.Values {
				values[key] = value
			}
			values["provider_email"] = email
			input := htmlmaster.Input{Values: values, Sections: source.Sections}
			components, err := htmlRevisionContractReadinessComponentsForV1(master, input)
			if err != nil {
				t.Fatal(err)
			}
			ready, err := compiled.ContractReadiness(input)
			if err != nil {
				t.Fatal(err)
			}
			actual := readinessActualOwnedResultBytesV1(ready)
			if components.retainedResultBytes < actual || components.parentBytes < components.retainedResultBytes+components.mailBytes {
				t.Fatalf("retained decision result omitted: actual%d components%+v", actual, components)
			}
			if len(email) <= 254 {
				_, parseErr := mail.ParseAddress(email)
				if parseErr != nil && components.mailBytes < int64(len(parseErr.Error())) {
					t.Fatal("actual mail diagnostic omitted")
				}
			}
		})
	}
	// All missing party fields/terms and conflicting identities produce actual
	// structured outputs, not merely the component implementation's formula.
	values := map[string]string{}
	input := htmlmaster.Input{Values: values}
	components, err := htmlRevisionContractReadinessComponentsForV1(master, input)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := compiled.ContractReadiness(input)
	if err != nil {
		t.Fatal(err)
	}
	if ready.Complete || len(ready.Issues) < 16 || components.retainedResultBytes < readinessActualOwnedResultBytesV1(ready) {
		t.Fatalf("incomplete result not covered: %+v", ready)
	}
	for _, issue := range ready.Issues {
		if len(issue.Path) > 70 {
			t.Fatal("actual path ceiling changed")
		}
	}
}

func TestHTMLRevisionReadinessExactMailGuardAndCheckedArithmeticV1(t *testing.T) {
	previous := int64(-1)
	for n := int64(0); n <= 254; n++ {
		size, err := htmlRevisionReadinessMailBytesV1(n)
		if err != nil || size <= previous {
			t.Fatalf("mail logical envelope not monotone at%d: %d,%v", n, size, err)
		}
		previous = size
	}
	for _, n := range []int64{-1, 255, math.MaxInt64} {
		if _, err := htmlRevisionReadinessMailBytesV1(n); err == nil {
			t.Fatalf("outside actual mail guard accepted: %d", n)
		}
	}
	total := int64(math.MaxInt64)
	if htmlRevisionReadinessAddV1(&total, 1, 1) {
		t.Fatal("addition overflow accepted")
	}
	total = 0
	if htmlRevisionReadinessAddV1(&total, math.MaxInt64, 2) || htmlRevisionReadinessAddV1(&total, -1, 1) {
		t.Fatal("multiplication overflow/negative accepted")
	}
	source, _, _ := testfixture.HTMLContract(t)
	master, err := htmlmaster.Decode(source.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for k, v := range source.Values {
		values[k] = v
	}
	values["provider_email"] = strings.Repeat("z", 255)
	values["customer_email"] = strings.Repeat("z", 255)
	guarded, err := htmlRevisionContractReadinessComponentsForV1(master, htmlmaster.Input{Values: values})
	if err != nil || guarded.mailBytes != 0 {
		t.Fatalf("pre-ParseAddress >254 guard not preserved: %+v,%v", guarded, err)
	}
	noProfile, err := htmlRevisionContractReadinessComponentsForV1(htmlmaster.Master{}, htmlmaster.Input{})
	if err != nil || noProfile.retainedResultBytes != 0 || noProfile.profileJSONBytes != 0 || noProfile.mailBytes != 0 {
		t.Fatalf("absent profile fabricated work: %+v,%v", noProfile, err)
	}
}

func TestHTMLRevisionReadinessActualSigningPageTextOutputV1(t *testing.T) {
	source, _, _ := testfixture.BrandedHTMLContract(t)
	master, err := htmlmaster.Decode(source.MasterJSON)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := htmlmaster.Compile(master)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string, len(source.Values))
	for k, v := range source.Values {
		values[k] = v
	}
	values["provider_company"] = strings.Repeat("w", 129)
	input := htmlmaster.Input{Values: values, Sections: source.Sections}
	components, err := htmlRevisionContractReadinessComponentsForV1(master, input)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := compiled.ContractReadiness(input)
	if err != nil {
		t.Fatal(err)
	}
	formatted := false
	for _, issue := range ready.Issues {
		if issue.Code == "signing_page_text" && strings.Contains(issue.Message, "at most") {
			formatted = true
		}
	}
	if !formatted {
		t.Fatal("genuine signing-page formatting branch was not reached")
	}
	if components.retainedResultBytes < readinessActualOwnedResultBytesV1(ready) {
		t.Fatal("actual dynamically formatted readiness result omitted")
	}
}
