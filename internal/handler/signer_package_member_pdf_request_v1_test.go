// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
)

func TestSignerPackageMemberPDFRequestRequiresOneStrongCompletePreconditionV1(t *testing.T) {
	manifest, legal := strings.Repeat("ab", 32), strings.Repeat("cd", 32)
	tag := `"` + manifest + "." + legal + `"`
	for _, test := range []struct {
		name, position string
		values         []string
		status         int
	}{
		{"main", "0", []string{tag}, 0},
		{"last_annex", "16", []string{" \t" + tag + "\t "}, 0},
		{"missing", "0", nil, http.StatusPreconditionRequired},
		{"empty", "0", []string{" \t"}, http.StatusPreconditionRequired},
		{"weak", "0", []string{"W/" + tag}, http.StatusBadRequest},
		{"wildcard", "0", []string{"*"}, http.StatusBadRequest},
		{"multiple_lines", "0", []string{tag, tag}, http.StatusBadRequest},
		{"multiple_tags", "0", []string{tag + ", " + tag}, http.StatusBadRequest},
		{"one_digest", "0", []string{`"` + manifest + `"`}, http.StatusBadRequest},
		{"uppercase", "0", []string{strings.ToUpper(tag)}, http.StatusBadRequest},
		{"bad_hex", "0", []string{`"g` + tag[2:]}, http.StatusBadRequest},
		{"unquoted", "0", []string{manifest + "." + legal}, http.StatusBadRequest},
		{"negative", "-1", []string{tag}, http.StatusBadRequest},
		{"overflow", "999999999999999999999", []string{tag}, http.StatusBadRequest},
		{"past_limit", "17", []string{tag}, http.StatusBadRequest},
		{"leading_zero", "01", []string{tag}, http.StatusBadRequest},
		{"signed", "+1", []string{tag}, http.StatusBadRequest},
		{"empty_position", "", []string{tag}, http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := http.Header{}
			for _, value := range test.values {
				header.Add("If-Match", value)
			}
			observed, status := signerPackageMemberExpectedV1(test.position, header)
			if status != test.status {
				t.Fatalf("status=%d, want %d", status, test.status)
			}
			if status == 0 && (!bytes.Equal(observed.ManifestSHA256[:], bytes.Repeat([]byte{0xab}, 32)) || !bytes.Equal(observed.LegalCommitmentSHA256[:], bytes.Repeat([]byte{0xcd}, 32))) {
				t.Fatal("precondition lost a commitment")
			}
		})
	}
}

func TestSignerPackageMemberPDFZeroDigestsRemainObservationsV1(t *testing.T) {
	header := http.Header{}
	header.Set("If-Match", `"`+strings.Repeat("0", 64)+"."+strings.Repeat("0", 64)+`"`)
	observed, status := signerPackageMemberExpectedV1("0", header)
	if status != 0 || observed.ManifestSHA256 != ([32]byte{}) || observed.LegalCommitmentSHA256 != ([32]byte{}) {
		t.Fatal("syntactically valid observations must reach the native capture comparison")
	}
}
