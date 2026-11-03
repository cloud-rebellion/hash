// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package documentfolders

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestFolderFilterHasOneUnambiguousScope(t *testing.T) {
	id := uuid.New()
	for _, tc := range []struct {
		values []string
		kind   string
		id     uuid.UUID
		bad    bool
	}{
		{nil, "all", uuid.Nil, false},
		{[]string{"unfiled"}, "unfiled", uuid.Nil, false},
		{[]string{id.String()}, "folder", id, false},
		{[]string{""}, "", uuid.Nil, true},
		{[]string{"all"}, "", uuid.Nil, true},
		{[]string{uuid.Nil.String()}, "", uuid.Nil, true},
		{[]string{"not-a-uuid"}, "", uuid.Nil, true},
		{[]string{id.String(), "unfiled"}, "", uuid.Nil, true},
	} {
		got, err := ParseFilter(tc.values)
		if tc.bad {
			if !errors.Is(err, ErrInput) {
				t.Errorf("invalid filter admitted: %q", tc.values)
			}
			continue
		}
		if err != nil || got.Kind != tc.kind || got.ID != tc.id {
			t.Errorf("scope mismatch: %q", tc.values)
		}
	}
}
func TestFolderNamesUseCharacterBoundsAndRejectControls(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		bad       bool
	}{
		{"  Customers  ", "Customers", false}, {"Svenska kunder – Öst", "Svenska kunder – Öst", false},
		{strings.Repeat("ö", 80), strings.Repeat("ö", 80), false},
		{"", "", true}, {" \t ", "", true}, {strings.Repeat("ö", 81), "", true},
		{"Two\nlines", "", true}, {"zero\x00byte", "", true}, {string([]byte{0xff}), "", true},
	} {
		got, err := NormalizeName(tc.raw)
		if tc.bad {
			if !errors.Is(err, ErrInput) {
				t.Error("invalid folder name admitted")
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Error("valid folder name changed")
		}
	}
}
