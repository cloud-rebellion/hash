// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package commentwindow

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCursorRetainsPostgreSQLMicrosecondPositionAndScope(t *testing.T) {
	org, document, row := uuid.New(), uuid.New(), uuid.New()
	at := time.Date(2026, 10, 16, 13, 4, 5, 123456000, time.FixedZone("fixture", 7200))
	cursor, err := Cursor(org, document, row, at)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		key  string
		want Direction
	}{{"before", Older}, {"after", Newer}} {
		selection, err := Parse(item.key + "=" + cursor)
		if err != nil {
			t.Fatal(err)
		}
		direction, actual, id, err := selection.ForScope(org, document)
		if err != nil || direction != item.want || id != row || !actual.Equal(at) || actual.Nanosecond() != 123456000 {
			t.Fatal("cursor lost its exact stored position", actual, id, err)
		}
		if _, _, _, err := selection.ForScope(uuid.New(), document); err == nil {
			t.Fatal("cursor accepted another organisation")
		}
		if _, _, _, err := selection.ForScope(org, uuid.New()); err == nil {
			t.Fatal("cursor accepted another document")
		}
	}
	if _, err := Cursor(org, document, row, at.Add(time.Nanosecond)); err == nil {
		t.Fatal("cursor silently rounded an unrepresentable position")
	}
}

func TestCursorRejectsAmbiguousAndMalformedSelections(t *testing.T) {
	cursor, err := Cursor(uuid.New(), uuid.New(), uuid.New(), time.Now().UTC().Truncate(time.Microsecond))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint64(raw[33:41], math.MaxInt64)
	unrepresentable := base64.RawURLEncoding.EncodeToString(raw)
	for _, query := range []string{"before=", "before=x", "before=" + cursor + "&before=" + cursor, "before=" + cursor + "&after=" + cursor, "limit=1000", "offset=0", "after=%xx", "after=" + strings.Repeat("x", 1000), "after=" + unrepresentable, "after=" + strings.Repeat("!", 76)} {
		if _, err := Parse(query); err == nil {
			t.Fatalf("accepted ambiguous or invalid selection %q", query)
		}
	}
	selection, err := Parse("")
	if err != nil {
		t.Fatal(err)
	}
	direction, _, _, err := selection.ForScope(uuid.New(), uuid.New())
	if err != nil || direction != Latest {
		t.Fatal("empty query must select latest", err)
	}
}
