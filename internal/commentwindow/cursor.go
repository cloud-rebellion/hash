// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package commentwindow

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"time"

	"github.com/google/uuid"
)

const Limit = 50
const cursorBytes = 1 + 16 + 16 + 8 + 16
const cursorTextBytes = 76

var ErrSelection = errors.New("invalid comment page selection")

type Direction uint8

const (
	Latest Direction = iota
	Older
	Newer
)

// A cursor selects a position only. It supplies no tenant, document or access
// authority: the actual admitted scope must match again before any query.
type Selection struct {
	direction     Direction
	org, document uuid.UUID
	id            uuid.UUID
	at            time.Time
}

func Parse(rawQuery string) (Selection, error) {
	if len(rawQuery) > 2*cursorTextBytes+20 {
		return Selection{}, ErrSelection
	}
	query, err := url.ParseQuery(rawQuery)
	if err != nil {
		return Selection{}, ErrSelection
	}
	if len(query) == 0 {
		return Selection{}, nil
	}
	if len(query) != 1 {
		return Selection{}, ErrSelection
	}
	for key, values := range query {
		if (key != "before" && key != "after") || len(values) != 1 || len(values[0]) != cursorTextBytes {
			return Selection{}, ErrSelection
		}
		raw, err := base64.RawURLEncoding.Strict().DecodeString(values[0])
		if err != nil || len(raw) != cursorBytes || raw[0] != 1 {
			return Selection{}, ErrSelection
		}
		s := Selection{direction: Older, at: time.UnixMicro(int64(binary.BigEndian.Uint64(raw[33:41]))).UTC()}
		copy(s.org[:], raw[1:17])
		copy(s.document[:], raw[17:33])
		copy(s.id[:], raw[41:57])
		if key == "after" {
			s.direction = Newer
		}
		if s.org == uuid.Nil || s.document == uuid.Nil || s.id == uuid.Nil || s.at.IsZero() || s.at.Year() < 1 || s.at.Year() > 9999 {
			return Selection{}, ErrSelection
		}
		return s, nil
	}
	return Selection{}, ErrSelection
}

func (s Selection) ForScope(org, document uuid.UUID) (Direction, time.Time, uuid.UUID, error) {
	if org == uuid.Nil || document == uuid.Nil || s.direction > Newer {
		return Latest, time.Time{}, uuid.Nil, ErrSelection
	}
	if s.direction == Latest {
		if s.org != uuid.Nil || s.document != uuid.Nil || s.id != uuid.Nil || !s.at.IsZero() {
			return Latest, time.Time{}, uuid.Nil, ErrSelection
		}
		return Latest, time.UnixMicro(0).UTC(), uuid.Nil, nil
	}
	if s.org != org || s.document != document || s.id == uuid.Nil {
		return Latest, time.Time{}, uuid.Nil, ErrSelection
	}
	return s.direction, s.at, s.id, nil
}

func Cursor(org, document, id uuid.UUID, at time.Time) (string, error) {
	if org == uuid.Nil || document == uuid.Nil || id == uuid.Nil || at.IsZero() || at.Year() < 1 || at.Year() > 9999 || !at.Equal(time.UnixMicro(at.UnixMicro())) {
		return "", ErrSelection
	}
	var raw [cursorBytes]byte
	raw[0] = 1
	copy(raw[1:17], org[:])
	copy(raw[17:33], document[:])
	binary.BigEndian.PutUint64(raw[33:41], uint64(at.UnixMicro()))
	copy(raw[41:57], id[:])
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
