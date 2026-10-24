// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/bright-interaction/hash/internal/secretbox"
	"github.com/google/uuid"
)

var ErrStaffAuthEmail = errors.New("sealed staff authentication email unavailable")

type staffAuthEmailBody struct {
	HTML string `json:"html"`
	Text string `json:"text"`
}

func NewStaffAuthMailBox(current, previous string) (*secretbox.Box, error) {
	key, err := hex.DecodeString(current)
	if err != nil {
		return nil, ErrStaffAuthEmail
	}
	old, err := hex.DecodeString(previous)
	if err != nil {
		return nil, ErrStaffAuthEmail
	}
	box, err := secretbox.New(key, old)
	if err != nil {
		return nil, ErrStaffAuthEmail
	}
	return box, nil
}

func staffAuthEmailAAD(id uuid.UUID, to, subject string) []byte {
	body, _ := json.Marshal(struct {
		Purpose string
		ID      uuid.UUID
		To      string
		Subject string
	}{"hash.staff-auth-email.v1", id, to, subject})
	return body
}

func SealStaffAuthEmail(box *secretbox.Box, id uuid.UUID, msg Message) ([]byte, error) {
	if box == nil || id == uuid.Nil || len(msg.HTML)+len(msg.Text) > 16000 {
		return nil, ErrStaffAuthEmail
	}
	raw, err := json.Marshal(staffAuthEmailBody{HTML: msg.HTML, Text: msg.Text})
	if err != nil {
		return nil, ErrStaffAuthEmail
	}
	sealed, err := box.Seal(raw, staffAuthEmailAAD(id, msg.To, msg.Subject))
	if err != nil {
		return nil, ErrStaffAuthEmail
	}
	return sealed, nil
}

func OpenStaffAuthEmail(box *secretbox.Box, id uuid.UUID, to, subject string, sealed []byte) (Message, error) {
	if box == nil || len(sealed) > 32768 {
		return Message{}, ErrStaffAuthEmail
	}
	raw, _, err := box.Open(sealed, staffAuthEmailAAD(id, to, subject))
	if err != nil {
		return Message{}, ErrStaffAuthEmail
	}
	var body staffAuthEmailBody
	if err := json.Unmarshal(raw, &body); err != nil || len(body.HTML)+len(body.Text) > 16000 {
		return Message{}, ErrStaffAuthEmail
	}
	return Message{To: to, Subject: subject, HTML: body.HTML, Text: body.Text}, nil
}
