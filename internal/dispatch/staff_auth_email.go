// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package dispatch

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"

	"github.com/bright-interaction/hash/internal/secretbox"
	"github.com/google/uuid"
)

var ErrStaffAuthEmail = errors.New("sealed staff authentication email unavailable")

type staffAuthEmailBody struct {
	HTML string `json:"html"`
	Text string `json:"text"`
}

// StaffAuthEmailMessageV1 renders fixed account-security copy before sealing.
// The caller supplies a canonical request locale and the native one-use link;
// queued delivery never rereads browser preferences or rerenders this message.
func StaffAuthEmailMessageV1(to, purpose, locale, link string) (Message, error) {
	var subject, action string
	switch locale {
	case "en":
		switch purpose {
		case "register":
			subject, action = "Verify your Hash email", "Verify your email"
		case "setup":
			subject, action = "Set your Hash password", "Choose your own password"
		case "reset":
			subject, action = "Reset your Hash password", "Reset your password"
		default:
			return Message{}, ErrStaffAuthEmail
		}
	case "sv":
		switch purpose {
		case "register":
			subject, action = "Verifiera din e-postadress för Hash", "Verifiera din e-postadress"
		case "setup":
			subject, action = "Välj ditt lösenord för Hash", "Välj ditt eget lösenord"
		case "reset":
			subject, action = "Återställ ditt lösenord för Hash", "Återställ ditt lösenord"
		default:
			return Message{}, ErrStaffAuthEmail
		}
	default:
		return Message{}, ErrStaffAuthEmail
	}
	instruction := action + " using the link below."
	disclaimer := "If you did not request this, ignore this email. The link expires and can be used once."
	if locale == "sv" {
		instruction = action + " med länken nedan."
		disclaimer = "Om du inte begärde detta kan du ignorera meddelandet. Länken upphör att gälla och kan bara användas en gång."
	}
	return Message{
		To: to, Subject: subject,
		HTML: "<p>" + html.EscapeString(instruction) + "</p><p><a href=\"" + html.EscapeString(link) + "\">" + html.EscapeString(action) + "</a></p><p>" + html.EscapeString(disclaimer) + "</p>",
		Text: action + ":\n" + link + "\n\n" + disclaimer,
	}, nil
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
