// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package reviewgate classifies the M124 review-gate refusals so every writer
// that can hit the gate reports the same coded conflict instead of an
// availability error.
package reviewgate

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Code is the stable machine code every writer returns with a gate refusal.
const Code = "pdf_review_required"

// Message reports whether err, or anything it wraps (the application session
// wraps in-transaction errors but keeps the cause), is a review-gate refusal,
// and the fixed text to show. The body never carries database text.
func Message(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "23514" {
		return "", false
	}
	switch pg.Message {
	case "Replaced PDF requires review before sending":
		return "The replaced PDF has not been reviewed. Review its current pages, then send.", true
	case "Signing document requires a fresh human review before sending":
		return "A signing document must be reviewed by a person in a staff session before sending.", true
	}
	return "", false
}
