// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
)

const MinimumSendExpiryLeadV1 = 5 * time.Minute

var ErrSendExpiryTooSoonV1 = errors.New("document expiry must be at least 5 minutes in the future")

// The same admission margin applies to initial Send and its first irreversible
// retention step. Already-started retention must be reconciled separately.
func ValidateSendExpiryV1(expiresAt pgtype.Timestamptz, now time.Time) error {
	if expiresAt.Valid && !expiresAt.Time.After(now.Add(MinimumSendExpiryLeadV1)) {
		return ErrSendExpiryTooSoonV1
	}
	return nil
}
