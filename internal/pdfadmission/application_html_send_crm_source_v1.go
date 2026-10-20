// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/jackc/pgx/v5"
)

// This reads the actual existing account+encrypted credential using M92's
// cheap SHARE header, one positive same-reader body loan, and original SHARE
// body. It never adopts the configured resolver's arbitrary DB reader, bearer,
// ciphertext or caller-provided account identity. Missing is genuinely absent.
func (w *ApplicationHTMLSendWorkV1) readCRMSourceV1(ctx context.Context) (*generated.CrmConnection, error) {
	if w == nil || w.self != w {
		return nil, ErrHTMLSendWorkV1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.valid(ctx) || w.state == nil {
		return nil, ErrHTMLSendWorkV1
	}
	s := w.session.state
	h, err := w.queries.GetHTMLAuthoringCRMConnectionHeaderV1(ctx, s.org)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, err
	}
	if h == nil || h.OrgID != s.org || h.ID == [16]byte{} || h.RawTextBytes < 0 {
		return nil, ErrHTMLSendWorkV1
	}
	closeBody, err := w.actor.acquireOwnedRetainedBodyV1(ctx, h.RawTextBytes, 0)
	if err != nil {
		return nil, errors.Join(ErrHTMLSendWorkV1, err)
	}
	w.closes = append(w.closes, closeBody)
	row, err := w.queries.GetCRMConnectionByOrgForShare(ctx, s.org)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, pgx.ErrNoRows
	}
	if err != nil {
		return nil, resolver.ErrSourceFreshness
	}
	if row == nil || row.OrgID != s.org || row.ID != h.ID || int64(len(row.Status)+len(row.Origin)+len(row.CrmTeamID)+len(row.CrmUserID)+len(row.CredentialCiphertext)) != h.RawTextBytes {
		return nil, ErrHTMLSendWorkV1
	}
	copy := *row
	copy.Status = strings.Clone(row.Status)
	copy.Origin = strings.Clone(row.Origin)
	copy.CrmTeamID = strings.Clone(row.CrmTeamID)
	copy.CrmUserID = strings.Clone(row.CrmUserID)
	copy.CredentialCiphertext = bytes.Clone(row.CredentialCiphertext)
	return &copy, nil
}
