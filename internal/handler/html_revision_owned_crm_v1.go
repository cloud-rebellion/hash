// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5"
)

// This runs inside the original native revision stage, after its live
// parent/member/credential/privacy/CAS/source checks. Reuse that actual bounded
// document rather than loading and decoding a second legacy full source. Only
// the original bounded mapping ledger and account are freshly locked here;
// final-stage locks stay held through BOTH audits, mapping review and COMMIT.
func (a *crmMappingAdmission) checkOwnedLockedV1(ctx context.Context, db generated.DBTX, actor authoring.Actor, doc *generated.Document, commitment string) error {
	if err := a.checkDeadline(); err != nil {
		return err
	}
	if db == nil || doc == nil || a.source == nil || a.source.doc == nil || doc.ID != a.source.doc.ID || doc.OrgID != actor.OrgID ||
		a.witness.ExpectedOrgID != actor.OrgID || a.witness.ExpectedUserID != actor.UserID || len(doc.HtmlSourceJson) == 0 {
		return errCRMDocumentChanged
	}
	expected, err := time.Parse(time.RFC3339Nano, a.witness.ExpectedUpdatedAt)
	if err != nil || !doc.UpdatedAt.Time.Equal(expected) || commitment != a.witness.ExpectedHTMLSourceCommitment {
		return errCRMDocumentChanged
	}
	q := generated.New(db)
	bindings, err := q.ListCRMMappingBindingsForShare(ctx, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: actor.OrgID})
	if err != nil {
		return err
	}
	fingerprint, err := crmreview.FullBindingFingerprint(bindings)
	if err != nil {
		return err
	}
	if fingerprint != a.witness.ExpectedBindingFingerprint {
		return errCRMDocumentChanged
	}
	connection, err := q.GetCRMConnectionByOrgForShare(ctx, actor.OrgID)
	if errors.Is(err, pgx.ErrNoRows) {
		connection, err = nil, nil
	}
	if err != nil {
		return err
	}
	if connection == nil {
		if a.witness.ExpectedConnectionID != "" || a.witness.ExpectedConnectionGeneration != "0" {
			return errCRMDocumentChanged
		}
	} else if connection.ID.String() != a.witness.ExpectedConnectionID || strconv.FormatInt(connection.Generation, 10) != a.witness.ExpectedConnectionGeneration {
		return errCRMDocumentChanged
	}
	if a.observation.snapshot != nil && (connection == nil || connection.Status != "active" || crmIdentity(connection) != a.observation.snapshot.Identity) {
		return errCRMDocumentChanged
	}
	return a.checkDeadline()
}
