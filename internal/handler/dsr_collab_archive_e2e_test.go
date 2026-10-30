//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/bright-interaction/hash/internal/db/generated"
)

func TestDSRErasureRequiresReviewOfCollabRecoveryArchivesE2E(t *testing.T) {
	ctx, pool, q, server, orgID, userID, doc, recipient := setupCompletedDSREvidenceE2E(t)
	dsr, err := q.CreateDataSubjectRequest(ctx, generated.CreateDataSubjectRequestParams{
		OrgID: orgID, DocumentID: pgtype.UUID{Bytes: doc.ID, Valid: true}, RecipientID: pgtype.UUID{Bytes: recipient.ID, Valid: true},
		SubjectEmail: recipient.Email, SubjectName: recipient.Name, Kind: "erasure", RequestedVia: "sender",
		PayloadJson: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	// The archive is deliberately opaque. The erasure handler must neither
	// parse it nor assume a missing legacy generation means it contains no PII.
	archivedReplay := []byte("old opaque replay: " + recipient.Name + " " + recipient.Email)
	var archiveID uuid.UUID
	if err := pool.QueryRow(ctx, `INSERT INTO collab_recovery_archives
(document_id, observed_canonical_generation, origin, ydoc_state, recovered_by)
SELECT document_id, generation, 'persisted', $2, $3
FROM collab_document_generations WHERE document_id=$1 RETURNING id`, doc.ID, archivedReplay, userID).Scan(&archiveID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}

	for _, status := range []string{"open", "in_progress"} {
		if status == "in_progress" {
			recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, status)
			if recorder.Code != http.StatusOK {
				t.Fatalf("start review status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		}
		recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
		if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "separate privacy review") {
			t.Fatalf("archive erasure from %s status=%d body=%s", status, recorder.Code, recorder.Body.String())
		}
		freshDSR, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
		if err != nil {
			t.Fatal(err)
		}
		if freshDSR.Status != status || freshDSR.SubjectEmail != recipient.Email || freshDSR.SubjectName != recipient.Name || freshDSR.FulfilledAt.Valid {
			t.Fatalf("blocked erasure changed request: status/email/name/fulfilled=%q/%q/%q/%v", freshDSR.Status, freshDSR.SubjectEmail, freshDSR.SubjectName, freshDSR.FulfilledAt.Valid)
		}
		freshRecipient, err := q.GetRecipient(ctx, generated.GetRecipientParams{ID: recipient.ID, OrgID: orgID})
		if err != nil {
			t.Fatal(err)
		}
		if freshRecipient.Email != recipient.Email || freshRecipient.Name != recipient.Name {
			t.Fatal("blocked erasure changed recipient identifiers")
		}
		signatures, err := q.ListSignaturesByDocument(ctx, doc.ID)
		if err != nil || len(signatures) != 1 {
			t.Fatalf("blocked erasure signatures=%d err=%v", len(signatures), err)
		}
		if signatures[0].TypedName != "Original Legal Name" || !signatures[0].SignerUa.Valid || signatures[0].SignerUa.String != "test-agent" {
			t.Fatal("blocked erasure changed signature identifiers")
		}
		var retainedReplay []byte
		var archivedGeneration pgtype.Int8
		if err := pool.QueryRow(ctx, `SELECT ydoc_state,history_generation FROM collab_recovery_archives WHERE id=$1`, archiveID).Scan(&retainedReplay, &archivedGeneration); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if !bytes.Equal(retainedReplay, archivedReplay) || archivedGeneration.Valid {
			t.Fatal("blocked erasure changed archive bytes or invented a legacy generation")
		}
		var terminalEvents int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id=$1 AND kind IN ('data_subject.anonymized','data_subject.fulfilled')`, orgID).Scan(&terminalEvents); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		if terminalEvents != 0 {
			t.Fatal("blocked erasure published terminal audit events")
		}
	}

	present, err := q.HasCollabRecoveryArchivesForDSR(ctx, generated.HasCollabRecoveryArchivesForDSRParams{DocumentID: doc.ID, OrgID: uuid.New()})
	if err != nil || present {
		t.Fatalf("foreign-tenant archive presence=%v err=%v", present, err)
	}

	// This represents completed, approved archive handling in the fixture,
	// rather than teaching the recipient workflow to delete shared history.
	if _, err := pool.Exec(ctx, `DELETE FROM collab_recovery_archives WHERE id=$1`, archiveID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	recorder := transitionDSRE2E(server, orgID, userID, dsr.ID, "fulfilled")
	if recorder.Code != http.StatusOK {
		t.Fatalf("reviewed erasure status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	freshDSR, err := q.GetDataSubjectRequest(ctx, generated.GetDataSubjectRequestParams{ID: dsr.ID, OrgID: orgID})
	if err != nil || freshDSR.Status != "fulfilled" || freshDSR.SubjectEmail != AnonymizedEmail(dsr.ID) {
		t.Fatalf("reviewed erasure did not complete: request=%+v err=%v", freshDSR, err)
	}
}
