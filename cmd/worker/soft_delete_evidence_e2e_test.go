//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestSoftDeletePurgeRetainsAnomalousEvidenceBeforeObjectIOE2E(t *testing.T) {
	ctx, pool, w, org, user, cutoff := setupSoftDeletePurgeE2E(t)
	for _, kind := range []string{"source aliases final", "separate audit payload", "send intent", "accepted recipient", "empty filled field"} {
		t.Run(kind, func(t *testing.T) {
			doc := seedSoftDeletePurgeClaimE2E(t, ctx, w, org, user, cutoff)
			var err error
			switch kind {
			case "source aliases final":
				_, err = pool.Exec(ctx, `UPDATE documents SET final_pdf_key=pdf_storage_key,final_pdf_sha=pdf_sha256,final_pdf_version_id=pdf_storage_version_id WHERE id=$1`, doc.ID)
			case "separate audit payload":
				_, err = pool.Exec(ctx, `UPDATE documents SET audit_payload_key=$2,audit_payload_sha256=$3,audit_payload_version_id='retained-payload-version' WHERE id=$1`, doc.ID, doc.PdfStorageKey.String+".payload.txt", bytes.Repeat([]byte{7}, 32))
			case "send intent":
				// Create the intent through its guarded draft query, then model
				// legacy/anomalous soft deletion without discarding the intent.
				_, err = pool.Exec(ctx, `UPDATE documents SET deleted_at=NULL WHERE id=$1`, doc.ID)
				checkSoftDeletePurgeE2E(t, err, "stage sealing intent on visible draft")
				_, err = w.queries.CreateSendSealingIntent(ctx, generated.CreateSendSealingIntentParams{DocumentID: doc.ID, OrgID: org, ActorUserID: pgtype.UUID{Bytes: user, Valid: true}, ActorEmail: "fixture@example.test", ActorIp: "127.0.0.1", Via: "e2e", Tool: "retirement-boundary"})
				checkSoftDeletePurgeE2E(t, err, "seed durable sealing intent")
				_, err = pool.Exec(ctx, `UPDATE documents SET deleted_at=$2 WHERE id=$1`, doc.ID, doc.DeletedAt)
			case "accepted recipient":
				_, err = pool.Exec(ctx, `INSERT INTO recipients(document_id,role,email,name,status,magic_token_hash,magic_token_expires_at) VALUES($1,'acknowledger','fixture@example.test','Fixture','accepted',$2,clock_timestamp()+interval '1 hour')`, doc.ID, bytes.Repeat([]byte{8}, 32))
			case "empty filled field":
				_, err = pool.Exec(ctx, `INSERT INTO document_fields(document_id,type,page,x_pct,y_pct,w_pct,h_pct,required,value,options_json) VALUES($1,'text',1,0,0,20,5,false,'','[]')`, doc.ID)
			}
			checkSoftDeletePurgeE2E(t, err, "seed retained evidence")
			// Metadata changes advance the lease. A fresh exact lease ensures
			// refusal is caused by retained evidence rather than stale admission.
			doc, err = w.queries.GetDocumentByID(ctx, doc.ID)
			checkSoftDeletePurgeE2E(t, err, "observe current exact lease")
			objects := &purgeDeleterStub{}
			rows, err := purgeClaimedSoftDeletedDocument(ctx, doc, cutoff, objects, w.beginSoftDeletePurge)
			if err == nil || !strings.Contains(err.Error(), "retained evidence") || rows != 0 || objects.calls != 0 {
				t.Fatalf("retained evidence rows=%d objects=%d err=%v", rows, objects.calls, err)
			}
			assertSoftDeletePurgeRowE2E(t, ctx, pool, doc, true)
			var sources int
			checkSoftDeletePurgeE2E(t, pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE id=$1 AND pdf_storage_key=$2 AND pdf_storage_version_id=$3`, doc.ID, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String).Scan(&sources), "verify source identity retained")
			if sources != 1 {
				t.Fatal("retained evidence lost its source cleanup identity")
			}
		})
	}
}
