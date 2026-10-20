//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// The two original negotiation tops now live in the handler package's genuine
// native PDF fixture. Keep this original shared snapshot for the separate PDF
// credential test; its caller and full-state assertions remain unchanged.
type negotiationCredentialQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func negotiationCredentialSnapshot(t *testing.T, ctx context.Context, q negotiationCredentialQuerier, f *multipartyPDFFixture) string {
	t.Helper()
	var state string
	if err := q.QueryRow(ctx, `SELECT jsonb_build_object(
		'document',(SELECT to_jsonb(d) FROM documents d WHERE id=$1),
		'recipients',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM recipients r WHERE document_id=$1),
		'fields',(SELECT jsonb_agg(to_jsonb(f) ORDER BY id) FROM document_fields f WHERE document_id=$1),
		'signatures',(SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM signatures s WHERE document_id=$1),
		'requests',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM change_requests c WHERE document_id=$1),
		'comments',(SELECT jsonb_agg(to_jsonb(c) ORDER BY id) FROM document_comments c WHERE document_id=$1),
		'events',(SELECT jsonb_agg(to_jsonb(e) ORDER BY id) FROM events e WHERE org_id=$2),
		'sealing',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM send_sealing_intents i WHERE document_id=$1),
		'finalization',(SELECT jsonb_agg(to_jsonb(i) ORDER BY document_id) FROM document_finalization_intents i WHERE document_id=$1),
		'outbox',(SELECT jsonb_agg(to_jsonb(ed) ORDER BY id) FROM email_deliveries ed
			WHERE to_email IN (SELECT email FROM recipients WHERE document_id=$1
				UNION SELECT u.email FROM users u JOIN documents d ON d.sender_id=u.id WHERE d.id=$1)))::text`, f.docID, f.orgID).Scan(&state); err != nil { //nolint:rawsql -- compare all persisted effects without exposing hashes/addresses
		t.Fatal(err)
	}
	return state
}
