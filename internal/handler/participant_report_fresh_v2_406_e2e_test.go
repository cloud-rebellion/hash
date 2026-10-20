//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fresh native journeys select V2; archived V1 verification fixtures stay exact.
// This test-only oracle parses the WHOLE signed readable section and checks
// original complete family rows. It does not rebuild the native report or
// replace each journey's known comment/proposal/response/version assertions.
// Callers retain their independent original detached-signature verification.
func assertFreshParticipantReport406(t *testing.T, f lifecycleAuthorizationFixture, document *generated.Document, payload []byte) render.ParticipantReportV2 {
	t.Helper()
	if document == nil || document.ID == [16]byte{} || document.OrgID != f.org || document.Status != "completed" || document.ParticipantReportSchema != render.ParticipantReportSchemaV2 || len(payload) == 0 || len(payload) > render.MaxCertificatePayloadBytesV1 {
		t.Fatal("fresh participant report lacks the native V2 completion pin")
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.DocumentID != document.ID.String() || claims.OrgID != f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(document.FinalPdfSha) {
		t.Fatal("fresh signed report claims disagree with the native document")
	}
	marker := []byte(render.ParticipantReportHTMLV3Start)
	endMarker := []byte(`</pre></div></section>`)
	if bytes.Count(payload, marker) != 1 || bytes.Count(payload, []byte(render.ParticipantReportCanonicalCarrierV2)) != 1 {
		t.Fatal("fresh report must contain one exact V2 canonical and HTMLV3 section")
	}
	start := bytes.Index(payload, marker)
	end := bytes.Index(payload[start:], endMarker)
	if end < 0 {
		t.Fatal("fresh full HTMLV3 section is incomplete")
	}
	report, digest, err := render.ParseParticipantReportHTMLV3(string(payload[start : start+end+len(endMarker)]))
	if err != nil || report.Schema != render.ParticipantReportSchemaV2 || report.DocumentID != document.ID.String() || report.HistoryScope.OrgID != f.org.String() || report.HistoryScope.RootDocumentID != document.ID.String() || digest != claims.ParticipantReportSHA256 || report.Cutoff != claims.ParticipantReportCutoff || report.SourceRowsV2() != claims.ParticipantReportRows {
		t.Fatal("fresh full readable report differs from exact signed V2 commitments")
	}
	cutoff, err := time.Parse(time.RFC3339Nano, report.Cutoff)
	if err != nil || cutoff.IsZero() || cutoff.UTC().Format(time.RFC3339Nano) != report.Cutoff {
		t.Fatal("fresh report cutoff is not exact")
	}
	var receipts int
	err = f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM document_participant_reports_v1 r
 WHERE r.document_id=$1 AND r.org_id=$2 AND r.schema_version=$3
 AND encode(r.report_sha256,'hex')=$4 AND r.cutoff=$5 AND r.history_rows=$6
 AND r.completion_effective_at=$7 AND r.final_pdf_sha256=$8
 AND r.audit_cert_sha256=$9 AND r.audit_payload_sha256=$10 AND r.audit_signature_sha256=$11`,
		document.ID, f.org, render.ParticipantReportSchemaV2, digest, cutoff, report.SourceRowsV2(), document.CompletionEffectiveAt,
		document.FinalPdfSha, document.AuditCertSha256, document.AuditPayloadSha256, document.AuditSignatureSha256).Scan(&receipts)
	if err != nil || receipts != 1 {
		t.Fatal("fresh V2 report lost its unique exact native artifact receipt")
	} //nolint:rawsql -- read-only original receipt association, never evidence repair

	// Exact existing query family includes root and direct envelope children,
	// even a child with no visible events. Legal annex source documents do not
	// acquire family membership merely by being selected in the package.
	documents, err := f.q.ListParticipantReportHistoryScopeV2(f.ctx, generated.ListParticipantReportHistoryScopeV2Params{OrgID: f.org, DocumentID: document.ID})
	if err != nil || len(documents) == 0 || len(documents) > render.MaxParticipantReportRowsV1 {
		t.Fatal("actual complete report family unavailable")
	}
	originals, err := f.q.ListParticipantReportEventRowsV1(f.ctx, generated.ListParticipantReportEventRowsV1Params{OrgID: f.org, DocumentID: document.ID, Cutoff: pgtype.Timestamptz{Time: cutoff, Valid: true}})
	if err != nil || len(originals) == 0 || len(originals) > render.MaxParticipantReportRowsV1 {
		t.Fatal("actual complete original report event rows unavailable")
	}
	if render.VerifyParticipantReportOriginalEventsV2(render.ParticipantNarrativeScopeDraft402{Org: f.org, Root: document.ID, Documents: documents}, originals, report) != nil {
		t.Fatal("fresh participant event facts differ from original hashed family preimages")
	}
	return report
}
