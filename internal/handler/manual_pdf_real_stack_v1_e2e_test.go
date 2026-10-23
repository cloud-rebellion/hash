//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// This is the ordinary two-party backend journey with actual PostgreSQL,
// restricted PDF worker, Chromium renderer and versioned Object Lock storage.
// It reuses the controlled estate opt-in, not the pre-sign product feature.
// Signatures use the existing Sign.Sign integration; session identity is a
// signed fixture and invitations are durable outbox rows. Browser paint,
// SMTP/inbox delivery, malware-provider and production capacity are not proved.
func TestOwnedManualPDFRealObjectLockChromiumTwoSignAndFourArtifactsE2E(t *testing.T) {
	if os.Getenv("HASH_PRESIGN_EXECUTION_E2E") != "1" {
		t.Skip("explicit disposable real-renderer/Object-Lock estate required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL", "HASH_E2E_RENDERER_IMAGE_ID", "HASH_E2E_S3_ENDPOINT", "HASH_E2E_S3_BUCKET", "HASH_E2E_S3_ACCESS_KEY", "HASH_E2E_S3_SECRET_KEY"} {
		if os.Getenv(name) == "" {
			t.Fatal("missing explicit controlled dependency", name)
		}
	}
	if !regexp.MustCompile(`^sha256:[0-9a-f]{64}$`).MatchString(os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")) || !strings.HasPrefix(os.Getenv("HASH_E2E_S3_BUCKET"), "hash-presign488-") {
		t.Fatal("exact renderer and unique disposable bucket required")
	}
	// Same pre-birth allocation as the effective core37 real-stack fixture.
	limits := workguard.LimitsV1{Global: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 8, ProviderStreams: 1, RendererRequests: 1}, Organisation: workguard.VectorV1{ParentBytes: 2 << 30, DBStagingBytes: 384 << 20, ChildAddressBytes: 2 << 30, PDFWorkers: 1, SQLSessions: 4, ProviderStreams: 1, RendererRequests: 1}, MaxGrants: 128, MaxOrganisationGrants: 64}
	trace := &presign488QueryTrace{}
	t.Cleanup(func() {
		if t.Failed() {
			trace.mu.Lock()
			defer trace.mu.Unlock()
			t.Logf("bounded native query failures (no SQL, arguments or messages): %+v", trace.failures)
		}
	})
	q := newOwnedPublicReadFixtureAllocated257dV1(t, false, limits, trace)
	f := q.f
	stored, err := storage.New(f.ctx, storage.Config{Endpoint: os.Getenv("HASH_E2E_S3_ENDPOINT"), Region: "us-east-1", Bucket: os.Getenv("HASH_E2E_S3_BUCKET"), AccessKey: os.Getenv("HASH_E2E_S3_ACCESS_KEY"), SecretKey: os.Getenv("HASH_E2E_S3_SECRET_KEY"), BucketLookup: "path", RequireObjectLock: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal("disposable Object Lock storage unavailable")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	provider, err := minio.New(os.Getenv("HASH_E2E_S3_ENDPOINT"), &minio.Options{Creds: credentials.NewStaticV4(os.Getenv("HASH_E2E_S3_ACCESS_KEY"), os.Getenv("HASH_E2E_S3_SECRET_KEY"), ""), Secure: false, Region: "us-east-1", BucketLookup: minio.BucketLookupPath, Transport: transport})
	if err != nil {
		t.Fatal("independent disposable provider observer unavailable")
	}
	f.s.Storage, f.s.Send.Storage, f.s.Sign.Storage = stored, stored, stored
	f.s.Sign.PDF = render.NewGotenberg(os.Getenv("HASH_E2E_RENDERER_URL"))
	if f.s.PreSignExecutionEnabled {
		t.Fatal("ordinary journey must not enable delegated execution")
	}
	// Install all real dependencies before the ordinary PDF is created. The
	// common helper preserves the original source, fields, Send, both manual
	// signatures, four verified artifacts, downloads and outbox/privacy checks.
	journey := runOwnedManualPDFPublicJourneyV1(t, q)
	completed := journey.completed
	if f.s.PreSignExecutionEnabled || completed.SigningAdmissionPolicy != "historical" || completed.ParticipantReportSchema != render.ParticipantReportSchemaV2 {
		t.Fatal("ordinary completion selected delegated or fitted behavior")
	}
	var delegated int
	if err = f.pool.QueryRow(f.ctx, `SELECT count(*) FROM presign_executions WHERE org_id=$1 AND document_id=$2`, f.org, completed.ID).Scan(&delegated); err != nil || delegated != 0 {
		t.Fatal("ordinary completion created delegated execution", err)
	} //nolint:rawsql -- actual ordinary-ceremony non-delegation oracle only
	if !completed.FinalizationRetainUntil.Valid || completed.FinalizationRetainUntil.InfinityModifier != pgtype.Finite || !completed.FinalizationRetainUntil.Time.After(time.Now()) {
		t.Fatal("actual finite completed retention deadline missing")
	}
	until := completed.FinalizationRetainUntil.Time
	type artifact struct {
		role         string
		key, version pgtype.Text
		digest       []byte
		body         []byte
	}
	for _, a := range []artifact{{"original_pdf", journey.original.PdfStorageKey, journey.original.PdfStorageVersionID, journey.original.PdfSha256, journey.originalPDF}, {"final_pdf", completed.FinalPdfKey, completed.FinalPdfVersionID, completed.FinalPdfSha, journey.verified[0]}, {"audit_certificate", completed.AuditCertKey, completed.AuditCertVersionID, completed.AuditCertSha256, journey.verified[1]}, {"audit_payload", completed.AuditPayloadKey, completed.AuditPayloadVersionID, completed.AuditPayloadSha256, journey.verified[2]}, {"audit_signature", completed.AuditSignatureKey, completed.AuditSignatureVersionID, completed.AuditSignatureSha256, journey.verified[3]}} {
		if !a.key.Valid || !a.version.Valid || a.version.String == "" || len(a.digest) != sha256.Size || len(a.body) == 0 {
			t.Fatal("ordinary source or final artifact lacks exact immutable pins")
		}
		mode, actual, retentionErr := provider.GetObjectRetention(f.ctx, os.Getenv("HASH_E2E_S3_BUCKET"), a.key.String, a.version.String)
		if retentionErr != nil || mode == nil || *mode != minio.Compliance || actual == nil || actual.Before(until) {
			// Fixed semantic role/mode and times only; never expose keys, object
			// VersionIds, raw provider errors, capabilities or signed evidence.
			modeKind := "absent"
			if mode != nil {
				modeKind = "other"
				switch *mode {
				case minio.Compliance:
					modeKind = "compliance"
				case minio.Governance:
					modeKind = "governance"
				}
			}
			gotDeadline := "absent"
			if actual != nil {
				gotDeadline = actual.UTC().Format(time.RFC3339Nano)
			}
			info, statErr := provider.StatObject(f.ctx, os.Getenv("HASH_E2E_S3_BUCKET"), a.key.String, minio.StatObjectOptions{VersionID: a.version.String})
			t.Fatalf("actual source/final version lacks COMPLIANCE through durable completion deadline: role=%s mode=%s got_deadline=%s want_deadline=%s version_match=%t retention_error=%t stat_error=%t", a.role, modeKind, gotDeadline, until.UTC().Format(time.RFC3339Nano), statErr == nil && info.VersionID == a.version.String, retentionErr != nil, statErr != nil)
		}
		object, getErr := provider.GetObject(f.ctx, os.Getenv("HASH_E2E_S3_BUCKET"), a.key.String, minio.GetObjectOptions{VersionID: a.version.String})
		if getErr != nil {
			t.Fatal("independent exact-version body unavailable")
		}
		info, statErr := object.Stat()
		body, readErr := io.ReadAll(io.LimitReader(object, int64(len(a.body))+1))
		closeErr := object.Close()
		sum := sha256.Sum256(body)
		if statErr != nil || readErr != nil || closeErr != nil || info.VersionID != a.version.String || info.Size != int64(len(a.body)) || !bytes.Equal(body, a.body) || !bytes.Equal(sum[:], a.digest) {
			t.Fatal("independent version, bounded body or SHA differs from original committed artifact")
		}
	}
	claims, err := evidence.ParseCertificateCommitments(journey.verified[2])
	if err != nil || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || claims.DocumentID != completed.ID.String() || claims.OrgID != f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) {
		t.Fatal("signed ordinary certificate does not bind actual V2/final PDF")
	}
	carrier := render.ParticipantReportCanonicalCarrierV2
	signedHTML := string(journey.verified[2])
	start := strings.Index(signedHTML, carrier)
	if start < 0 || strings.Count(signedHTML, carrier) != 1 {
		t.Fatal("one signed ordinary canonical carrier required")
	}
	tail := signedHTML[start+len(carrier):]
	end := strings.Index(tail, "</pre>")
	if end < 0 {
		t.Fatal("ordinary report carrier incomplete")
	}
	canonical := []byte(html.UnescapeString(tail[:end]))
	report, err := render.DecodeParticipantReportCanonicalV2(canonical)
	if err != nil || report.Schema != render.ParticipantReportSchemaV2 || report.DocumentID != completed.ID.String() || report.DelegatedExecution != nil || report.Cutoff != claims.ParticipantReportCutoff || report.SourceRowsV2() != claims.ParticipantReportRows || render.ParticipantReportCanonicalSHA256V2(canonical) != claims.ParticipantReportSHA256 {
		t.Fatal("closed signed ordinary report or canonical commitment differs")
	}
	manual := 0
	for _, event := range report.Events {
		if event.Event.Kind == "document.signed" {
			manual++
		}
	}
	if manual != 2 {
		t.Fatal("ordinary report does not retain both manual signature events")
	}
	q.assertObserversOnlyV1(t)
}
