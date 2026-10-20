//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

// New separate403 fixture; original256 remains byte-exact and one-Send.
// The browser performs all ceremony/negotiation/revision/signature mutations.
// These independent backend checks never create their successful effects.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/evidence"
	frontendcsp "github.com/bright-interaction/hash/internal/frontend"
	"github.com/bright-interaction/hash/internal/htmlsource"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// Fixed counters observe actual browser HTTP mutations, not test-oracle reads.
// Tokens/paths/bodies are never retained. They do not change route behavior.
type packageBrowserHTTPCounts403 struct {
	send, request, approve, reopen, revision, staffComment, signerComment, signatures atomic.Int64
	downloads                                                                         *packageBrowserNativeDownloads419
}

func (c *packageBrowserHTTPCounts403) handler403(root uuid.UUID, next http.Handler) http.Handler {
	staff := "/api/v1/documents/" + root.String()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c.downloads != nil {
			c.downloads.observe419(r)
		}
		if r.Method == http.MethodPost {
			switch {
			case r.URL.Path == staff+"/send":
				c.send.Add(1)
			case r.URL.Path == staff+"/comments":
				c.staffComment.Add(1)
			case r.URL.Path == staff+"/revise":
				c.reopen.Add(1)
			case r.URL.Path == staff+"/html/revisions":
				c.revision.Add(1)
			case strings.HasPrefix(r.URL.Path, staff+"/change-requests/") && strings.HasSuffix(r.URL.Path, "/approve"):
				c.approve.Add(1)
			case strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/request-changes"):
				c.request.Add(1)
			case strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/comments"):
				c.signerComment.Add(1)
			case strings.HasPrefix(r.URL.Path, "/sign/") && strings.HasSuffix(r.URL.Path, "/sign"):
				c.signatures.Add(1)
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (c *packageBrowserHTTPCounts403) snapshot403() map[string]int64 {
	return map[string]int64{"send": c.send.Load(), "request_changes": c.request.Load(), "staff_approve": c.approve.Load(), "reopen": c.reopen.Load(), "html_revision": c.revision.Load(), "staff_comment": c.staffComment.Load(), "signer_comment": c.signerComment.Load(), "signatures": c.signatures.Load()}
}
func (c *packageBrowserHTTPCounts403) exact403() bool {
	return c.send.Load() == 2 && c.request.Load() == 1 && c.approve.Load() == 1 && c.reopen.Load() == 1 && c.revision.Load() == 1 && c.staffComment.Load() == 1 && c.signerComment.Load() == 1 && c.signatures.Load() == 2
}

type packageBrowserPeer403 struct {
	mu            sync.Mutex
	strict        *completedPackagePeer248
	org           uuid.UUID
	allowRevision bool
	revisionKey   string
	failure       error
}
type packageBrowserStatus403 struct {
	http.ResponseWriter
	code int
}

func (w *packageBrowserStatus403) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}
func (w *packageBrowserStatus403) Write(raw []byte) (int, error) {
	if w.code == 0 {
		w.code = 200
	}
	return w.ResponseWriter.Write(raw)
}

// One concrete namespace/client, serial provider policy and at most one newly
// rendered draft PDF object. Old originals cannot be overwritten. Lock covers
// both originalKeys read by strict peer and the one deliberate new-key insert.
func (p *packageBrowserPeer403) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	prefix := "org/" + p.org.String() + "/documents/"
	leaf := strings.TrimPrefix(key, prefix)
	_, parseErr := uuid.Parse(strings.TrimSuffix(leaf, ".pdf"))
	candidate := strings.HasPrefix(key, prefix) && !strings.Contains(leaf, "/") && strings.HasSuffix(leaf, ".pdf") && parseErr == nil
	if candidate && r.Method == http.MethodPut && r.URL.RawQuery == "" {
		p.strict.main.base.mu.Lock()
		_, exists := p.strict.main.base.objects[key]
		p.strict.main.base.mu.Unlock()
		if !p.allowRevision || p.revisionKey != "" || exists || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("Content-Type") != "application/pdf" {
			p.failure = errors.New("403 refused repeated, unowned or overwriting draft PUT")
			http.Error(w, "owned new revision required", 400)
			return
		}
		status := &packageBrowserStatus403{ResponseWriter: w}
		p.strict.main.base.ServeHTTP(status, r)
		if status.code == 0 {
			status.code = http.StatusOK
		}
		if status.code != http.StatusOK {
			p.failure = errors.New("403 draft object PUT failed")
			return
		}
		p.revisionKey = key
		return
	}
	p.strict.ServeHTTP(w, r)
}
func (p *packageBrowserPeer403) revision403(allow bool) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.allowRevision = allow
	return p.revisionKey
}
func (p *packageBrowserPeer403) register403(key string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failure != nil || key == "" || key != p.revisionKey {
		return errors.New("actual single revision object differs")
	}
	if _, exists := p.strict.originalKeys[key]; exists {
		return errors.New("revision reused original object")
	}
	p.strict.originalKeys[key] = struct{}{}
	p.allowRevision = false
	return nil
}

// Single synchronous owner: the real native worker returns and its deferred
// batch consumer closes before a private invitation stage can be written.
func packageBrowserRunWorker403(ctx context.Context, q *ownedPublicReadFixtureV1, root uuid.UUID, stage int, client *storage.Client, cfg pdfadmission.PackageSendCompletionConfigV1) (pdfadmission.HTMLSendPackageIntentMetadataV1, error) {
	var result pdfadmission.HTMLSendPackageIntentMetadataV1
	var count int
	if stage < 1 || stage > 2 {
		return result, errors.New("undeclared package browser worker stage")
	}
	if err := q.f.pool.QueryRow(ctx, "SELECT count(*)::integer FROM document_package_send_attempts_v1 WHERE document_id=$1 AND org_id=$2", root, q.f.org).Scan(&count); err != nil || count != stage {
		return result, errors.Join(err, errors.New("exact declared attempt count required"))
	}
	batch, err := q.runtime.SessionsV1().ScanPendingPackageSendRecoveryV1(ctx, pdfadmission.PackageSendRecoveryCursorV1{})
	if batch != nil {
		defer batch.CloseConsumerV1()
	}
	if err != nil || batch == nil {
		return result, errors.Join(err, errors.New("native recovery scan unavailable"))
	}
	more, err := batch.WithNextSendV1(client, cfg, func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
		if result.AttemptID != uuid.Nil || !v.RetentionVerified || !v.CompletionVerified || v.Status != "sent" || v.Attempt.Capture.DocumentID != root || v.Attempt.Capture.OrgID != q.f.org || v.Attempt.Capture.MemberCount != 3 {
			return errors.New("actual403 worker lost retained/invited package")
		}
		result = pdfadmission.HTMLSendPackageIntentMetadataV1{AttemptID: v.Attempt.AttemptID, Capture: v.Attempt.Capture, CreatedAt: v.Attempt.CreatedAt, Article13NoticeEpochAt: v.Attempt.Article13NoticeEpochAt, RetainUntil: v.Attempt.RetainUntil}
		return nil
	})
	if err != nil || !more || result.AttemptID == uuid.Nil {
		return result, errors.Join(err, errors.New("actual403 worker did not complete"))
	}
	return result, nil
}
func packageBrowserAttemptEffects403(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	packageAttemptInspect235(t, q, m, false, "completed")
	var outcome string
	var recipients, invites, effect, sent, invited, receipts, mails int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT c.outcome,c.recipient_count,c.invite_count,octet_length(c.effect_sha256),
 (SELECT count(*) FROM events e WHERE e.document_id=c.document_id AND e.org_id=c.org_id AND e.kind='document.sent' AND e.payload_json->>'package_send_attempt_id'=c.attempt_id::text),
 (SELECT count(*) FROM events e WHERE e.document_id=c.document_id AND e.org_id=c.org_id AND e.kind='recipient.invited' AND e.payload_json->>'package_send_attempt_id'=c.attempt_id::text),
 (SELECT count(*) FROM document_package_send_initial_invite_receipts_v1 i WHERE i.attempt_id=c.attempt_id AND i.org_id=c.org_id),
 (SELECT count(*) FROM document_package_send_initial_invite_receipts_v1 i JOIN email_deliveries e ON e.id=i.email_delivery_id WHERE i.attempt_id=c.attempt_id AND i.org_id=c.org_id AND e.status='pending')
 FROM document_package_send_completions_v1 c WHERE c.attempt_id=$1 AND c.document_id=$2 AND c.org_id=$3`, m.AttemptID, m.Capture.DocumentID, q.f.org).Scan(&outcome, &recipients, &invites, &effect, &sent, &invited, &receipts, &mails)
	if err != nil || outcome != "sent" || recipients != 2 || invites != 2 || effect != 32 || sent != 1 || invited != 2 || receipts != 2 || mails != 2 {
		t.Fatal("actual403 attempt-specific effects incomplete", err)
	}
}
func packageBrowserMemberFrom403(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document, category string) packageBrowserMember403 {
	t.Helper()
	if !doc.PdfStorageKey.Valid || !doc.PdfStorageVersionID.Valid || len(doc.PdfSha256) != 32 {
		t.Fatal("403 original lacks actual version tuple")
	}
	raw, err := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, doc.PdfStorageKey.String, doc.PdfStorageVersionID.String, doc.PdfSha256)
	if err != nil || len(raw) == 0 {
		t.Fatal("403 exact native original read failed", err)
	}
	pages, err := sanitize.PageCountWithContext(q.f.ctx, raw)
	if err != nil || pages < 1 {
		t.Fatal("403 actual PDF measurement failed", err)
	}
	member := packageBrowserMember403{ID: doc.ID, Title: doc.Name, Category: category, SHA256: hex.EncodeToString(doc.PdfSha256), Bytes: int64(len(raw)), Pages: int32(pages)}
	if len(doc.HtmlSourceJson) != 0 {
		member.SourceCommitment, err = htmlsource.Commitment(doc)
		if err != nil || !doc.HtmlCurrentMaterializationSequence.Valid {
			t.Fatal("403 actual HTML source tuple unavailable", err)
		}
		member.Materialization = doc.HtmlCurrentMaterializationSequence.Int32
	}
	return member
}
func packageBrowserStageFrom403(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1, stage int, docs []*generated.Document) packageBrowserStage403 {
	t.Helper()
	copy := documentpackage.IncorporationCopyV1()
	value := packageBrowserStage403{Schema: 1, Stage: stage, RootID: m.Capture.DocumentID, AttemptID: m.AttemptID, PackageID: m.Capture.PackageID, Revision: strconv.FormatInt(m.Capture.Revision, 10), Generation: strconv.FormatInt(m.Capture.DraftGeneration, 10), RootUpdatedAt: m.Capture.RootUpdatedAt.UTC().Format(time.RFC3339Nano), NoticeEpoch: m.Article13NoticeEpochAt.UTC().Format(time.RFC3339Nano), ManifestSHA256: hex.EncodeToString(m.Capture.CanonicalSHA256[:]), LegalSHA256: hex.EncodeToString(m.Capture.CommitmentSHA256[:]), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256}
	for i, d := range docs {
		category := ""
		if i > 0 {
			category = []string{"DPA", "NDA"}[i-1]
		}
		value.Members = append(value.Members, packageBrowserMemberFrom403(t, q, d, category))
	}
	parties, fields, _ := assertBrandedStateE2E(t, q.f, docs[0])
	value.Fields = ownedRealBrowserFieldGeometryV1(t, fields)
	for _, party := range parties {
		token := packageNegotiationToken278(t, q, m.AttemptID, party.ID)
		w := q.requestV1(token, "")
		var page signerContextResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &page) != nil || page.DocumentID != docs[0].ID || page.Privacy.NoticeDigest == "" {
			t.Fatal("403 actual attempt notice context missing")
		}
		value.Parties = append(value.Parties, packageBrowserParty403{RecipientID: party.ID, Name: party.Name, Role: party.Role, Email: party.Email, Token: token, NoticeDigest: page.Privacy.NoticeDigest})
	}
	return value
}

func packageBrowserNegotiation403(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, first packageBrowserStage403) []render.ParticipantReportEventV1 {
	t.Helper()
	changes, err := q.f.q.ListChangeRequests(q.f.ctx, root)
	if err != nil || len(changes) != 1 {
		t.Fatal("403 real negotiation request missing", err)
	}
	change := changes[0]
	if change.Message != packageBrowserRequest403 || change.BlockID != "" || change.Quote != "" || change.Context != "" || change.Proposed != "" || !change.Resolution.Valid || change.Resolution.String != "approved" {
		t.Fatal("403 request or staff decision differs; no PDF proposal fields are invented")
	}
	var recipient uuid.UUID
	var notice string
	for _, party := range first.Parties {
		if party.Role == "customer" {
			recipient = party.RecipientID
			notice = party.NoticeDigest
		}
	}
	if recipient == uuid.Nil || !change.RecipientID.Valid || uuid.UUID(change.RecipientID.Bytes) != recipient {
		t.Fatal("403 request not from intended customer")
	}
	var notification int
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM email_deliveries WHERE to_email=$1 AND strpos(text_body,$2)>0 AND strpos(html_body,$2)>0", q.f.user.Email, packageBrowserRequest403).Scan(&notification); err != nil || notification != 1 {
		t.Fatal("403 owner negotiation notification missing or duplicated", err)
	}
	rows, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: root, Valid: true}, Limit: 1000})
	if err != nil || len(rows) >= 1000 {
		t.Fatal("403 complete event oracle unavailable", err)
	}
	counts := [3]int{}
	var witness []render.ParticipantReportEventV1
	for _, event := range rows {
		if event.Kind != audit.KindChangesRequested && event.Kind != audit.KindDocumentRevised {
			continue
		}
		sum, e := audit.RecomputeEventRowHash(event)
		var fields map[string]json.RawMessage
		if e != nil || !bytes.Equal(sum, event.RowHash) || json.Unmarshal(event.PayloadHashed, &fields) != nil {
			t.Fatal("403 original negotiation preimage changed", e)
		}
		text := func(key string) string {
			var value string
			if json.Unmarshal(fields[key], &value) != nil {
				t.Fatal("403 original typed negotiation field unavailable")
			}
			return value
		}
		if event.Kind == audit.KindDocumentRevised {
			if len(fields) != 0 || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != q.f.user.ID || event.RecipientID.Valid {
				t.Fatal("403 revision actor/payload changed")
			}
			counts[2]++
		} else if _, decision := fields["resolution"]; decision {
			if len(fields) != 2 || text("change_request") != change.ID.String() || text("resolution") != "approved" || !event.ActorUserID.Valid || uuid.UUID(event.ActorUserID.Bytes) != q.f.user.ID || event.RecipientID.Valid {
				t.Fatal("403 staff UI decision association changed")
			}
			counts[1]++
		} else {
			if len(fields) != 9 || text("change_request") != change.ID.String() || text("message") != packageBrowserRequest403 || text("block_id") != "" || text("quote") != "" || text("context") != "" || text("proposed") != "" || text("notice_digest") != notice || event.ActorUserID.Valid || !event.RecipientID.Valid || uuid.UUID(event.RecipientID.Bytes) != recipient {
				t.Fatal("403 request original ID/notice/text/recipient changed")
			}
			counts[0]++
		}
		values, e := render.ParticipantReportEventsV1([]*generated.Event{event}, event.CreatedAt.Time)
		if e != nil || len(values) != 1 {
			t.Fatal("403 original event commitment invalid", e)
		}
		witness = append(witness, values[0])
	}
	if counts != [3]int{1, 1, 1} {
		t.Fatal("403 omitted/repeated actual request/decision/revision", counts)
	}
	comments, err := q.f.q.ListParticipantReportCommentsV1(q.f.ctx, generated.ListParticipantReportCommentsV1Params{OrgID: q.f.org, DocumentID: root, Cutoff: pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}})
	if err != nil || len(comments) != 2 {
		t.Fatal("403 actual shared comments missing or duplicated", err)
	}
	bodies := map[string]bool{}
	for _, comment := range comments {
		proof, e := render.ParticipantReportCommentV1FromRow(comment, rows)
		if e != nil || proof.Evidence != "body-and-actor-associated" {
			t.Fatal("403 shared comment original association failed", e)
		}
		switch proof.Body {
		case packageBrowserRecipientComment403:
			if proof.Side != "signer" || proof.ActorID != recipient.String() {
				t.Fatal("403 customer comment actor changed")
			}
		case packageBrowserOwnerComment403:
			if proof.Side != "sender" || proof.ActorID != q.f.user.ID.String() {
				t.Fatal("403 staff reply actor changed")
			}
		default:
			t.Fatal("403 unexpected shared message")
		}
		if bodies[proof.Body] {
			t.Fatal("403 repeated shared message")
		}
		bodies[proof.Body] = true
	}
	return witness
}

type packageBrowserArtifact403 struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}
type packageBrowserCompletedParty403 struct {
	RecipientID     uuid.UUID `json:"recipientID"`
	Token           string    `json:"token"`
	EmailDeliveryID uuid.UUID `json:"emailDeliveryID"`
	MessageSHA256   string    `json:"messageSHA256"`
}
type packageBrowserTerminal403 struct {
	Schema         int                               `json:"schema"`
	RootID         uuid.UUID                         `json:"rootID"`
	AttemptID      uuid.UUID                         `json:"attemptID"`
	PackageID      uuid.UUID                         `json:"packageID"`
	ManifestSHA256 string                            `json:"manifestSHA256"`
	LegalSHA256    string                            `json:"legalSHA256"`
	ReportSchema   string                            `json:"reportSchema"`
	ReportSHA256   string                            `json:"reportSHA256"`
	CompletionAt   string                            `json:"completionAt"`
	Artifacts      []packageBrowserArtifact403       `json:"artifacts"`
	Parties        []packageBrowserCompletedParty403 `json:"parties"`
}

// Independent real handler refusals run before second invitation handoff, so
// they cannot race a legitimate browser response. They do not replace UI gates.
func packageBrowserResponseRefusals403(t *testing.T, q *ownedPublicReadFixtureV1, meta pdfadmission.HTMLSendPackageIntentMetadataV1, first, second packageBrowserStage403) {
	t.Helper()
	copy := documentpackage.IncorporationCopyV1()
	for _, party := range second.Parties {
		f := packageResponseHTTPFixture247{q: q, m: meta, recipient: party.RecipientID, token: party.Token, notice: party.NoticeDigest, path: "sign", response: documentpackage.ResponseV1{ManifestSHA256: second.ManifestSHA256, LegalCommitmentSHA256: second.LegalSHA256, IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}}
		before := f.state247(t)
		if denied := f.post247(t, nil); denied.Code != http.StatusPreconditionRequired || f.state247(t) != before {
			t.Fatal("403 omitted package consent was accepted or changed state", denied.Code)
		}
		stale := f.response
		stale.ManifestSHA256 = first.ManifestSHA256
		stale.LegalCommitmentSHA256 = first.LegalSHA256
		if denied := f.post247(t, &stale); denied.Code != http.StatusPreconditionFailed || f.state247(t) != before {
			t.Fatal("403 earlier commitment authorized new terms or changed state", denied.Code)
		}
	}
	for _, old := range first.Parties {
		if unavailable := q.requestV1(old.Token, ""); unavailable.Code == http.StatusOK {
			t.Fatal("403 old public invitation remained readable")
		}
	}
}

func packageBrowserCaptureHistory403(t *testing.T, q *ownedPublicReadFixtureV1, original, revised *generated.Document, first, second pdfadmission.HTMLSendPackageIntentMetadataV1) {
	t.Helper()
	pkg, err := q.f.q.LockDocumentPackageByRootV1(q.f.ctx, generated.LockDocumentPackageByRootV1Params{DocumentID: original.ID, OrgID: q.f.org})
	if err != nil || pkg.ID != first.Capture.PackageID || second.Capture.PackageID != pkg.ID || second.AttemptID == first.AttemptID || second.Capture.Revision != first.Capture.Revision+1 || second.Capture.CanonicalSHA256 == first.Capture.CanonicalSHA256 || second.Capture.CommitmentSHA256 == first.Capture.CommitmentSHA256 || !second.Article13NoticeEpochAt.After(first.Article13NoticeEpochAt) {
		t.Fatal("403 two native freezes did not advance exactly")
	}
	old, _ := captureLoad219(t, q.f, pkg, first.Capture.Revision)
	current, _ := captureLoad219(t, q.f, pkg, second.Capture.Revision)
	oldMain, newMain := old.Manifest().Main(), current.Manifest().Main()
	if oldMain.DocumentID != original.ID || oldMain.PDF.Key != original.PdfStorageKey.String || oldMain.PDF.VersionID != original.PdfStorageVersionID.String || oldMain.PDF.SHA256 != hex.EncodeToString(original.PdfSha256) || newMain.DocumentID != original.ID || newMain.PDF.Key != revised.PdfStorageKey.String || newMain.PDF.VersionID != revised.PdfStorageVersionID.String || newMain.PDF.SHA256 != hex.EncodeToString(revised.PdfSha256) || oldMain.Source.CommitmentSHA256 == newMain.Source.CommitmentSHA256 || !reflect.DeepEqual(old.Manifest().Annexes(), current.Manifest().Annexes()) {
		t.Fatal("403 captures lost exact main origin/revision or immutable annexes")
	}
}

// The terminal handoff is derived only after actual native publication/outbox.
// It gives the browser exact original-byte targets, never verified:true.
func packageBrowserTerminalFrom403(t *testing.T, q *ownedPublicReadFixtureV1, original, revised, completed *generated.Document, first, second pdfadmission.HTMLSendPackageIntentMetadataV1, firstStage, secondStage packageBrowserStage403, originals []packageNegotiationOriginal278, witness []render.ParticipantReportEventV1, initialPins map[uuid.UUID]string) packageBrowserTerminal403 {
	t.Helper()
	if completed.Status != "completed" || !completed.CompletionEffectiveAt.Valid || !completed.FinalPdfVersionID.Valid || !completed.AuditCertVersionID.Valid || !completed.AuditPayloadVersionID.Valid || !completed.AuditSignatureVersionID.Valid || completed.PdfStorageKey != revised.PdfStorageKey || completed.PdfStorageVersionID != revised.PdfStorageVersionID || !bytes.Equal(completed.PdfSha256, revised.PdfSha256) {
		t.Fatal("403 actual terminal/version publication incomplete")
	}
	var firstResponses, responses, reports, deliveries, signatures, captures, confirmations int
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*) FROM document_package_responses_v1 WHERE attempt_id=$1),
 (SELECT count(*) FROM document_package_responses_v1 WHERE attempt_id=$2),
 (SELECT count(*) FROM document_participant_reports_v1 r WHERE r.document_id=$3 AND r.org_id=$4 AND r.completion_effective_at=$5 AND r.final_pdf_sha256=$6 AND r.audit_cert_sha256=$7 AND r.audit_payload_sha256=$8 AND r.audit_signature_sha256=$9),
 (SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$3 AND org_id=$4),
 (SELECT count(*) FROM signatures WHERE document_id=$3),
 (SELECT count(*) FROM document_package_captures_v1 WHERE document_id=$3 AND org_id=$4),
 (SELECT count(*) FROM document_lawful_basis_confirmations WHERE document_id=$3 AND org_id=$4)`, first.AttemptID, second.AttemptID, completed.ID, q.f.org, completed.CompletionEffectiveAt, completed.FinalPdfSha, completed.AuditCertSha256, completed.AuditPayloadSha256, completed.AuditSignatureSha256).Scan(&firstResponses, &responses, &reports, &deliveries, &signatures, &captures, &confirmations)
	if err != nil || firstResponses != 0 || responses != 2 || reports != 1 || deliveries != 3 || signatures != 2 || captures != 2 || confirmations != 1 {
		t.Fatal("403 exact native terminal receipts incomplete", err)
	}
	confirmation, err := q.f.q.GetDocumentLawfulBasisConfirmation(q.f.ctx, generated.GetDocumentLawfulBasisConfirmationParams{DocumentID: completed.ID, OrgID: q.f.org})
	if err != nil || confirmation == nil || confirmation.LawfulBasis != "contract" || !confirmation.ConfirmedBy.Valid || uuid.UUID(confirmation.ConfirmedBy.Bytes) != q.f.user.ID || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		t.Fatal("403 actual controller instruction missing", err)
	}

	actualSignatures, err := q.f.q.ListSignaturesByDocument(q.f.ctx, completed.ID)
	if err != nil || len(actualSignatures) != 2 {
		t.Fatal("403 exact actual signature rows unavailable", err)
	}
	actualFields, err := q.f.q.ListFieldsByDocument(q.f.ctx, completed.ID)
	if err != nil || len(actualFields) != 2 {
		t.Fatal("403 exact actual field rows unavailable", err)
	}
	for _, party := range secondStage.Parties {
		matches := 0
		for _, signature := range actualSignatures {
			if signature.RecipientID != party.RecipientID {
				continue
			}
			matchedField := false
			for _, field := range actualFields {
				if field.ID == signature.FieldID && field.RecipientID.Valid && uuid.UUID(field.RecipientID.Bytes) == party.RecipientID && field.Type == "signature" && field.Required {
					matchedField = true
				}
			}
			if !matchedField || signature.TypedName != party.Name || len(signature.ImageSha256) != 32 || !signature.ImageVersionID.Valid || !signature.ImageVersionPinRequired {
				t.Fatal("403 signature lost intended recipient/required field/name/exact image pin")
			}
			matches++
		}
		if matches != 1 {
			t.Fatal("403 missing or duplicate intended signature")
		}
	}
	var generation int64
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT draft_generation FROM document_packages_v1 WHERE id=$1 AND document_id=$2 AND org_id=$3", second.Capture.PackageID, completed.ID, q.f.org).Scan(&generation); err != nil {
		t.Fatal(err)
	}
	pins := packageLayoutPins226(t, q, pdfadmission.DocumentPackageInventoryV1{PackageID: second.Capture.PackageID.String(), Generation: strconv.FormatInt(generation, 10)})
	if len(pins) != 2 || pins[secondStage.Members[1].ID] != initialPins[secondStage.Members[1].ID] || pins[secondStage.Members[2].ID] != initialPins[secondStage.Members[2].ID] {
		t.Fatal("403 original selected annex pins changed")
	}
	for _, pin := range originals {
		raw, e := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, pin.key, pin.version, pin.digest)
		if e != nil || !bytes.Equal(raw, pin.raw) {
			t.Fatal("403 previous original was overwritten or lost", e)
		}
	}
	for i, member := range secondStage.Members[1:] {
		doc := packageLatest223(t, q, member.ID)
		pin := originals[i+1]
		if doc.PdfStorageKey.String != pin.key || doc.PdfStorageVersionID.String != pin.version || hex.EncodeToString(doc.PdfSha256) != member.SHA256 {
			t.Fatal("403 independent annex source PDF version tuple changed")
		}
	}
	payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	detached, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(detached)) {
		t.Fatal("403 original mandatory payload detached signature failed", err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.DocumentID != completed.ID.String() || claims.OrgID != q.f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 {
		t.Fatal("403 current mandatory report claims disagree", err)
	}
	report := assertFreshParticipantReport406(t, q.f, completed, payload)
	if len(report.Comments) != 2 {
		t.Fatal("403 signed shared-comment report incomplete")
	}
	commentBodies := map[string]bool{}
	for _, comment := range report.Comments {
		if comment.Evidence != "body-and-actor-associated" || comment.EventID == "" || comment.EventRowSHA256 == "" || commentBodies[comment.Body] || (comment.Body != packageBrowserRecipientComment403 && comment.Body != packageBrowserOwnerComment403) {
			t.Fatal("403 report lost exact shared comment evidence")
		}
		commentBodies[comment.Body] = true
	}
	result := packageBrowserTerminal403{Schema: 1, RootID: completed.ID, AttemptID: second.AttemptID, PackageID: second.Capture.PackageID, ManifestSHA256: secondStage.ManifestSHA256, LegalSHA256: secondStage.LegalSHA256, ReportSchema: claims.ParticipantReportSchema, ReportSHA256: claims.ParticipantReportSHA256, CompletionAt: completed.CompletionEffectiveAt.Time.UTC().Format(time.RFC3339Nano)}
	artifacts := []struct {
		name, key string
		sha       []byte
		version   pgtype.Text
	}{{"final-pdf", completed.FinalPdfKey.String, completed.FinalPdfSha, completed.FinalPdfVersionID}, {"evidence-report", completed.AuditCertKey.String, completed.AuditCertSha256, completed.AuditCertVersionID}, {"signed-report-payload", completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID}, {"detached-report-signature", completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID}}
	for _, artifact := range artifacts {
		raw, e := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, artifact.key, artifact.sha, artifact.version)
		sum := sha256.Sum256(raw)
		if e != nil || len(raw) == 0 || !bytes.Equal(sum[:], artifact.sha) || ((artifact.name == "final-pdf" || artifact.name == "evidence-report") && !bytes.HasPrefix(raw, []byte("%PDF-"))) {
			t.Fatal("403 exact stored terminal artifact unavailable", artifact.name, e)
		}
		result.Artifacts = append(result.Artifacts, packageBrowserArtifact403{Name: artifact.name, SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(raw))})
	}
	var ownerRows int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM document_participant_report_deliveries_v1 r JOIN email_deliveries e ON e.id=r.email_delivery_id
 WHERE r.document_id=$1 AND r.org_id=$2 AND r.audience='sender' AND e.to_email=$3 AND e.status='pending'
 AND r.message_sha256=hash_package_send_message_sha256_v1(e.id)
 AND strpos(e.html_body,$4)>0 AND strpos(e.text_body,$4)>0 AND strpos(e.html_body,$5)>0 AND strpos(e.text_body,$5)>0`, completed.ID, q.f.org, q.f.user.Email, "/api/v1/documents/"+completed.ID.String()+"/final-pdf", "/api/v1/documents/"+completed.ID.String()+"/audit-cert").Scan(&ownerRows)
	if err != nil || ownerRows != 1 {
		t.Fatal("403 owner completion outbox missing, duplicated or mismatched", err)
	}
	tokenPattern := regexp.MustCompile(`/completed/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`)
	for _, party := range secondStage.Parties {
		var delivery uuid.UUID
		var body, htmlBody, messageSHA string
		var exact bool
		err := q.f.pool.QueryRow(q.f.ctx, `SELECT e.id,e.text_body,e.html_body,encode(r.message_sha256,'hex'),r.message_sha256=hash_package_send_message_sha256_v1(e.id)
 FROM document_participant_report_deliveries_v1 r JOIN email_deliveries e ON e.id=r.email_delivery_id
 WHERE r.document_id=$1 AND r.org_id=$2 AND r.audience='recipient' AND r.recipient_id=$3 AND e.to_email=$4 AND e.status='pending'`, completed.ID, q.f.org, party.RecipientID, party.Email).Scan(&delivery, &body, &htmlBody, &messageSHA, &exact)
		matches := tokenPattern.FindAllStringSubmatch(body, -1)
		if err != nil || !exact || delivery == uuid.Nil || len(matches) != 1 || !packageBrowserDigest403(messageSHA) {
			t.Fatal("403 actual recipient completion outbox missing or ambiguous", err)
		}
		token := matches[0][1]
		for _, path := range []string{"/completed/" + token, "/sign/" + token + "/final-pdf", "/sign/" + token + "/audit-cert"} {
			if !strings.Contains(body, path) || !strings.Contains(htmlBody, path) {
				t.Fatal("403 completion email omitted exact archive/final/report links")
			}
		}
		for _, stage := range []packageBrowserStage403{firstStage, secondStage} {
			for _, old := range stage.Parties {
				if token == old.Token {
					t.Fatal("403 completion credential reused an invitation")
				}
			}
		}
		result.Parties = append(result.Parties, packageBrowserCompletedParty403{RecipientID: party.RecipientID, Token: token, EmailDeliveryID: delivery, MessageSHA256: messageSHA})
	}
	if len(result.Parties) != 2 || result.Parties[0].Token == result.Parties[1].Token {
		t.Fatal("403 completion credentials not distinct")
	}
	// Independently inspect actual immutable archive and authorized root-only
	// forensic bundle using an actual persisted read-only completion credential.
	// This expected URL object is NOT a synthetic signing response or mutation.
	archived := signerSignResponse{Completed: true, FinalPDFURL: "/sign/" + result.Parties[0].Token + "/final-pdf", AuditCertURL: "/sign/" + result.Parties[0].Token + "/audit-cert", PackagePortalURL: "/completed/" + result.Parties[0].Token}
	packageNegotiationEvidence278(t, q, completed, first, second, originals, revised, witness, archived)
	for _, old := range secondStage.Parties {
		credential, e := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(old.Token))
		if credential != nil {
			if closeErr := credential.CloseReadV1(); closeErr != nil {
				t.Fatal("403 completion lookup did not close", closeErr)
			}
		}
		if e == nil {
			t.Fatal("403 second invitation survived terminal credential rotation")
		}
	}
	return result
}

func TestPublicNegotiatedPackageWithExternalBrowser403E2E(t *testing.T) {
	if os.Getenv("HASH_BROWSER_E2E") != "1" {
		t.Skip("explicit owned package browser required")
	}
	for _, name := range []string{"HASH_E2E_DB_URL", "HASH_E2E_PDF_WORKER_PATH", "HASH_E2E_RENDERER_URL"} {
		if os.Getenv(name) == "" {
			t.Fatalf("selected package browser requires %s", name)
		}
	}
	base, err := url.Parse(os.Getenv("HASH_SIGNER_PDF_BROWSER_BASE"))
	if err != nil || base.Scheme != "https" || base.Hostname() != "127.0.0.1" || base.Port() == "" || base.Path != "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		t.Fatal("exact private HTTPS origin required")
	}
	front, input, done, artifacts := os.Getenv("HASH_SIGNER_PDF_BROWSER_FRONTEND"), os.Getenv("HASH_SIGNER_PDF_BROWSER_INPUT"), os.Getenv("HASH_SIGNER_PDF_BROWSER_DONE"), os.Getenv("HASH_SIGNER_PDF_BROWSER_ARTIFACTS")
	for _, path := range []string{front, input, done, artifacts} {
		if !filepath.IsAbs(path) {
			t.Fatal("absolute owned browser paths required")
		}
	}
	firstPath := filepath.Join(filepath.Dir(input), "ceremony-first403.json")
	secondPath := filepath.Join(filepath.Dir(input), "ceremony-second403.json")
	terminalPath := filepath.Join(filepath.Dir(input), "ceremony-terminal403.json")
	paths := []string{input, done, firstPath, secondPath, terminalPath}
	for _, path := range packageBrowserNativeDownloadPaths419(filepath.Dir(input)) {
		paths = append(paths, path)
	}
	seenPaths := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seenPaths[path] {
			t.Fatal("distinct private browser403 paths required")
		}
		seenPaths[path] = true
		if _, e := os.Lstat(path); !os.IsNotExist(e) {
			t.Fatal("fresh private browser403 paths required")
		}
	}
	defer func() {
		for _, path := range paths {
			if path != done {
				_ = os.Remove(path)
			}
		}
	}()
	target, err := url.Parse(os.Getenv("HASH_E2E_RENDERER_URL"))
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil || target.Path != "" || target.RawQuery != "" || target.Fragment != "" {
		t.Fatal("private actual renderer origin required")
	}
	probe, err := (&http.Client{Timeout: 5 * time.Second}).Get(target.String() + "/version")
	if err != nil {
		t.Fatal("actual renderer unavailable")
	}
	version, readErr := io.ReadAll(io.LimitReader(probe.Body, 256))
	_ = probe.Body.Close()
	if readErr != nil || probe.StatusCode != 200 || strings.TrimSpace(string(version)) != "8.36.0-hash.5" {
		t.Fatal("actual renderer version differs")
	}
	image := os.Getenv("HASH_E2E_RENDERER_IMAGE_ID")
	if !strings.HasPrefix(image, "sha256:") || len(image) != 71 {
		t.Fatal("root-bound renderer image required")
	}
	if b, e := hex.DecodeString(strings.TrimPrefix(image, "sha256:")); e != nil || len(b) != 32 {
		t.Fatal("invalid renderer image pin")
	}

	q := newOwnedAttachmentBrowserFixture228(t, base.String(), target.String())
	q.template = createBrandedDesignE2E(t, q.f, q.cookie)
	ownedCreationPrepareProPlanV1(t, q)
	if err := malwarescan.Configure(q.f.ctx, "", "development"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := malwarescan.Configure(context.Background(), "", "development"); err != nil {
			t.Error(err)
		}
	})
	// This real preview/approval helper explicitly never swaps in a synthetic renderer.
	approveBrandedDesignE2E(t, q.f, q.template, q.storagePeer, q.cookie)
	creationInput := htmlCreationInputE2E(q.template)
	creationInput.Name = "Browser403 services agreement"
	creationInput.Values = htmlStringMap{"scope": "Agreed terms"}
	created := submitHTMLDocumentCreationE2E(t, q.f, q.template.ID, creationInput, q.cookie)
	var creation struct {
		Document documentResponse `json:"document"`
	}
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &creation) != nil || creation.Document.ID == uuid.Nil {
		t.Fatal("403 genuine real-rendered HTML template creation failed", created.Code)
	}
	original := reviewPackageHTML221(t, q, packageLatest223(t, q, creation.Document.ID))
	assertBrandedStateE2E(t, q.f, original)
	dpa := packageImported220(t, q, "Data processing agreement")
	nda := packageImported220(t, q, "Nondisclosure agreement")
	originals := []packageNegotiationOriginal278{packageNegotiationOriginalRead278(t, q, original), packageNegotiationOriginalRead278(t, q, dpa), packageNegotiationOriginalRead278(t, q, nda)}
	keys := map[string]struct{}{}
	for _, pin := range originals {
		keys[pin.key] = struct{}{}
	}
	if len(keys) != 3 {
		t.Fatal("403 original storage key reused")
	}
	strict := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: map[string]time.Time{}, entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: original.PdfStorageKey.String, originalKeys: keys, until: map[string]time.Time{}}
	peer := &packageBrowserPeer403{strict: strict, org: q.f.org}
	objects := httptest.NewServer(peer)
	t.Cleanup(objects.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(objects.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package-browser403", SecretKey: "synthetic-package-browser403-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.Storage, q.f.s.Send.Storage, q.f.s.Sign.Storage = client, client, client
	q.f.s.ActionSecret = "synthetic-package-browser403-action-key"
	q.f.s.Sign.ActionSecret = q.f.s.ActionSecret
	q.f.s.Evidence = &evidence.Builder{Q: q.f.q, Storage: client, Versions: q.f.s.Versions, Signer: q.f.s.Sign.Signer, PublicKeyPEM: q.f.s.Sign.Signer.PublicKeyPEM(), CertificateTrustedPublicKeys: []string{q.f.s.Sign.Signer.PublicKeyBase64()}, Issuer: "Controlled package browser403"}
	for i, annex := range []*generated.Document{dpa, nda} {
		view := packageLayoutView226(t, q, original.ID)
		current := packageLatest223(t, q, original.ID)
		raw, _ := json.Marshal(map[string]any{"member_document_id": annex.ID.String(), "expected_updated_at": current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_member_updated_at": annex.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": view.PackageID, "expected_generation": view.Generation, "ordinal": i + 1, "title": annex.Name, "category": []string{"DPA", "NDA"}[i]})
		selected := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+original.ID.String()+"/attachments", string(raw), q.cookie)
		if selected.Code != 201 {
			t.Fatal("403 prepared native annex selection failed", selected.Code)
		}
	}
	initial := packageLayoutView226(t, q, original.ID)
	initialPins := packageLayoutPins226(t, q, initial)
	if len(initial.Members) != 2 {
		t.Fatal("403 both original annexes required")
	}
	current := packageLatest223(t, q, original.ID)
	members := []packageBrowserMember403{packageBrowserMemberFrom403(t, q, current, ""), packageBrowserMemberFrom403(t, q, dpa, "DPA"), packageBrowserMemberFrom403(t, q, nda, "NDA")}
	parties, fields, _ := assertBrandedStateE2E(t, q.f, current)
	var initialParties []packageBrowserParty403
	for _, party := range parties {
		initialParties = append(initialParties, packageBrowserParty403{RecipientID: party.ID, Name: party.Name, Role: party.Role, Email: party.Email})
	}
	shell, err := os.ReadFile(filepath.Join(front, "index.html"))
	if err != nil {
		t.Fatal("403 current built frontend required")
	}
	q.f.s.CSPScriptSrc = frontendcsp.InlineScriptCSP(shell)
	assets := http.FileServer(http.Dir(front))
	q.f.s.Frontend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clean := filepath.Clean("/" + r.URL.Path)
		if st, e := os.Stat(filepath.Join(front, clean)); e == nil && !st.IsDir() {
			assets.ServeHTTP(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(front, "index.html"))
	})
	server := httptest.NewUnstartedServer(nil)
	_ = server.Listener.Close()
	server.Listener, err = net.Listen("tcp", net.JoinHostPort("0.0.0.0", base.Port()))
	if err != nil {
		t.Fatal("403 private HTTPS unavailable")
	}
	nativeDownloads := &packageBrowserNativeDownloads419{}
	httpCounts := &packageBrowserHTTPCounts403{downloads: nativeDownloads}
	server.Config.Handler = httpCounts.handler403(original.ID, q.f.s.Routes())
	server.StartTLS()
	defer server.Close()
	if until, ok := q.f.ctx.Deadline(); !ok || time.Until(until) < 155*time.Second {
		t.Fatal("original fixture has insufficient403 browser budget")
	}
	// Original150s browser allowance starts before the bootstrap is visible. All
	// synchronous worker calls share this deadline, not a refreshed phase timer.
	browserCtx, cancelBrowser := context.WithTimeout(q.f.ctx, 150*time.Second)
	defer cancelBrowser()
	cfg := packageCompletionConfig241(t, q)
	packet := map[string]any{"schema": 1, "case": "hash-negotiated-package403", "base": base.String(), "rootID": original.ID, "templateID": q.template.ID, "templateVersion": q.template.Version, "templateContentSHA256": hex.EncodeToString(q.template.HtmlContentSha256), "dpaID": dpa.ID, "ndaID": nda.ID, "members": members, "parties": initialParties, "fields": ownedRealBrowserFieldGeometryV1(t, fields), "session": map[string]string{"name": SessionCookieName, "value": q.cookie}, "rendererImage": image, "handoffs": map[string]string{"first": "ceremony-first403.json", "second": "ceremony-second403.json", "terminal": "ceremony-terminal403.json"}, "expectations": map[string]string{"initialScope": "Agreed terms", "revisedScope": packageBrowserRevisedScope403, "recipientComment": packageBrowserRecipientComment403, "ownerComment": packageBrowserOwnerComment403, "requestMessage": packageBrowserRequest403, "revisionSummary": packageBrowserRevisionSummary403, "decision": "approved", "requesterRole": "customer", "structuredPDFProposal": "not-exposed-by-current-UI"}}
	if err := packageBrowserPrivate256(input, packet); err != nil {
		t.Fatal("403 bounded private bootstrap failed")
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var first, second pdfadmission.HTMLSendPackageIntentMetadataV1
	var firstStage, secondStage packageBrowserStage403
	var firstHistory string
	var revised *generated.Document
	var witness []render.ParticipantReportEventV1
	terminalReady := false
	var terminal packageBrowserTerminal403
	stage := 0
	for {
		select {
		case <-browserCtx.Done():
			t.Fatal("403 original package browser budget ended")
		case <-tick.C:
		}
		var attempts int
		if err := q.f.pool.QueryRow(browserCtx, "SELECT count(*)::integer FROM document_package_send_attempts_v1 WHERE document_id=$1 AND org_id=$2", original.ID, q.f.org).Scan(&attempts); err != nil || attempts < stage || attempts > 2 {
			t.Fatal("403 undeclared repeated or missing native attempt", err)
		}
		if attempts == stage+1 {
			if stage == 1 {
				witness = packageBrowserNegotiation403(t, q, original.ID, firstStage)
				revised = packageLatest223(t, q, original.ID)
				if revised.PdfStorageKey == original.PdfStorageKey || revised.HtmlCurrentMaterializationID == original.HtmlCurrentMaterializationID || revised.HtmlCurrentMaterializationSequence.Int32 != original.HtmlCurrentMaterializationSequence.Int32+1 || !bytes.Equal(revised.HtmlSourceJson, original.HtmlSourceJson) {
					t.Fatal("403 real revision failed to preserve original or create one new materialization")
				}
				var values map[string]string
				if json.Unmarshal(revised.VariablesJson, &values) != nil || values["scope"] != packageBrowserRevisedScope403 {
					t.Fatal("403 actual declared scope was not edited")
				}
				var exactRevision int
				if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*) FROM html_document_materializations WHERE id=$1 AND document_id=$2 AND org_id=$3 AND summary=$4 AND created_by=$5", revised.HtmlCurrentMaterializationID, revised.ID, q.f.org, packageBrowserRevisionSummary403, q.f.user.ID).Scan(&exactRevision); err != nil || exactRevision != 1 {
					t.Fatal("403 actual owner revision summary/actor missing", err)
				}
				if err := peer.register403(revised.PdfStorageKey.String); err != nil {
					t.Fatal(err)
				}
				if packageNegotiationHistory278(t, q, first) != firstHistory {
					t.Fatal("403 revision changed first immutable history")
				}
			}
			meta, e := packageBrowserRunWorker403(browserCtx, q, original.ID, stage+1, client, cfg)
			if e != nil {
				t.Fatal("403 actual native worker failed", e)
			}
			packageBrowserAttemptEffects403(t, q, meta)
			doc := packageLatest223(t, q, original.ID)
			saved := packageBrowserStageFrom403(t, q, meta, stage+1, []*generated.Document{doc, dpa, nda})
			if stage == 0 {
				if packageBrowserValidateStage403(saved, nil) != nil {
					t.Fatal("403 first native stage invalid")
				}
				first, firstStage = meta, saved
				firstHistory = packageNegotiationHistory278(t, q, first)
				peer.revision403(true)
				if err := packageBrowserPrivate256(firstPath, saved); err != nil {
					t.Fatal("403 first actual invitations unavailable")
				}
			} else {
				if packageBrowserValidateStage403(saved, &firstStage) != nil {
					t.Fatal("403 revised native stage changed original annex or commitment protocol")
				}
				second, secondStage = meta, saved
				packageBrowserCaptureHistory403(t, q, original, revised, first, second)
				packageBrowserResponseRefusals403(t, q, second, firstStage, secondStage)
				for _, old := range firstStage.Parties {
					credential, e := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(old.Token))
					if credential != nil {
						if closeErr := credential.CloseReadV1(); closeErr != nil {
							t.Fatal("403 retired invitation lookup did not close", closeErr)
						}
					}
					if e == nil {
						t.Fatal("403 old invitation survived revised Send")
					}
				}
				if err := packageBrowserPrivate256(secondPath, saved); err != nil {
					t.Fatal("403 second actual invitations unavailable")
				}
			}
			stage++
		}
		if stage == 2 && !terminalReady {
			doc := packageLatest223(t, q, original.ID)
			if doc.Status == "completed" {
				terminal = packageBrowserTerminalFrom403(t, q, original, revised, doc, first, second, firstStage, secondStage, originals, witness, initialPins)
				if err := nativeDownloads.arm419(base, terminal, filepath.Dir(input)); err != nil {
					t.Fatal("419 exact native download observation could not arm")
				}
				if err := packageBrowserPrivate256(terminalPath, terminal); err != nil {
					t.Fatal("403 actual terminal handoff unavailable")
				}
				terminalReady = true
			}
		}
		doneNow, e := packageBrowserReadDone403(done)
		if e != nil {
			t.Fatal("403 external browser rejected ceremony", e)
		}
		if doneNow {
			if stage != 2 || !terminalReady {
				t.Fatal("403 browser claimed success before real terminal effects")
			}
			break
		}
	}
	if packageNegotiationHistory278(t, q, first) != firstHistory {
		t.Fatal("403 final/archive changed immutable initial capture")
	}
	if err := q.f.pool.QueryRow(q.f.ctx, "SELECT count(*)::integer FROM document_package_send_attempts_v1 WHERE document_id=$1 AND org_id=$2", original.ID, q.f.org).Scan(&stage); err != nil || stage != 2 {
		t.Fatal("403 repeated native Send after terminal handoff", err)
	}
	nativeDownloadRequests, err := nativeDownloads.complete419()
	if err != nil {
		t.Fatal("419 four exact native HTTP downloads not verified")
	}
	if !httpCounts.exact403() {
		t.Fatal("403 actual HTTP mutation counts differ from declared browser journey", httpCounts.snapshot403())
	}
	packageCompletionActualChain241(t, q, len(witness)+8)
	q.assertObserversOnlyV1(t)
	peer.mu.Lock()
	peerFailure := peer.failure
	revisionKey := peer.revisionKey
	peer.mu.Unlock()
	strict.main.mu.Lock()
	providerFailure := strict.main.failure
	for _, pin := range originals {
		if strict.main.until[pin.key].Before(first.RetainUntil) {
			providerFailure = errors.Join(providerFailure, errors.New("403 original retained policy shortened"))
		}
	}
	if strict.main.until[revisionKey].Before(second.RetainUntil) {
		providerFailure = errors.Join(providerFailure, errors.New("403 revised original retention missing"))
	}
	strict.main.mu.Unlock()
	if peerFailure != nil || providerFailure != nil {
		t.Fatal("403 strict native provider protocol failed", peerFailure, providerFailure)
	}
	if err := os.MkdirAll(artifacts, 0700); err != nil {
		t.Fatal(err)
	}
	safe := map[string]any{"schema": 1, "passed": true, "root_id": original.ID, "template_id": q.template.ID, "template_content_sha256": hex.EncodeToString(q.template.HtmlContentSha256), "first_attempt_id": first.AttemptID, "second_attempt_id": second.AttemptID, "package_id": second.Capture.PackageID, "first_revision": firstStage.Revision, "second_revision": secondStage.Revision, "first_manifest_sha256": firstStage.ManifestSHA256, "second_manifest_sha256": secondStage.ManifestSHA256, "first_legal_sha256": firstStage.LegalSHA256, "second_legal_sha256": secondStage.LegalSHA256, "members": secondStage.Members, "terminal_artifacts": terminal.Artifacts, "report_schema": terminal.ReportSchema, "responses": 2, "signatures": 2, "reports": 1, "deliveries": 3, "captures": 2, "controller_confirmations": 1, "owner_request_notification": true, "owner_completion_outbox": true, "recipient_completion_outbox": 2, "shared_comment_body_actor_associations": true, "initial_history_unchanged": true, "old_invitations_revoked": true, "missing_and_stale_consent_refused_without_effects": true, "original_versions_preserved": true, "actual_worker_calls_returned_and_batch_consumers_closed": true, "retention_verified": true, "organization_chain_verified": true, "detached_report_signature_verified": true, "renderer_image": image, "browser_http_mutations": httpCounts.snapshot403(), "native_download_requests": nativeDownloadRequests, "scope": "Controlled actual real-renderer/public UI two-attempt negotiated package backend. Native auth/storage/mail boundaries synthetic. Current mandatory report schema is recorded; participant-safe full verified narrative/structured PDF proposal UI/amendments/configured providers/capacity/release remain separate."}
	if err := packageBrowserPrivate256(filepath.Join(artifacts, "package-browser-backend403.json"), safe); err != nil {
		t.Fatal("403 safe backend receipt failed")
	}
}
