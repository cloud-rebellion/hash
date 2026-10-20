//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/evidence"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	pdfapi "github.com/pdfcpu/pdfcpu/pkg/api"
	pdfmodel "github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// Same synthetic namespace/client throughout authoring, both native package
// Sends and real signatures/report publication. Only one actual draft revision
// may PUT a new org/<tenant>/documents/<uuid>.pdf object without retention.
// Existing originals always use the strict exact-version/COMPLIANCE peer;
// final/report outputs keep completedPackagePeer248's retained PUT policy.
type packageNegotiationPeer278 struct {
	strict *completedPackagePeer248
	org    uuid.UUID
	mu     sync.Mutex
	draft  bool
	puts   []string
}

func (p *packageNegotiationPeer278) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	draft := p.draft
	p.mu.Unlock()
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	prefix := "org/" + p.org.String() + "/documents/"
	leaf := strings.TrimPrefix(key, prefix)
	_, parseErr := uuid.Parse(strings.TrimSuffix(leaf, ".pdf"))
	if draft && r.Method == http.MethodPut && r.URL.RawQuery == "" && strings.HasPrefix(key, prefix) && !strings.Contains(leaf, "/") && strings.HasSuffix(leaf, ".pdf") && parseErr == nil {
		p.strict.main.base.mu.Lock()
		_, exists := p.strict.main.base.objects[key]
		p.strict.main.base.mu.Unlock()
		if exists || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") || r.Header.Get("Content-Type") != "application/pdf" {
			http.Error(w, "draft fixture refused overwrite or unowned PUT", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		if len(p.puts) != 0 {
			p.mu.Unlock()
			http.Error(w, "draft fixture permits one actual new revision object", http.StatusBadRequest)
			return
		}
		p.puts = append(p.puts, key)
		p.mu.Unlock()
		p.strict.main.base.ServeHTTP(w, r)
		return
	}
	p.strict.ServeHTTP(w, r)
}

type packageNegotiationOriginal278 struct {
	key, version string
	digest, raw  []byte
}

func packageNegotiationOriginalRead278(t *testing.T, q *ownedPublicReadFixtureV1, d *generated.Document) packageNegotiationOriginal278 {
	t.Helper()
	raw, err := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, d.PdfStorageKey.String, d.PdfStorageVersionID.String, d.PdfSha256)
	if err != nil || len(raw) == 0 {
		t.Fatal("actual package original unavailable", err)
	}
	return packageNegotiationOriginal278{key: d.PdfStorageKey.String, version: d.PdfStorageVersionID.String, digest: bytes.Clone(d.PdfSha256), raw: raw}
}

// Read-only complete immutable rows, scoped to an actual dispatched attempt.
// Live recipient state/outbox displays deliberately are not treated as frozen.
func packageNegotiationHistory278(t *testing.T, q *ownedPublicReadFixtureV1, m pdfadmission.HTMLSendPackageIntentMetadataV1) string {
	t.Helper()
	var raw string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT jsonb_build_object(
 'capture',(SELECT to_jsonb(c) FROM document_package_captures_v1 c WHERE c.package_id=a.package_id AND c.revision=a.capture_revision AND c.org_id=a.org_id),
 'members',(SELECT jsonb_agg(to_jsonb(m) ORDER BY member_position) FROM document_package_capture_members_v1 m WHERE m.package_id=a.package_id AND m.revision=a.capture_revision AND m.org_id=a.org_id),
 'attempt',to_jsonb(a),
 'completion',(SELECT to_jsonb(c) FROM document_package_send_completions_v1 c WHERE c.attempt_id=a.attempt_id),
 'invites',(SELECT jsonb_agg(to_jsonb(i) ORDER BY recipient_id) FROM document_package_send_initial_invite_receipts_v1 i WHERE i.attempt_id=a.attempt_id),
 'retention',(SELECT jsonb_agg(to_jsonb(r) ORDER BY member_position) FROM document_package_send_member_retention_v1 r WHERE r.attempt_id=a.attempt_id))::text
 FROM document_package_send_attempts_v1 a WHERE a.attempt_id=$1 AND a.org_id=$2 AND a.document_id=$3`, m.AttemptID, q.f.org, m.Capture.DocumentID).Scan(&raw)
	if err != nil || raw == "" {
		t.Fatal("actual immutable package history absent", err)
	}
	return raw
}

func packageNegotiationToken278(t *testing.T, q *ownedPublicReadFixtureV1, attempt, recipient uuid.UUID) string {
	t.Helper()
	var body string
	err := q.f.pool.QueryRow(q.f.ctx, `SELECT e.text_body FROM email_deliveries e
 JOIN document_package_send_initial_invite_receipts_v1 i ON i.email_delivery_id=e.id
 WHERE i.attempt_id=$1 AND i.org_id=$2 AND i.recipient_id=$3`, attempt, q.f.org, recipient).Scan(&body)
	match := regexp.MustCompile(`/sign/([A-Za-z0-9_-]{43})(?:[^A-Za-z0-9_-]|$)`).FindStringSubmatch(body)
	if err != nil || len(match) != 2 {
		t.Fatal("actual attempt-scoped public invitation missing", err)
	}
	return match[1]
}

func packageNegotiationSend278(t *testing.T, q *ownedPublicReadFixtureV1, root uuid.UUID, client *storage.Client) pdfadmission.HTMLSendPackageIntentMetadataV1 {
	t.Helper()
	view := packageLayoutView226(t, q, root)
	d := packageLatest223(t, q, root)
	input := packageSendInputV1{ExpectedUpdatedAt: d.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), PackageID: view.PackageID, Generation: view.Generation}
	raw, err := json.Marshal(sendDocumentInput{LawfulBasis: "contract", PackageSend: &input})
	if err != nil {
		t.Fatal(err)
	}
	w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.String()+"/send", string(raw), q.cookie)
	var sent sendDocumentResponse
	if w.Code != http.StatusAccepted || json.Unmarshal(w.Body.Bytes(), &sent) != nil || sent.Status != "sealing" || len(sent.Links) != 0 || sent.PackageSend == nil || sent.PackageSend.Outcome != "active" {
		t.Fatal("actual package Send did not allocate durable sealing", w.Code, w.Body.String())
	}
	aid, err := uuid.Parse(sent.PackageSend.AttemptID)
	if err != nil || aid == uuid.Nil {
		t.Fatal("actual public package attempt missing", err)
	}
	batch := packageWorkerScan239(t, q, pdfadmission.PackageSendRecoveryCursorV1{})
	defer batch.CloseConsumerV1()
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	more, err := batch.WithNextSendV1(client, packageCompletionConfig241(t, q), func(v pdfadmission.HTMLSendPackageSendObservationV1) error {
		if m.AttemptID != uuid.Nil || v.Attempt.AttemptID != aid || v.Attempt.Capture.DocumentID != root || v.Attempt.Capture.MemberCount != 3 || !v.CompletionVerified || !v.RetentionVerified || v.Status != "sent" {
			t.Fatal("actual public package worker lost capture/retention/effects")
		}
		m = pdfadmission.HTMLSendPackageIntentMetadataV1{AttemptID: aid, Capture: v.Attempt.Capture, CreatedAt: v.Attempt.CreatedAt, Article13NoticeEpochAt: v.Attempt.Article13NoticeEpochAt, RetainUntil: v.Attempt.RetainUntil}
		return nil
	})
	if err != nil || !more || m.AttemptID != aid {
		t.Fatal("actual public package worker did not finish", err)
	}
	batch.CloseConsumerV1()
	packageWorkerDrained239(t, q)
	packageAttemptInspect235(t, q, m, false, "completed")
	return m
}

// One real main+DPA+NDA journey, with no direct status/signature/consent/cache/
// capture/receipt writes. Synthetic renderer bytes prove protocol/ownership,
// not the visual rendering of revised prose or remote provider conformance.
func TestPublicPackageNegotiationRevisionResendAndEvidenceV1E2E(t *testing.T) {
	q := inspectionFixturePG236(t)
	q.f.s.ActionSecret = "synthetic-package-negotiation278-action-key"
	q.f.s.Sign.ActionSecret = q.f.s.ActionSecret
	input := htmlCreationInputE2E(q.template)
	input.Name = "Main services agreement"
	input.Values = htmlStringMap{"scope": "Agreed terms"}
	created := submitHTMLDocumentCreationE2E(t, q.f, q.template.ID, input, q.cookie)
	var creation struct {
		Document documentResponse `json:"document"`
	}
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &creation) != nil || creation.Document.ID == uuid.Nil {
		t.Fatal("genuine declared-text HTML main creation failed", created.Code, created.Body.String())
	}
	root := reviewPackageHTML221(t, q, packageLatest223(t, q, creation.Document.ID))
	dpa := packageImported220(t, q, "Data processing agreement")
	nda := packageImported220(t, q, "Nondisclosure agreement")
	parties, err := q.f.q.ListRecipientsByDocument(q.f.ctx, root.ID)
	if err != nil || len(parties) != 2 {
		t.Fatal("genuine intended template parties missing", err)
	}
	originals := []packageNegotiationOriginal278{packageNegotiationOriginalRead278(t, q, root), packageNegotiationOriginalRead278(t, q, dpa), packageNegotiationOriginalRead278(t, q, nda)}
	keys := map[string]struct{}{}
	for _, pin := range originals {
		keys[pin.key] = struct{}{}
	}
	if len(keys) != 3 {
		t.Fatal("package authoring reused original object identities")
	}
	strict := &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: map[string]time.Time{}, entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: root.PdfStorageKey.String, originalKeys: keys, until: map[string]time.Time{}}
	peer := &packageNegotiationPeer278{strict: strict, org: q.f.org}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-package-negotiation278", SecretKey: "synthetic-package-negotiation278-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	q.f.s.Storage, q.f.s.Send.Storage, q.f.s.Sign.Storage = client, client, client
	q.f.s.Evidence = &evidence.Builder{Q: q.f.q, Storage: client, Versions: q.f.s.Versions, Signer: q.f.s.Sign.Signer, PublicKeyPEM: q.f.s.Sign.Signer.PublicKeyPEM(), CertificateTrustedPublicKeys: []string{q.f.s.Sign.Signer.PublicKeyBase64()}, Issuer: "Synthetic package negotiation278"}
	for i, annex := range []*generated.Document{dpa, nda} {
		view := packageLayoutView226(t, q, root.ID)
		current := packageLatest223(t, q, root.ID)
		body, err := json.Marshal(map[string]any{"member_document_id": annex.ID.String(), "expected_updated_at": current.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_member_updated_at": annex.UpdatedAt.Time.UTC().Format(time.RFC3339Nano), "expected_package_id": view.PackageID, "expected_generation": view.Generation, "ordinal": i + 1, "title": annex.Name, "category": []string{"DPA", "NDA"}[i]})
		if err != nil {
			t.Fatal(err)
		}
		w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/attachments", string(body), q.cookie)
		if w.Code != http.StatusCreated {
			t.Fatal("genuine public attachment selection failed", w.Code, w.Body.String())
		}
	}
	first := packageNegotiationSend278(t, q, root.ID, client)
	firstHistory := packageNegotiationHistory278(t, q, first)
	token := packageNegotiationToken278(t, q, first.AttemptID, parties[0].ID)
	bootstrap := q.requestV1(token, "")
	var page signerContextResponse
	if bootstrap.Code != http.StatusOK || json.Unmarshal(bootstrap.Body.Bytes(), &page) != nil || page.DocumentID != root.ID || page.Privacy.NoticeDigest == "" {
		t.Fatal("actual package recipient notice missing", bootstrap.Code)
	}
	n := &nativeNegotiation262{q: q, document: packageLatest223(t, q, root.ID), token: token, noticeDigest: page.Privacy.NoticeDigest, recipient: parties[0].ID}
	n.pauseV1(t)
	if w := n.resolveV1(t, true, true); w.Code != http.StatusOK {
		t.Fatal("actual package owner email approval failed", w.Code, w.Body.String())
	}
	if w := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/revise", "", q.cookie); w.Code != http.StatusOK {
		t.Fatal("actual unsigned package Revise failed", w.Code, w.Body.String())
	}
	wantEvents := nativeNegotiationEventWitness262(t, n, true, true)
	if old, err := q.f.s.Sign.LookupByToken(q.f.ctx, auth.HashMagicToken(token)); err == nil {
		_ = old.CloseReadV1()
		t.Fatal("original package invitation survived reopened draft")
	}
	draft := packageLatest223(t, q, root.ID)
	if draft.Status != "draft" || draft.SentAt.Valid || !bytes.Equal(draft.HtmlSourceJson, root.HtmlSourceJson) {
		t.Fatal("package revision lost original source or draft state")
	}
	peer.mu.Lock()
	peer.draft = true
	peer.mu.Unlock()
	revised := packageReviseHTML232(t, q, draft, "Revised agreed terms")
	peer.mu.Lock()
	peer.draft = false
	puts := append([]string(nil), peer.puts...)
	peer.mu.Unlock()
	if len(puts) != 1 || puts[0] != revised.PdfStorageKey.String || revised.PdfStorageKey == root.PdfStorageKey || revised.HtmlCurrentMaterializationID == root.HtmlCurrentMaterializationID || revised.HtmlCurrentMaterializationSequence.Int32 != root.HtmlCurrentMaterializationSequence.Int32+1 {
		t.Fatal("actual package main revision reused old materialization/object")
	}
	var values map[string]string
	if json.Unmarshal(revised.VariablesJson, &values) != nil || values["scope"] != n.change.Proposed || values["scope"] != "Revised agreed terms" {
		t.Fatal("actual package declared prose was not revised")
	}
	keys[revised.PdfStorageKey.String] = struct{}{} // Real completed authoring PUT, before any new worker call.
	second := packageNegotiationSend278(t, q, root.ID, client)
	if second.AttemptID == first.AttemptID || second.Capture.PackageID != first.Capture.PackageID || second.Capture.Revision != first.Capture.Revision+1 || second.Capture.CanonicalSHA256 == first.Capture.CanonicalSHA256 || second.Capture.CommitmentSHA256 == first.Capture.CommitmentSHA256 || !second.Article13NoticeEpochAt.After(first.Article13NoticeEpochAt) {
		t.Fatal("actual renegotiated package reused original attempt/capture/commitment/epoch")
	}
	if packageNegotiationHistory278(t, q, first) != firstHistory {
		t.Fatal("renegotiation changed immutable original package history")
	}
	pkg, err := q.f.q.LockDocumentPackageByRootV1(q.f.ctx, generated.LockDocumentPackageByRootV1Params{DocumentID: root.ID, OrgID: q.f.org})
	if err != nil || pkg.ID != first.Capture.PackageID {
		t.Fatal("actual package identity changed across negotiation", err)
	}
	oldCapture, _ := captureLoad219(t, q.f, pkg, first.Capture.Revision)
	newCapture, _ := captureLoad219(t, q.f, pkg, second.Capture.Revision)
	oldMain, newMain := oldCapture.Manifest().Main(), newCapture.Manifest().Main()
	if oldMain.DocumentID != root.ID || oldMain.PDF.Key != root.PdfStorageKey.String || oldMain.PDF.VersionID != root.PdfStorageVersionID.String || oldMain.PDF.SHA256 != hex.EncodeToString(root.PdfSha256) || newMain.DocumentID != root.ID || newMain.PDF.Key != revised.PdfStorageKey.String || newMain.PDF.VersionID != revised.PdfStorageVersionID.String || newMain.PDF.SHA256 != hex.EncodeToString(revised.PdfSha256) || oldMain.Source.CommitmentSHA256 == newMain.Source.CommitmentSHA256 || !reflect.DeepEqual(oldCapture.Manifest().Annexes(), newCapture.Manifest().Annexes()) {
		t.Fatal("new canonical package capture changed annexes or lost exact old/new main source bindings")
	}
	copy := documentpackage.IncorporationCopyV1()
	f := packageResponseHTTPFixture247{q: q, m: second, path: "sign", response: documentpackage.ResponseV1{ManifestSHA256: hex.EncodeToString(second.Capture.CanonicalSHA256[:]), LegalCommitmentSHA256: hex.EncodeToString(second.Capture.CommitmentSHA256[:]), IncorporationVersion: copy.Version, IncorporationSHA256: copy.SHA256, Consent: true}}
	var terminal signerSignResponse
	for i, party := range parties {
		f.recipient = party.ID
		f.token = packageNegotiationToken278(t, q, second.AttemptID, party.ID)
		if f.token == token {
			t.Fatal("new package invitation reused retired credential")
		}
		var context signerContextResponse
		w := q.requestV1(f.token, "")
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &context) != nil || context.Privacy.NoticeDigest == "" {
			t.Fatal("new package notice bootstrap failed", w.Code)
		}
		f.notice = context.Privacy.NoticeDigest
		metadata := q.requestV1(f.token, "/package")
		var presented struct {
			Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
		}
		if metadata.Code != http.StatusOK || json.Unmarshal(metadata.Body.Bytes(), &presented) != nil || presented.Package == nil || presented.Package.ManifestSHA256 != f.response.ManifestSHA256 || presented.Package.LegalCommitmentSHA256 != f.response.LegalCommitmentSHA256 || len(presented.Package.Annexes) != 2 || presented.Package.Annexes[0].Category != "DPA" || presented.Package.Annexes[1].Category != "NDA" {
			t.Fatal("participant was not presented exact revised main/DPA/NDA", metadata.Code)
		}
		if denied := f.post247(t, nil); denied.Code != http.StatusPreconditionRequired {
			t.Fatal("revised whole-package consent was optional", denied.Code)
		}
		stale := f.response
		stale.ManifestSHA256, stale.LegalCommitmentSHA256 = hex.EncodeToString(first.Capture.CanonicalSHA256[:]), hex.EncodeToString(first.Capture.CommitmentSHA256[:])
		before := f.state247(t)
		if denied := f.post247(t, &stale); denied.Code != http.StatusPreconditionFailed || f.state247(t) != before {
			t.Fatal("original package commitment authorized changed package", denied.Code)
		}
		signed := f.post247(t, &f.response)
		if signed.Code != http.StatusOK || json.Unmarshal(signed.Body.Bytes(), &terminal) != nil || terminal.Completed != (i == len(parties)-1) {
			t.Fatal("actual revised package signature/report completion failed", i, signed.Code, signed.Body.String())
		}
	}
	completed := packageLatest223(t, q, root.ID)
	if completed.Status != "completed" || !completed.FinalPdfKey.Valid {
		t.Fatal("negotiated package did not reach real completed artifact")
	}
	packageNegotiationEvidence278(t, q, completed, first, second, originals, revised, wantEvents, terminal)
	if packageNegotiationHistory278(t, q, first) != firstHistory {
		t.Fatal("completion/export changed the original captured package attempt")
	}
	strict.main.mu.Lock()
	protocolErr := strict.main.failure
	for _, pin := range originals {
		if strict.main.until[pin.key].Before(first.RetainUntil) {
			strict.main.mu.Unlock()
			t.Fatal("original retained package policy was shortened")
		}
	}
	strict.main.mu.Unlock()
	if protocolErr != nil {
		t.Fatal("strict original provider rejected negotiated ceremony", protocolErr)
	}
	packageCompletionActualChain241(t, q, len(wantEvents)+6)
	q.assertObserversOnlyV1(t)
}

func packageNegotiationEvidence278(t *testing.T, q *ownedPublicReadFixtureV1, completed *generated.Document, first, second pdfadmission.HTMLSendPackageIntentMetadataV1, originals []packageNegotiationOriginal278, revised *generated.Document, wantEvents []render.ParticipantReportEventV1, terminal signerSignResponse) {
	t.Helper()
	payload, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditPayloadKey.String, completed.AuditPayloadSha256, completed.AuditPayloadVersionID)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := readDocumentArtifact(q.f.ctx, q.f.s.Storage, completed, completed.AuditSignatureKey.String, completed.AuditSignatureSha256, completed.AuditSignatureVersionID)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := evidence.ParseCertificateCommitments(payload)
	if err != nil || claims.DocumentID != completed.ID.String() || claims.OrgID != q.f.org.String() || claims.FinalPDFSHA256 != hex.EncodeToString(completed.FinalPdfSha) || claims.ParticipantReportSchema != render.ParticipantReportSchemaV2 || !sign.Verify(q.f.s.Sign.Signer.PublicKeyBase64(), string(payload), string(signature)) {
		t.Fatal("actual negotiated certificate/artifact claims or signature differ", err)
	}
	report := assertFreshParticipantReport406(t, q.f, completed, payload)
	if len(report.Members) != 3 || len(report.Responses) != 2 {
		t.Fatal("actual package participant report inventory incomplete")
	}
	for _, want := range wantEvents {
		matches := 0
		for _, actual := range report.Events {
			if actual.Event.ID == want.ID {
				if actual.Event != want {
					t.Fatal("signed package negotiation tuple differs from original event")
				}
				if want.Kind == audit.KindChangesRequested && actual.Request == nil && actual.Decision == nil {
					t.Fatal("fresh negotiation request/decision lost original typed details")
				}
				matches++
			}
		}
		if matches != 1 {
			t.Fatal("signed report omitted/duplicated request decision or revision", matches)
		}
	}
	for _, response := range report.Responses {
		if response.AttemptID != second.AttemptID.String() || response.ManifestSHA256 != hex.EncodeToString(second.Capture.CanonicalSHA256[:]) || response.LegalCommitmentSHA256 != hex.EncodeToString(second.Capture.CommitmentSHA256[:]) || response.IncorporationVersion != documentpackage.IncorporationCopyV1().Version || response.IncorporationSHA256 != documentpackage.IncorporationCopyV1().SHA256 || response.Kind != "signed" || response.SignatureID == "" || response.EventID == "" || response.EventRowSHA256 == "" {
			t.Fatal("mandatory report response lost exact revised package binding")
		}
		var exact int
		if err := q.f.pool.QueryRow(q.f.ctx, `SELECT count(*) FROM document_package_responses_v1
 WHERE attempt_id=$1 AND org_id=$2 AND document_id=$3 AND recipient_id::text=$4
 AND signature_id::text=$5 AND response_event_id::text=$6 AND encode(response_event_row_sha256,'hex')=$7
 AND response_kind=$8 AND encode(manifest_sha256,'hex')=$9 AND encode(legal_commitment_sha256,'hex')=$10
 AND incorporation_version=$11 AND encode(incorporation_sha256,'hex')=$12`, second.AttemptID, q.f.org, completed.ID, response.RecipientID, response.SignatureID, response.EventID, response.EventRowSHA256, response.Kind, response.ManifestSHA256, response.LegalCommitmentSHA256, response.IncorporationVersion, response.IncorporationSHA256).Scan(&exact); err != nil || exact != 1 {
			t.Fatal("signed report package response tuple differs from actual atomic receipt", err, exact)
		}
	}
	var firstResponses, secondResponses, reports, deliveries int
	err = q.f.pool.QueryRow(q.f.ctx, `SELECT
 (SELECT count(*) FROM document_package_responses_v1 WHERE attempt_id=$1),
 (SELECT count(*) FROM document_package_responses_v1 WHERE attempt_id=$2),
 (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$3 AND org_id=$4),
 (SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$3 AND org_id=$4)`, first.AttemptID, second.AttemptID, completed.ID, q.f.org).Scan(&firstResponses, &secondResponses, &reports, &deliveries)
	if err != nil || firstResponses != 0 || secondResponses != 2 || reports != 1 || deliveries != 3 {
		t.Fatal("actual package response/report/delivery receipts differ", err, firstResponses, secondResponses, reports, deliveries)
	}
	for _, pin := range originals {
		raw, err := q.f.s.Storage.GetVerifiedVersion(q.f.ctx, pin.key, pin.version, pin.digest)
		if err != nil || !bytes.Equal(raw, pin.raw) {
			t.Fatal("negotiation deleted/changed exact original package object", err)
		}
	}
	fresh := strings.TrimSuffix(strings.TrimPrefix(terminal.FinalPDFURL, "/sign/"), "/final-pdf")
	if len(fresh) != 43 || terminal.PackagePortalURL != "/completed/"+fresh {
		t.Fatal("completed negotiated package portal absent")
	}
	archive := completedPackageFixture248{active: packageResponseHTTPFixture247{q: q, m: second}, token: fresh, etag: signerPackageMemberETag246(second.Capture.CanonicalSHA256, second.Capture.CommitmentSHA256)}
	memberPins := []packageNegotiationOriginal278{packageNegotiationOriginalRead278(t, q, revised), originals[1], originals[2]}
	for i, pin := range memberPins {
		w := archive.get248(q.f.ctx, fresh, "/completed-package/members/"+strconv.Itoa(i)+"/pdf", archive.etag)
		sum := sha256.Sum256(pin.raw)
		member := report.Members[i]
		if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), pin.raw) || w.Header().Get("X-Hash-PDF-SHA256") != hex.EncodeToString(sum[:]) || member.Position != int32(i) || member.PDFSHA256 != hex.EncodeToString(sum[:]) || member.PDFVersionID != pin.version || member.PDFBytes != int64(len(pin.raw)) {
			t.Fatal("completed package/report changed exact revised original/member", i, w.Code)
		}
	}
	for _, endpoint := range []string{terminal.FinalPDFURL, terminal.AuditCertURL} {
		w := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(w, httptest.NewRequest(http.MethodGet, endpoint, nil).WithContext(q.f.ctx))
		if w.Code != http.StatusOK || !bytes.HasPrefix(w.Body.Bytes(), []byte("%PDF-")) {
			t.Fatal("real final/report artifact download failed", w.Code)
		}
		if endpoint == terminal.FinalPDFURL {
			sum := sha256.Sum256(w.Body.Bytes())
			if !bytes.Equal(sum[:], completed.FinalPdfSha) {
				t.Fatal("final PDF download differs from signed artifact commitment")
			}
		}
	}
	bundle := submitSessionOperationE2E(q.f.s, http.MethodGet, "/api/v1/documents/"+completed.ID.String()+"/evidence-bundle", "", q.cookie)
	if bundle.Code != http.StatusOK || !bytes.HasPrefix(bundle.Body.Bytes(), []byte("%PDF-")) {
		t.Fatal("actual controlled evidence bundle export failed", bundle.Code, bundle.Body.String())
	}
	verified := VerifyEvidenceBundleWithTrust(bundle.Body.Bytes(), EvidenceTrustSet{ManifestPublicKeys: []string{q.f.s.Sign.Signer.PublicKeyBase64()}, CertificatePublicKeys: []string{q.f.s.Sign.Signer.PublicKeyBase64()}})
	if !verified.OK || !verified.SignatureValid || !verified.ManifestSignatureValid || !verified.KeyTrusted {
		t.Fatal("actual negotiated bundle verification failed", verified.Errors)
	}
	conf := pdfmodel.NewDefaultConfiguration()
	conf.ValidationMode = pdfmodel.ValidationRelaxed
	attachments, err := pdfapi.ExtractAttachmentsRaw(bytes.NewReader(bundle.Body.Bytes()), "", []string{"events.json", "final-pdf.pdf", "audit-cert-payload.txt"}, conf)
	if err != nil || len(attachments) != 3 {
		t.Fatal("actual controlled bundle attachments missing", err)
	}
	files := map[string][]byte{}
	for _, a := range attachments {
		name := path.Base(a.FileName)
		if _, duplicate := files[name]; duplicate || name != a.FileName {
			t.Fatal("actual bundle attachment alias/duplicate")
		}
		raw, err := io.ReadAll(io.LimitReader(a.Reader, (16<<20)+1))
		if err != nil || len(raw) > 16<<20 {
			t.Fatal("controlled fixture attachment exceeds bounded read", err)
		}
		files[name] = raw
	}
	if !bytes.Equal(files["audit-cert-payload.txt"], payload) || evidence.VerifyCeremonyEventsJSON(files["events.json"], completed.ID.String(), q.f.org.String(), claims.DocumentEventsSHA256, claims.DocumentEventsCount) != nil {
		t.Fatal("bundle changed original signed certificate or complete event-set commitment")
	}
	final := sha256.Sum256(files["final-pdf.pdf"])
	if !bytes.Equal(final[:], completed.FinalPdfSha) {
		t.Fatal("controlled bundle final PDF differs from immutable signed final")
	}
	var exported evidence.CeremonyEventsFile
	if json.Unmarshal(files["events.json"], &exported) != nil {
		t.Fatal("actual exported event preimages malformed")
	}
	rows, err := q.f.q.ListEventsByDocumentChronological(q.f.ctx, generated.ListEventsByDocumentChronologicalParams{DocumentID: pgtype.UUID{Bytes: completed.ID, Valid: true}, Limit: int32(claims.DocumentEventsCount)})
	if err != nil || len(rows) != claims.DocumentEventsCount {
		t.Fatal("actual certificate-bound original event set unavailable", err)
	}
	for _, want := range wantEvents {
		var actual *generated.Event
		for _, row := range rows {
			if row.ID.String() == want.ID {
				actual = row
			}
		}
		matches := 0
		for _, row := range exported.Events {
			if row.ID != want.ID {
				continue
			}
			matches++
			preimage, err := base64.StdEncoding.DecodeString(row.PayloadHashedB64)
			var display, originalDisplay map[string]any
			// The exported display JSON is deliberately pretty-printed. Compare
			// its values, while the hash preimage above stays byte-for-byte exact.
			if actual == nil || err != nil || !bytes.Equal(preimage, actual.PayloadHashed) || row.RowHashSHA256 != want.RowSHA256 || json.Unmarshal(row.PayloadJSON, &display) != nil || json.Unmarshal(actual.PayloadJson, &originalDisplay) != nil || !reflect.DeepEqual(display, originalDisplay) {
				t.Fatal("controlled bundle lost original request/decision/revision preimage or row hash")
			}
		}
		if matches != 1 {
			t.Fatal("controlled bundle omitted/duplicated original negotiation preimage", matches)
		}
	}
}
