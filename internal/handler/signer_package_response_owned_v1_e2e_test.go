//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/documentpackage"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// This extends the same strict main-version peer with actual signature PUT,
// listing, retention and readback operations. It is a local S3 protocol fixture,
// not a claim about an external provider. The constructor exists before Send
// retention and is reused by the actual native response owner.
type packageResponseStoragePeer247 struct {
	main                   *packageRetentionNativePeer240
	mu                     sync.Mutex
	until                  map[string]time.Time
	hold                   bool
	entered, release       chan struct{}
	enterOnce, releaseOnce sync.Once
}

func (p *packageResponseStoragePeer247) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/hash-import-fixture/")
	signature := strings.Contains(key, "/signatures/")
	if r.URL.Query().Has("versions") && strings.Contains(r.URL.Query().Get("prefix"), "/signatures/") {
		p.main.base.ServeHTTP(w, r)
		return
	}
	if !signature {
		p.main.ServeHTTP(w, r)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
		http.Error(w, "missing SDK authentication", http.StatusForbidden)
		return
	}
	if r.URL.Query().Has("retention") {
		if r.Method != http.MethodGet || r.URL.Query().Get("versionId") != "import-version-1" {
			http.Error(w, "unexpected signature retention mutation", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		until := p.until[key]
		p.mu.Unlock()
		if until.IsZero() {
			http.Error(w, "signature retention absent", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, "<Retention><Mode>COMPLIANCE</Mode><RetainUntilDate>"+until.Format(time.RFC3339Nano)+"</RetainUntilDate></Retention>")
		return
	}
	if r.Method == http.MethodPut {
		p.mu.Lock()
		hold := p.hold
		p.mu.Unlock()
		if hold {
			p.enterOnce.Do(func() { close(p.entered) })
			select {
			case <-p.release:
			case <-r.Context().Done():
				return
			}
		}
	}
	if r.Method == http.MethodPut {
		until, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
		if err != nil || r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" || !until.After(time.Now()) || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
			http.Error(w, "signature retention missing", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.until[key] = until
		p.mu.Unlock()
	}
	p.main.base.ServeHTTP(w, r)
}

type packageResponseHTTPFixture247 struct {
	peer                *packageResponseStoragePeer247
	q                   *ownedPublicReadFixtureV1
	m                   pdfadmission.HTMLSendPackageIntentMetadataV1
	recipient           uuid.UUID
	token, notice, path string
	response            documentpackage.ResponseV1
}

// The older convenience helper assigns every party the legacy single-signer
// role. A genuine two-party PDF requires unique named roles, each with its
// own visible signature field; otherwise native Send correctly refuses it.
func packageResponsePreparedSignedBirth247(t *testing.T, q *ownedPublicReadFixtureV1) (pdfadmission.HTMLSendPackageIntentMetadataV1, uuid.UUID) {
	t.Helper()
	root := packageImported220(t, q, "Two-party native package response")
	var lastRecipient uuid.UUID
	for i, role := range []string{"provider", "customer"} {
		input, err := json.Marshal(map[string]any{"email": role + "@package-response.test", "name": "Native package " + role, "role": role, "locale": "en"})
		if err != nil {
			t.Fatal(err)
		}
		party := submitSessionOperationE2E(q.f.s, http.MethodPost, "/api/v1/documents/"+root.ID.String()+"/recipients", string(input), q.cookie)
		var recipient recipientResponse
		if party.Code != http.StatusCreated || json.Unmarshal(party.Body.Bytes(), &recipient) != nil || recipient.ID == uuid.Nil || recipient.DocumentID != root.ID || recipient.Role != role {
			t.Fatal("genuine named package recipient creation failed", role, party.Code)
		}
		field := httptest.NewRecorder()
		q.f.s.Routes().ServeHTTP(field, ownedPlainRequestV1(t, q, "REST", "add_document_field", "", map[string]any{
			"document_id": root.ID.String(), "type": "signature", "recipient_id": recipient.ID.String(), "page": 1, "required": true,
			"label": "Signature " + role, "x_pct": 20, "y_pct": 55 + 20*i, "w_pct": 45, "h_pct": 10}, nil))
		if field.Code != http.StatusCreated {
			t.Fatal("genuine named package signature placement failed", role, field.Code)
		}
		lastRecipient = recipient.ID
	}
	confirmation, err := q.f.q.ConfirmDocumentLawfulBasis(q.f.ctx, generated.ConfirmDocumentLawfulBasisParams{
		DocumentID: root.ID, OrgID: q.f.org, LawfulBasis: "contract", ConfirmedBy: pgtype.UUID{Bytes: q.f.user.ID, Valid: true}, Via: "test"})
	if err != nil || confirmation == nil || confirmation.DocumentID != root.ID || strings.TrimSpace(confirmation.ControllerName) == "" || strings.TrimSpace(confirmation.ControllerContact) == "" {
		t.Fatal("actual named package lawful-basis/disclosure preparation failed", err)
	}
	root = packageLatest223(t, q, root.ID)
	p := packageCreate223(t, q, root)
	root = packageLatest223(t, q, root.ID)
	if !root.RequiresSignature {
		t.Fatal("actual named package draft lost signature mode")
	}
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	err = packageCaptureRun234(t, q, root, p, func(*pdfadmission.ApplicationHTMLSendOperationV1, *pdfadmission.ApplicationHTMLSendPackageDraftV1, authoring.Actor) error {
		return nil
	}, func(call context.Context, w *pdfadmission.ApplicationHTMLSendWorkV1, prior *pdfadmission.ApplicationHTMLSendPackageDraftV1) error {
		if _, err := packageCaptureAppend234(t, call, w, prior); err != nil {
			return err
		}
		var err error
		m, err = w.CreatePackageIntentV1(call, pdfadmission.HTMLSendIntentActorV1{IP: "127.0.0.1", Via: "synthetic-owned-test", Tool: "native-named-package-response"})
		if err != nil {
			return err
		}
		if _, err = w.FreezeBrandingV1(call); err != nil {
			return err
		}
		return w.BeginSendSealingV1(call)
	})
	if err != nil || m.AttemptID == uuid.Nil || lastRecipient == uuid.Nil {
		t.Fatal("actual named package Send birth failed", err)
	}
	packageWorkerDrained239(t, q)
	return m, lastRecipient
}

func newPackageResponseHTTPFixture247(t *testing.T, signed bool) packageResponseHTTPFixture247 {
	t.Helper()
	q := inspectionFixturePG236(t)
	var m pdfadmission.HTMLSendPackageIntentMetadataV1
	var recipient uuid.UUID
	if signed {
		m, recipient = packageResponsePreparedSignedBirth247(t, q)
	} else {
		m, recipient = packageCompletionPreparedBirth241(t, q, 2, false)
	}
	inner := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	peer := &packageResponseStoragePeer247{main: inner, until: make(map[string]time.Time), entered: make(chan struct{}), release: make(chan struct{})}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(q.f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-response-access", SecretKey: "synthetic-response-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	packageCompletionRun241(t, q, client, m, "sent")
	q.f.s.Sign.Storage = client
	t.Cleanup(func() {
		inner.mu.Lock()
		failure := inner.failure
		inner.mu.Unlock()
		if failure != nil {
			t.Error("genuine response provider", failure)
		}
	})
	token := signerPackageToken242(t, q, recipient)
	rc := q.lookupV1(t, token)
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	if err = rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	f := packageResponseHTTPFixture247{peer: peer, q: q, m: m, recipient: recipient, token: token, notice: notice.NoticeDigest, path: "accept"}
	if signed {
		f.path = "sign"
	}
	request := httptest.NewRequest(http.MethodGet, q.f.s.PublicURL+"/sign/"+token+"/package", nil).WithContext(q.f.ctx)
	response := httptest.NewRecorder()
	q.f.s.Routes().ServeHTTP(response, request)
	var body struct {
		Package *pdfadmission.SignerPackagePresentationV1 `json:"package"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body.Package == nil || body.Package.Incorporation != documentpackage.IncorporationCopyV1() || response.Header().Get("X-Hash-Document-Id") != m.Capture.DocumentID.String() || response.Header().Get("X-Hash-Recipient-Id") != recipient.String() || response.Header().Get("X-Hash-Notice-Digest") != notice.NoticeDigest {
		t.Fatal("actual package presentation/copy/scope unavailable", response.Code)
	}
	f.response = documentpackage.ResponseV1{ManifestSHA256: body.Package.ManifestSHA256, LegalCommitmentSHA256: body.Package.LegalCommitmentSHA256, IncorporationVersion: body.Package.Incorporation.Version, IncorporationSHA256: body.Package.Incorporation.SHA256, Consent: true}
	q.assertObserversOnlyV1(t)
	return f
}
func (f packageResponseHTTPFixture247) post247(t *testing.T, response *documentpackage.ResponseV1) *httptest.ResponseRecorder {
	t.Helper()
	body := map[string]any{}
	if f.path == "sign" {
		body["typed_name"] = "Synthetic Package Recipient"
		body["font"] = "Caveat"
	}
	if response != nil {
		body["package_response"] = response
	}
	return f.postBody247(t, body)
}
func (f packageResponseHTTPFixture247) postBody247(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, f.q.f.s.PublicURL+"/sign/"+f.token+"/"+f.path, bytes.NewReader(raw)).WithContext(f.q.f.ctx)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(signerNoticeDigestHeader, f.notice)
	w := httptest.NewRecorder()
	f.q.f.s.Routes().ServeHTTP(w, r)
	return w
}
func (f packageResponseHTTPFixture247) state247(t *testing.T) string {
	t.Helper()
	var s string
	err := f.q.f.pool.QueryRow(f.q.f.ctx, `SELECT jsonb_build_object('recipient',to_jsonb(r),'responses',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM document_package_responses_v1 x WHERE x.document_id=r.document_id),'signatures',(SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) FROM signatures x WHERE x.document_id=r.document_id),'events',(SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY created_at,id),'[]'::jsonb) FROM events x WHERE x.document_id=r.document_id))::text FROM recipients r WHERE r.id=$1`, f.recipient).Scan(&s)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignerPackageResponseConsentRefusalsV1E2E(t *testing.T) {
	for _, signed := range []bool{false, true} {
		kind := "accepted"
		if signed {
			kind = "signed"
		}
		t.Run(kind, func(t *testing.T) {
			f := newPackageResponseHTTPFixture247(t, signed)
			cases := []struct {
				name    string
				change  func(*documentpackage.ResponseV1)
				missing bool
				status  int
			}{
				{name: "privacy alone is not package consent", missing: true, status: http.StatusPreconditionRequired},
				{name: "unchecked package consent", change: func(r *documentpackage.ResponseV1) { r.Consent = false }, status: http.StatusBadRequest},
				{name: "stale manifest", change: func(r *documentpackage.ResponseV1) { r.ManifestSHA256 = strings.Repeat("a", 64) }, status: http.StatusPreconditionFailed},
				{name: "stale legal commitment", change: func(r *documentpackage.ResponseV1) { r.LegalCommitmentSHA256 = strings.Repeat("b", 64) }, status: http.StatusPreconditionFailed},
				{name: "unpresented incorporation version", change: func(r *documentpackage.ResponseV1) { r.IncorporationVersion = "other" }, status: http.StatusBadRequest},
				{name: "unpresented incorporation copy", change: func(r *documentpackage.ResponseV1) { r.IncorporationSHA256 = strings.Repeat("c", 64) }, status: http.StatusBadRequest},
			}
			for _, c := range cases {
				t.Run(c.name, func(t *testing.T) {
					before := f.state247(t)
					observed := f.response
					if c.change != nil {
						c.change(&observed)
					}
					in := &observed
					if c.missing {
						in = nil
					}
					got := f.post247(t, in)
					if got.Code != c.status {
						t.Fatal("response did not refuse before effects", got.Code, got.Body.String())
					}
					if f.state247(t) != before {
						t.Fatal("refused consent changed response effects")
					}
					f.q.assertObserversOnlyV1(t)
				})
			}
		})
	}
}

func TestSignerPackageResponseExactAtomicAndRetryV1E2E(t *testing.T) {
	for _, signed := range []bool{false, true} {
		kind := "accepted"
		if signed {
			kind = "signed"
		}
		t.Run(kind, func(t *testing.T) {
			f := newPackageResponseHTTPFixture247(t, signed)
			got := f.post247(t, &f.response)
			if got.Code != http.StatusOK {
				t.Fatal("genuine native package response failed", got.Code, got.Body.String())
			}
			var result signerSignResponse
			if json.Unmarshal(got.Body.Bytes(), &result) != nil || result.Completed || result.Status != "in_progress" {
				t.Fatal("first of two parties completed a contract")
			}
			row, err := f.q.f.q.InspectDocumentPackageResponseV1(f.q.f.ctx, generated.InspectDocumentPackageResponseV1Params{AttemptID: f.m.AttemptID, OrgID: f.m.Capture.OrgID, DocumentID: f.m.Capture.DocumentID, RecipientID: f.recipient})
			if err != nil || row == nil || row.ResponseKind != kind || !bytes.Equal(row.ManifestSha256, f.m.Capture.CanonicalSHA256[:]) || !bytes.Equal(row.LegalCommitmentSha256, f.m.Capture.CommitmentSHA256[:]) || row.IncorporationVersion != f.response.IncorporationVersion || hex.EncodeToString(row.IncorporationSha256) != f.response.IncorporationSHA256 {
				t.Fatal("atomic exact response receipt absent", err)
			}
			event, err := f.q.f.q.GetEventByID(f.q.f.ctx, row.ResponseEventID)
			if err != nil {
				t.Fatal(err)
			}
			ip := ""
			if event.Ip != nil {
				ip = event.Ip.String()
			}
			hash := audit.ChainHashRecord(audit.HashInput{Prev: event.PrevHash, OrgID: event.OrgID, DocID: f.m.Capture.DocumentID, RecID: f.recipient, Kind: event.Kind, IP: ip, UA: event.Ua.String, CreatedAt: event.CreatedAt.Time, Payload: event.PayloadHashed})
			if !bytes.Equal(hash, event.RowHash) || !bytes.Equal(hash, row.ResponseEventRowSha256) || event.Kind != "document."+kind {
				t.Fatal("receipt does not bind actual independently recomputed audit row")
			}
			if signed {
				sigs, err := f.q.f.q.ListSignaturesByDocument(f.q.f.ctx, f.m.Capture.DocumentID)
				if err != nil || len(sigs) != 1 || sigs[0] == nil || !row.SignatureID.Valid || uuid.UUID(row.SignatureID.Bytes) != sigs[0].ID || !sigs[0].ImageVersionID.Valid {
					t.Fatal("response did not bind actual retained native signature", err)
				}
			}
			before := f.state247(t)
			retry := f.post247(t, &f.response)
			if retry.Code != http.StatusOK {
				t.Fatal("identical observed package retry failed", retry.Code, retry.Body.String())
			}
			if f.state247(t) != before {
				t.Fatal("identical retry duplicated response/signature/audit effects")
			}
			if signed {
				for _, conflict := range []struct{ name, typedName, font string }{
					{"changed typed name", "Different Package Recipient", "Caveat"},
					{"changed signature font", "Synthetic Package Recipient", "Dancing Script"},
				} {
					t.Run(conflict.name, func(t *testing.T) {
						requests := f.q.storagePeer.requests.Load()
						got := f.postBody247(t, map[string]any{"typed_name": conflict.typedName, "font": conflict.font, "package_response": &f.response})
						if got.Code != http.StatusPreconditionFailed {
							t.Fatal("conflicting signed retry was accepted", got.Code, got.Body.String())
						}
						if f.state247(t) != before || f.q.storagePeer.requests.Load() != requests {
							t.Fatal("conflicting signed retry changed response effects or accessed evidence storage")
						}
					})
				}
			}
			f.q.assertObserversOnlyV1(t)
		})
	}
}

// A signature object can be retained before the credential expires. That
// provider side effect never licenses a late SQL response. The original link
// deadline, not a later successful upload, controls the atomic response.
func TestSignerPackageResponseOriginalExpiryAfterStorageWaitV1E2E(t *testing.T) {
	f := newPackageResponseHTTPFixture247(t, true)
	if _, err := f.q.f.pool.Exec(f.q.f.ctx, "UPDATE recipients SET magic_token_expires_at=clock_timestamp()+interval '3 seconds' WHERE id=$1", f.recipient); err != nil {
		t.Fatal(err)
	}
	before := f.state247(t)
	f.peer.mu.Lock()
	f.peer.hold = true
	f.peer.mu.Unlock()
	done := make(chan struct{})
	var response *httptest.ResponseRecorder
	release := func() { f.peer.releaseOnce.Do(func() { close(f.peer.release) }) }
	t.Cleanup(func() {
		release()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("actual response writer did not join")
		}
	})
	go func() { defer close(done); response = f.post247(t, &f.response) }()
	select {
	case <-f.peer.entered:
	case <-done:
		t.Fatal("response never reached actual signature PUT", response.Code, response.Body.String())
	case <-f.q.f.ctx.Done():
		t.Fatal("actual signature PUT was not reached", f.q.f.ctx.Err())
	}
	select {
	case <-time.After(3500 * time.Millisecond):
	case <-f.q.f.ctx.Done():
		t.Fatal(f.q.f.ctx.Err())
	}
	release()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("expired signature response did not join")
	}
	if response.Code != http.StatusGone {
		t.Fatal("original expired link committed a late signature", response.Code, response.Body.String())
	}
	if f.state247(t) != before {
		t.Fatal("late response changed SQL status/signature/audit/receipt effects")
	}
	f.q.assertObserversOnlyV1(t)
}
