//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
)

type ordinaryPreparationFaultPeer249 struct {
	base    *htmlCreationStorageE2E
	fail    atomic.Bool
	blocked string
	mu      sync.Mutex
	puts    map[string]int
}

func (p *ordinaryPreparationFaultPeer249) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPut && !r.URL.Query().Has("retention") {
		if p.fail.Load() && strings.Contains(r.URL.Path, p.blocked) {
			http.Error(w, "synthetic interruption before this output PUT", http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.puts[r.URL.Path]++
		p.mu.Unlock()
	}
	p.base.ServeHTTP(w, r)
}
func (p *ordinaryPreparationFaultPeer249) putCounts249() map[string]int {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[string]int{}
	for k, n := range p.puts {
		out[k] = n
	}
	return out
}

// The output PUT succeeds and returns its genuine provider version; only the
// following exact-version policy observation fails. Original PDFs continue on
// the strict readable-policy peer, independently of this output-only fault.
type ordinaryPreparationRetentionFaultPeer249 struct {
	base            *completedPackagePeer248
	outputPrefix    string
	finalPrefix     string
	denyRetention   atomic.Bool
	resume          atomic.Bool
	mu              sync.Mutex
	finalPath       string
	finalPuts       int
	latestReads     int
	versionLists    int
	outputPuts      int
	retentionReads  int
	deadline        time.Time
	resumeVersion   string
	protocolErr     error
	beforeOutputPut func() error
}

func (p *ordinaryPreparationRetentionFaultPeer249) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	final := strings.HasPrefix(r.URL.Path, p.finalPrefix)
	output := false
	for _, prefix := range []string{"final-", "audit-", "audit-payload-", "audit-signature-"} {
		output = output || strings.HasPrefix(r.URL.Path, p.outputPrefix+prefix)
	}
	// A bucket-wide or ancestor-prefix version listing can include the pinned
	// final even though the request URL names only the bucket. Unrelated exact
	// signature prefixes remain on their existing protocol path.
	listing := false
	if (r.URL.Path == "/hash-import-fixture" || r.URL.Path == "/hash-import-fixture/") && (r.URL.Query().Has("versions") || r.URL.Query().Has("list-type")) {
		prefix := r.URL.Query().Get("prefix")
		finalPrefix := strings.TrimPrefix(p.finalPrefix, "/hash-import-fixture/")
		listing = strings.HasPrefix(prefix, finalPrefix) || strings.HasPrefix(finalPrefix, prefix)
	}
	firstOutputPut := false
	p.mu.Lock()
	if output && r.Method == http.MethodPut && !r.URL.Query().Has("retention") {
		firstOutputPut = p.outputPuts == 0
		p.outputPuts++
	}
	if p.resume.Load() && listing {
		p.versionLists++
		p.protocolErr = fmt.Errorf("pinned ordinary final used a bucket listing")
	}
	if final {
		if p.finalPath == "" {
			p.finalPath = r.URL.Path
		} else if p.finalPath != r.URL.Path {
			p.protocolErr = fmt.Errorf("ordinary recovery changed its final output identity")
		}
		switch {
		case (r.Method == http.MethodHead || r.Method == http.MethodGet) && r.URL.Query().Get("versionId") == "":
			p.latestReads++
			if p.resume.Load() {
				p.protocolErr = fmt.Errorf("pinned ordinary final used an unversioned read")
			}
		case r.Method == http.MethodPut && !r.URL.Query().Has("retention"):
			p.finalPuts++
			deadline, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
			if err != nil || r.Header.Get("X-Amz-Object-Lock-Mode") != "COMPLIANCE" || p.resume.Load() {
				p.protocolErr = fmt.Errorf("ordinary final PUT omitted its compliance deadline or replaced a pinned output")
			}
			p.deadline = deadline
		case r.Method == http.MethodGet && r.URL.Query().Has("retention"):
			p.retentionReads++
			if r.URL.Query().Get("versionId") != "import-version-1" || (p.resume.Load() && r.URL.Query().Get("versionId") != p.resumeVersion) {
				p.protocolErr = fmt.Errorf("ordinary policy observation omitted the actual positive version")
			}
		case r.Method == http.MethodPut && r.URL.Query().Has("retention"):
			raw, err := io.ReadAll(io.LimitReader(r.Body, 8193))
			_ = r.Body.Close()
			r.Body = io.NopCloser(bytes.NewReader(raw))
			var policy struct {
				Mode  string    `xml:"Mode"`
				Until time.Time `xml:"RetainUntilDate"`
			}
			if err != nil || len(raw) > 8192 || xml.Unmarshal(raw, &policy) != nil || policy.Mode != "COMPLIANCE" || !policy.Until.Equal(p.deadline) || !p.resume.Load() || p.resumeVersion == "" || r.URL.Query().Get("versionId") != p.resumeVersion || r.Header.Get("X-Amz-Bypass-Governance-Retention") != "" {
				p.protocolErr = fmt.Errorf("ordinary retention write changed the observed version or original deadline")
			}
		}
	}
	failure := p.protocolErr
	p.mu.Unlock()
	if failure != nil {
		http.Error(w, "invalid strict ordinary output protocol", http.StatusBadRequest)
		return
	}
	if firstOutputPut && p.beforeOutputPut != nil {
		if err := p.beforeOutputPut(); err != nil {
			p.mu.Lock()
			p.protocolErr = fmt.Errorf("original output bodies were not frozen before first provider PUT")
			p.mu.Unlock()
			http.Error(w, "unfrozen ordinary output protocol", http.StatusBadRequest)
			return
		}
	}
	if final && r.Method == http.MethodGet && r.URL.Query().Has("retention") && p.denyRetention.Load() {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "<Error><Code>AccessDenied</Code><Message>synthetic post-PUT retention observation refusal</Message></Error>")
		return
	}
	p.base.ServeHTTP(w, r)
}

func TestOrdinaryFinalizationCheckpointsLateRetentionFailureV1E2E(t *testing.T) {
	q := newOwnedPublicReadFixtureV1(t)
	f := q.f
	doc, parties := q.createSentV1(t)
	peer := &ordinaryPreparationRetentionFaultPeer249{
		base:         &completedPackagePeer248{main: &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}, mainKey: doc.PdfStorageKey.String, until: make(map[string]time.Time)},
		outputPrefix: "/hash-import-fixture/org/" + f.org.String() + "/documents/" + doc.ID.String() + "/",
		finalPrefix:  "/hash-import-fixture/org/" + f.org.String() + "/documents/" + doc.ID.String() + "/final-",
	}
	var frozenBeforePut atomic.Bool
	peer.beforeOutputPut = func() error {
		var frozen bool
		err := f.pool.QueryRow(f.ctx, `SELECT p.certificate_input_frozen AND p.certificate_render_html IS NOT NULL AND (SELECT count(*) FROM document_ordinary_finalization_outputs_v1 o WHERE o.document_id=p.document_id AND o.org_id=p.org_id AND o.payload IS NOT NULL)=4 FROM document_ordinary_finalization_preparations_v1 p WHERE p.document_id=$1 AND p.org_id=$2 AND p.staged_at IS NULL`, doc.ID, f.org).Scan(&frozen)
		if err != nil || !frozen {
			return fmt.Errorf("complete durable original preparation absent before PUT")
		}
		frozenBeforePut.Store(true)
		return nil
	}
	peer.denyRetention.Store(true)
	server := httptest.NewServer(peer)
	defer server.Close()
	client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-ordinary-retention", SecretKey: "synthetic-ordinary-retention-secret", BucketLookup: "path", RequireObjectLock: true, RequireExistingBucket: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	creationStorage := f.s.Storage
	f.s.Storage, f.s.Sign.Storage = client, client
	for i, party := range parties {
		result, err := ordinaryPreparationSign249(t, q, party.Token, party.Name)
		if err != nil || result == nil || result.Completed {
			t.Fatalf("signature %d did not retain a pending real finalization: %+v %v", i, result, err)
		}
	}
	current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || current.Status != "finalizing" || !current.FinalizationRetainUntil.Valid {
		t.Fatal("late policy refusal did not leave the actual ceremony pending", err)
	}
	before := ordinaryPreparationRows249(t, q, doc.ID)
	if len(before) != 4 || before["final_pdf"].version != "import-version-1" || before["final_pdf"].verified {
		t.Fatal("positive unverified provider identity was not checkpointed into actual M109", before["final_pdf"])
	}
	for kind, row := range before {
		if !row.hasBody || (kind != "final_pdf" && row.version != "") {
			t.Fatal("late retention failure lost a frozen body or published later output", kind)
		}
	}
	var renderDigest, reportDigest string
	var signature []byte
	if err = f.pool.QueryRow(f.ctx, `SELECT encode(certificate_render_sha256,'hex'),encode(report_sha256,'hex') FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1 AND org_id=$2 AND certificate_input_frozen AND staged_at IS NULL AND published_at IS NULL`, doc.ID, f.org).Scan(&renderDigest, &reportDigest); err != nil {
		t.Fatal("late observation occurred before durable certificate input freeze", err)
	}
	if err = f.pool.QueryRow(f.ctx, `SELECT payload FROM document_ordinary_finalization_outputs_v1 WHERE document_id=$1 AND org_id=$2 AND kind='certificate_signature'`, doc.ID, f.org).Scan(&signature); err != nil || len(signature) == 0 {
		t.Fatal("original certificate signature was not durably frozen", err)
	}
	peer.mu.Lock()
	puts, latest, reads, target, protocolErr := peer.finalPuts, peer.latestReads, peer.retentionReads, peer.deadline, peer.protocolErr
	peer.mu.Unlock()
	if protocolErr != nil || !frozenBeforePut.Load() || puts != 1 || reads == 0 || !target.Equal(current.FinalizationRetainUntil.Time) {
		t.Fatal("fault did not follow the actual retained PUT at the original deadline", puts, latest, reads, target, protocolErr)
	}
	// Only after the original certificate and signature are frozen, move the
	// organization ledger forward. Recovery must keep their original identity.
	func() {
		// The unrelated document is created through its original genuine storage
		// protocol. The pending original's Sign client/namespace never changes.
		f.s.Storage = creationStorage
		defer func() { f.s.Storage = client }()
		_, _ = q.createSentV1(t)
	}()
	if f.s.Sign.Storage != client || f.s.Storage != client {
		t.Fatal("unrelated ledger advance replaced the original finalization client")
	}
	peer.mu.Lock()
	peer.resumeVersion = before["final_pdf"].version
	peer.mu.Unlock()
	peer.resume.Store(true)
	peer.denyRetention.Store(false)
	if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
		t.Fatal("fresh native exact-version recovery failed", err)
	}
	after := ordinaryPreparationRows249(t, q, doc.ID)
	for kind, old := range before {
		now, ok := after[kind]
		if !ok || old.key != now.key || old.digest != now.digest || now.hasBody || !now.verified || now.version == "" || (old.version != "" && old.version != now.version) {
			t.Fatal("recovery changed the original frozen output or positive version", kind)
		}
	}
	peer.mu.Lock()
	afterPuts, afterLatest, afterReads, afterTarget, lists, protocolErr := peer.finalPuts, peer.latestReads, peer.retentionReads, peer.deadline, peer.versionLists, peer.protocolErr
	peer.mu.Unlock()
	if protocolErr != nil || afterPuts != puts || afterLatest != latest || afterReads <= reads || lists != 0 || !afterTarget.Equal(target) {
		t.Fatal("pinned recovery used latest, replaced the output or changed its deadline", afterPuts, afterLatest, afterReads, protocolErr)
	}
	q.storagePeer.mu.Lock()
	storedSignature := bytes.Clone(q.storagePeer.objects[after["certificate_signature"].key])
	q.storagePeer.mu.Unlock()
	if !bytes.Equal(signature, storedSignature) {
		t.Fatal("recovery re-signed the certificate at a newer chain head")
	}
	var same bool
	if err = f.pool.QueryRow(f.ctx, `SELECT encode(certificate_render_sha256,'hex')=$3 AND encode(report_sha256,'hex')=$4 AND published_at IS NOT NULL AND bodies_retired_at IS NOT NULL FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1 AND org_id=$2`, doc.ID, f.org, renderDigest, reportDigest).Scan(&same); err != nil || !same {
		t.Fatal("recovery changed the original report/render identity", err)
	}
	completed, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
	if err != nil || completed.Status != "completed" || completed.CompletionEffectiveAt != current.CompletionEffectiveAt || completed.FinalizationRetainUntil != current.FinalizationRetainUntil || completed.FinalPdfVersionID.String != before["final_pdf"].version || hex.EncodeToString(completed.FinalPdfSha) != before["final_pdf"].digest {
		t.Fatal("recovery published different completion, retention or final artifact commitments", err)
	}
	var reports, deliveries int64
	if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1)`, doc.ID).Scan(&reports, &deliveries); err != nil || reports != 1 || deliveries != int64(len(parties)+1) {
		t.Fatal("late-retention recovery lost or duplicated mandatory effects", reports, deliveries, err)
	}
	if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
		t.Fatal("completed retry failed", err)
	}
	q.assertObserversOnlyV1(t)
}

// These are genuine PostgreSQL/native Sign -> pending -> fresh FinalizeStranded
// journeys. External renderer/S3 peers are synthetic; no OS crash or configured
// provider acceptance is claimed. Faults stop before certificate PDF capture,
// after each positive pin, or before Stage COMMIT, without bypassing any guard.
func TestOrdinaryFinalizationFrozenPreparationRecoveryV1E2E(t *testing.T) {
	for _, phase := range []string{"frozen-html", "after-final-pin", "after-certificate-pin", "after-payload-pin", "after-signature-pin"} {
		t.Run(phase, func(t *testing.T) {
			q := newOwnedPublicReadFixtureV1(t)
			f := q.f
			doc, parties := q.createSentV1(t)
			peer := &ordinaryPreparationFaultPeer249{base: q.storagePeer, puts: map[string]int{}}
			switch phase {
			case "after-final-pin":
				peer.blocked = "/audit-"
			case "after-certificate-pin":
				peer.blocked = "/audit-payload-"
			case "after-payload-pin":
				peer.blocked = "/audit-signature-"
			}
			peer.fail.Store(peer.blocked != "")
			server := httptest.NewServer(peer)
			defer server.Close()
			client, err := storage.New(f.ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "hash-import-fixture", AccessKey: "synthetic-ordinary-recovery", SecretKey: "synthetic-ordinary-recovery-secret", BucketLookup: "path", AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
			if err != nil {
				t.Fatal(err)
			}
			f.s.Storage = client
			f.s.Sign.Storage = client
			if phase == "after-signature-pin" {
				_, err = f.pool.Exec(f.ctx, `CREATE FUNCTION synthetic_interrupt_ordinary_stage249() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic interruption before ordinary Stage'; END $$; CREATE TRIGGER synthetic_interrupt_ordinary_stage249 BEFORE INSERT ON document_finalization_intents FOR EACH ROW EXECUTE FUNCTION synthetic_interrupt_ordinary_stage249()`)
				if err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql -- isolated refusal-only failure injection; no fabricated successful state
			var renderCalls atomic.Int64
			if phase == "frozen-html" {
				renderer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					raw, err := io.ReadAll(io.LimitReader(r.Body, render.MaxHTMLMultipartBytes+1))
					_ = r.Body.Close()
					if err != nil || len(raw) > render.MaxHTMLMultipartBytes {
						http.Error(w, "invalid bounded fixture request", http.StatusBadRequest)
						return
					}
					if bytes.Contains(raw, []byte("Participant negotiation and signature report")) {
						renderCalls.Add(1)
						http.Error(w, "synthetic interruption after frozen HTML", http.StatusServiceUnavailable)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(raw))
					q.renderer.ServeHTTP(w, r)
				}))
				defer renderer.Close()
				f.s.Sign.PDF = render.NewGotenberg(renderer.URL)
			}
			for i, party := range parties {
				result, err := ordinaryPreparationSign249(t, q, party.Token, party.Name)
				if err != nil || result == nil || result.Completed {
					t.Fatalf("signature %d should commit while finalization remains pending: %+v %v", i, result, err)
				}
			}
			current, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil || current.Status != "finalizing" {
				t.Fatal("interrupted genuine ceremony not pending", err)
			}
			var htmlDigest, reportDigest string
			var frozen, published bool
			if err = f.pool.QueryRow(f.ctx, `SELECT encode(certificate_render_sha256,'hex'),encode(report_sha256,'hex'),certificate_input_frozen,published_at IS NOT NULL FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1 AND org_id=$2`, doc.ID, f.org).Scan(&htmlDigest, &reportDigest, &frozen, &published); err != nil || !frozen || published || len(htmlDigest) != 64 || len(reportDigest) != 64 {
				t.Fatal("original exact input not frozen", err)
			} //nolint:rawsql -- actual pending preparation evidence
			before := ordinaryPreparationRows249(t, q, doc.ID)
			wantPins := map[string]int{"frozen-html": 0, "after-final-pin": 1, "after-certificate-pin": 2, "after-payload-pin": 3, "after-signature-pin": 4}[phase]
			pins := 0
			for _, r := range before {
				if r.version != "" {
					pins++
				}
			}
			if pins != wantPins {
				t.Fatalf("positive pins=%d want=%d", pins, wantPins)
			}
			if phase == "frozen-html" && (len(before) != 3 || renderCalls.Load() == 0) {
				t.Fatal("fault did not happen after exact HTML freeze and before certificate PDF capture")
			}
			if phase == "frozen-html" {
				ordinaryPreparationRefusals249(t, q, current)
			}
			if phase == "after-signature-pin" {
				if _, err = f.pool.Exec(f.ctx, `DROP TRIGGER synthetic_interrupt_ordinary_stage249 ON document_finalization_intents; DROP FUNCTION synthetic_interrupt_ordinary_stage249()`); err != nil {
					t.Fatal(err)
				}
			} //nolint:rawsql -- remove only the isolated refusal injection
			peer.fail.Store(false)
			// A separate genuine document advances the organization ledger. A frozen
			// certificate must neither re-sign at its newer head nor consult new CSS.
			_, _ = q.createSentV1(t)
			f.s.Sign.PDF = render.NewGotenberg(q.rendererServer.URL)
			putsBefore := peer.putCounts249()
			if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
				t.Fatal("fresh native recovery failed", err)
			}
			after := ordinaryPreparationRows249(t, q, doc.ID)
			if len(after) != 4 {
				t.Fatal("exact four outputs absent", len(after))
			}
			for kind, old := range before {
				now, ok := after[kind]
				if !ok || old.digest != now.digest || (old.version != "" && old.version != now.version) {
					t.Fatal("frozen output or positive pin changed", kind)
				}
				if now.hasBody {
					t.Fatal("published database output body retained", kind)
				}
			}
			for kind, r := range after {
				if r.hasBody || !r.verified || r.version == "" {
					t.Fatal("published output incomplete", kind)
				}
			}
			var same, retired bool
			if err = f.pool.QueryRow(f.ctx, `SELECT certificate_render_html IS NULL AND bodies_retired_at IS NOT NULL,encode(certificate_render_sha256,'hex')=$3 AND encode(report_sha256,'hex')=$4 AND published_at IS NOT NULL FROM document_ordinary_finalization_preparations_v1 WHERE document_id=$1 AND org_id=$2`, doc.ID, f.org, htmlDigest, reportDigest).Scan(&retired, &same); err != nil || !retired || !same {
				t.Fatal("frozen input changed or duplicate SQL bodies remained", err)
			} //nolint:rawsql -- genuine publication body retirement witness
			// Previously persisted pins take exact-only read/retain recovery, without
			// another logical data PUT. Equal-byte physical SDK retries are not prohibited.
			putsAfter := peer.putCounts249()
			for kind, r := range before {
				if r.version != "" {
					key := "/hash-import-fixture/" + r.key
					if putsAfter[key] != putsBefore[key] {
						t.Fatal("persisted pin was uploaded again", kind)
					}
				}
			}
			current, err = f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: doc.ID, OrgID: f.org})
			if err != nil || current.Status != "completed" {
				t.Fatal("actual recovered completion absent", err)
			}
			if got := hex.EncodeToString(current.AuditPayloadSha256); got != after["certificate_payload"].digest {
				t.Fatal("published payload differs from original preparation")
			}
			var reports, deliveries int64
			if err = f.pool.QueryRow(f.ctx, `SELECT (SELECT count(*) FROM document_participant_reports_v1 WHERE document_id=$1),(SELECT count(*) FROM document_participant_report_deliveries_v1 WHERE document_id=$1)`, doc.ID).Scan(&reports, &deliveries); err != nil || reports != 1 || deliveries != int64(len(parties)+1) {
				t.Fatal("recovery duplicated or lost mandatory effects", reports, deliveries, err)
			} //nolint:rawsql -- exact native completion effect inventory
			if err = f.s.Sign.FinalizeStranded(f.ctx, f.org, doc.ID); err != nil {
				t.Fatal(err)
			}
			q.assertObserversOnlyV1(t)
		})
	}
}

type ordinaryPreparationRow249 struct {
	key, digest, version string
	hasBody, verified    bool
}

func ordinaryPreparationRows249(t *testing.T, q *ownedPublicReadFixtureV1, doc uuid.UUID) map[string]ordinaryPreparationRow249 {
	t.Helper()
	rows, err := q.f.pool.Query(q.f.ctx, `SELECT kind,storage_key,encode(sha256,'hex'),coalesce(version_id,''),payload IS NOT NULL,verified_at IS NOT NULL FROM document_ordinary_finalization_outputs_v1 WHERE document_id=$1 AND org_id=$2 ORDER BY kind`, doc, q.f.org)
	if err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- measured fixed-four scalar metadata only
	defer rows.Close()
	out := map[string]ordinaryPreparationRow249{}
	for rows.Next() {
		var kind string
		var r ordinaryPreparationRow249
		if err = rows.Scan(&kind, &r.key, &r.digest, &r.version, &r.hasBody, &r.verified); err != nil {
			t.Fatal(err)
		}
		out[kind] = r
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
func ordinaryPreparationSign249(t *testing.T, q *ownedPublicReadFixtureV1, token, name string) (*sign.Result, error) {
	t.Helper()
	rc := q.lookupV1(t, token)
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	a13, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	result, err := q.f.s.Sign.Sign(q.f.ctx, rc, sign.SignInput{TypedName: name, Font: "Caveat", Notice: a13, IP: "127.0.0.1", UserAgent: "Synthetic ordinary durable output recovery"})
	if closeErr := rc.CloseReadV1(); closeErr != nil {
		t.Fatal(closeErr)
	}
	return result, err
}

// Actual database guards are exercised against a genuine pending ceremony.
// No successful finalization intent, report or completion row is fabricated.
func ordinaryPreparationRefusals249(t *testing.T, q *ownedPublicReadFixtureV1, doc *generated.Document) {
	t.Helper()
	for _, statement := range []string{
		`UPDATE document_ordinary_finalization_preparations_v1 SET history_rows=NULL WHERE document_id=$1`,
		`UPDATE document_ordinary_finalization_outputs_v1 SET payload=NULL WHERE document_id=$1`,
		`DELETE FROM document_ordinary_finalization_outputs_v1 WHERE document_id=$1`,
	} {
		tx, err := q.f.pool.Begin(q.f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = tx.Exec(q.f.ctx, statement, doc.ID)
		_ = tx.Rollback(q.f.ctx)
		if err == nil {
			t.Fatal("pending original evidence mutation accepted", statement)
		}
	} //nolint:rawsql -- bounded negative assertions against real M109 evidence
	tx, err := q.f.pool.Begin(q.f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(q.f.ctx) }()
	sum := bytes.Repeat([]byte{0x23}, 32)
	digest := hex.EncodeToString(sum)
	dir := "org/" + doc.OrgID.String() + "/documents/" + doc.ID.String() + "/"
	_, err = tx.Exec(q.f.ctx, `INSERT INTO document_finalization_intents(document_id,org_id,mode,completion_effective_at,retain_until,final_pdf_key,final_pdf_sha256,final_pdf_version_id,audit_cert_key,audit_cert_sha256,audit_cert_version_id,audit_payload_key,audit_payload_sha256,audit_payload_version_id,audit_signature_key,audit_signature_sha256,audit_signature_version_id) VALUES($1,$2,'signature',$3,$4,$5,$6,'synthetic-unverified-version',$7,$6,'synthetic-unverified-version',$8,$6,'synthetic-unverified-version',$9,$6,'synthetic-unverified-version')`, doc.ID, doc.OrgID, doc.CompletionEffectiveAt, doc.FinalizationRetainUntil, dir+"final-"+digest+".pdf", sum, dir+"audit-"+digest+".pdf", dir+"audit-payload-"+digest+".txt", dir+"audit-signature-"+digest+".txt")
	if err != nil {
		t.Fatal("refusal probe did not reach deferred M109 boundary", err)
	} //nolint:rawsql -- adversarial transaction, never committed or published
	if _, err = tx.Exec(q.f.ctx, `DELETE FROM document_finalization_intents WHERE document_id=$1`, doc.ID); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- reproduces deferred live-row disappearance attempt
	_, err = tx.Exec(q.f.ctx, `SET CONSTRAINTS ordinary_finalization_intent_guard_v1 IMMEDIATE`)
	if err == nil || !strings.Contains(err.Error(), "ordinary intent requires exact durable original outputs") {
		t.Fatal("insert/delete bypass escaped immutable NEW-tuple guard", err)
	} //nolint:rawsql -- forces only the actual M109 deferred constraint
}
