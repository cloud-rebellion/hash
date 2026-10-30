//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Explicit synthetic test capacity, not deployed limits or approval. This
// unique disposable DB uses the genuine direct factory, original observer,
// native coordinator and physical cleanup; no caller Tx or READY is supplied.
// The sole opt-in profile is for metadata's >128KiB source-read fixture.
// Logical source recipe credit is not measured RSS or installation capacity.
type htmlAuthoringNativeTestProfileE2E uint8

const htmlAuthoringMetadataReadProfileE2E htmlAuthoringNativeTestProfileE2E = 1

func setupHTMLAuthoringNativeFixtureV1(t *testing.T, f lifecycleAuthorizationFixture, profiles ...htmlAuthoringNativeTestProfileE2E) {
	t.Helper()
	cfg, err := pgx.ParseConfig(os.Getenv("HASH_E2E_DB_URL"))
	if err != nil {
		t.Fatal(err)
	}
	applicationName := "hash_html_native_" + uuid.NewString()
	cfg.RuntimeParams["application_name"] = applicationName
	cfg.RuntimeParams["statement_timeout"] = "15000"
	cfg.RuntimeParams["lock_timeout"] = "10000"
	cfg.RuntimeParams["idle_in_transaction_session_timeout"] = "30000"
	parentBytes := int64(2 << 30)
	if len(profiles) > 1 || len(profiles) == 1 && profiles[0] != htmlAuthoringMetadataReadProfileE2E {
		t.Fatal("unsupported native HTML test profile")
	}
	if len(profiles) == 1 {
		// Explicit finite experiment at factory birth; no live limits change.
		// Every ordinary caller retains the original2GiB Parent allocation.
		parentBytes = 3 << 30
	}
	limits := workguard.VectorV1{ParentBytes: parentBytes, DBStagingBytes: 2 << 30, SQLSessions: 16}
	coordinator, err := workguard.NewV1(workguard.LimitsV1{Global: limits, Organisation: limits, MaxGrants: 256, MaxOrganisationGrants: 128})
	if err != nil {
		t.Fatal(err)
	}
	work, err := pdfadmission.NewWorkAdmissionV1(coordinator)
	if err != nil {
		t.Fatal(err)
	}
	factory, err := pdfadmission.NewApplicationSessionFactoryV1(cfg, work, pdfadmission.ApplicationSessionDirectProfileV1)
	if err != nil {
		t.Fatal(err)
	}
	f.s.HTMLCreationSessions = factory
	htmlAuthoringNativeApplicationsE2E.Store(factory, applicationName)
	htmlAuthoringNativeSnapshotsE2E.Store(factory, func() workguard.SnapshotV1 { return coordinator.SnapshotV1(f.org) })
	t.Cleanup(func() {
		defer htmlAuthoringNativeApplicationsE2E.Delete(factory)
		defer htmlAuthoringNativeSnapshotsE2E.Delete(factory)
		// The public factory cannot self-observe its final control backend. Preserve
		// exactly one unresolved SQL grant per genuinely initialized organization.
		observers := factory.PendingV1().ObserverSessions
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		closeErr := factory.CloseV1(ctx)
		pending := factory.PendingV1()
		if pending.WorkSessions != 0 || pending.UnknownStarts != 0 || pending.HTMLAdmissions != 0 || pending.HTMLInputProducers != 0 || pending.HTMLCanonicalConsumers != 0 || pending.ObserverSessions != observers {
			t.Errorf("native HTML cleanup disposition wrong: %+v; original observers=%d", pending, observers)
		}
		if observers > 0 {
			if !errors.Is(closeErr, pdfadmission.ErrApplicationSessionUnknownV1) {
				t.Errorf("final observer retirement falsely resolved: %v", closeErr)
			}
		} else if closeErr != nil {
			t.Errorf("unused factory close: %v", closeErr)
		}
		snapshot := coordinator.SnapshotV1(f.org)
		expected := workguard.VectorV1{SQLSessions: int64(observers)}
		if snapshot.Global != expected || snapshot.GlobalGrants != int64(observers) {
			t.Errorf("observer debt was lost or body work leaked: %+v expected=%+v", snapshot, expected)
		}
		if snapshot.Organisation.ParentBytes != 0 || snapshot.Organisation.DBStagingBytes != 0 || snapshot.Organisation.ChildAddressBytes != 0 || snapshot.Organisation.PDFWorkers != 0 || snapshot.Organisation.ProviderStreams != 0 || snapshot.Organisation.RendererRequests != 0 || snapshot.Organisation.SQLSessions < 0 || snapshot.Organisation.SQLSessions > 1 || snapshot.OrganisationGrants != snapshot.Organisation.SQLSessions {
			t.Errorf("organization cleanup debt wrong: %+v", snapshot)
		}
		// Independent scoped backend absence is fixture evidence only. It supplies
		// no factory refund/retirement API or production process-generation proof.
		witness, witnessCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer witnessCancel()
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			var active int
			err := f.pool.QueryRow(witness, "SELECT count(*)::integer FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1", applicationName).Scan(&active) //nolint:rawsql -- unique synthetic factory backend witness
			if err != nil {
				t.Error("independent native backend witness:", err)
				break
			}
			if active == 0 {
				break
			}
			select {
			case <-ticker.C:
			case <-witness.Done():
				t.Errorf("native fixture backend still active: %d", active)
				return
			}
		}
		// Root's exact disposable DB/container teardown follows; unresolved observer
		// accounting is not force-closed or turned into a reusable in-process credit.
	})
}

// Test-only registry binds a native waiter to the SAME actual factory whose
// distinct application_name is configured above. It never substitutes a pool
// identity or supplies retirement/admission authority.
var htmlAuthoringNativeApplicationsE2E sync.Map

// Read-only diagnostics for this exact synthetic factory; never admission or
// retirement authority and never a substitute for the real coordinator.
var htmlAuthoringNativeSnapshotsE2E sync.Map

func htmlAuthoringNativeSnapshotE2E(t *testing.T, s *Server) workguard.SnapshotV1 {
	t.Helper()
	read, ok := htmlAuthoringNativeSnapshotsE2E.Load(s.HTMLCreationSessions)
	if !ok {
		t.Fatal("native HTML fixture has no coordinator diagnostic")
	}
	return read.(func() workguard.SnapshotV1)()
}

func htmlAuthoringNativeApplicationNameE2E(t *testing.T, s *Server) string {
	t.Helper()
	name, ok := htmlAuthoringNativeApplicationsE2E.Load(s.HTMLCreationSessions)
	if !ok {
		t.Fatal("native HTML fixture has no registered backend identity")
	}
	application, ok := name.(string)
	if !ok || application == "" {
		t.Fatal("native HTML fixture backend identity is invalid")
	}
	return application
}

func awaitHTMLAuthoringOperationLockE2E(t *testing.T, f lifecycleAuthorizationFixture, query, event string) {
	t.Helper()
	awaitSessionOperationLockE2E(t, f.ctx, f.pool, query, event, htmlAuthoringNativeApplicationNameE2E(t, f.s))
}

// Observe the exact configured native query queued behind this actual parent
// lock holder. With two writers the second can wait on a tuple queue behind the
// first; the explicit one-hop blocker chain still reaches the SAME held parent.
func awaitHTMLAuthoringTemplateParentWaitersE2E(t *testing.T, f lifecycleAuthorizationFixture, holderPID int32, want int) {
	t.Helper()
	application := htmlAuthoringNativeApplicationNameE2E(t, f.s)
	if holderPID <= 0 || (want != 1 && want != 2) {
		t.Fatal("invalid exact parent wait fixture")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var count int
		err := f.pool.QueryRow(f.ctx, `SELECT count(*)::integer FROM pg_stat_activity a
		 WHERE a.datname=current_database() AND a.application_name=$1 AND a.state='active'
		 AND a.wait_event_type='Lock' AND a.query LIKE '%-- name: GetHTMLAuthoringTemplateHeaderForUpdateV1%'
		 AND ($2=ANY(pg_blocking_pids(a.pid)) OR EXISTS(
		  SELECT 1 FROM unnest(pg_blocking_pids(a.pid)) AS blocked(pid)
		  WHERE $2=ANY(pg_blocking_pids(blocked.pid))))`, application, holderPID).Scan(&count) //nolint:rawsql -- exact native factory and actual test-held parent blocker
		if err != nil {
			t.Fatal(err)
		}
		if count == want {
			return
		}
		if count > want {
			t.Fatalf("unexpected native parent waiters=%d want=%d", count, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("actual native parent waiters did not reach %d", want)
}

// Always cancel and join the actual request goroutine before native cleanup
// assertions. Releasing its real test-held lock is failure cleanup only; this
// helper never closes consumers, retires sessions or refunds coordinator debt.
func joinHTMLAuthoringRequestE2E(t *testing.T, cancel context.CancelFunc, finished <-chan struct{}, locks ...pgx.Tx) bool {
	t.Helper()
	cancel()
	cleanup, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cleanupCancel()
	for _, tx := range locks {
		if tx != nil {
			_ = tx.Rollback(cleanup)
		}
	}
	select {
	case <-finished:
		return true
	case <-time.After(20 * time.Second):
		t.Error("actual HTML request goroutine did not join before fixture cleanup")
		return false
	}
}

func TestHTMLAuthoringFreshCachesReplayAndMissingCacheRefusalE2E(t *testing.T) {
	renderer := &htmlCreationRendererE2E{}
	f, _ := setupHTMLDocumentCreationE2E(t, renderer)
	template := createHTMLTemplateE2E(t, f)
	if observers := f.s.HTMLCreationSessions.PendingV1().ObserverSessions; observers != 1 {
		t.Fatalf("single-org fresh journey observers=%d", observers)
	}
	var templateOK, revisionOK bool
	oracleTemplate := "SELECT m.master_wire_bytes=octet_length(t.html_master_json::text)::bigint AND m.variables_wire_bytes=octet_length(t.variables_json::text)::bigint AND m.blocks_wire_bytes=0 AND m.fields_wire_bytes=octet_length(t.fields_json::text)::bigint, r.master_wire_bytes=octet_length(v.html_master_json::text)::bigint AND r.variables_wire_bytes=octet_length(v.variables_json::text)::bigint FROM templates t JOIN html_authoring_template_sizes_v1 m ON m.template_id=t.id JOIN html_template_revisions v ON v.template_id=t.id AND v.version=t.version JOIN html_authoring_revision_sizes_v1 r ON r.template_id=v.template_id AND r.version=v.version WHERE t.id=$1 AND t.org_id=$2"
	err := f.pool.QueryRow(f.ctx, oracleTemplate, template.ID, f.org).Scan(&templateOK, &revisionOK) //nolint:rawsql -- bounded synthetic writer output oracle
	if err != nil || !templateOK || !revisionOK {
		t.Fatalf("fresh same-transaction template caches missing/wrong: %v %v %v", templateOK, revisionOK, err)
	}
	approveHTMLCreationTemplateE2E(t, f, template)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	input := htmlCreationInputE2E(template)
	input.RequestID = uuid.New()
	created := submitHTMLDocumentCreationE2E(t, f, template.ID, input, cookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("fresh native creation=%d %s", created.Code, created.Body.String())
	}
	var original struct {
		Document documentResponse "json:\"document\""
		Replayed bool             "json:\"replayed\""
	}
	if err = json.Unmarshal(created.Body.Bytes(), &original); err != nil || original.Document.ID == uuid.Nil {
		t.Fatalf("native creation response invalid: %v", err)
	}
	doc, err := f.q.GetDocument(f.ctx, generated.GetDocumentParams{ID: original.Document.ID, OrgID: f.org})
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(toDocumentResponse(doc))
	if err != nil {
		t.Fatal(err)
	}
	var expected documentResponse
	if err = json.Unmarshal(expectedJSON, &expected); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(expected, original.Document) {
		t.Fatalf("fresh response changed public shape: actual=%+v expected=%+v", original.Document, expected)
	}
	replay := submitHTMLDocumentCreationE2E(t, f, template.ID, input, cookie)
	if replay.Code != http.StatusOK {
		t.Fatalf("admitted replay=%d %s", replay.Code, replay.Body.String())
	}
	var repeated struct {
		Document documentResponse "json:\"document\""
		Replayed bool             "json:\"replayed\""
	}
	if err = json.Unmarshal(replay.Body.Bytes(), &repeated); err != nil || !repeated.Replayed || !reflect.DeepEqual(original.Document, repeated.Document) {
		t.Fatalf("replay projection changed current response: %v", err)
	}
	var responseOK bool
	oracleResponse := "SELECT m.blocks_wire_bytes=COALESCE(octet_length(d.blocks_json::text)::bigint,0) AND m.metadata_wire_bytes=octet_length(d.metadata::text)::bigint AND p.variables_wire_bytes=octet_length(d.variables_json::text)::bigint FROM documents d JOIN html_creation_response_sizes_v1 m ON m.document_id=d.id JOIN document_signing_policy_sizes_v1 p ON p.document_id=d.id WHERE d.id=$1 AND d.org_id=$2"
	if err = f.pool.QueryRow(f.ctx, oracleResponse, doc.ID, f.org).Scan(&responseOK); err != nil || !responseOK {
		t.Fatalf("fresh response/policy caches wrong: %v %v", responseOK, err)
	} //nolint:rawsql -- bounded exact synthetic fresh output oracle
	// Losing a cheap cache is not permission to measure/expand an old row.
	if _, err = f.pool.Exec(f.ctx, "DELETE FROM html_creation_response_sizes_v1 WHERE document_id=$1 AND org_id=$2", doc.ID, f.org); err != nil {
		t.Fatal(err)
	} //nolint:rawsql -- cheap synthetic cache removal
	before := len(renderer.sources())
	refused := submitHTMLDocumentCreationE2E(t, f, template.ID, input, cookie)
	if refused.Code != http.StatusServiceUnavailable || len(renderer.sources()) != before {
		t.Fatalf("uncached replay must refuse before a new render: status=%d renders=%d/%d", refused.Code, len(renderer.sources()), before)
	}
	var count int
	if err = f.pool.QueryRow(f.ctx, "SELECT count(*)::integer FROM html_creation_response_sizes_v1 WHERE document_id=$1", doc.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("replay silently refreshed an old cache", err)
	} //nolint:rawsql -- exact cheap fixture cache assertion
}

// Reachable lock-order component regression on genuine fresh route/receipt
// rows. Parent-first locking is exercised without deleting retained history,
// disabling triggers, granting purge authority or mutating immutable pins.
func TestHTMLCreationReplayDoesNotLockRequestBeforeParentE2E(t *testing.T) {
	f, _ := setupHTMLDocumentCreationE2E(t, &htmlCreationRendererE2E{})
	template := createHTMLTemplateE2E(t, f)
	approveHTMLCreationTemplateE2E(t, f, template)
	cookie := dsrSessionCookieE2E(t, f.s, f.user.ID, f.user.SessionGeneration, time.Hour)
	input := htmlCreationInputE2E(template)
	input.RequestID = uuid.New()
	created := submitHTMLDocumentCreationE2E(t, f, template.ID, input, cookie)
	if created.Code != http.StatusCreated {
		t.Fatalf("fresh native creation=%d %s", created.Code, created.Body.String())
	}
	var original struct {
		Document documentResponse "json:\"document\""
	}
	if err := json.Unmarshal(created.Body.Bytes(), &original); err != nil || original.Document.ID == uuid.Nil {
		t.Fatalf("fresh response: %v", err)
	}
	parent, err := f.pool.BeginTx(f.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	var locked uuid.UUID
	if err = parent.QueryRow(f.ctx, "SELECT id FROM documents WHERE id=$1 AND org_id=$2 FOR UPDATE", original.Document.ID, f.org).Scan(&locked); err != nil {
		_ = parent.Rollback(f.ctx)
		t.Fatal(err)
	} //nolint:rawsql -- genuine fixed UUID parent lock, no source body
	parentPID := int32(parent.Conn().PgConn().PID())
	done := make(chan *httptest.ResponseRecorder, 1)
	joined := false
	go func() {
		done <- submitSessionOperationE2E(f.s, http.MethodGet, "/api/v1/templates/"+template.ID.String()+"/html/document-requests/"+input.RequestID.String(), "", cookie)
	}()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = parent.Rollback(cleanup)
		if !joined {
			select {
			case <-done:
			case <-cleanup.Done():
				t.Error("replay fixture caller did not join")
			}
		}
	}()
	wait, cancel := context.WithTimeout(f.ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		err = f.pool.QueryRow(wait, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database() AND a.wait_event_type='Lock' AND $1::integer=ANY(pg_blocking_pids(a.pid)) AND a.query LIKE '%html_creation_response_sizes_v1%')", parentPID).Scan(&blocked) //nolint:rawsql -- bounded independent exact-parent wait observation
		if err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ticker.C:
		case <-wait.Done():
			t.Fatal("real replay never reached the blocked document header")
		}
	}
	// Old request SHARE -> document SHARE blocks this reachable parent-first
	// reference lock. Original immutable MVCC pins let it succeed immediately.
	var request uuid.UUID
	if err = parent.QueryRow(f.ctx, "SELECT request_id FROM html_document_creation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3 FOR UPDATE NOWAIT", f.org, f.user.ID, input.RequestID).Scan(&request); err != nil || request != input.RequestID {
		t.Fatalf("replay inverted parent/request ordering: %v", err)
	} //nolint:rawsql -- fixed immutable receipt row lock only
	if err = parent.Rollback(f.ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case response := <-done:
		joined = true
		if response.Code != http.StatusOK {
			t.Fatalf("replay after parent release=%d %s", response.Code, response.Body.String())
		}
	case <-wait.Done():
		t.Fatal("replay did not complete after parent release")
	}
}
