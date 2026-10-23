// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"crypto/sha256"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// This is the existing explicitly synthetic SQL/session fixture, not genuine
// database authority or a live Object Lock claim. The actual source constructor,
// shared coordinator, provider loans and concrete first-party S3 SDK execute.
// The separate real ordinary journey qualifies MinIO retention and completion.
type historicalSourceRetentionPeerV1 struct {
	mu               sync.Mutex
	until            map[string]time.Time
	puts, gets       map[string]int
	objectCalls      int
	stale, wrongBody bool
	wrongVersion     bool
	payload          []byte
}

func (p *historicalSourceRetentionPeerV1) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.URL.Path == "/source-retention" || r.URL.Path == "/source-retention/" {
		w.Header().Set("Content-Type", "application/xml")
		switch {
		case r.URL.Query().Has("versioning"):
			_, _ = io.WriteString(w, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>Enabled</Status></VersioningConfiguration>`)
		case r.URL.Query().Has("object-lock"):
			_, _ = io.WriteString(w, `<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>`)
		default:
			w.WriteHeader(http.StatusOK)
		}
		return
	}
	p.objectCalls++
	key := strings.TrimPrefix(r.URL.Path, "/source-retention/")
	until, known := p.until[key]
	if !known || r.URL.Query().Get("versionId") != "version-one" {
		http.Error(w, "fixed synthetic object/version unavailable", http.StatusNotFound)
		return
	}
	if r.URL.Query().Has("retention") {
		w.Header().Set("Content-Type", "application/xml")
		if r.Method == http.MethodPut {
			var input struct {
				Mode  string    `xml:"Mode"`
				Until time.Time `xml:"RetainUntilDate"`
			}
			if xml.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&input) != nil || input.Mode != "COMPLIANCE" || input.Until.Before(until) {
				http.Error(w, "fixed synthetic retention refused", http.StatusBadRequest)
				return
			}
			p.puts[key]++
			if !p.stale {
				p.until[key] = input.Until
			}
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = fmt.Fprintf(w, `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>COMPLIANCE</Mode><RetainUntilDate>%s</RetainUntilDate></Retention>`, until.UTC().Format(time.RFC3339))
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(p.payload)))
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("ETag", `"fixed"`)
	w.Header().Set("Last-Modified", "Wed, 15 Oct 2025 00:00:00 GMT")
	version := "version-one"
	if p.wrongVersion {
		version = "different-version"
	}
	w.Header().Set("X-Amz-Version-Id", version)
	if r.Method == http.MethodGet {
		p.gets[key]++
		body := append([]byte(nil), p.payload...)
		if p.wrongBody {
			body[0] ^= 1
		}
		_, _ = w.Write(body)
	}
}

type historicalSourceNoExecutionRowV1 struct{}

func (historicalSourceNoExecutionRowV1) Scan(...any) error { return pgx.ErrNoRows }

func historicalSourceRetentionFixtureV1(t *testing.T, requires bool, change func(*generated.Document), consume func(context.Context, *ApplicationHistoricalFinalizationSourceEvidenceV1, *historicalSourceRetentionPeerV1, *workguard.CoordinatorV1, time.Time)) {
	t.Helper()
	fixture, session, coordinator := applicationRequestLoanFixtureV1(t)
	session.state.tx.(*applicationSessionTxTestV1).row = historicalSourceNoExecutionRowV1{}
	factory := &ApplicationSessionFactoryV1{state: session.state.factory}
	factory.state.htmlAdmissions = make(map[*ApplicationAdmissionV1]*applicationHTMLAdmissionRegistrationV1)
	ctx := applicationTestContextV1(t)
	operation, err := factory.NewHTMLSendOperationV1(ctx, fixture.scope.OrgID, fixture.scope.DocumentID)
	if err != nil {
		t.Fatal(err)
	}
	stage := &ApplicationHTMLSendSQLStageV1{operation: operation, purpose: HTMLHistoricalFinalizationSourceV1, ctx: ctx, cancel: func() {}, session: session, active: true}
	stage.self = stage
	operation.stages = append(operation.stages, stage)
	now := time.Date(2026, 10, 23, 12, 0, 1, 0, time.UTC)
	target := storage.EvidenceRetentionDeadline(now, 7)
	payload := []byte("synthetic original source retention protocol body")
	sum := sha256.Sum256(payload)
	peer := &historicalSourceRetentionPeerV1{until: map[string]time.Time{"original.pdf": target.Add(-time.Second), "rendered.pdf": target.Add(-time.Second), "manual.png": target.Add(-time.Second)}, puts: make(map[string]int), gets: make(map[string]int), payload: payload}
	server := httptest.NewServer(peer)
	t.Cleanup(server.Close)
	client, err := storage.New(ctx, storage.Config{Endpoint: strings.TrimPrefix(server.URL, "http://"), Region: "us-east-1", Bucket: "source-retention", AccessKey: "synthetic", SecretKey: "synthetic-secret", BucketLookup: "path", RequireExistingBucket: true, RequireObjectLock: true, AllowInsecureDevelopmentEndpoint: true, SkipTransientLifecycle: true})
	if err != nil {
		t.Fatal(err)
	}
	var work *ApplicationHTMLSendWorkV1
	var source *ApplicationHistoricalFinalizationSourceEvidenceV1
	t.Cleanup(func() {
		if source != nil {
			source.CloseConsumerV1()
		}
		if work != nil {
			work.CloseConsumerV1()
		}
		if !applicationDoneV1(fixture.done) {
			close(fixture.done)
		}
		cleanup, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		_ = fixture.adapter.CloseV1(cleanup)
	})
	err = session.WithTxV1(ctx, func(call context.Context, _ generated.DBTX) error {
		var err error
		work, err = session.NewHTMLSendWorkV1(call, stage)
		if err != nil {
			return err
		}
		// Fixed small synthetic row set is paid before being installed; no SQL
		// row or user authority is claimed by this private regression fixture.
		raw := int64(8192) + 4*int64(unsafe.Sizeof(generated.Document{})) + 2*int64(unsafe.Sizeof(generated.Signature{}))
		closeRows, err := work.actor.acquireOwnedRetainedBodyV1(call, raw, raw)
		if err != nil {
			return err
		}
		work.closes = append(work.closes, closeRows)
		stamp := pgtype.Timestamptz{Time: now, Valid: true}
		doc := &generated.Document{ID: fixture.scope.DocumentID, OrgID: fixture.scope.OrgID, Status: "finalizing", SourceKind: "pdf", RequiresSignature: requires, EvidenceVersionPinsRequired: true, UpdatedAt: stamp, CompletionEffectiveAt: stamp, CompletionEffectiveAtBound: true, FinalizationRetainUntil: pgtype.Timestamptz{Time: target, Valid: true}, PdfStorageKey: pgtype.Text{String: "original.pdf", Valid: true}, PdfStorageVersionID: pgtype.Text{String: "version-one", Valid: true}, PdfSha256: sum[:], RenderedPdfKey: pgtype.Text{String: "rendered.pdf", Valid: true}, RenderedPdfVersionID: pgtype.Text{String: "version-one", Valid: true}, RenderedPdfSha: sum[:]}
		if change != nil {
			change(doc)
		}
		work.state = &generated.GetHTMLSendDocumentStateHeaderV1Row{ID: doc.ID, OrgID: doc.OrgID, BoundedStatus: doc.Status, RequiresSignature: requires, EvidenceVersionPinsRequired: true, UpdatedAt: stamp}
		work.sourceDocument = doc
		work.models = &HTMLSendModelsV1{Document: doc}
		work.finalization = &applicationHistoricalFinalizationV1{signatureRead: true}
		if requires {
			work.finalization.signatures = []*generated.Signature{{ID: uuid.New(), DocumentID: doc.ID, SignatureKind: "manual", ImageStorageKey: "manual.png", ImageVersionID: pgtype.Text{String: "version-one", Valid: true}, ImageVersionPinRequired: true, ImageSha256: sum[:]}}
		}
		source, err = work.NewHistoricalFinalizationSourceEvidenceV1(call, client)
		if err != nil {
			return err
		}
		consume(call, source, peer, coordinator, target)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHistoricalOrdinarySourceRetentionExtendsExactVersionsAndAcknowledgementsV1(t *testing.T) {
	for _, scenario := range []struct {
		name               string
		requires, rendered bool
		change             func(*generated.Document)
	}{{"signature", true, true, nil}, {"acknowledgement", false, true, nil}, {"original-only", false, false, func(d *generated.Document) {
		d.RenderedPdfKey = pgtype.Text{}
		d.RenderedPdfVersionID = pgtype.Text{}
		d.RenderedPdfSha = nil
	}}, {"same-exact-version", false, false, func(d *generated.Document) {
		d.RenderedPdfKey = d.PdfStorageKey
		d.RenderedPdfVersionID = d.PdfStorageVersionID
		d.RenderedPdfSha = d.PdfSha256
	}}} {
		t.Run(scenario.name, func(t *testing.T) {
			historicalSourceRetentionFixtureV1(t, scenario.requires, scenario.change, func(call context.Context, source *ApplicationHistoricalFinalizationSourceEvidenceV1, peer *historicalSourceRetentionPeerV1, c *workguard.CoordinatorV1, target time.Time) {
				before := c.SnapshotV1(source.document.OrgID)
				if err := source.retainPrivateSignaturesV1(call, target); err != nil {
					t.Fatal(err)
				}
				if c.SnapshotV1(source.document.OrgID) != before {
					t.Fatal("original source provider/body loans did not drain")
				}
				peer.mu.Lock()
				defer peer.mu.Unlock()
				keys := []string{"original.pdf"}
				if scenario.rendered {
					keys = append(keys, "rendered.pdf")
				} else if peer.puts["rendered.pdf"] != 0 || peer.gets["rendered.pdf"] != 0 {
					t.Fatal("absent or already-selected rendered source issued duplicate provider work")
				}
				for _, key := range keys {
					if !peer.until[key].Equal(target) || peer.puts[key] != 1 || peer.gets[key] == 0 {
						t.Fatal("source version was not extended and verified through exact completion deadline")
					}
				}
				if scenario.requires && (!peer.until["manual.png"].Equal(target) || peer.puts["manual.png"] != 1) {
					t.Fatal("ordinary source extension displaced existing signature image retention")
				}
				if !scenario.requires && (peer.puts["manual.png"] != 0 || peer.gets["manual.png"] != 0) {
					t.Fatal("acknowledgement fabricated a signature image")
				}
			})
		})
	}
}

func TestHistoricalOrdinarySourceRetentionRefusesPartialPinsBeforeProviderV1(t *testing.T) {
	for name, change := range map[string]func(*generated.Document){
		"missing original": func(d *generated.Document) {
			d.PdfStorageKey = pgtype.Text{}
			d.PdfStorageVersionID = pgtype.Text{}
			d.PdfSha256 = nil
		},
		"missing version":  func(d *generated.Document) { d.PdfStorageVersionID = pgtype.Text{} },
		"invalid digest":   func(d *generated.Document) { d.PdfSha256 = d.PdfSha256[:31] },
		"partial rendered": func(d *generated.Document) { d.RenderedPdfKey.Valid = false },
		"unpinned legacy":  func(d *generated.Document) { d.EvidenceVersionPinsRequired = false },
		"conflicting same version": func(d *generated.Document) {
			d.RenderedPdfKey = d.PdfStorageKey
			d.RenderedPdfSha = append([]byte(nil), d.PdfSha256...)
			d.RenderedPdfSha[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			historicalSourceRetentionFixtureV1(t, false, change, func(call context.Context, source *ApplicationHistoricalFinalizationSourceEvidenceV1, peer *historicalSourceRetentionPeerV1, _ *workguard.CoordinatorV1, target time.Time) {
				if err := source.retainPrivateSignaturesV1(call, target); err == nil {
					t.Fatal("invalid native source pin accepted")
				}
				peer.mu.Lock()
				defer peer.mu.Unlock()
				if peer.objectCalls != 0 {
					t.Fatal("incomplete source cohort performed provider work")
				}
			})
		})
	}
}

func TestHistoricalOrdinarySourceRetentionRequiresProviderReadbackAndSharedCapacityV1(t *testing.T) {
	for _, mode := range []string{"stale-retention", "wrong-body", "wrong-version", "occupied-provider", "fitted"} {
		t.Run(mode, func(t *testing.T) {
			historicalSourceRetentionFixtureV1(t, true, nil, func(call context.Context, source *ApplicationHistoricalFinalizationSourceEvidenceV1, peer *historicalSourceRetentionPeerV1, c *workguard.CoordinatorV1, target time.Time) {
				peer.mu.Lock()
				peer.stale = mode == "stale-retention"
				peer.wrongBody = mode == "wrong-body"
				peer.wrongVersion = mode == "wrong-version"
				peer.mu.Unlock()
				if mode == "fitted" {
					source.work.finalization.signatures[0].SignatureKind = "manual_pdf_fit_v1"
				}
				if mode == "occupied-provider" {
					g, err := c.TryAcquireV1(call, source.document.OrgID, workguard.VectorV1{ProviderStreams: 1})
					if err != nil {
						t.Fatal(err)
					}
					defer g.Close()
				}
				before := c.SnapshotV1(source.document.OrgID)
				if err := source.retainPrivateSignaturesV1(call, target); err == nil {
					t.Fatal("unproved retention/body/version or denied lane became success")
				}
				if c.SnapshotV1(source.document.OrgID) != before {
					t.Fatal("failed source retention changed held coordinator debt")
				}
				peer.mu.Lock()
				defer peer.mu.Unlock()
				if (mode == "occupied-provider" || mode == "fitted") && peer.objectCalls != 0 {
					t.Fatal("refused resource/mode performed provider calls")
				}
			})
		})
	}
}
