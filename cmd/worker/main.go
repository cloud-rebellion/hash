// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

// Package main runs background workers: webhook re-drives, reminder fires,
// expiration sweeps, email delivery, and compliance/retention jobs. Independent
// loops run on different cadences. Each
// loop logs but never panics; transient errors trigger a retry on the next
// tick.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/branding"
	"github.com/bright-interaction/hash/internal/compliance"
	"github.com/bright-interaction/hash/internal/config"
	mdb "github.com/bright-interaction/hash/internal/db"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/eidas"
	"github.com/bright-interaction/hash/internal/envelopes"
	"github.com/bright-interaction/hash/internal/flarereport"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/sanitize"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/sign"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/webhooksecret"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
)

// Invites and other transactional mail are user-facing, synchronous workflow
// outcomes even though delivery is durably queued. A 20-second poll made a
// freshly-sent document appear to have lost its invitation for most of that
// window. One query per second keeps delivery near-real-time without coupling
// request handlers to SMTP availability.
const emailDispatchPollInterval = time.Second

// runWorker supervises one critical loop. A panic or unexpected return makes
// the process unhealthy immediately so Compose/systemd can restart all loops;
// keeping the process alive after (for example) expiration or finalize-retry
// died would present a dangerously false healthy state.
func runWorker(ctx context.Context, name string, fn func()) {
	superviseWorker(ctx, name, fn, flarereport.CaptureWorkerFatal, os.Exit)
}

// optionalWorkerConfigured gates optional loops before their goroutine is
// launched. Once configured, they use the same fail-fast supervisor as every
// critical loop.
func optionalWorkerConfigured(name string, configured bool) bool {
	if !configured {
		slog.Info("optional worker loop disabled by configuration", "loop", name)
		return false
	}
	return true
}

// superviseWorker accepts its synchronous reporter and terminator as
// dependencies so report-before-exit behavior can be tested without network
// access or exiting the test process.
func superviseWorker(ctx context.Context, name string, fn func(), reportFatal func(string, bool), terminate func(int)) {
	defer func() {
		if recover() != nil {
			// Do not log the recovered value: warn/error logs are exported to a
			// shared observability boundary and panic payloads are arbitrary data.
			slog.Error("worker loop panicked", "loop", name)
			reportFatal(name, true)
			terminate(1)
		}
	}()
	fn()
	if ctx.Err() != nil {
		slog.Info("worker loop stopped", "loop", name, "reason", ctx.Err())
		return
	}
	slog.Error("worker loop exited unexpectedly", "loop", name)
	reportFatal(name, false)
	terminate(1)
}

func initWorkerObservability(ctx context.Context, ready <-chan struct{}, release, environment string) *flarereport.Lifecycle {
	return flarereport.InitFlareWithContext(ctx, ready, "hash-worker", release, environment)
}
func main() { os.Exit(runWorkerMain()) }
func runWorkerMain() (exitCode int) {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("config load", "err", err)
		return 1
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	})))
	// The worker is the sole SMTP sender and owns every background lifecycle
	// loop. Give it a distinct heartbeat/log identity so silence or a crash loop
	// cannot be mistaken for a healthy HTTP server. An absent/invalid DSN remains
	// a fail-safe no-op and never blocks local or self-hosted startup.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	telemetryReady := make(chan struct{})
	telemetry := initWorkerObservability(ctx, telemetryReady, cfg.Release, cfg.Environment)
	defer func() {
		if exitCode != 0 {
			flarereport.CaptureOperationFailure(context.Background(), flarereport.OperationWorker, flarereport.FailureUnavailable)
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := telemetry.Close(cleanup); err != nil {
			slog.Warn("telemetry shutdown incomplete", "category", "deadline")
		}
	}()
	if err := sanitize.ConfigurePDFWorkerWithObserverV1(ctx, os.Getenv("HASH_PDF_WORKER"), cfg.Environment, flarereport.PDFWorkerObserverV1(ctx)); err != nil {
		slog.Error("PDF worker unavailable")
		return 1
	}

	pool, err := pgxpool.New(ctx, cfg.DBURL)
	if err != nil {
		slog.Error("pool", "err", err)
		return 1
	}
	defer pool.Close()

	// Run migrations from the worker too so a fresh deploy boots cleanly
	// even if the server hasn't started yet.
	if err := runMigrations(ctx, cfg.DBURL); err != nil {
		slog.Error("migrations", "err", err)
		return 1
	}
	// This worker has one separately assigned process allocation. Reuse its
	// exact runtime for every sign engine; never borrow the HTTP process budget.
	var workRuntime *pdfadmission.WorkRuntimeV1
	if cfg.WorkRuntime != nil {
		workRuntime, err = pdfadmission.NewWorkRuntimeV1(pool, cfg.WorkRuntime.Limits, cfg.WorkRuntime.TotalDBConnections)
		if err != nil {
			slog.Error("configured process work runtime unavailable")
			return 1
		}
		defer func() {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelCleanup()
			if err := workRuntime.CloseV1(cleanupCtx); err != nil {
				// Cancellation of loops is not whole-process/controller retirement.
				slog.Warn("process work cleanup remains unresolved")
			}
		}()
	}
	queries := generated.New(pool)
	webhookKeys, err := webhooksecret.NewKeyringHex(
		cfg.WebhookEncryptionKey, cfg.WebhookEncryptionKeyPrevious,
	)
	if err != nil {
		slog.Error("webhook encryption keyring", "err", err)
		return 1
	}
	webhookSecrets, err := webhooksecret.NewManager(pool, webhookKeys, cfg.WebhookSecret)
	if err != nil {
		slog.Error("webhook secret manager", "err", err)
		return 1
	}
	webhookBackfill, err := webhookSecrets.Backfill(ctx)
	if err != nil {
		slog.Error("webhook secret backfill", "err", err)
		return 1
	}
	slog.Info("webhook secrets verified at rest",
		"rows", webhookBackfill.Rows,
		"encrypted_legacy", webhookBackfill.EncryptedLegacy,
		"rewrapped_previous_key", webhookBackfill.RewrappedPreviousKey,
		"cleared_plaintext", webhookBackfill.ClearedPlaintext,
	)
	auditLog := audit.New(queries, pool)
	// Worker-emitted events (document.expired, reminder.sent) must fan out to
	// customer webhooks too; previously only the server registered this hook,
	// so those events never reached subscribers.
	dispatch.RegisterWebhookFanout(auditLog, queries)

	mailer, err := dispatch.NewSMTPMailer(dispatch.SMTPConfig{
		Host: cfg.SMTPHost, Port: cfg.SMTPPort, User: cfg.SMTPUser,
		Password: cfg.SMTPPassword, From: cfg.SMTPFrom,
	})
	if err != nil {
		slog.Error("smtp init", "err", err)
		return 1
	}

	// Engines + direct sends enqueue into email_deliveries (durable); only the
	// email-dispatch loop below talks to SMTP, so a transient outage retries
	// instead of dropping the message. `mailer` above is the real SMTP sender,
	// reused by that loop.
	queueMailer := dispatch.QueueingMailer{Q: queries}

	// Endpoint secrets are resolved and authenticated by webhookSecrets. Keep the
	// dispatcher's legacy instance fallback empty so no future call can silently
	// bypass a failed ciphertext authentication.
	dispatcher := dispatch.NewDispatcher(dispatch.SignaturePair{})
	dispatcher.AllowPrivate = config.IsLocalDevelopment(cfg.PublicURL)

	// Phase 12.2: optional EDPB feed + flagger. Empty endpoint disables
	// the rollup loop entirely (it short-circuits with a single info log).
	var feed compliance.Feed
	if cfg.ComplianceFeedURL != "" {
		feed = compliance.NewHTTPFeed(cfg.ComplianceFeedURL, config.IsLocalDevelopment(cfg.PublicURL))
	}

	// Signing engine for the finalize-retry loop. Mirrors the server's wiring
	// (storage + Gotenberg + cert signer + branding/envelope callbacks) so a
	// worker-driven finalize produces a byte-identical final PDF + audit cert
	// to the inline path. CRITICAL: the worker must read the SAME
	// HASH_AUDIT_PRIVATE_KEY as the server, else retry-finalized certs would
	// be signed by a different ed25519 key.
	var signEngine *sign.Engine
	store, serr := storage.New(ctx, storage.Config{
		Endpoint:                         cfg.S3Endpoint,
		Region:                           cfg.S3Region,
		Bucket:                           cfg.S3Bucket,
		AccessKey:                        cfg.S3AccessKey,
		SecretKey:                        cfg.S3SecretKey,
		UseSSL:                           cfg.S3UseSSL,
		SSEMode:                          cfg.S3SSEMode,
		SSECKeyFile:                      cfg.S3SSECKeyFile,
		SSECKeySHA256:                    cfg.S3SSECKeySHA256,
		BucketLookup:                     cfg.S3BucketLookup,
		RequireObjectLock:                !config.IsLocalDevelopment(cfg.PublicURL),
		RequireExistingBucket:            !config.IsLocalDevelopment(cfg.PublicURL),
		SkipTransientLifecycle:           cfg.Environment != "development",
		AllowInsecureDevelopmentEndpoint: cfg.Environment == "development" && config.IsLocalDevelopment(cfg.PublicURL),
	})
	if serr != nil {
		slog.Error("worker: storage init failed", "err", serr)
		return 1
	}
	signer, kerr := sign.NewCertSigner(cfg.AuditPrivateKey)
	if kerr != nil || signer == nil {
		slog.Error("worker: audit cert signer init failed", "err", kerr)
		return 1
	}
	brandingResolver := branding.NewResolver(queries)
	pdfClient, pdfConfigErr := render.NewGotenbergWithSignatureFitToken(cfg.GotenbergURL, cfg.GotenbergSignatureFitToken)
	if pdfConfigErr != nil {
		slog.Error("worker: private signature renderer configuration invalid")
		return 1
	}
	envelopesEngine := envelopes.New(queries)
	signEngine = &sign.Engine{
		Pool:        pool,
		WorkRuntime: workRuntime,
		Queries:     queries,
		Storage:     store,
		PDF:         pdfClient,
		Audit:       auditLog,
		Mailer:      queueMailer,
		Signer:      signer,
		OrgName:     cfg.OperatorName,
		BaseURL:     cfg.PublicURL,
		BrandingCSS: func(ctx context.Context, doc *generated.Document) (string, error) {
			if doc == nil {
				return branding.DefaultBranding().CSSVariables(), nil
			}
			b, err := brandingResolver.ResolveFrozen(ctx, doc.ID)
			if err != nil {
				return "", err
			}
			return b.CSSVariables(), nil
		},
		EnvelopeManifestHTML: func(ctx context.Context, doc *generated.Document) string {
			if doc == nil || !doc.IsEnvelope {
				return ""
			}
			m, err := envelopesEngine.BuildManifest(ctx, doc)
			if err != nil {
				return ""
			}
			return m.HTMLSection()
		},
		EnvelopeChildren: func(ctx context.Context, doc *generated.Document) ([]*generated.Document, error) {
			if doc == nil || !doc.IsEnvelope {
				return nil, nil
			}
			return envelopesEngine.Children(ctx, doc.ID, doc.OrgID)
		},
	}

	if workRuntime != nil {
		if err := signEngine.InitializeWorkRuntimeV1(); err != nil {
			slog.Error("configured signing work runtime unavailable")
			return 1
		}
		defer func() {
			cleanupCtx, cancelCleanup := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelCleanup()
			if err := signEngine.CloseWorkRuntimeRequestsV1(cleanupCtx); err != nil {
				slog.Warn("signing request cleanup remains unresolved")
			}
		}()
	}

	var billingEngine *billing.Engine
	switch {
	case cfg.BillingProvider == "operator":
		billingEngine = billing.NewOperator(queries, cfg.OperatorEntitlements)
		if err := billingEngine.ValidateOperatorPlans(ctx); err != nil {
			slog.Error("operator entitlement validation", "err", err)
			return 1
		}
	case cfg.BillingProvider == "mollie":
		billingEngine = billing.New(queries, billing.NewMollieProvider(cfg.MollieAPIKey, cfg.MollieBaseURL, cfg.MollieWebhookPathSecret), cfg.PublicURL, cfg.PublicURL+"/webhooks/billing/"+cfg.MollieWebhookPathSecret)
	case config.IsLocalDevelopment(cfg.PublicURL):
		billingEngine = billing.New(queries, billing.MockProvider{}, cfg.PublicURL, "")
	}
	if billingEngine == nil {
		slog.Error("billing: worker entitlement engine unavailable")
		return 1
	}

	// Lifecycle engine for reminders and durable send-sealing recovery. Draft
	// preparation (resolver/billing) has already completed before the sealing
	// intent commits; recovery rechecks the frozen envelope/eIDAS/source state,
	// applies retention idempotently, then atomically mints links/outbox/audit.
	sendEngine := &send.Engine{
		WorkRuntime: workRuntime,
		Billing:     billingEngine,
		Pool:        pool,
		Queries:     queries,
		Audit:       auditLog,
		Mailer:      queueMailer,
		EIDAS:       eidas.New(queries),
		Envelopes:   envelopesEngine,
		Storage:     store,
		PublicURL:   cfg.PublicURL,
		OrgName:     cfg.OperatorName,
		Environment: cfg.Environment,
	}

	w := &worker{
		telemetry:         telemetry,
		billing:           billingEngine,
		pool:              pool,
		queries:           queries,
		audit:             auditLog,
		mailer:            queueMailer,
		emailSender:       mailer,
		dispatcher:        dispatcher,
		webhookSecrets:    webhookSecrets,
		signEngine:        signEngine,
		storage:           store,
		sendEngine:        sendEngine,
		baseURL:           cfg.PublicURL,
		orgName:           cfg.OperatorName,
		complianceFeed:    feed,
		complianceFlagger: compliance.NewFlagger(queries),
	}

	// Independent loops use different cadences so a slow database query in one
	// loop doesn't starve another. Each configured loop runs under fatal
	// supervision so a panic or unexpected return lets the process supervisor
	// restart the complete worker.
	go runWorker(ctx, "reminders", func() { w.loopReminders(ctx) })
	go runWorker(ctx, "expirations", func() { w.loopExpirations(ctx) })
	go runWorker(ctx, "webhook_redrive", func() { w.loopWebhookRedrive(ctx) })
	go runWorker(ctx, "email_dispatch", func() { w.loopEmailDispatch(ctx) })
	// Reuse the existing serial rollup owner for the bounded backlog read.
	// Join this owner before the earlier deferred pool.Close can run.
	telemetryRollupDone := make(chan struct{})
	go func() {
		defer close(telemetryRollupDone)
		runWorker(ctx, "telemetry_rollup", func() { w.loopTelemetryRollup(ctx) })
	}()
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-telemetryRollupDone:
		case <-cleanup.Done():
			slog.Warn("telemetry rollup observer shutdown incomplete", "category", "deadline")
			exitCode = 1
		}
	}()
	if optionalWorkerConfigured("compliance_rollup", w.complianceFlagger != nil && w.complianceFeed != nil) {
		go runWorker(ctx, "compliance_rollup", func() { w.loopComplianceRollup(ctx) })
	}
	go runWorker(ctx, "quota_warnings", func() { w.loopQuotaWarnings(ctx) })
	go runWorker(ctx, "soft_delete_purge", func() { w.loopSoftDeletePurge(ctx) })
	go runWorker(ctx, "collab_archive_purge", func() { w.loopCollabArchivePurge(ctx) })
	go runWorker(ctx, "finalize_retry", func() { w.loopFinalizeRetry(ctx) })
	go runWorker(ctx, "send_sealing", func() { w.loopSendSealing(ctx) })

	close(telemetryReady)
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	slog.Info("hash worker started")
	<-stop
	slog.Info("worker shutting down")
	// Mark loop returns as expected before deferred resource cleanup begins.
	// In particular, pool.Close must not race a still-live supervision context
	// and turn a graceful SIGTERM into exit status 1.
	cancel()
	return 0
}

// loopSendSealing closes the S3/SQL crash window in Send. Any process exit or
// commit failure after a document enters non-editable `sealing` is recovered
// from the durable intent; a post-retention failure can never fall back to an
// ordinary deletable draft.
func (w *worker) loopSendSealing(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	w.runSendSealingOnce(ctx)
	w.runPackageSendRecoveryOnceV1(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runSendSealingOnce(ctx)
			w.runPackageSendRecoveryOnceV1(ctx)
		}
	}
}

func (w *worker) runSendSealingOnce(ctx context.Context) {
	started := time.Now()
	state := w.runSendSealingOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobSendSealing, started, state)
}
func (w *worker) runSendSealingOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	if w.sendEngine == nil {
		slog.Warn("send_sealing: lifecycle engine unavailable")
		return flarereport.InvocationUnavailable
	}
	if w.sendEngine.WorkRuntime == nil || !w.sendEngine.WorkRuntime.MatchesPoolV1(w.pool) {
		slog.Warn("send_sealing: configured native runtime unavailable")
		return flarereport.InvocationUnavailable
	}
	scanCtx, scanCancel := context.WithTimeout(ctx, 2*time.Minute)
	scan, err := w.sendEngine.WorkRuntime.SessionsV1().ScanPendingHTMLSendRecoveryScopesV1(scanCtx)
	scanCancel()
	if scan != nil {
		defer scan.CloseConsumerV1()
	}
	if err != nil {
		slog.Warn("send_sealing: list intents", "err", err)
		return flarereport.InvocationUnavailable
	}
	intents, err := scan.ScopesV1()
	if err != nil {
		slog.Warn("send_sealing: list intents", "err", err)
		return flarereport.InvocationUnavailable
	}
	state := flarereport.InvocationReturned
	for _, intent := range intents {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		result, err := w.sendEngine.ResumeSendSealing(rctx, intent.DocumentID, intent.OrgID)
		if err != nil {
			state = flarereport.InvocationPartial
			slog.Warn("send_sealing: resume failed", "document_id", intent.DocumentID, "err", err)
		}
		if err == nil && result.Status == "sealing" {
			state = mergeWorkerInvocation385(state, flarereport.InvocationPending)
		}
		result.CloseConsumerV1()
		cancel()
	}
	return state
}

type worker struct {
	telemetry *flarereport.Lifecycle // existing joined process owner; job calls never perform network I/O
	// Position only, owned by the same serial Send-recovery loop. A restart
	// starts a new pass; no cursor grants replay or claims a job completed.
	packageSendRecoveryCursor pdfadmission.PackageSendRecoveryCursorV1
	pool                      *pgxpool.Pool
	queries                   *generated.Queries
	audit                     *audit.Logger
	mailer                    dispatch.Mailer // queue-backed: enqueues into email_deliveries
	emailSender               dispatch.Mailer // real SMTP, used only by loopEmailDispatch
	emailDrainFailed          bool            // owned exclusively by the email dispatch loop
	dispatcher                *dispatch.Dispatcher
	webhookSecrets            *webhooksecret.Manager
	// signEngine drives the finalize-retry loop. nil when storage init failed
	// at boot, in which case the loop short-circuits.
	signEngine *sign.Engine
	// storage is shared with signEngine and used by the soft-delete purge to
	// remove document-owned source PDFs before their DB rows are hard-deleted.
	// nil when object-storage initialization failed; purge then retains any row
	// that still needs object cleanup for a later retry.
	storage purgeObjectDeleter
	// sendEngine drives reminder re-minting through the shared lifecycle engine
	// so worker-minted links always carry an expiry.
	sendEngine *send.Engine
	baseURL    string
	billing    *billing.Engine
	orgName    string

	// Phase 12.2: nil when HASH_COMPLIANCE_FEED_URL is unset, so
	// the compliance rollup loop short-circuits with a single info log.
	complianceFeed    compliance.Feed
	complianceFlagger *compliance.Flagger
}

// loopReminders fires reminder emails on the schedule_json cadence.
func (w *worker) loopReminders(ctx context.Context) {
	tick := time.NewTicker(60 * time.Minute)
	defer tick.Stop()
	w.runRemindersOnce(ctx) // run immediately on boot too
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runRemindersOnce(ctx)
		}
	}
}

func (w *worker) runRemindersOnce(ctx context.Context) {
	started := time.Now()
	state := w.runRemindersOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobReminders, started, state)
}
func (w *worker) runRemindersOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	due, err := w.queries.GetDueReminders(ctx, 100)
	if err != nil {
		slog.Warn("reminders: get due", "err", err)
		return flarereport.InvocationUnavailable
	}
	state := flarereport.InvocationReturned
	for _, rem := range due {
		state = mergeWorkerInvocation385(state, w.fireReminderObserved(ctx, rem))
	}
	return state
}
func (w *worker) fireReminder(ctx context.Context, rem *generated.Reminder) {
	w.fireReminderObserved(ctx, rem)
}
func (w *worker) fireReminderObserved(ctx context.Context, rem *generated.Reminder) flarereport.JobInvocationState {
	doc, err := w.queries.GetDocumentByID(ctx, rem.DocumentID)
	if err != nil {
		slog.Warn("reminders: load document", "doc_id", rem.DocumentID, "err", err)
		return flarereport.InvocationPartial
	}
	if doc.Status != "sent" && doc.Status != "in_progress" {
		// Cancel: doc moved out of the remindable window.
		if err := w.queries.CancelReminder(ctx, rem.DocumentID); err != nil {
			return flarereport.InvocationPartial
		}
		return flarereport.InvocationReturned
	}

	if !doc.SentAt.Valid {
		slog.Warn("reminders: sent document has no send timestamp", "document_id", doc.ID)
		return flarereport.InvocationPartial
	}

	// Route the mint + email + audit through the shared lifecycle engine so the
	// reminder link always carries an expiry. The raw UPDATE this replaced left
	// magic_token_expires_at NULL, so worker-minted reminder links never
	// expired (and re-mints of post-expiry links would otherwise be born dead).
	sender, err := w.queries.GetUser(ctx, doc.SenderID)
	if err != nil {
		slog.Warn("reminders: load negotiation owner failed", "document_id", doc.ID, "err", err)
		return flarereport.InvocationPartial
	}
	if sender == nil || sender.ID != doc.SenderID || sender.OrgID != doc.OrgID || sender.Email == "" {
		slog.Warn("reminders: negotiation owner identity unavailable", "document_id", doc.ID)
		return flarereport.InvocationPartial
	}
	if w.sendEngine == nil {
		slog.Warn("reminders: lifecycle engine unavailable", "document_id", doc.ID)
		return flarereport.InvocationPartial
	}
	if _, rerr := w.sendEngine.Remind(ctx, send.Actor{
		OrgID: doc.OrgID, Email: sender.Email, Via: "worker",
	}, doc.ID, true); rerr != nil {
		slog.Warn("reminders: engine remind failed", "document_id", doc.ID, "err", rerr)
		// Leave the schedule due. A later worker tick retries token rotation,
		// outbox persistence, and audit as one transaction.
		return flarereport.InvocationPartial
	}

	return flarereport.InvocationReturned
}

// loopExpirations transitions sent / in_progress documents past expires_at.
func (w *worker) loopExpirations(ctx context.Context) {
	tick := time.NewTicker(60 * time.Minute)
	defer tick.Stop()
	w.runExpirationsOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runExpirationsOnce(ctx)
		}
	}
}

func (w *worker) runExpirationsOnce(ctx context.Context) {
	started := time.Now()
	state := w.runExpirationsOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobExpirations, started, state)
}
func (w *worker) runExpirationsOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	docs, err := w.queries.GetExpirableDocuments(ctx, 100)
	if err != nil {
		slog.Warn("expirations: list", "err", err)
		return flarereport.InvocationUnavailable
	}
	state := flarereport.InvocationReturned
	for _, d := range docs {
		transitioned, err := w.expireDocument(ctx, d)
		if err != nil {
			state = flarereport.InvocationPartial
			slog.Warn("expirations: transition failed", "document_id", d.ID, "err", err)
			continue
		}
		if !transitioned {
			continue
		}
	}
	return state
}

// expireDocument delegates to the shared lifecycle engine so envelope wrappers
// and children expire atomically under the same parent-first lock order used by
// send, void, topology changes, and finalize.
func (w *worker) expireDocument(ctx context.Context, candidate *generated.Document) (bool, error) {
	if w.sendEngine == nil {
		return false, errors.New("expiration lifecycle engine unavailable")
	}
	return w.sendEngine.Expire(ctx, candidate)
}

// expireDocument delegates to the shared lifecycle engine so envelope wrappers
// and children expire atomically under the same parent-first lock order used by
// send, void, topology changes, and finalize.

// loopWebhookRedrive ships pending + retrying deliveries until success or
// the backoff schedule is exhausted.
func (w *worker) loopWebhookRedrive(ctx context.Context) {
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	w.runWebhookRedriveOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runWebhookRedriveOnce(ctx)
		}
	}
}

func (w *worker) runWebhookRedriveOnce(ctx context.Context) {
	started := time.Now()
	state := w.runWebhookRedriveOnceObserved(ctx)
	w.reportInvocation385(ctx, flarereport.JobWebhookRedrive, started, state)
}
func (w *worker) runWebhookRedriveOnceObserved(ctx context.Context) flarereport.JobInvocationState {
	state := flarereport.InvocationReturned
	drainCtx, cancel := context.WithTimeout(ctx, webhookDrainTimeout)
	defer cancel()
	// The event ledger is the durable webhook outbox boundary. Reconstruct any
	// fan-out row that was lost if the server/worker exited after committing an
	// event but before its asynchronous audit hook ran.
	reconcileCtx, cancelReconcile := context.WithTimeout(drainCtx, webhookReadTimeout)
	_, reconcileErr := w.queries.ReconcileMissingWebhookDeliveries(reconcileCtx, 500)
	cancelReconcile()
	if reconcileErr != nil {
		state = flarereport.InvocationPartial
		slog.Warn("webhooks: reconcile missing deliveries", "code", "reconciliation_unavailable", "error_type", fmt.Sprintf("%T", reconcileErr))
		// Existing deliveries can still make progress while reconciliation is
		// temporarily unavailable, so continue to the claim step.
	}

	deps := w.webhookDeliveryDependencies()
	originalMark := deps.mark
	deps.mark = func(markCtx context.Context, claim *generated.WebhookDelivery, outcome webhookDeliveryOutcome) (int64, error) {
		rows, err := originalMark(markCtx, claim, outcome)
		if err != nil || rows == 1 && (outcome.status == "retrying" || outcome.status == "failed") {
			state = flarereport.InvocationPartial
		}
		return rows, err
	}
	err := drainWebhookDeliveries(drainCtx, webhookDrainLimit, w.queries.ClaimNextDueWebhookDelivery, func(attemptCtx context.Context, d *generated.WebhookDelivery) error {
		applied, err := processClaimedWebhookDelivery(attemptCtx, d, deps)
		if err != nil {
			state = flarereport.InvocationPartial
			slog.Warn("webhooks: delivery checkpoint unavailable", "code", "checkpoint_unavailable", "delivery_id", d.ID, "error_type", fmt.Sprintf("%T", err))
		} else if !applied {
			slog.Info("webhooks: stale delivery claim", "code", "claim_superseded", "delivery_id", d.ID)
		}
		return err
	})
	if err != nil && drainCtx.Err() == nil {
		slog.Warn("webhooks: claim drain unavailable", "code", "claim_unavailable", "error_type", fmt.Sprintf("%T", err))
	}
	if err != nil || drainCtx.Err() != nil {
		state = flarereport.InvocationPartial
	}
	return state
}

// loopEmailDispatch drains the durable email queue, sending each message over
// real SMTP with backoff retries. Mirrors the webhook redrive loop so a
// transient SMTP outage retries instead of dropping invites/reminders.
func (w *worker) loopEmailDispatch(ctx context.Context) {
	tick := time.NewTicker(emailDispatchPollInterval)
	defer tick.Stop()
	w.runEmailDispatchOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			w.runEmailDispatchOnce(ctx)
		}
	}
}

func (w *worker) runEmailDispatchOnce(ctx context.Context) {
	started := time.Now()
	tick := flarereport.JobTick{Job: flarereport.JobEmailDispatch}
	err := dispatchClaimedEmails(ctx, w.queries.ClaimDueEmailDeliveries, func(ctx context.Context, d *generated.EmailDelivery) error {
		tick.Selected++
		tick.Attempted++
		observeJobAge(&tick, d.CreatedAt)
		outcome, err := w.attemptEmailObserved(ctx, d)
		switch outcome {
		case emailSentAcknowledged:
			tick.SentAcknowledged++
		case emailRetryAcknowledged:
			tick.RetryScheduled++
		case emailFailureAcknowledged:
			tick.TerminalFailed++
		}
		if err != nil {
			tick.Failed++
		} else {
			tick.Returned++
		}
		return err
	})
	tick.Unavailable = err != nil
	tick.BatchLimitReached = tick.Selected == 50
	tick.Duration = time.Since(started)
	w.telemetry.RecordJobTick(ctx, tick)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		slog.Warn("email_dispatch: drain failed", "err", err)
		if !w.emailDrainFailed {
			// Report a stable, data-free incident rather than raw database or SMTP
			// errors that may contain customer addresses or connection details.
			flarereport.CaptureErr(errors.New("hash-worker email dispatch persistence unavailable"))
		}
		w.emailDrainFailed = true
		return
	}
	if w.emailDrainFailed {
		slog.Info("email_dispatch: persistence recovered")
	}
	w.emailDrainFailed = false
}

// Lease just the next message, not a batch that waits behind SMTP I/O.
func dispatchClaimedEmails(ctx context.Context, claim func(context.Context, int32) ([]*generated.EmailDelivery, error), attempt func(context.Context, *generated.EmailDelivery) error) error {
	for i := 0; i < 50; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		due, err := claim(ctx, 1)
		if err != nil {
			return err
		}
		if len(due) == 0 {
			return nil
		}
		if err := attempt(ctx, due[0]); err != nil {
			return err
		}
	}
	return nil
}

func (w *worker) attemptEmail(ctx context.Context, d *generated.EmailDelivery) error {
	_, err := w.attemptEmailObserved(ctx, d)
	return err
}

// The result describes an actual SMTP attempt plus its existing durable queue
// acknowledgement. It never claims a recipient mailbox receipt.
func (w *worker) attemptEmailObserved(ctx context.Context, d *generated.EmailDelivery) (emailAttemptOutcome, error) {
	var headers map[string]string
	if len(d.HeadersJson) > 0 {
		_ = json.Unmarshal(d.HeadersJson, &headers)
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err := w.emailSender.Send(sctx, dispatch.Message{
		To: d.ToEmail, Subject: d.Subject, HTML: d.HtmlBody, Text: d.TextBody,
		ReplyTo: d.ReplyTo, FromName: d.FromName, Headers: headers,
	})
	cancel()
	if err == nil {
		if err := w.queries.MarkEmailDeliverySent(ctx, d.ID); err != nil {
			return emailCheckpointFailed, fmt.Errorf("email delivery %s sent acknowledgement failed: %w", d.ID, err)
		}
		return emailSentAcknowledged, nil
	}
	// The claimed row has not recorded this failure yet; use the number of prior
	// failures so a first SMTP outage retries after one minute.
	next, ok := dispatch.Backoff(int(d.Attempts))
	if !ok {
		if markErr := w.queries.MarkEmailDeliveryFailed(ctx, generated.MarkEmailDeliveryFailedParams{
			ID: d.ID, LastError: truncate(err.Error(), 500),
		}); markErr != nil {
			return emailCheckpointFailed, fmt.Errorf("email delivery %s failure acknowledgement failed: %w", d.ID, markErr)
		}
		return emailFailureAcknowledged, nil
	}
	if markErr := w.queries.MarkEmailDeliveryRetrying(ctx, generated.MarkEmailDeliveryRetryingParams{
		ID:            d.ID,
		LastError:     truncate(err.Error(), 500),
		NextAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(next), Valid: true},
	}); markErr != nil {
		return emailCheckpointFailed, fmt.Errorf("email delivery %s retry acknowledgement failed: %w", d.ID, markErr)
	}
	return emailRetryAcknowledged, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func runMigrations(ctx context.Context, dsn string) error {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return err
	}
	migrationCtx, stopMigration := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stopMigration()
	db := stdlib.OpenDB(*cfg.ConnConfig)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	defer db.Close()
	return mdb.RunMigrationsContext(migrationCtx, db)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}
