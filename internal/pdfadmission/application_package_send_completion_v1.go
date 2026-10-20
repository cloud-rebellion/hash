// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unsafe"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/magictoken"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/bright-interaction/hash/internal/workguard"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// Instance configuration is output input, never document/attempt authority.
// Only a genuine registered batch's private current slot can run this program.
// This worker always persists email in the transaction; it has no direct-mail
// fallback and returns no plaintext tokens or reconstructed invitation links.
type PackageSendCompletionConfigV1 struct {
	PublicURL string
	OrgName   string
	Audit     *audit.Logger
}

type HTMLSendPackageSendObservationV1 struct {
	Attempt            HTMLSendPackageAttemptObservationV1
	RetentionVerified  bool
	CompletionVerified bool
	Status             string
}

type applicationPackageSendPendingAuditV1 struct {
	id        uuid.UUID
	owner     *ApplicationHTMLAuditEventConsumerV1
	published bool
}

func (h *ApplicationPackageSendRecoveryBatchV1) WithNextSendV1(client *storage.Client, cfg PackageSendCompletionConfigV1, consume func(HTMLSendPackageSendObservationV1) error) (bool, error) {
	if consume == nil || !packageSendCompletionConfigValidV1(cfg) {
		return false, ErrHTMLSendPackageRetentionV1
	}
	return h.withNextPackageSendV1(client, &cfg, consume)
}

func packageSendCompletionConfigValidV1(cfg PackageSendCompletionConfigV1) bool {
	if cfg.Audit == nil || len(cfg.PublicURL) == 0 || len(cfg.PublicURL) > 4096 || strings.TrimSpace(cfg.PublicURL) != cfg.PublicURL || strings.HasSuffix(cfg.PublicURL, "/") {
		return false
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.User != nil || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.Path != "" || u.String() != cfg.PublicURL {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	if u.Scheme != "http" {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// The retention comparator remains unchanged. Only the separate private
// completion phase may acknowledge an exact active->terminal transition.
func packageSendTerminalProgressV1(before, after HTMLSendPackageAttemptObservationV1) bool {
	if before.Outcome != HTMLSendPackageAttemptActiveV1 || !before.TerminalAt.IsZero() || (after.Outcome != HTMLSendPackageAttemptCompletedV1 && after.Outcome != HTMLSendPackageAttemptAbortedV1) || after.TerminalAt.IsZero() {
		return false
	}
	if after.Outcome == HTMLSendPackageAttemptCompletedV1 {
		if after.RetentionStartedAt.IsZero() || after.RetentionCompletedAt.IsZero() {
			return false
		}
	} else if !after.RetentionStartedAt.IsZero() || !after.RetentionCompletedAt.IsZero() {
		return false
	}
	after.Outcome = before.Outcome
	after.TerminalAt = before.TerminalAt
	return packageRetentionProgressV1(before, after)
}

func (p *applicationPackageSendRetentionPlanV1) prepareOrAbortV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if p.current.Outcome != HTMLSendPackageAttemptActiveV1 {
		return p.observeCompletionV1(call, w)
	}
	c := p.current.Capture
	version, versionErr := w.queries.GetDocumentPackageSendCompletionVersionV1(call)
	if versionErr != nil || version != 1 {
		return ErrHTMLSendPackageRetentionV1
	}
	// Missing new schema is refused before any provider start, not discovered
	// after an irreversible write. Absence of a receipt for this active attempt
	// is expected; it is not a successful historical completion observation.
	_, readErr := w.queries.InspectDocumentPackageSendCompletionV1(call, generated.InspectDocumentPackageSendCompletionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if !errors.Is(readErr, pgx.ErrNoRows) {
		return ErrHTMLSendPackageRetentionV1
	}
	if p.current.RetentionStartedAt.IsZero() {
		if err := ValidateSendExpiryV1(w.state.ExpiresAt, time.Now()); err != nil {
			if err := p.prepareCompletionControlsV1(call, 0); err != nil {
				return err
			}
			_, err := w.readPackageSendCompletionIntentV1(call, p)
			if err != nil {
				return err
			}
			if _, err = w.newPackageSendAuditsV1(call, p, true); err != nil {
				return err
			}
			c := p.current.Capture
			match := generated.DeleteDocumentPackageSealingIntentV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]}
			rows, err := w.queries.AbortDocumentPackageSendSealingV1(call, generated.AbortDocumentPackageSendSealingV1Params(match))
			if err != nil || rows != 1 {
				return ErrHTMLSendPackageRetentionV1
			}
			row, err := w.queries.TerminalizeDocumentPackageSendAttemptV1(call, generated.TerminalizeDocumentPackageSendAttemptV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], Outcome: "aborted"})
			if err != nil || row == nil || !row.TerminalOutcome.Valid || row.TerminalOutcome.String != "aborted" {
				return ErrHTMLSendPackageRetentionV1
			}
			if rows, err = w.queries.DeleteDocumentPackageSealingIntentV1(call, match); err != nil || rows != 1 {
				return ErrHTMLSendPackageRetentionV1
			}
			if err = p.appendCompletionAuditV1(call, w, HTMLAuditPackageSendAbortedV1, uuid.Nil); err != nil {
				return err
			}
			p.effectStatus, p.effectVerified = "draft", false
			return nil
		}
	}
	if _, err := w.preparePackageSendCompletionV1(call, p); err != nil {
		return err
	}
	if err := p.prepareCompletionControlsV1(call, len(w.sourceRecipients)); err != nil {
		return err
	}
	return p.preflightCompletionOutputsV1(call, w)
}

// The actual measured recipient collection, not a guessed all-mode cap, owns
// the private effect/audit controls. Allocation and every fixed-key payload are
// prepaid before storage starts. Overflow or capacity refusal never writes S3.
func (p *applicationPackageSendRetentionPlanV1) prepareCompletionControlsV1(call context.Context, count int) error {
	if count < 0 || int64(count) > int64(1<<31-1) {
		return ErrHTMLSendPackageRetentionV1
	}
	if p.completionControls != nil {
		if p.completionRecipientCount != count || len(p.pendingAudits) != count+2 {
			return ErrHTMLSendPackageRetentionV1
		}
		return nil
	}
	n := int64(count) + 2
	cost := int64(4096) + 8*int64(unsafe.Sizeof(applicationPackageSendAuditBatchV1{}))
	if err := htmlSendResolverAddV1(&cost, n, 8*(int64(unsafe.Sizeof(applicationPackageSendPendingAuditV1{}))+32*int64(unsafe.Sizeof(any(nil)))+32*int64(unsafe.Sizeof(""))+1024)); err != nil {
		return err
	}
	grant, err := p.coordinator.TryAcquireV1(call, p.entry.org, workguard.VectorV1{ParentBytes: cost, DBStagingBytes: cost})
	if err != nil {
		return ErrHTMLSendPackageRetentionV1
	}
	p.completionControls = grant
	p.completionRecipientCount = count
	p.pendingAudits = make([]applicationPackageSendPendingAuditV1, count+2)
	return nil
}

// Exercise the real output and audit admission envelopes before irreversible
// retention. These are tokenless, unappended event consumers; their original
// loans are held together through the end of this preparation, then retired.
// Final publication repeats fresh admission because availability can change.
func (p *applicationPackageSendRetentionPlanV1) preflightCompletionOutputsV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	audits, err := w.newPackageSendAuditsV1(call, p, false)
	if err != nil {
		return err
	}
	defer p.closePendingAuditsV1()
	defer audits.closeConsumerV1()
	if !audits.noInvite {
		if err = w.PrepareCompletionOutputsV1(call, p.completion.PublicURL, p.completion.OrgName); err != nil {
			return err
		}
	}
	for i := 0; i < audits.eventCount; i++ {
		audits.mu.Lock()
		if audits.consumerClosed || audits.released || i >= len(audits.slots) {
			audits.mu.Unlock()
			return ErrHTMLSendPackageRetentionV1
		}
		purpose, recipient := audits.slots[i].purpose, uuid.UUID(audits.slots[i].recipient.Bytes)
		audits.mu.Unlock()
		if p.pendingAuditCount >= len(p.pendingAudits) {
			return ErrHTMLSendPackageRetentionV1
		}
		owner, err := audits.newNextV1(call, purpose, recipient)
		if err != nil {
			return err
		}
		p.pendingAudits[p.pendingAuditCount] = applicationPackageSendPendingAuditV1{owner: owner}
		p.pendingAuditCount++
	}
	return nil
}

func (p *applicationPackageSendRetentionPlanV1) finalizeSendV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	if p.current.Outcome != HTMLSendPackageAttemptActiveV1 {
		return p.observeCompletionV1(call, w)
	}
	if p.current.RetentionStartedAt.IsZero() || p.current.RetentionCompletedAt.IsZero() {
		return ErrHTMLSendPackageRetentionV1
	}
	// Re-read all immutable members/receipts in the final root-locked SQL phase.
	// A previous aggregate marker or callback value is not completion authority.
	if err := p.completeV1(call, w); err != nil {
		return err
	}
	if _, err := w.preparePackageSendCompletionV1(call, p); err != nil {
		return err
	}
	if p.completionControls == nil || p.completionRecipientCount != len(w.sourceRecipients) {
		return ErrHTMLSendPackageRetentionV1
	}
	doc := w.sourceDocument
	audits, err := w.newPackageSendAuditsV1(call, p, false)
	if err != nil {
		return err
	}
	noInvite := audits.noInvite
	if !noInvite {
		if err = w.PrepareCompletionOutputsV1(call, p.completion.PublicURL, p.completion.OrgName); err != nil {
			return err
		}
		exp := magictoken.Expiry(doc.ExpiresAt, time.Now().UTC().Truncate(time.Microsecond))
		for _, recipient := range w.sourceRecipients {
			if _, err = w.RotateAndMarkRecipientV1(call, recipient.ID, exp); err != nil {
				return err
			}
		}
	}
	doc, err = w.completePackageDocumentSendV1(call, p)
	if err != nil {
		return err
	}
	if !noInvite {
		if err = w.queries.UpsertReminderSchedule(call, generated.UpsertReminderScheduleParams{DocumentID: doc.ID, Column2: []byte(`[{"days_after_send":3},{"days_after_send":7}]`), FiresRemaining: 2}); err != nil {
			return err
		}
		// Render every actual locale before the first outbox write, matching the
		// existing finite completion order; each output is prepaid by the Work.
		for _, recipient := range w.sourceRecipients {
			if _, err = w.RenderInviteV1(call, recipient.ID); err != nil {
				return err
			}
		}
		for i := range w.completionOutputs.recipients {
			item := &w.completionOutputs.recipients[i]
			if err = w.EnqueueEmailDeliveryV1(call, item.message); err != nil {
				return err
			}
		}
		for _, recipient := range w.sourceRecipients {
			if err = p.appendCompletionAuditV1(call, w, HTMLAuditPackageRecipientInvitedV1, recipient.ID); err != nil {
				return err
			}
		}
	}
	if err = p.appendCompletionAuditV1(call, w, HTMLAuditPackageDocumentSentV1, uuid.Nil); err != nil {
		return err
	}
	if noInvite {
		if _, err = w.ExpireCompletedSendV1(call); err != nil {
			return err
		}
		if err = w.queries.InvalidateRecipientTokens(call, doc.ID); err != nil {
			return err
		}
		if err = w.queries.CancelReminder(call, doc.ID); err != nil {
			return err
		}
		if err = p.appendCompletionAuditV1(call, w, HTMLAuditPackageDocumentExpiredV1, uuid.Nil); err != nil {
			return err
		}
	}
	c := p.current.Capture
	if !noInvite {
		for i := range w.completionOutputs.recipients {
			item := &w.completionOutputs.recipients[i]
			row, e := w.queries.InsertDocumentPackageInitialInviteReceiptV1(call, generated.InsertDocumentPackageInitialInviteReceiptV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], RecipientID: item.id, EmailDeliveryID: item.outboxID})
			if e != nil || row == nil || row.RecipientID != item.id || row.EmailDeliveryID != item.outboxID || !bytes.Equal(row.TokenHash, item.tokenHash[:]) || !applicationStampEqualV1(row.TokenExpiresAt, item.tokenExpiry) {
				return ErrHTMLSendPackageRetentionV1
			}
		}
	}
	if _, err = w.queries.RecordDocumentPackageSendCompletionV1(call, generated.RecordDocumentPackageSendCompletionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]}); err != nil {
		return err
	}
	if _, err = w.queries.TerminalizeDocumentPackageSendAttemptV1(call, generated.TerminalizeDocumentPackageSendAttemptV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:], Outcome: "completed"}); err != nil {
		return err
	}
	rows, err := w.queries.DeleteDocumentPackageSealingIntentV1(call, generated.DeleteDocumentPackageSealingIntentV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if err != nil || rows != 1 {
		return ErrHTMLSendPackageRetentionV1
	}
	return p.observeCompletionV1(call, w)
}

func (p *applicationPackageSendRetentionPlanV1) observeCompletionV1(call context.Context, w *ApplicationHTMLSendWorkV1) error {
	c := p.current.Capture
	row, err := w.queries.InspectDocumentPackageSendCompletionV1(call, generated.InspectDocumentPackageSendCompletionV1Params{AttemptID: p.entry.attempt, OrgID: p.entry.org, DocumentID: p.entry.document, ExpectedManifestSha256: c.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: c.CommitmentSHA256[:]})
	if errors.Is(err, pgx.ErrNoRows) {
		// Historical terminal state is preserved, never replay permission or a
		// fabricated receipt. A newly written completion must have a real receipt.
		if p.current.Outcome == HTMLSendPackageAttemptActiveV1 {
			return ErrHTMLSendPackageRetentionV1
		}
		p.effectVerified = false
		if p.current.Outcome == HTMLSendPackageAttemptAbortedV1 {
			p.effectStatus = "draft"
		}
		return nil
	}
	if err != nil || row == nil || row.AttemptID != p.entry.attempt || row.OrgID != p.entry.org || row.DocumentID != p.entry.document || (row.Outcome != "sent" && row.Outcome != "expired") || !bytes.Equal(row.ManifestSha256, c.CanonicalSHA256[:]) || !bytes.Equal(row.LegalCommitmentSha256, c.CommitmentSHA256[:]) || len(row.EffectSha256) != 32 {
		return ErrHTMLSendPackageRetentionV1
	}
	if !applicationStampV1(row.Article13NoticeEpochAt) || !row.Article13NoticeEpochAt.Time.Equal(p.current.Article13NoticeEpochAt) || !applicationStampV1(row.RetainUntil) || !row.RetainUntil.Time.Equal(p.current.RetainUntil) || !applicationStampV1(row.CreatedAt) || row.SentEventID == uuid.Nil || len(row.SentEventRowSha256) != 32 || row.RecipientCount < 0 || row.InviteCount < 0 || row.InviteCount > row.RecipientCount {
		return ErrHTMLSendPackageRetentionV1
	}
	if row.Outcome == "sent" {
		if row.InviteCount != row.RecipientCount || row.ExpiredEventID.Valid || len(row.ExpiredEventRowSha256) != 0 {
			return ErrHTMLSendPackageRetentionV1
		}
	} else if row.InviteCount != 0 || !row.ExpiredEventID.Valid || uuid.UUID(row.ExpiredEventID.Bytes) == uuid.Nil || len(row.ExpiredEventRowSha256) != 32 {
		return ErrHTMLSendPackageRetentionV1
	}
	p.effectVerified, p.effectStatus = true, row.Outcome
	return nil
}

// This fixed in-package bridge uses the same native audit consumer and exact
// chain normalization as ownedaudit. It accepts no caller transaction, SQL or
// publication callback. All event fields come from this actual private program.
func (p *applicationPackageSendRetentionPlanV1) appendCompletionAuditV1(call context.Context, w *ApplicationHTMLSendWorkV1, purpose HTMLAuditPurposeV1, recipient uuid.UUID) error {
	if p.completion == nil || p.completion.Audit == nil || w == nil || p.pendingAuditCount >= len(p.pendingAudits) {
		return ErrHTMLSendPackageRetentionV1
	}
	w.mu.Lock()
	audits := w.packageAudits
	valid := w.packageCompletionScopeV1(call, p) && audits != nil
	if valid {
		audits.mu.Lock()
		valid = audits.plan == p && audits.work == w
		audits.mu.Unlock()
	}
	w.mu.Unlock()
	if !valid {
		return ErrHTMLSendPackageRetentionV1
	}
	owner, err := audits.newNextV1(call, purpose, recipient)
	if err != nil {
		return err
	}
	var id uuid.UUID
	err = owner.WithPreparedV1(call, func(in ApplicationHTMLAuditPreparedV1, appendOne func(generated.InsertEventIdentityV1Params) (uuid.UUID, error)) error {
		created := time.Now().UTC().Truncate(time.Microsecond)
		if in.PreviousCreatedAt.Valid && !created.After(in.PreviousCreatedAt.Time) {
			created = in.PreviousCreatedAt.Time.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
		}
		var ip *netip.Addr
		ipText := ""
		if parsed, e := netip.ParseAddr(in.IP); e == nil {
			ip = &parsed
			ipText = parsed.String()
		}
		actor := uuid.UUID(in.ActorUserID.Bytes)
		hash := audit.ChainHashRecord(audit.HashInput{Prev: in.PreviousHash, OrgID: in.OrgID, DocID: in.DocumentID, RecID: recipient, ActorID: actor, Kind: in.Kind, IP: ipText, UA: in.UserAgent, CreatedAt: created, Payload: in.Raw})
		var e error
		id, e = appendOne(generated.InsertEventIdentityV1Params{OrgID: in.OrgID, DocumentID: pgtype.UUID{Bytes: in.DocumentID, Valid: true}, RecipientID: in.RecipientID, ActorUserID: in.ActorUserID, Kind: in.Kind, Ip: ip, Ua: pgtype.Text{String: in.UserAgent, Valid: in.UserAgent != ""}, PayloadJson: in.Raw, PayloadHashed: in.Raw, PrevHash: in.PreviousHash, RowHash: hash, CreatedAt: pgtype.Timestamptz{Time: created, Valid: true}})
		return e
	})
	if err != nil {
		owner.CloseConsumerV1()
		return err
	}
	p.pendingAudits[p.pendingAuditCount] = applicationPackageSendPendingAuditV1{id: id, owner: owner}
	p.pendingAuditCount++
	return nil
}

func (p *applicationPackageSendRetentionPlanV1) publishPendingAuditsV1() error {
	for i := 0; i < p.pendingAuditCount; i++ {
		pending := &p.pendingAudits[i]
		if pending.published {
			continue
		}
		in, done, err := pending.owner.BeginPublicationV1(pending.id)
		if err != nil {
			return err
		}
		pending.published = true
		doc := in.DocumentID
		entry := audit.Entry{OrgID: in.OrgID, DocumentID: &doc, Kind: in.Kind, IP: in.IP, UserAgent: in.UserAgent, Payload: in.Payload}
		if in.ActorUserID.Valid {
			id := uuid.UUID(in.ActorUserID.Bytes)
			entry.ActorUserID = &id
		}
		if in.RecipientID.Valid {
			id := uuid.UUID(in.RecipientID.Bytes)
			entry.RecipientID = &id
		}
		p.completion.Audit.PublishJoinedV1(audit.PendingEvent{ID: pending.id, Entry: entry}, done)
	}
	return nil
}

func (p *applicationPackageSendRetentionPlanV1) closePendingAuditsV1() {
	for i := 0; i < p.pendingAuditCount; i++ {
		if p.pendingAudits[i].owner != nil {
			p.pendingAudits[i].owner.CloseConsumerV1()
		}
		p.pendingAudits[i] = applicationPackageSendPendingAuditV1{}
	}
	p.pendingAuditCount = 0
}
