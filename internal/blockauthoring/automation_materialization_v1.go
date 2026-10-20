// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/recipients"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/versions"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"sync"
	"time"
)

var ErrAutomationTemplateNotFoundV1 = errors.New("automation signature request template not found")
var ErrAutomationTemplateInvalidV1 = errors.New("automation signature request template is invalid")
var ErrAutomationExpiryTooSoonV1 = errors.New("expires_at must be at least 5 minutes in the future")

type AutomationTemplatePreconditionErrorV1 struct {
	ExpectedVersion, ActualVersion int32
	ContentDigestMismatch          bool
}

func (*AutomationTemplatePreconditionErrorV1) Error() string {
	return "template version or content digest does not match"
}

type AutomationInputV1 struct {
	TemplateID                             uuid.UUID
	TemplateVersion                        int32
	TemplateContentSHA256, Name, ExpiresAt string
	Variables                              map[string]string
	Recipients                             []recipients.Values
	IdempotencyKeyHash, RequestHash        [32]byte
	TemplateSnapshotHook                   func()
}
type AutomationResultV1 struct {
	Request  *generated.AutomationSignatureRequest
	Replayed bool
	state    *automationResultStateV1
}
type automationResultStateV1 struct {
	once       sync.Once
	factory    *pdfadmission.ApplicationSessionFactoryV1
	reader     *pdfadmission.ApplicationHTMLAuthoringReaderV1
	claim      *pdfadmission.ApplicationAutomationRequestWriterV1
	template   *pdfadmission.ApplicationBlocksTemplateSourceV1
	writer     *pdfadmission.ApplicationBlocksCreationWriterV1
	recipients *pdfadmission.ApplicationAutomationRecipientsV1
	audits     *pdfadmission.ApplicationAutomationAuditsV1
}

func (r *AutomationResultV1) CloseConsumerV1() {
	if r == nil || r.state == nil {
		return
	}
	s := r.state
	s.once.Do(func() {
		if s.audits != nil {
			s.audits.CloseConsumerV1()
		}
		if s.recipients != nil {
			s.recipients.CloseConsumerV1()
		}
		if s.claim != nil {
			s.claim.CloseConsumerV1()
		}
		if s.writer != nil {
			s.writer.CloseConsumerV1()
		}
		if s.template != nil {
			s.template.CloseConsumerV1()
		}
		if s.reader != nil {
			s.reader.CloseConsumerV1()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.factory != nil {
			_ = s.factory.ReconcileCleanupV1(ctx)
		}
	})
}

// The existing composite machine command remains one ReadCommitted native
// transaction: quota advisory lock -> live author/credential -> durable claim
// or replay -> approved template pin -> exact preflight -> fresh doc and
// interleaved recipient/audit writes -> quota -> version -> bind -> final
// credential -> acknowledged commit -> original joined hooks. Send stays its
// separate existing durable reservation/recovery phase.
func MaterializeAutomationV1(ctx context.Context, d DependenciesV1, actor ActorV1, in AutomationInputV1) (result *AutomationResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil {
		return nil, errors.New("native automation materialization dependencies unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, uuid.New())
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, fmt.Errorf("begin automation signature request: %w", err)
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &automationResultStateV1{factory: d.Sessions}
	result = &AutomationResultV1{state: state}
	committed := false
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		closeErr := session.CloseV1(cleanup)
		_, reconcileErr := admission.ReconcileCleanupV1(cleanup)
		if !committed {
			failure = errors.Join(failure, closeErr, reconcileErr)
		}
	}()
	var events []audit.PendingEvent
	var owners []*pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var user *generated.User
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.claim, err = session.NewAutomationRequestWriterV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		if d.Billing != nil {
			if err = q.LockAutomationSignatureRequestQuota(call, actor.OrgID.String()); err != nil {
				return fmt.Errorf("lock automation signature request quota: %w", err)
			}
		}
		if err = state.reader.AcquireActorV1(call, actor.OrgID, actor.UserID, false); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return auth.ErrMutationPermissionRevoked
			}
			return err
		}
		user, err = q.GetUserForShare(call, generated.GetUserForShareParams{ID: actor.UserID, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && user.Role != string(auth.RoleSender) && user.Role != string(auth.RoleOwner)) {
			return auth.ErrMutationPermissionRevoked
		}
		if err != nil {
			return fmt.Errorf("load automation transaction authorization: %w", err)
		}
		copy := *user
		if err = actor.Authorize(call, tx, &copy); err != nil {
			return err
		}
		result.Request, result.Replayed, err = state.claim.ClaimV1(call, in.IdempotencyKeyHash, in.RequestHash)
		if err != nil {
			return err
		}
		if result.Replayed {
			copy := *user
			return actor.Authorize(call, tx, &copy)
		}
		if in.ExpiresAt != "" {
			expiry, parseErr := time.Parse(time.RFC3339Nano, in.ExpiresAt)
			if parseErr != nil {
				return errors.New("canonical automation expiry became invalid")
			}
			if !expiry.After(time.Now().UTC().Add(send.MinimumExpiryLead)) {
				return ErrAutomationExpiryTooSoonV1
			}
		}
		state.template, err = session.NewBlocksTemplateSourceV1(call, state.reader)
		if err != nil {
			return err
		}
		template, err := state.template.GetTemplateForShare(call, generated.GetTemplateForShareParams{ID: in.TemplateID, OrgID: actor.OrgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAutomationTemplateNotFoundV1
		}
		if errors.Is(err, pdfadmission.ErrBlocksTemplateSourceKindV1) {
			return fmt.Errorf("%w: template is not blocks-source", ErrAutomationTemplateInvalidV1)
		}
		if err != nil {
			return fmt.Errorf("load automation signature request template: %w", err)
		}
		content, err := state.template.CanonicalContentV1(call)
		if err != nil {
			return fmt.Errorf("%w: invalid canonical content: %w", ErrAutomationTemplateInvalidV1, err)
		}
		digest := content.SHA256Hex()
		if template.Version != in.TemplateVersion || digest != in.TemplateContentSHA256 {
			return &AutomationTemplatePreconditionErrorV1{ExpectedVersion: in.TemplateVersion, ActualVersion: template.Version, ContentDigestMismatch: digest != in.TemplateContentSHA256}
		}
		if in.TemplateSnapshotHook != nil {
			in.TemplateSnapshotHook()
		}
		seed, err := state.template.WithAutomationSeedV1(call, in.Variables, in.Recipients, send.ValidateAutomationBlockRequestWithAdmissionV1)
		if err != nil {
			return err
		}
		state.writer, err = session.NewBlocksCreationWriterV1(call, state.reader)
		if err != nil {
			return err
		}
		if err = state.writer.BindTemplateV1(call, state.template); err != nil {
			return err
		}
		if err = state.writer.PrepareSourceV1(call, seed.BlocksJSON, seed.VariablesJSON); err != nil {
			return err
		}
		var expires pgtype.Timestamptz
		if in.ExpiresAt != "" {
			at, parseErr := time.Parse(time.RFC3339Nano, in.ExpiresAt)
			if parseErr != nil {
				return errors.New("canonical automation expiry became invalid")
			}
			expires = pgtype.Timestamptz{Time: at, Valid: true}
		}
		document, err := state.writer.CreateBlocksDocument(call, generated.CreateBlocksDocumentParams{OrgID: actor.OrgID, TemplateID: pgtype.UUID{Bytes: template.ID, Valid: true}, Name: in.Name, SenderID: actor.UserID, ExpiresAt: expires})
		if err != nil {
			return fmt.Errorf("create automation signature document: %w", err)
		}
		if err = state.writer.MeasureFreshPolicyV1(call); err != nil {
			return err
		}
		state.recipients, err = session.NewAutomationRecipientsV1(call, state.reader, state.writer, in.Recipients)
		if err != nil {
			return err
		}
		state.audits, err = session.NewAutomationAuditsV1(call, state.reader, state.claim, state.template, state.recipients, actor.UserID, actor.IP, actor.UserAgent)
		if err != nil {
			return err
		}
		events = make([]audit.PendingEvent, 0, len(in.Recipients)+1)
		owners = make([]*pdfadmission.ApplicationHTMLAuditEventConsumerV1, 0, len(in.Recipients)+1)
		docID, actorID := document.ID, actor.UserID
		appendEvent := func(recipient *uuid.UUID, kind string) error {
			pending, owner, e := ownedaudit.LogAutomationMaterializationV1(d.Audit, call, state.audits, audit.Entry{OrgID: actor.OrgID, DocumentID: &docID, RecipientID: recipient, ActorUserID: &actorID, Kind: kind, IP: actor.IP, UserAgent: actor.UserAgent})
			if e != nil {
				return e
			}
			events = append(events, detachEventIDsV1(pending))
			owners = append(owners, owner)
			return nil
		}
		if err = appendEvent(nil, audit.KindDocumentCreated); err != nil {
			return fmt.Errorf("audit automation signature document: %w", err)
		}
		for range in.Recipients {
			created, e := state.recipients.CreateNextV1(call)
			if e != nil {
				return fmt.Errorf("create automation signature recipient: %w", e)
			}
			recipientID := created.ID
			if e = appendEvent(&recipientID, audit.KindRecipientCreated); e != nil {
				return fmt.Errorf("audit automation signature recipient: %w", e)
			}
		}
		if d.Billing != nil {
			if err = state.writer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
				return fmt.Errorf("enforce automation signature request quota: %w", err)
			}
		}
		if _, err = versions.New(q).SnapshotWithParentIdentityV1(call, versions.SnapshotInput{DocumentID: document.ID, OrgID: document.OrgID, Name: document.Name, SourceKind: document.SourceKind, BlocksJSON: document.BlocksJson, VariablesJS: document.VariablesJson, CreatedBy: &actor.UserID, Via: versions.ViaAgent, Summary: "automation signature request"}); err != nil {
			return fmt.Errorf("snapshot automation signature document: %w", err)
		}
		result.Request, err = state.claim.BindFreshDocumentV1(call, state.writer)
		if err != nil {
			return fmt.Errorf("bind automation signature document: %w", err)
		}
		copy = *user
		return actor.Authorize(call, tx, &copy)
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		if result.Replayed {
			return result, fmt.Errorf("commit automation signature request replay: %w", err)
		}
		return result, fmt.Errorf("commit automation signature request: %w", err)
	}
	committed = true
	for i, event := range events {
		if err = ownedaudit.PublishV1(d.Audit, event, owners[i]); err != nil {
			return result, err
		}
	}
	return result, nil
}
