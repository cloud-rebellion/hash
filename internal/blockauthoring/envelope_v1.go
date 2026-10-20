// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package blockauthoring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/ownedaudit"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"sort"
	"time"
)

type EnvelopeOperationV1 uint8

const (
	EnvelopeCreateV1 EnvelopeOperationV1 = iota + 1
	EnvelopePromoteV1
	EnvelopeAttachV1
	EnvelopeDetachV1
	EnvelopeReorderV1
)

var ErrEnvelopeTargetV1 = errors.New("document not eligible for envelope mutation")

type EnvelopeInputV1 struct {
	Operation EnvelopeOperationV1
	Root      uuid.UUID
	Children  []uuid.UUID
	Name      string
	Position  int32
}
type EnvelopeResultV1 struct {
	Document *generated.Document
	Children []*generated.ListEnvelopeChildMetadataForReadRow
	owner    *ResultV1
}

func (r *EnvelopeResultV1) CloseConsumerV1() {
	if r != nil && r.owner != nil {
		r.owner.CloseConsumerV1()
	}
}
func envelopeTargetV1(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEnvelopeTargetV1
	}
	return err
}

// The original MCP whole-instrument parent -> sorted current/requested children
// -> member -> mutation -> audit -> original credential checks stay atomic.
// REST now shares those live credential/evidence/privacy checks. Topology-only
// writes do not invalidate M91/M92/M93 and NEVER remeasure existing rows. Their
// original retained JSON and exact allowed output tuples remain genuinely owned.
func EnvelopeV1(ctx context.Context, d DependenciesV1, actor ActorV1, input EnvelopeInputV1) (result *EnvelopeResultV1, failure error) {
	if d.Sessions == nil || d.Audit == nil || actor.OrgID == uuid.Nil || actor.UserID == uuid.Nil || actor.Authorize == nil || input.Operation < EnvelopeCreateV1 || input.Operation > EnvelopeReorderV1 {
		return nil, errors.New("owned envelope dependencies unavailable")
	}
	root := input.Root
	if input.Operation == EnvelopeCreateV1 {
		if root != uuid.Nil {
			return nil, ErrEnvelopeTargetV1
		}
		root = uuid.New()
	} else if root == uuid.Nil {
		return nil, ErrEnvelopeTargetV1
	}
	ctx, cancel := context.WithTimeout(ctx, authoring.MutationTimeout)
	defer cancel()
	session, err := d.Sessions.OpenV1(ctx, actor.OrgID, root)
	if err != nil {
		if session != nil {
			cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			_ = session.CloseV1(cleanup)
		}
		return nil, err
	}
	admission, err := session.NewAdmissionV1(ctx)
	if err != nil {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = session.CloseV1(cleanup)
		return nil, err
	}
	state := &resultStateV1{factory: d.Sessions}
	owner := &ResultV1{state: state}
	result = &EnvelopeResultV1{owner: owner}
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
	var pending audit.PendingEvent
	var eventOwner *pdfadmission.ApplicationHTMLAuditEventConsumerV1
	var doc *generated.Document
	var children []*generated.ListEnvelopeChildMetadataForReadRow
	err = session.WithTxV1(ctx, func(call context.Context, db generated.DBTX) error {
		var err error
		state.reader, err = session.NewHTMLAuthoringReaderV1(call)
		if err != nil {
			return err
		}
		state.topology, err = session.NewEnvelopeTopologyV1(call, state.reader)
		if err != nil {
			return err
		}
		tx := &nativeBlocksPolicyTxV1{DBTX: db}
		q := generated.New(tx)
		docs := make(map[uuid.UUID]*generated.Document)
		var users []generated.User
		gate := func(member *generated.User) error {
			if member == nil || member.ID != actor.UserID || member.OrgID != actor.OrgID || (member.Role != string(auth.RoleSender) && member.Role != string(auth.RoleOwner)) {
				return auth.ErrMutationPermissionRevoked
			}
			original := *member
			if err := actor.Authorize(call, tx, member); err != nil {
				return err
			}
			users = append(users, original)
			return nil
		}
		read := func(id uuid.UUID) error {
			if docs[id] != nil {
				return nil
			}
			row, err := state.topology.ReadDocumentV1(call, id, actor.UserID, func(access pdfadmission.HTMLRevisionReadAccessV1) error {
				if !access.Draft {
					return authoring.ErrDocumentNotDraft
				}
				return nil
			}, gate)
			if errors.Is(err, pgx.ErrNoRows) {
				return authoring.ErrDocumentNotFound
			}
			if err != nil {
				return err
			}
			retained, err := q.HasRetainedDraftSigningEvidence(call, generated.HasRetainedDraftSigningEvidenceParams{DocumentID: id, OrgID: actor.OrgID})
			if err != nil {
				return fmt.Errorf("inspect draft evidence: %w", err)
			}
			if retained {
				return authoring.ErrDocumentHasEvidence
			}
			fence, err := q.TryCollabArchivePrivacyFence(call, actor.OrgID)
			if err != nil {
				return fmt.Errorf("fence draft privacy review: %w", err)
			}
			if !fence {
				return authoring.ErrPrivacyReviewChanging
			}
			pending, err := q.HasPendingDocumentPrivacyRequests(call, generated.HasPendingDocumentPrivacyRequestsParams{DocumentID: id, OrgID: actor.OrgID})
			if err != nil {
				return fmt.Errorf("inspect draft privacy review: %w", err)
			}
			if pending {
				return authoring.ErrPendingPrivacyReview
			}
			if err = call.Err(); err != nil {
				return err
			}
			docs[id] = row
			return nil
		}
		ids := append([]uuid.UUID(nil), input.Children...)
		if input.Operation != EnvelopeCreateV1 {
			if err = read(root); err != nil {
				return err
			}
			if docs[root].IsEnvelope {
				existing, err := state.topology.ChildIDsV1(call, root)
				if err != nil {
					return err
				}
				ids = append(ids, existing...)
			}
		}
		sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
		for _, id := range ids {
			if err = read(id); err != nil {
				return err
			}
		}
		if input.Operation == EnvelopeCreateV1 {
			if err = state.topology.ReadMemberV1(call, actor.UserID, gate); err != nil {
				return err
			}
			if err = d.Billing.LockDocumentQuotaMutation(call, q, actor.OrgID); err != nil {
				return err
			}
			state.writer, err = session.NewBlocksCreationWriterV1(call, state.reader)
			if err != nil {
				return err
			}
			if err = state.writer.PrepareSourceV1(call, []byte("{\"version\":1,\"blocks\":[]}"), []byte("{}")); err != nil {
				return err
			}
			fresh, err := state.writer.CreateBlocksDocument(call, generated.CreateBlocksDocumentParams{OrgID: actor.OrgID, Name: input.Name, SenderID: actor.UserID})
			if err != nil {
				return err
			}
			if err = state.writer.EnforceDocumentQuotaV1(call, d.Billing); err != nil {
				return err
			}
			if err = state.writer.MeasureFreshPolicyV1(call); err != nil {
				return err
			}
			if err = state.topology.RegisterFreshRootV1(call, state.writer); err != nil {
				return err
			}
			docs[root] = fresh
			doc, err = state.topology.PromoteV1(call, root)
			if err != nil {
				return envelopeTargetV1(err)
			}
			for i, id := range input.Children {
				if _, err = state.topology.AttachV1(call, root, id, int32(i+1)); err != nil {
					return envelopeTargetV1(err)
				}
			}
		} else {
			switch input.Operation {
			case EnvelopePromoteV1:
				doc, err = state.topology.PromoteV1(call, root)
			case EnvelopeAttachV1:
				if len(input.Children) != 1 {
					return ErrEnvelopeTargetV1
				}
				doc, err = state.topology.AttachV1(call, root, input.Children[0], input.Position)
			case EnvelopeDetachV1:
				if len(input.Children) != 1 {
					return ErrEnvelopeTargetV1
				}
				child := docs[input.Children[0]]
				if child == nil || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != root {
					return ErrEnvelopeTargetV1
				}
				doc, err = state.topology.DetachV1(call, input.Children[0])
			case EnvelopeReorderV1:
				if !docs[root].IsEnvelope || docs[root].ParentEnvelopeID.Valid {
					return ErrEnvelopeTargetV1
				}
				for _, id := range input.Children {
					child := docs[id]
					if child == nil || !child.ParentEnvelopeID.Valid || uuid.UUID(child.ParentEnvelopeID.Bytes) != root {
						return ErrEnvelopeTargetV1
					}
				}
				err = state.topology.ReorderV1(call, root, input.Children)
				if err == nil {
					children, err = state.topology.MetadataV1(call, root)
				}
			}
			if err != nil {
				return envelopeTargetV1(err)
			}
		}
		payload := map[string]any{"via": actor.Via, "tool": actor.Tool}
		switch input.Operation {
		case EnvelopeCreateV1:
			payload["child_count"] = len(input.Children)
		case EnvelopeAttachV1, EnvelopeDetachV1:
			payload["child_id"] = input.Children[0].String()
		case EnvelopeReorderV1:
			payload["count"] = len(input.Children)
		}
		id, user := root, actor.UserID
		pending, eventOwner, err = ownedaudit.LogV1(d.Audit, call, session, pdfadmission.HTMLAuditEnvelopeUpdatedV1, audit.Entry{OrgID: actor.OrgID, ActorUserID: &user, DocumentID: &id, Kind: audit.KindDocumentUpdated, IP: actor.IP, UserAgent: actor.UserAgent, Payload: payload})
		if eventOwner != nil {
			state.events = append(state.events, eventOwner)
		}
		if err != nil {
			return err
		}
		pending = detachEventIDsV1(pending)
		for _, member := range users {
			copy := member
			if err = actor.Authorize(call, tx, &copy); err != nil {
				return err
			}
		}
		return call.Err()
	})
	if err != nil {
		return result, err
	}
	if err = session.CommitV1(ctx); err != nil {
		return result, err
	}
	committed = true
	result.Document = doc
	result.Children = children
	if err = ownedaudit.PublishV1(d.Audit, pending, eventOwner); err != nil {
		return result, err
	}
	return result, nil
}
