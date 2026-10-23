// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CleanupPreSignPreparationV1 never creates or replaces an execution. Exact
// observed versions are persisted before deletion. Unknown absent history is
// deliberately left as durable inventory debt and reported pending.
func (s *PreSignServiceV1) CleanupPreSignPreparationV1(ctx context.Context, org, document, preparation uuid.UUID) error {
	if !s.runtimeV1() {
		return presignregistry.ErrUnavailable
	}
	o, err := s.Send.newOwnedSendOperationV1(ctx, org, document)
	if err != nil {
		return err
	}
	defer o.closeConsumerV1()
	var owner *pdfadmission.ApplicationPreSignCleanupV1
	err = o.phaseV1(pdfadmission.HTMLPreSignRecoveryV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		if _, err := p.work.StateV1(c); err != nil {
			return err
		}
		var err error
		owner, err = p.work.StartPreSignCleanupV1(c, preparation, s.Storage)
		return err
	})
	if err != nil {
		return err
	}
	defer owner.CloseConsumerV1()
	if err = owner.ObserveV1(); err != nil {
		return err
	}
	err = o.phaseV1(pdfadmission.HTMLPreSignRecoveryV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		if _, err := p.work.StateV1(c); err != nil {
			return err
		}
		return owner.RecordResolutionsV1(c, p.work)
	})
	if err != nil {
		return err
	}
	if err = owner.DeleteV1(); err != nil {
		return err
	}
	err = o.phaseV1(pdfadmission.HTMLPreSignRecoveryV1, func(c context.Context, p *ownedSendPhaseV1, _ *generated.Queries, _ pgx.Tx) error {
		if _, err := p.work.StateV1(c); err != nil {
			return err
		}
		return owner.MarkDeletedV1(c, p.work)
	})
	if err != nil {
		return err
	}
	if owner.PendingV1() {
		return pdfadmission.ErrPreSignCleanupPendingV1
	}
	return nil
}
