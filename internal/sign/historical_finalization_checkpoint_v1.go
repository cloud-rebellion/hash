// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
)

type historicalFinalizationCheckpointV1 uint8

const (
	historicalRetentionStartedV1 historicalFinalizationCheckpointV1 = iota + 1
	historicalRetentionCompletedV1
	historicalRetentionFailedV1
)

func (e *Engine) markHistoricalFinalizationCheckpointOwnedV1(ctx context.Context, intent *generated.DocumentFinalizationIntent, kind historicalFinalizationCheckpointV1, message string) (rows int64, failure error) {
	if e == nil || ctx == nil || intent == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return 0, ErrSigningAdmissionUnavailableV1
	}
	factory := e.WorkRuntime.SessionsV1()
	native, err := factory.NewHTMLSendOperationV1(ctx, intent.OrgID, intent.DocumentID)
	if err != nil {
		return 0, blockSignatureFailureV1(err)
	}
	operation := &ownedBlocksSignatureOperationV1{native: native, factory: factory, original: ctx}
	defer func() { failure = blockSignatureFailureV1(errors.Join(failure, operation.closeV1())) }()
	failure = operation.phaseV1(pdfadmission.HTMLHistoricalFinalizationCheckpointV1, func(call context.Context, _ *pdfadmission.ApplicationSessionV1, w *pdfadmission.ApplicationHTMLSendWorkV1) error {
		if _, err := w.StateV1(call); err != nil {
			return err
		}
		if _, err := w.ReadHistoricalFinalizationIntentV1(call); err != nil {
			return err
		}
		var err error
		switch kind {
		case historicalRetentionStartedV1:
			rows, err = w.MarkHistoricalFinalizationRetentionStartedV1(call, intent)
		case historicalRetentionCompletedV1:
			rows, err = w.MarkHistoricalFinalizationRetentionCompleteV1(call, intent)
		case historicalRetentionFailedV1:
			rows, err = w.MarkHistoricalFinalizationAttemptFailedV1(call, intent, message)
		default:
			return ErrSigningAdmissionUnavailableV1
		}
		return err
	})
	return rows, failure
}
