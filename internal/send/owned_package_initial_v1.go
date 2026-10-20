// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// A repeated public Send with the exact reviewed selection observes the unique
// existing job. It neither replays the original transaction nor assumes that a
// previously dispatched COMMIT succeeded. The native lookup uses current staff
// credentials, root/recipient privacy fences and immutable persisted identity.
func (e *Engine) findOwnedPackageSendSelectionV1(ctx context.Context, op *ownedSendOperationV1, actor Actor) (out SendResult, found bool, failure error) {
	var phase *ownedSendPhaseV1
	failure = op.phaseV1(pdfadmission.HTMLSendIntentReadV1, func(call context.Context, p *ownedSendPhaseV1, _ *generated.Queries, tx pgx.Tx) error {
		phase = p
		state, err := p.work.StateV1(call)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocumentNotFound
		}
		if err != nil {
			return err
		}
		user, err := authorizeOwnedLifecycleActorV1(call, p, tx, &actor)
		if err != nil {
			return err
		}
		observation, err := p.work.FindPackageSendSelectionAttemptV1(call, actor.PackageSend)
		if err != nil {
			return err
		}
		switch observation.Outcome {
		case pdfadmission.HTMLSendPackageAttemptNotRecordedV1:
			if state.BoundedStatus != "draft" {
				return pdfadmission.ErrPackageSendSelectionChangedV1
			}
		case pdfadmission.HTMLSendPackageAttemptActiveV1:
			if state.BoundedStatus != "sealing" {
				return pdfadmission.ErrHTMLSendPackageInspectionV1
			}
			out.Status, out.PackageAttemptID, found = "sealing", observation.AttemptID, true
		case pdfadmission.HTMLSendPackageAttemptCompletedV1:
			// Old captured history must not label a genuinely later Send epoch.
			if !state.SentAt.Valid || !state.Article13NoticeEpochAt.Valid || !state.SentAt.Time.Equal(observation.Article13NoticeEpochAt) || !state.Article13NoticeEpochAt.Time.Equal(observation.Article13NoticeEpochAt) {
				return pdfadmission.ErrPackageSendSelectionChangedV1
			}
			switch state.BoundedStatus {
			case "sent", "in_progress", "changes_requested", "finalizing", "completed", "declined", "voided", "expired":
				out.Status, out.PackageAttemptID, found = state.BoundedStatus, observation.AttemptID, true
			default:
				return pdfadmission.ErrHTMLSendPackageInspectionV1
			}
		case pdfadmission.HTMLSendPackageAttemptAbortedV1:
			// Aborting is not renewed permission to retain/send the old draft.
			return pdfadmission.ErrPackageSendSelectionChangedV1
		default:
			return pdfadmission.ErrHTMLSendPackageInspectionV1
		}
		return reauthorizeLifecycleActor(call, tx, actor, user)
	})
	if phase != nil {
		failure = errors.Join(failure, phase.stage.CloseSQLV1())
		if phase.session == nil || !phase.session.RetiredV1() {
			failure = errors.Join(failure, pdfadmission.ErrApplicationSessionUnknownV1)
		}
	}
	if failure != nil {
		return SendResult{}, false, failure
	}
	if !op.valid(ctx) {
		return SendResult{}, false, pdfadmission.ErrHTMLSendPackageInspectionV1
	}
	return out, found, nil
}

// A fixed internal diagnostic, never the public error payload. PostgreSQL
// messages/detail/query/values and credential material are deliberately absent.
func packageSendFailureDiagnosticV1(phase string, err error) {
	switch phase {
	case "selection_lookup", "preparation", "measurement", "admission", "confirmation", "branding", "capture", "intent", "begin_sealing", "commit":
	default:
		phase = "admission"
	}
	attrs := []any{"phase", phase, "error_type", fmt.Sprintf("%T", err), "no_rows", errors.Is(err, pgx.ErrNoRows), "source_changed", errors.Is(err, pdfadmission.ErrDocumentPackageSourceChangedV1)}
	var database *pgconn.PgError
	if errors.As(err, &database) {
		attrs = append(attrs, "sqlstate", packageSendSQLIdentifierV1(database.Code), "constraint", packageSendSQLIdentifierV1(database.ConstraintName), "table", packageSendSQLIdentifierV1(database.TableName))
	}
	slog.Warn("package_send refused", attrs...)
}
func packageSendSQLIdentifierV1(value string) string {
	if len(value) > 63 {
		return ""
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return ""
		}
	}
	return value
}
