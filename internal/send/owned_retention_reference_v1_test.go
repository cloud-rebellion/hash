// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package send

import (
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/jackc/pgx/v5/pgtype"
	"testing"
	"time"
)

func TestNativeSendRetentionProjectionPreservesOriginalDecisionsV1(t *testing.T) {
	epoch := pgtype.Timestamptz{Time: time.Date(2024, 2, 29, 12, 1, 2, 0, time.UTC), Valid: true}
	due := pgtype.Timestamptz{Time: storage.EvidenceRetentionDeadline(epoch.Time, 7), Valid: true}
	cases := map[string]*generated.SendSealingIntent{
		"valid":          {Article13NoticeEpochAt: epoch, RetainUntil: due},
		"missing epoch":  {RetainUntil: due},
		"missing due":    {Article13NoticeEpochAt: epoch},
		"wrong due":      {Article13NoticeEpochAt: epoch, RetainUntil: pgtype.Timestamptz{Time: due.Time.Add(time.Second), Valid: true}},
		"fractional due": {Article13NoticeEpochAt: epoch, RetainUntil: pgtype.Timestamptz{Time: due.Time.Add(time.Microsecond), Valid: true}},
		"started":        {Article13NoticeEpochAt: epoch, RetainUntil: due, RetentionStartedAt: epoch},
		"completed":      {Article13NoticeEpochAt: epoch, RetainUntil: due, RetentionCompletedAt: epoch},
		"delegated":      {Article13NoticeEpochAt: epoch, RetainUntil: due, PresignExecutionID: pgtype.UUID{Valid: true}},
	}
	for name, row := range cases {
		t.Run(name, func(t *testing.T) {
			projection := pdfadmission.HTMLSendRetentionProjectionV1{DocumentID: row.DocumentID, OrgID: row.OrgID, PresignExecutionID: row.PresignExecutionID, Article13NoticeEpochAt: row.Article13NoticeEpochAt, RetainUntil: row.RetainUntil, RetentionStartedAt: row.RetentionStartedAt, RetentionCompletedAt: row.RetentionCompletedAt}
			old, oldErr := canonicalSendSealingRetainUntil(row)
			actual, actualErr := canonicalOwnedSendSealingRetainUntilV1(projection)
			if (oldErr == nil) != (actualErr == nil) || oldErr != nil && oldErr.Error() != actualErr.Error() || !old.Equal(actual) {
				t.Fatalf("original deadline decision changed: %v / %v", oldErr, actualErr)
			}
			if sendSealingReversible(row) != ownedSendRetentionReversibleV1(projection) {
				t.Fatal("original reversible/delegated policy changed")
			}
		})
	}
}
