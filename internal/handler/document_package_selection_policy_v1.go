// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"context"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/packageauthoring"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"time"
)

var errDocumentPackageChangedV1 = packageauthoring.ErrChangedV1

func readDocumentPackageSelectionV1(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor, ids [2]uuid.UUID, expected [2]time.Time) ([2]*generated.Document, [2]*packageauthoring.GuardV1, error) {
	return packageauthoring.ReadSelectionV1(call, db, owner, actor, ids, expected)
}
func readDocumentPackageDraftSelectionV1(call context.Context, db generated.DBTX, owner *pdfadmission.ApplicationDocumentPackageSelectionV1, actor authoring.Actor, ids [2]uuid.UUID, expected [2]time.Time, draft pdfadmission.DocumentPackageDraftExpectedV1) ([2]*generated.Document, [2]*packageauthoring.GuardV1, error) {
	return packageauthoring.ReadDraftSelectionV1(call, db, owner, actor, ids, expected, draft)
}
