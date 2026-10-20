// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/render"
	"github.com/bright-interaction/hash/internal/storage"
)

// archivedSignatureSpan reads the exact committed evidence used by both the
// signer view and terminal PDF. Legacy digest lookup is read-only here;
// finalization's existing pin-upgrade transaction remains authoritative.
func (e *Engine) archivedSignatureSpan(ctx context.Context, documentID uuid.UUID, signature *generated.Signature) (render.ArchivedSignatureSpan, error) {
	if e == nil || e.Storage == nil || signature == nil || documentID == uuid.Nil ||
		signature.DocumentID != documentID || signature.ID == uuid.Nil || signature.RecipientID == uuid.Nil ||
		strings.TrimSpace(signature.ImageStorageKey) == "" || len(signature.ImageSha256) != sha256.Size {
		return render.ArchivedSignatureSpan{}, errors.New("signature archive: incomplete evidence commitment")
	}
	if err := render.ValidateSignatureName(signature.TypedName); err != nil {
		return render.ArchivedSignatureSpan{}, fmt.Errorf("signature archive: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return render.ArchivedSignatureSpan{}, err
	}
	var raw []byte
	var err error
	if signature.ImageVersionPinRequired {
		if !signature.ImageVersionID.Valid || strings.TrimSpace(signature.ImageVersionID.String) == "" {
			return render.ArchivedSignatureSpan{}, errors.New("signature archive: required version is missing")
		}
		raw, err = e.Storage.GetVerifiedVersion(ctx, signature.ImageStorageKey, signature.ImageVersionID.String, signature.ImageSha256)
	} else {
		if signature.ImageVersionID.Valid {
			return render.ArchivedSignatureSpan{}, errors.New("signature archive: partial legacy version commitment")
		}
		var stored storage.StoredObject
		raw, stored, err = e.Storage.ResolveVerifiedLegacy(ctx, signature.ImageStorageKey, signature.ImageSha256)
		if err == nil && (strings.TrimSpace(stored.VersionID) == "" || subtle.ConstantTimeCompare(stored.SHA256[:], signature.ImageSha256) != 1) {
			return render.ArchivedSignatureSpan{}, errors.New("signature archive: legacy resolution commitment mismatch")
		}
	}
	if err != nil {
		return render.ArchivedSignatureSpan{}, fmt.Errorf("read signature archive %s: %w", signature.ID, err)
	}
	if err := ctx.Err(); err != nil {
		return render.ArchivedSignatureSpan{}, err
	}
	return validateArchivedSignatureBytes(raw, signature)
}

func validateArchivedSignatureBytes(raw []byte, signature *generated.Signature) (render.ArchivedSignatureSpan, error) {
	if len(raw) == 0 || len(raw) > render.MaxArchivedSignatureSpanBytes {
		return render.ArchivedSignatureSpan{}, errors.New("signature archive: invalid byte count")
	}
	sum := sha256.Sum256(raw)
	if subtle.ConstantTimeCompare(sum[:], signature.ImageSha256) != 1 {
		return render.ArchivedSignatureSpan{}, errors.New("signature archive: digest mismatch")
	}
	span, err := render.ValidateArchivedSignatureSpan(raw, signature.TypedName, signature.Font)
	if err != nil {
		return render.ArchivedSignatureSpan{}, fmt.Errorf("validate signature archive %s: %w", signature.ID, err)
	}
	return span, nil
}
