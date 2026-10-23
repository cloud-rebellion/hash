// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

// This closed descriptor is a storage identity, not a SQL reservation or
// permission to compensate. The production owner persists all eight exact
// descriptors and upload_attempted BEFORE at most one call per role. Unknown
// PUT/COMMIT outcomes retain debt; empty history cannot discharge an attempted
// upload. No path here applies Object Lock before a durable execution intent.
type PresignTransientReservationV1 struct {
	OrgID, DocumentID, PreparationID uuid.UUID
	Role                             string
	SHA256                           [sha256.Size]byte
	Bytes                            int64
}

func (r PresignTransientReservationV1) KeyV1() string {
	return "org/" + r.OrgID.String() + "/documents/" + r.DocumentID.String() + "/presign/" + r.PreparationID.String() + "/" + r.Role
}
func (r PresignTransientReservationV1) ContentTypeV1() string {
	switch r.Role {
	case "signature_span":
		return "text/html; charset=utf-8"
	case "signature_font", "inter_font":
		return "font/woff2"
	case "overlay_recipe", "overlay_proof":
		return "application/json"
	case "signature_fragment", "disclosure_fragment", "visible_pdf":
		return "application/pdf"
	default:
		return ""
	}
}
func (r PresignTransientReservationV1) validateV1() error {
	limit := int64(1 << 20)
	if r.Role == "signature_fragment" || r.Role == "disclosure_fragment" || r.Role == "visible_pdf" {
		limit = 50 << 20
	}
	if r.OrgID == uuid.Nil || r.DocumentID == uuid.Nil || r.PreparationID == uuid.Nil || r.ContentTypeV1() == "" ||
		r.SHA256 == [sha256.Size]byte{} || r.Bytes < 1 || r.Bytes > limit {
		return errors.New("pre-sign object: invalid exact owned role")
	}
	return nil
}

func (c *Client) presignTransientMetadataV1(ctx context.Context, r PresignTransientReservationV1, version string) error {
	if !validFitVersionID(version) {
		return errors.New("pre-sign object: immutable provider version required")
	}
	info, err := c.mc.StatObject(ctx, c.bucket, r.KeyV1(), c.statOpts(version))
	if err != nil {
		return err
	}
	if info.VersionID != version || info.Size != r.Bytes || info.ContentType != r.ContentTypeV1() {
		return errors.New("pre-sign object: version size or type differs")
	}
	return ctx.Err()
}

// The caller is the fixed local-IO owner below, with a body/coordinator grant
// and constructor-owned authenticated transport. Whole history is bounded to
// the exact operation key and its single permitted version.
func (c *Client) putPresignTransientV1(ctx context.Context, r PresignTransientReservationV1, data []byte, scratch []byte) (StoredObject, error) {
	stored := StoredObject{SHA256: r.SHA256}
	if r.validateV1() != nil || int64(len(data)) != r.Bytes || sha256.Sum256(data) != r.SHA256 {
		return stored, errors.New("pre-sign upload: reserved payload differs")
	}
	if err := ctx.Err(); err != nil {
		return stored, err
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.KeyV1(), ""); err != nil {
		return stored, fmt.Errorf("pre-sign upload: empty owned history required: %w", err)
	}
	opts := c.putOpts(r.ContentTypeV1())
	opts.DisableMultipart = true
	info, err := c.mc.PutObject(ctx, c.bucket, r.KeyV1(), bytes.NewReader(data), r.Bytes, opts)
	if err != nil {
		return stored, fmt.Errorf("pre-sign upload outcome requires reconciliation: %w", err)
	}
	version, err := c.persistableVersionID(r.KeyV1(), info.VersionID)
	if err != nil || !validFitVersionID(version) {
		return stored, errors.New("pre-sign upload outcome lacks exact immutable version")
	}
	stored.VersionID = version
	if err = ctx.Err(); err != nil {
		return stored, err
	}
	if err = c.verifyExactKeyVersionInventory(ctx, r.KeyV1(), version); err != nil {
		return stored, err
	}
	if err = c.presignTransientMetadataV1(ctx, r, version); err != nil {
		return stored, err
	}
	if err = c.verifyEvidenceLocalVersionV1(ctx, r.KeyV1(), version, r.SHA256[:], scratch); err != nil {
		return stored, err
	}
	return stored, nil
}

func (c *Client) resolvePresignTransientV1(ctx context.Context, r PresignTransientReservationV1, scratch []byte) (StoredObject, bool, error) {
	if r.validateV1() != nil {
		return StoredObject{}, false, errors.New("pre-sign reconciliation: invalid exact reservation")
	}
	var version string
	err := scanExactKeyVersions(ctx, c.mc, c.bucket, r.KeyV1(), 2, func(_ context.Context, item minio.ObjectInfo) (bool, error) {
		if version != "" || item.IsDeleteMarker || item.Size != r.Bytes || !validFitVersionID(item.VersionID) {
			return false, errors.New("pre-sign reconciliation: unexpected exact-key history")
		}
		version = item.VersionID
		return false, nil
	})
	if err != nil {
		return StoredObject{}, false, err
	}
	if err = ctx.Err(); err != nil {
		return StoredObject{}, false, err
	}
	if version == "" {
		return StoredObject{}, false, nil
	} // observation only; attempted debt survives.
	if err = c.presignTransientMetadataV1(ctx, r, version); err != nil {
		return StoredObject{}, false, err
	}
	if err = c.verifyEvidenceLocalVersionV1(ctx, r.KeyV1(), version, r.SHA256[:], scratch); err != nil {
		return StoredObject{}, false, err
	}
	return StoredObject{VersionID: version, SHA256: r.SHA256}, true, nil
}

func (c *Client) deletePresignTransientV1(ctx context.Context, r PresignTransientReservationV1, version string, scratch []byte) error {
	if r.validateV1() != nil || !validFitVersionID(version) {
		return errors.New("pre-sign cleanup: exact resolved reservation required")
	}
	if err := c.verifyEvidenceLocalVersionV1(ctx, r.KeyV1(), version, r.SHA256[:], scratch); err != nil {
		if !isObjectNotFound(err) {
			return err
		}
		return c.verifyExactKeyVersionInventory(ctx, r.KeyV1(), "")
	}
	if err := c.verifyExactKeyVersionInventory(ctx, r.KeyV1(), version); err != nil {
		return err
	}
	if err := c.mc.RemoveObject(ctx, c.bucket, r.KeyV1(), minio.RemoveObjectOptions{VersionID: version}); err != nil {
		return err
	}
	if err := c.verifyDataPlaneObjectAbsent(ctx, r.KeyV1(), version, "pre-sign transient exact version"); err != nil {
		return err
	}
	return c.verifyExactKeyVersionInventory(ctx, r.KeyV1(), "")
}
