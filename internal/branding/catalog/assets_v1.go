// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/malwarescan"
	"github.com/bright-interaction/hash/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func assetDTOv1(r *generated.BrandAssetRevisionsV1) AssetV1 {
	return AssetV1{AssetID: r.AssetID, Revision: r.Revision, Name: r.Name, Original: ObjectV1{VersionID: r.OriginalVersionID, SHA256: hex.EncodeToString(r.OriginalSha256), Bytes: r.OriginalBytes, MediaType: r.OriginalMediaType, Width: r.OriginalWidth, Height: r.OriginalHeight}, Render: ObjectV1{VersionID: r.RenderVersionID, SHA256: hex.EncodeToString(r.RenderSha256), Bytes: r.RenderBytes, MediaType: "image/png", Width: r.RenderWidth, Height: r.RenderHeight}, RenderMethod: r.RenderMethod, CreatedAt: r.CreatedAt.Time}
}
func (s *ServiceV1) GetAssetV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, revision int64) (AssetV1, error) {
	if id == uuid.Nil || revision < 0 {
		return AssetV1{}, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (AssetV1, error) {
		r, e := q.GetBrandAssetV1(c, generated.GetBrandAssetV1Params{OrgID: actor.OrgID, AssetID: id, Revision: revision})
		if e != nil {
			return AssetV1{}, e
		}
		return assetDTOv1(r), nil
	})
}
func (s *ServiceV1) ListAssetsV1(ctx context.Context, actor authoring.Actor, limit int, after uuid.UUID) ([]AssetV1, error) {
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) ([]AssetV1, error) {
		rs, e := q.ListBrandAssetsV1(c, generated.ListBrandAssetsV1Params{OrgID: actor.OrgID, AfterID: after, PageSize: pageV1(limit)})
		if e != nil {
			return nil, e
		}
		out := make([]AssetV1, 0, len(rs))
		for _, r := range rs {
			out = append(out, assetDTOv1(r))
		}
		return out, nil
	})
}
func (s *ServiceV1) ListAssetRevisionsV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, before int64, limit int) ([]AssetV1, error) {
	if id == uuid.Nil || before < 0 {
		return nil, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) ([]AssetV1, error) {
		rs, e := q.ListBrandAssetRevisionsV1(c, generated.ListBrandAssetRevisionsV1Params{OrgID: actor.OrgID, AssetID: id, BeforeRevision: before, PageSize: pageV1(limit)})
		if e != nil {
			return nil, e
		}
		out := make([]AssetV1, 0, len(rs))
		for _, r := range rs {
			out = append(out, assetDTOv1(r))
		}
		return out, nil
	})
}
func (s *ServiceV1) GetUploadStatusV1(ctx context.Context, actor authoring.Actor, id uuid.UUID) (UploadStatusV1, error) {
	if id == uuid.Nil {
		return UploadStatusV1{}, ErrInputV1
	}
	return catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (UploadStatusV1, error) {
		r, e := q.GetBrandUploadObservationV1(c, generated.GetBrandUploadObservationV1Params{OrgID: actor.OrgID, RequestID: id})
		if e != nil {
			return UploadStatusV1{}, e
		}
		return UploadStatusV1{RequestID: r.RequestID, AssetID: r.AssetID, Revision: r.Revision, State: r.State}, nil
	}, true)
}
func uploadFingerprintV1(in AssetUploadV1, p preparedAssetV1) [32]byte {
	original, render := sha256.Sum256(p.original), sha256.Sum256(p.render)
	raw, _ := json.Marshal(struct {
		AssetID                                         uuid.UUID
		Expected                                        int64
		Name, MediaType, OriginalSHA, RenderSHA, Method string
	}{in.AssetID, in.ExpectedRevision, in.Name, in.MediaType, hex.EncodeToString(original[:]), hex.EncodeToString(render[:]), p.method})
	return sha256.Sum256(raw)
}
func (s *ServiceV1) UploadAssetV1(ctx context.Context, actor authoring.Actor, in AssetUploadV1) (AssetV1, error) {
	if s == nil || s.Pool == nil || s.Audit == nil || s.store == nil {
		return AssetV1{}, ErrUnavailableV1
	}
	ctx, release, e := AcquireInputV1(ctx, actor.OrgID)
	if e != nil {
		return AssetV1{}, e
	}
	defer release()
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	p, e := decodeAssetV1(in)
	if e != nil {
		return AssetV1{}, e
	}
	if e = malwarescan.ScanActive(ctx, p.original); e != nil {
		return AssetV1{}, e
	}
	if !bytes.Equal(p.original, p.render) {
		if e = malwarescan.ScanActive(ctx, p.render); e != nil {
			return AssetV1{}, e
		}
	}
	if e = validateAssetV1(ctx, in, &p); e != nil {
		return AssetV1{}, e
	}
	fingerprint := uploadFingerprintV1(in, p)
	intent, e := authoring.CommitOwnerMutation(ctx, s.Pool, s.Audit, actor, func(c context.Context, q *generated.Queries) (*generated.BrandAssetUploadsV1, error) {
		old, e := q.GetBrandUploadV1(c, generated.GetBrandUploadV1Params{OrgID: actor.OrgID, RequestID: in.RequestID})
		if e == nil {
			if !bytes.Equal(old.InputSha256, fingerprint[:]) || old.CreatedBy != actor.UserID {
				return nil, ErrConflictV1
			}
			return old, nil
		}
		if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
		id := in.AssetID
		if id == uuid.Nil {
			if in.ExpectedRevision != 0 {
				return nil, ErrInputV1
			}
			id = uuid.New()
			if e = q.InsertBrandAssetV1(c, generated.InsertBrandAssetV1Params{OrgID: actor.OrgID, ID: id, Name: in.Name, CreatedBy: actor.UserID}); e != nil {
				return nil, e
			}
		} else {
			head, e := q.GetBrandAssetHeadV1(c, generated.GetBrandAssetHeadV1Params{OrgID: actor.OrgID, AssetID: id})
			if e != nil {
				return nil, catalogErrorV1(e)
			}
			if head.HeadRevision != in.ExpectedRevision {
				return nil, ErrConflictV1
			}
		}
		revision := in.ExpectedRevision + 1
		prefix := fmt.Sprintf("org/%s/brand/%s/%d/", actor.OrgID, id, revision)
		return q.InsertBrandUploadV1(c, generated.InsertBrandUploadV1Params{OrgID: actor.OrgID, RequestID: in.RequestID, AssetID: id, Revision: revision, ExpectedRevision: in.ExpectedRevision, InputSha256: fingerprint[:], OriginalKey: prefix + "original", RenderKey: prefix + "render", CreatedBy: actor.UserID})
	}, func(r *generated.BrandAssetUploadsV1) audit.Entry {
		return eventV1(actor, "branding.asset_upload_prepared", map[string]any{"asset_id": r.AssetID, "revision": r.Revision, "request_id": r.RequestID})
	})
	if e != nil {
		return AssetV1{}, catalogErrorV1(e)
	}
	if intent.State == "committed" {
		return s.GetAssetV1(ctx, actor, intent.AssetID, intent.Revision)
	}
	var original, render storage.StoredObject
	original, e = s.store.PutVersioned(ctx, intent.OriginalKey, in.MediaType, p.original)
	if e == nil {
		want := sha256.Sum256(p.original)
		if original.SHA256 != want || original.VersionID == "" {
			e = ErrUnavailableV1
		}
		original.SHA256 = want
	}
	if e == nil {
		render, e = s.store.PutVersioned(ctx, intent.RenderKey, "image/png", p.render)
	}
	if e == nil {
		want := sha256.Sum256(p.render)
		if render.SHA256 != want || render.VersionID == "" {
			e = ErrUnavailableV1
		}
		render.SHA256 = want
	}
	if e != nil {
		s.compensateUploadV1(intent, fingerprint, original, render)
		return AssetV1{}, e
	}
	out, e := authoring.CommitOwnerMutation(ctx, s.Pool, s.Audit, actor, func(c context.Context, q *generated.Queries) (AssetV1, error) {
		current, e := q.GetBrandUploadV1(c, generated.GetBrandUploadV1Params{OrgID: actor.OrgID, RequestID: in.RequestID})
		if e != nil {
			return AssetV1{}, e
		}
		if !bytes.Equal(current.InputSha256, fingerprint[:]) || current.AssetID != intent.AssetID || current.Revision != intent.Revision || current.CreatedBy != actor.UserID {
			return AssetV1{}, ErrConflictV1
		}
		if current.State == "committed" {
			r, e := q.GetBrandAssetV1(c, generated.GetBrandAssetV1Params{OrgID: actor.OrgID, AssetID: intent.AssetID, Revision: intent.Revision})
			if e != nil {
				return AssetV1{}, e
			}
			return assetDTOv1(r), nil
		}
		head, e := q.GetBrandAssetHeadV1(c, generated.GetBrandAssetHeadV1Params{OrgID: actor.OrgID, AssetID: intent.AssetID})
		if e != nil {
			return AssetV1{}, e
		}
		if head.HeadRevision != intent.ExpectedRevision {
			return AssetV1{}, ErrConflictV1
		}
		// Reverify under the durable upload-row lock. A concurrent failed attempt's
		// exact-version compensation cannot invalidate a newly published revision.
		if b, e := s.store.GetVerifiedVersionBounded(c, intent.OriginalKey, original.VersionID, original.SHA256[:], int64(len(p.original))); e != nil || len(b) != len(p.original) {
			if e != nil {
				return AssetV1{}, e
			}
			return AssetV1{}, ErrUnavailableV1
		}
		if b, e := s.store.GetVerifiedVersionBounded(c, intent.RenderKey, render.VersionID, render.SHA256[:], int64(len(p.render))); e != nil || len(b) != len(p.render) {
			if e != nil {
				return AssetV1{}, e
			}
			return AssetV1{}, ErrUnavailableV1
		}
		r, e := q.InsertBrandAssetRevisionV1(c, generated.InsertBrandAssetRevisionV1Params{OrgID: actor.OrgID, AssetID: intent.AssetID, Revision: intent.Revision, RequestID: in.RequestID, Name: in.Name, OriginalKey: intent.OriginalKey, OriginalVersionID: original.VersionID, OriginalSha256: original.SHA256[:], OriginalBytes: int64(len(p.original)), OriginalMediaType: in.MediaType, OriginalWidth: p.width, OriginalHeight: p.height, RenderKey: intent.RenderKey, RenderVersionID: render.VersionID, RenderSha256: render.SHA256[:], RenderBytes: int64(len(p.render)), RenderWidth: p.renderWidth, RenderHeight: p.renderHeight, RenderMethod: p.method, CreatedBy: actor.UserID})
		if e != nil {
			return AssetV1{}, e
		}
		n, e := q.AdvanceBrandAssetV1(c, generated.AdvanceBrandAssetV1Params{OrgID: actor.OrgID, AssetID: intent.AssetID, ExpectedRevision: intent.ExpectedRevision, Revision: intent.Revision, Name: in.Name})
		if e != nil {
			return AssetV1{}, e
		}
		if n != 1 {
			return AssetV1{}, ErrConflictV1
		}
		if e = q.CommitBrandUploadV1(c, generated.CommitBrandUploadV1Params{OrgID: actor.OrgID, RequestID: in.RequestID}); e != nil {
			return AssetV1{}, e
		}
		return assetDTOv1(r), nil
	}, func(r AssetV1) audit.Entry {
		return eventV1(actor, "branding.asset_published", map[string]any{"asset_id": r.AssetID, "revision": r.Revision, "original_sha256": r.Original.SHA256, "render_sha256": r.Render.SHA256})
	})
	if e != nil {
		s.compensateUploadV1(intent, fingerprint, original, render)
	}
	return out, catalogErrorV1(e)
}

// A lost COMMIT acknowledgement is NOT permission to delete. Reconcile and
// lock the exact durable intent first; published or unknown state is preserved.
func (s *ServiceV1) compensateUploadV1(intent *generated.BrandAssetUploadsV1, fingerprint [32]byte, original, render storage.StoredObject) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	tx, e := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return
	}
	defer tx.Rollback(ctx)
	q := generated.New(tx)
	row, e := q.GetBrandUploadV1(ctx, generated.GetBrandUploadV1Params{OrgID: intent.OrgID, RequestID: intent.RequestID})
	if e != nil || row.State != "preparing" || !bytes.Equal(row.InputSha256, fingerprint[:]) || row.AssetID != intent.AssetID {
		return
	}
	for _, object := range []struct {
		key    string
		stored storage.StoredObject
	}{{intent.OriginalKey, original}, {intent.RenderKey, render}} {
		if object.stored.VersionID != "" {
			if e := s.store.DeleteVersion(ctx, object.key, object.stored.VersionID, object.stored.SHA256[:]); e != nil {
				slog.Error("brand asset exact-version cleanup incomplete", "org_id", intent.OrgID, "asset_id", intent.AssetID, "request_id", intent.RequestID)
			}
		}
	}
}

// ReadAssetContentV1 exposes original or render bytes only after same-tenant
// membership and original-credential checks. Storage keys are never caller input.
func (s *ServiceV1) ReadAssetContentV1(ctx context.Context, actor authoring.Actor, id uuid.UUID, revision int64, representation string) ([]byte, ObjectV1, func(), error) {
	if id == uuid.Nil || revision < 1 || (representation != "original" && representation != "render") || s == nil || s.store == nil {
		return nil, ObjectV1{}, nil, ErrInputV1
	}
	ctx, release, e := AcquireInputV1(ctx, actor.OrgID)
	if e != nil {
		return nil, ObjectV1{}, nil, e
	}
	type result struct {
		body   []byte
		object ObjectV1
	}
	out, e := catalogReadV1(ctx, s, actor, func(c context.Context, q *generated.Queries) (result, error) {
		r, e := q.GetBrandAssetV1(c, generated.GetBrandAssetV1Params{OrgID: actor.OrgID, AssetID: id, Revision: revision})
		if e != nil {
			return result{}, e
		}
		dto := assetDTOv1(r)
		key, object := r.OriginalKey, dto.Original
		if representation == "render" {
			key, object = r.RenderKey, dto.Render
		}
		sum, e := hex.DecodeString(object.SHA256)
		if e != nil {
			return result{}, ErrUnavailableV1
		}
		body, e := s.store.GetVerifiedVersionBounded(c, key, object.VersionID, sum, object.Bytes)
		if e != nil {
			return result{}, e
		}
		if int64(len(body)) != object.Bytes {
			return result{}, ErrUnavailableV1
		}
		return result{body, object}, nil
	})
	if e != nil {
		release()
		return nil, ObjectV1{}, nil, e
	}
	return out.body, out.object, release, nil
}
