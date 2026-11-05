-- name: ListBrandProfilesV1 :many
SELECT p.id,p.name,p.head_revision,r.content_sha256 FROM brand_profiles_v1 p
JOIN brand_profile_revisions_v1 r ON (r.org_id,r.profile_id,r.revision)=(p.org_id,p.id,p.head_revision)
WHERE p.org_id=sqlc.arg(org_id) AND p.archived_at IS NULL AND p.id>sqlc.arg(after_id)
ORDER BY p.id LIMIT sqlc.arg(page_size);

-- name: GetBrandProfileV1 :one
SELECT r.* FROM brand_profiles_v1 p JOIN brand_profile_revisions_v1 r ON r.org_id=p.org_id AND r.profile_id=p.id
WHERE p.org_id=sqlc.arg(org_id) AND p.id=sqlc.arg(profile_id) AND p.archived_at IS NULL
AND r.revision=CASE WHEN sqlc.arg(revision)::bigint=0 THEN p.head_revision ELSE sqlc.arg(revision)::bigint END;

-- name: GetBrandProfileHeadV1 :one
SELECT * FROM brand_profiles_v1 WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(profile_id) AND archived_at IS NULL FOR UPDATE;

-- name: InsertBrandProfileV1 :exec
INSERT INTO brand_profiles_v1(org_id,id,name,head_revision,created_by) VALUES(sqlc.arg(org_id),sqlc.arg(id),sqlc.arg(name),1,sqlc.arg(created_by));

-- name: InsertBrandProfileRevisionV1 :one
INSERT INTO brand_profile_revisions_v1(org_id,profile_id,revision,name,profile_json,content_sha256,created_by)
VALUES(sqlc.arg(org_id),sqlc.arg(profile_id),sqlc.arg(revision),sqlc.arg(name),sqlc.arg(profile_json),sqlc.arg(content_sha256),sqlc.arg(created_by)) RETURNING *;

-- name: AdvanceBrandProfileV1 :execrows
UPDATE brand_profiles_v1 SET head_revision=sqlc.arg(revision),name=sqlc.arg(name)
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(profile_id) AND head_revision=sqlc.arg(expected_revision) AND archived_at IS NULL;

-- name: InsertBrandProfileAssetV1 :exec
INSERT INTO brand_profile_revision_assets_v1(org_id,profile_id,profile_revision,slot,asset_id,asset_revision)
VALUES(sqlc.arg(org_id),sqlc.arg(profile_id),sqlc.arg(profile_revision),sqlc.arg(slot),sqlc.arg(asset_id),sqlc.arg(asset_revision));

-- name: ListBrandProfileRevisionsV1 :many
SELECT r.profile_id,r.name,r.revision,r.content_sha256 FROM brand_profile_revisions_v1 r
JOIN brand_profiles_v1 p ON p.org_id=r.org_id AND p.id=r.profile_id
WHERE r.org_id=sqlc.arg(org_id) AND r.profile_id=sqlc.arg(profile_id) AND p.archived_at IS NULL
AND (sqlc.arg(before_revision)::bigint=0 OR r.revision<sqlc.arg(before_revision)) ORDER BY r.revision DESC LIMIT sqlc.arg(page_size);

-- name: GetBrandDefaultV1 :one
SELECT d.*,r.content_sha256 FROM brand_org_defaults_v1 d JOIN brand_profile_revisions_v1 r
ON (r.org_id,r.profile_id,r.revision)=(d.org_id,d.profile_id,d.profile_revision) WHERE d.org_id=sqlc.arg(org_id);

-- name: DeleteBrandDefaultV1 :exec
DELETE FROM brand_org_defaults_v1 WHERE org_id=sqlc.arg(org_id);

-- name: InsertBrandDefaultV1 :exec
INSERT INTO brand_org_defaults_v1(org_id,profile_id,profile_revision,selection_revision)
VALUES(sqlc.arg(org_id),sqlc.arg(profile_id),sqlc.arg(profile_revision),sqlc.arg(selection_revision));

-- name: GetBrandAssetHeadV1 :one
SELECT * FROM brand_assets_v1 WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(asset_id) AND archived_at IS NULL FOR UPDATE;

-- name: InsertBrandAssetV1 :exec
INSERT INTO brand_assets_v1(org_id,id,name,created_by) VALUES(sqlc.arg(org_id),sqlc.arg(id),sqlc.arg(name),sqlc.arg(created_by));

-- name: GetBrandUploadV1 :one
SELECT * FROM brand_asset_uploads_v1 WHERE org_id=sqlc.arg(org_id) AND request_id=sqlc.arg(request_id) FOR UPDATE;

-- name: InsertBrandUploadV1 :one
INSERT INTO brand_asset_uploads_v1(org_id,request_id,asset_id,revision,expected_revision,input_sha256,original_key,render_key,created_by)
VALUES(sqlc.arg(org_id),sqlc.arg(request_id),sqlc.arg(asset_id),sqlc.arg(revision),sqlc.arg(expected_revision),sqlc.arg(input_sha256),sqlc.arg(original_key),sqlc.arg(render_key),sqlc.arg(created_by)) RETURNING *;

-- name: GetBrandAssetV1 :one
SELECT r.* FROM brand_assets_v1 a JOIN brand_asset_revisions_v1 r ON r.org_id=a.org_id AND r.asset_id=a.id
WHERE a.org_id=sqlc.arg(org_id) AND a.id=sqlc.arg(asset_id) AND a.archived_at IS NULL
AND r.revision=CASE WHEN sqlc.arg(revision)::bigint=0 THEN a.head_revision ELSE sqlc.arg(revision)::bigint END;

-- name: ListBrandAssetsV1 :many
SELECT r.* FROM brand_assets_v1 a JOIN brand_asset_revisions_v1 r ON (r.org_id,r.asset_id,r.revision)=(a.org_id,a.id,a.head_revision)
WHERE a.org_id=sqlc.arg(org_id) AND a.archived_at IS NULL AND a.id>sqlc.arg(after_id) ORDER BY a.id LIMIT sqlc.arg(page_size);

-- name: ListBrandAssetRevisionsV1 :many
SELECT r.* FROM brand_asset_revisions_v1 r JOIN brand_assets_v1 a ON a.org_id=r.org_id AND a.id=r.asset_id
WHERE r.org_id=sqlc.arg(org_id) AND r.asset_id=sqlc.arg(asset_id) AND a.archived_at IS NULL
AND (sqlc.arg(before_revision)::bigint=0 OR r.revision<sqlc.arg(before_revision)) ORDER BY r.revision DESC LIMIT sqlc.arg(page_size);

-- name: GetBrandUploadObservationV1 :one
SELECT * FROM brand_asset_uploads_v1 WHERE org_id=sqlc.arg(org_id) AND request_id=sqlc.arg(request_id);

-- name: InsertBrandAssetRevisionV1 :one
INSERT INTO brand_asset_revisions_v1(org_id,asset_id,revision,request_id,name,
original_key,original_version_id,original_sha256,original_bytes,original_media_type,original_width,original_height,
render_key,render_version_id,render_sha256,render_bytes,render_width,render_height,render_method,created_by)
VALUES(sqlc.arg(org_id),sqlc.arg(asset_id),sqlc.arg(revision),sqlc.arg(request_id),sqlc.arg(name),
sqlc.arg(original_key),sqlc.arg(original_version_id),sqlc.arg(original_sha256),sqlc.arg(original_bytes),sqlc.arg(original_media_type),sqlc.arg(original_width),sqlc.arg(original_height),
sqlc.arg(render_key),sqlc.arg(render_version_id),sqlc.arg(render_sha256),sqlc.arg(render_bytes),sqlc.arg(render_width),sqlc.arg(render_height),sqlc.arg(render_method),sqlc.arg(created_by)) RETURNING *;

-- name: AdvanceBrandAssetV1 :execrows
UPDATE brand_assets_v1 SET head_revision=sqlc.arg(revision),name=sqlc.arg(name)
WHERE org_id=sqlc.arg(org_id) AND id=sqlc.arg(asset_id) AND head_revision=sqlc.arg(expected_revision) AND archived_at IS NULL;

-- name: CommitBrandUploadV1 :exec
UPDATE brand_asset_uploads_v1 SET state='committed' WHERE org_id=sqlc.arg(org_id) AND request_id=sqlc.arg(request_id) AND state='preparing';

-- name: BrandTemplateAssetsMatchV1 :one
SELECT EXISTS(SELECT 1 FROM html_template_revisions h WHERE h.org_id=sqlc.arg(org_id) AND h.template_id=sqlc.arg(template_id) AND h.version=sqlc.arg(template_version)
AND (SELECT count(*) FROM brand_profile_revision_assets_v1 b WHERE b.org_id=sqlc.arg(org_id) AND b.profile_id=sqlc.arg(profile_id) AND b.profile_revision=sqlc.arg(profile_revision) AND b.slot=ANY(sqlc.arg(selected_slots)::text[]))=cardinality(sqlc.arg(selected_slots)::text[])
AND NOT EXISTS(SELECT 1 FROM brand_profile_revision_assets_v1 b JOIN brand_asset_revisions_v1 a
 ON (a.org_id,a.asset_id,a.revision)=(b.org_id,b.asset_id,b.asset_revision)
 WHERE b.org_id=sqlc.arg(org_id) AND b.profile_id=sqlc.arg(profile_id) AND b.profile_revision=sqlc.arg(profile_revision) AND b.slot=ANY(sqlc.arg(selected_slots)::text[])
 AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(h.html_master_json->'assets','[]'::jsonb)) x
 WHERE x->>'name'='brand_'||b.slot AND x->>'media_type'='image/png' AND x->>'sha256'=encode(a.render_sha256,'hex'))))::boolean AS matches;

-- name: InsertBrandTemplateBindingV1 :execrows
INSERT INTO brand_design_template_bindings_v1(org_id,template_id,template_version,profile_id,profile_revision,profile_sha256,selected_slots,created_by)
SELECT sqlc.arg(org_id),sqlc.arg(template_id),sqlc.arg(template_version),r.profile_id,r.revision,r.content_sha256,sqlc.arg(selected_slots)::text[],sqlc.arg(created_by)
FROM brand_profile_revisions_v1 r WHERE r.org_id=sqlc.arg(org_id) AND r.profile_id=sqlc.arg(profile_id) AND r.revision=sqlc.arg(profile_revision) AND r.content_sha256=sqlc.arg(profile_sha256);

-- name: GetBrandTemplateBindingV1 :one
SELECT * FROM brand_design_template_bindings_v1 WHERE org_id=sqlc.arg(org_id) AND template_id=sqlc.arg(template_id) AND template_version=sqlc.arg(template_version);
