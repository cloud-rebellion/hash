-- +goose Up
-- Brand libraries are organization data. Existing frozen document themes and
-- HTML source bytes are deliberately not rewritten by this migration.
CREATE TABLE brand_profiles_v1 (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL, name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 160),
 head_revision BIGINT NOT NULL CHECK(head_revision>0),
 archived_at TIMESTAMPTZ,
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,id)
);
CREATE TABLE brand_profile_revisions_v1 (
 org_id UUID NOT NULL, profile_id UUID NOT NULL, revision BIGINT NOT NULL CHECK(revision>0),
 name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 160),
 profile_json JSONB NOT NULL CHECK(jsonb_typeof(profile_json)='object' AND octet_length(profile_json::text)<=65536),
 content_sha256 BYTEA NOT NULL CHECK(octet_length(content_sha256)=32),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,profile_id,revision),
 FOREIGN KEY(org_id,profile_id) REFERENCES brand_profiles_v1(org_id,id) ON DELETE RESTRICT
);
ALTER TABLE brand_profiles_v1 ADD CONSTRAINT brand_profiles_head123_fk FOREIGN KEY(org_id,id,head_revision)
 REFERENCES brand_profile_revisions_v1(org_id,profile_id,revision) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE brand_assets_v1 (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL, name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 160),
 head_revision BIGINT NOT NULL DEFAULT 0 CHECK(head_revision>=0), archived_at TIMESTAMPTZ,
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,id)
);
-- Durable intent survives process death, provider acknowledgement loss, and
-- credential revocation. Retrying the SAME request resumes these exact keys.
CREATE TABLE brand_asset_uploads_v1 (
 org_id UUID NOT NULL, request_id UUID NOT NULL, asset_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK(revision>0), expected_revision BIGINT NOT NULL CHECK(expected_revision>=0),
 input_sha256 BYTEA NOT NULL CHECK(octet_length(input_sha256)=32),
 original_key TEXT NOT NULL CHECK(octet_length(original_key) BETWEEN 1 AND 1024),
 render_key TEXT NOT NULL CHECK(octet_length(render_key) BETWEEN 1 AND 1024),
 state TEXT NOT NULL DEFAULT 'preparing' CHECK(state IN ('preparing','committed')),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,request_id), UNIQUE(org_id,asset_id,revision),
 FOREIGN KEY(org_id,asset_id) REFERENCES brand_assets_v1(org_id,id) ON DELETE RESTRICT,
 CHECK(revision=expected_revision+1)
);
CREATE TABLE brand_asset_revisions_v1 (
 org_id UUID NOT NULL, asset_id UUID NOT NULL, revision BIGINT NOT NULL CHECK(revision>0),
 request_id UUID NOT NULL, name TEXT NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 160),
 original_key TEXT NOT NULL, original_version_id TEXT NOT NULL CHECK(octet_length(original_version_id) BETWEEN 1 AND 1024),
 original_sha256 BYTEA NOT NULL CHECK(octet_length(original_sha256)=32),
 original_bytes BIGINT NOT NULL CHECK(original_bytes BETWEEN 1 AND 8388608),
 original_media_type TEXT NOT NULL CHECK(original_media_type IN ('image/png','image/svg+xml')),
 original_width INTEGER NOT NULL CHECK(original_width BETWEEN 1 AND 16384),
 original_height INTEGER NOT NULL CHECK(original_height BETWEEN 1 AND 16384),
 render_key TEXT NOT NULL, render_version_id TEXT NOT NULL CHECK(octet_length(render_version_id) BETWEEN 1 AND 1024),
 render_sha256 BYTEA NOT NULL CHECK(octet_length(render_sha256)=32),
 render_bytes BIGINT NOT NULL CHECK(render_bytes BETWEEN 1 AND 2097152),
 render_width INTEGER NOT NULL CHECK(render_width BETWEEN 1 AND 4096),
 render_height INTEGER NOT NULL CHECK(render_height BETWEEN 1 AND 4096),
 render_method TEXT NOT NULL CHECK(render_method IN ('original_png_v1','provided_png_v1')),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,asset_id,revision),
 FOREIGN KEY(org_id,asset_id) REFERENCES brand_assets_v1(org_id,id) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,request_id) REFERENCES brand_asset_uploads_v1(org_id,request_id) ON DELETE RESTRICT,
 CHECK(render_width::bigint*render_height<=4194304)
);
CREATE TABLE brand_profile_revision_assets_v1 (
 org_id UUID NOT NULL, profile_id UUID NOT NULL, profile_revision BIGINT NOT NULL,
 slot TEXT NOT NULL CHECK(slot ~ '^[a-z][a-z0-9_]{0,47}$'),
 asset_id UUID NOT NULL, asset_revision BIGINT NOT NULL,
 PRIMARY KEY(org_id,profile_id,profile_revision,slot),
 FOREIGN KEY(org_id,profile_id,profile_revision) REFERENCES brand_profile_revisions_v1(org_id,profile_id,revision) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,asset_id,asset_revision) REFERENCES brand_asset_revisions_v1(org_id,asset_id,revision) ON DELETE RESTRICT
);
CREATE TABLE brand_org_defaults_v1 (
 org_id UUID PRIMARY KEY REFERENCES orgs(id) ON DELETE RESTRICT,
 profile_id UUID NOT NULL, profile_revision BIGINT NOT NULL,
 selection_revision BIGINT NOT NULL CHECK(selection_revision>0),
 updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(org_id,profile_id,profile_revision) REFERENCES brand_profile_revisions_v1(org_id,profile_id,revision) ON DELETE RESTRICT
);
CREATE TABLE brand_design_template_bindings_v1 (
 org_id UUID NOT NULL, template_id UUID NOT NULL, template_version INTEGER NOT NULL,
 profile_id UUID NOT NULL, profile_revision BIGINT NOT NULL,
 profile_sha256 BYTEA NOT NULL CHECK(octet_length(profile_sha256)=32),
 selected_slots TEXT[] NOT NULL CHECK(cardinality(selected_slots)<=16),
 created_by UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,template_id,template_version),
 FOREIGN KEY(template_id,org_id) REFERENCES templates(id,org_id) ON DELETE RESTRICT,
 FOREIGN KEY(template_id,template_version) REFERENCES html_template_revisions(template_id,version) ON DELETE RESTRICT,
 FOREIGN KEY(org_id,profile_id,profile_revision) REFERENCES brand_profile_revisions_v1(org_id,profile_id,revision) ON DELETE RESTRICT
);

-- +goose StatementBegin
CREATE FUNCTION hash_brand_revision_immutable_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'brand revisions and design provenance are immutable' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER brand_profile_revision_immutable_v1 BEFORE UPDATE OR DELETE ON brand_profile_revisions_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_revision_immutable_v1();
CREATE TRIGGER brand_asset_revision_immutable_v1 BEFORE UPDATE OR DELETE ON brand_asset_revisions_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_revision_immutable_v1();
CREATE TRIGGER brand_profile_asset_immutable_v1 BEFORE UPDATE OR DELETE ON brand_profile_revision_assets_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_revision_immutable_v1();
CREATE TRIGGER brand_design_binding_immutable_v1 BEFORE UPDATE OR DELETE ON brand_design_template_bindings_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_revision_immutable_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_brand_upload_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.state<>'preparing' OR NEW.state<>'committed'
  OR ROW(NEW.org_id,NEW.request_id,NEW.asset_id,NEW.revision,NEW.expected_revision,NEW.input_sha256,NEW.original_key,NEW.render_key,NEW.created_by,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.org_id,OLD.request_id,OLD.asset_id,OLD.revision,OLD.expected_revision,OLD.input_sha256,OLD.original_key,OLD.render_key,OLD.created_by,OLD.created_at) THEN
  RAISE EXCEPTION 'brand upload intent is immutable' USING ERRCODE='23514';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM brand_asset_revisions_v1 r WHERE r.org_id=NEW.org_id AND r.asset_id=NEW.asset_id AND r.revision=NEW.revision AND r.request_id=NEW.request_id AND r.original_key=NEW.original_key AND r.render_key=NEW.render_key) THEN
  RAISE EXCEPTION 'brand upload publication requires exact resolved revision' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER brand_upload_guard_v1 BEFORE UPDATE OR DELETE ON brand_asset_uploads_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_upload_guard_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_brand_asset_source_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE intent brand_asset_uploads_v1%ROWTYPE;
BEGIN
 SELECT * INTO STRICT intent FROM brand_asset_uploads_v1 WHERE org_id=NEW.org_id AND request_id=NEW.request_id FOR UPDATE;
 IF intent.state<>'preparing' OR ROW(NEW.org_id,NEW.asset_id,NEW.revision,NEW.created_by,NEW.original_key,NEW.render_key)
  IS DISTINCT FROM ROW(intent.org_id,intent.asset_id,intent.revision,intent.created_by,intent.original_key,intent.render_key)
  OR NEW.original_key<>format('org/%s/brand/%s/%s/original',NEW.org_id,NEW.asset_id,NEW.revision)
  OR NEW.render_key<>format('org/%s/brand/%s/%s/render',NEW.org_id,NEW.asset_id,NEW.revision) THEN
  RAISE EXCEPTION 'brand asset differs from durable upload intent' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER brand_asset_source_v1 BEFORE INSERT ON brand_asset_revisions_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_asset_source_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_brand_head_guard_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR NEW.org_id<>OLD.org_id OR NEW.id<>OLD.id OR NEW.created_by<>OLD.created_by OR NEW.created_at<>OLD.created_at
  OR NEW.head_revision<OLD.head_revision OR NEW.head_revision>OLD.head_revision+1 THEN
  RAISE EXCEPTION 'brand identity and revision sequence are immutable' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='brand_assets_v1' AND NEW.head_revision>0 AND NOT EXISTS(SELECT 1 FROM brand_asset_revisions_v1 r WHERE r.org_id=NEW.org_id AND r.asset_id=NEW.id AND r.revision=NEW.head_revision) THEN
  RAISE EXCEPTION 'brand asset head requires published revision' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER brand_profile_head_guard_v1 BEFORE UPDATE OR DELETE ON brand_profiles_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_head_guard_v1();
CREATE TRIGGER brand_asset_head_guard_v1 BEFORE UPDATE OR DELETE ON brand_assets_v1 FOR EACH ROW EXECUTE FUNCTION hash_brand_head_guard_v1();

-- Legacy writes cannot silently leave a selected catalog profile pointing at
-- independently changed scalar branding. The adapter clears or rewrites this
-- exact selection in the same transaction.
-- +goose StatementBegin
CREATE FUNCTION hash_brand_default_projection_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM brand_org_defaults_v1 WHERE org_id=NEW.org_id) THEN
  RAISE EXCEPTION 'selected brand profile requires catalog mutation' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER brand_default_projection_v1 BEFORE INSERT OR UPDATE ON org_branding FOR EACH ROW EXECUTE FUNCTION hash_brand_default_projection_v1();

-- +goose Down
LOCK TABLE brand_profiles_v1,brand_assets_v1,brand_asset_uploads_v1,brand_profile_revisions_v1,brand_asset_revisions_v1,brand_profile_revision_assets_v1,brand_org_defaults_v1,brand_design_template_bindings_v1 IN ACCESS EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM brand_profiles_v1) OR EXISTS(SELECT 1 FROM brand_assets_v1)
  OR EXISTS(SELECT 1 FROM brand_asset_uploads_v1) OR EXISTS(SELECT 1 FROM brand_design_template_bindings_v1) THEN
  RAISE EXCEPTION 'retained brand catalog forbids migration rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER brand_default_projection_v1 ON org_branding;
DROP FUNCTION hash_brand_default_projection_v1();
DROP TABLE brand_design_template_bindings_v1,brand_org_defaults_v1,brand_profile_revision_assets_v1,brand_asset_revisions_v1,brand_asset_uploads_v1;
ALTER TABLE brand_profiles_v1 DROP CONSTRAINT brand_profiles_head123_fk;
DROP TABLE brand_profile_revisions_v1,brand_profiles_v1,brand_assets_v1;
DROP FUNCTION hash_brand_revision_immutable_v1(),hash_brand_upload_guard_v1(),hash_brand_head_guard_v1(),hash_brand_asset_source_v1();
