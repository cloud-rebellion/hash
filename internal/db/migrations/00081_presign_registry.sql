-- +goose Up
-- Registry persistence only. No delegated execution or grant-use mutation is
-- enabled by this migration. Historical manual/source/evidence bytes are not
-- rewritten.
CREATE TABLE presign_workflows (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL,
 name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 200),
 current_revision BIGINT NOT NULL CHECK (current_revision BETWEEN 1 AND 1000000),
 archived_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (org_id,id), CHECK (id <> '00000000-0000-0000-0000-000000000000')
);
CREATE TABLE presign_workflow_revisions (
 org_id UUID NOT NULL,
 workflow_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
 policy_id UUID NOT NULL CHECK (policy_id <> '00000000-0000-0000-0000-000000000000'),
 canonical_definition BYTEA NOT NULL CHECK (octet_length(canonical_definition) BETWEEN 1 AND 262144),
 definition_sha256 BYTEA NOT NULL CHECK (octet_length(definition_sha256)=32),
 canonical_policy BYTEA NOT NULL CHECK (octet_length(canonical_policy) BETWEEN 1 AND 65536),
 policy_sha256 BYTEA NOT NULL CHECK (octet_length(policy_sha256)=32),
 template_id UUID NOT NULL,
 template_version INTEGER NOT NULL CHECK (template_version>0),
 template_content_sha256 BYTEA NOT NULL CHECK (octet_length(template_content_sha256)=32),
 approved_by UUID NOT NULL CHECK (approved_by <> '00000000-0000-0000-0000-000000000000'),
 approved_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (org_id,workflow_id,revision),
 UNIQUE (org_id,policy_id,revision),
 FOREIGN KEY (org_id,workflow_id) REFERENCES presign_workflows(org_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY (template_id,template_version) REFERENCES html_template_revisions(template_id,version) ON DELETE RESTRICT
);
ALTER TABLE presign_workflows ADD CONSTRAINT presign_workflows_current_revision
 FOREIGN KEY (org_id,id,current_revision) REFERENCES presign_workflow_revisions(org_id,workflow_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE presign_workflow_retirements (
 org_id UUID NOT NULL, workflow_id UUID NOT NULL, revision BIGINT NOT NULL,
 retired_by UUID NOT NULL, retired_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (org_id,workflow_id,revision),
 FOREIGN KEY (org_id,workflow_id,revision) REFERENCES presign_workflow_revisions(org_id,workflow_id,revision) ON DELETE RESTRICT
);
CREATE TABLE presign_grants (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 id UUID NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
 -- Preserve named consent after user removal; no destructive users cascade.
 grantor_user_id UUID NOT NULL CHECK (grantor_user_id <> '00000000-0000-0000-0000-000000000000'),
 current_revision BIGINT NOT NULL CHECK (current_revision BETWEEN 1 AND 1000000),
 revoked_at TIMESTAMPTZ,
 revoked_reason TEXT CHECK (revoked_reason IN ('authority_role_lost','identity_changed','member_removed','organization_changed','self_revoked','owner_revoked')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY (org_id,id),
 CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
);
CREATE TABLE presign_grant_revisions (
 org_id UUID NOT NULL, grant_id UUID NOT NULL,
 revision BIGINT NOT NULL CHECK (revision BETWEEN 1 AND 1000000),
 canonical_grant BYTEA NOT NULL CHECK (octet_length(canonical_grant) BETWEEN 1 AND 65536),
 grant_sha256 BYTEA NOT NULL CHECK (octet_length(grant_sha256)=32),
 policy_id UUID NOT NULL, policy_revision BIGINT NOT NULL,
 policy_sha256 BYTEA NOT NULL CHECK (octet_length(policy_sha256)=32),
 granted_at TIMESTAMPTZ NOT NULL, not_before TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL,
 max_uses BIGINT NOT NULL CHECK (max_uses BETWEEN 1 AND 1000000),
 -- No use increment exists until an execution/signature/sealing pairing is added.
 consumed_uses BIGINT NOT NULL DEFAULT 0 CHECK (consumed_uses=0),
 PRIMARY KEY (org_id,grant_id,revision),
 FOREIGN KEY (org_id,grant_id) REFERENCES presign_grants(org_id,id) DEFERRABLE INITIALLY DEFERRED,
 FOREIGN KEY (org_id,policy_id,policy_revision) REFERENCES presign_workflow_revisions(org_id,policy_id,revision) ON DELETE RESTRICT,
 CHECK (not_before>=granted_at AND expires_at>not_before AND expires_at<=granted_at+interval '366 days')
);
ALTER TABLE presign_grants ADD CONSTRAINT presign_grants_current_revision
 FOREIGN KEY (org_id,id,current_revision) REFERENCES presign_grant_revisions(org_id,grant_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE presign_grant_revocations (
 org_id UUID NOT NULL, grant_id UUID NOT NULL,
 revoked_at TIMESTAMPTZ NOT NULL,
 reason TEXT NOT NULL CHECK (reason IN ('authority_role_lost','identity_changed','member_removed','organization_changed','self_revoked','owner_revoked')),
 actor_user_id UUID,
 PRIMARY KEY (org_id,grant_id),
 FOREIGN KEY (org_id,grant_id) REFERENCES presign_grants(org_id,id) ON DELETE RESTRICT
);
CREATE TABLE presign_mutation_requests (
 org_id UUID NOT NULL REFERENCES orgs(id) ON DELETE RESTRICT,
 actor_user_id UUID NOT NULL CHECK (actor_user_id <> '00000000-0000-0000-0000-000000000000'),
 request_id UUID NOT NULL CHECK (request_id <> '00000000-0000-0000-0000-000000000000'),
 state TEXT NOT NULL CHECK (state IN ('committed','closed')),
 operation TEXT NOT NULL CHECK (operation IN ('workflow.approve','workflow.retire','workflow.archive','grant.create','grant.revise','grant.self_revoke','grant.owner_revoke','request.close')),
 command_sha256 BYTEA,
 resource_kind TEXT,
 resource_id UUID,
 resource_revision BIGINT,
 resource_sha256 BYTEA,
 outcome_json JSONB NOT NULL,
 occurred_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY (org_id,actor_user_id,request_id),
 CHECK ((state='closed' AND operation='request.close' AND command_sha256 IS NULL AND resource_kind IS NULL AND resource_id IS NULL AND resource_revision IS NULL AND resource_sha256 IS NULL)
  OR (state='committed' AND operation<>'request.close' AND command_sha256 IS NOT NULL AND octet_length(command_sha256)=32 AND resource_kind IS NOT NULL AND resource_kind IN ('workflow','grant') AND resource_id IS NOT NULL AND resource_id <> '00000000-0000-0000-0000-000000000000' AND resource_revision IS NOT NULL AND resource_revision BETWEEN 1 AND 1000000 AND resource_sha256 IS NOT NULL AND octet_length(resource_sha256)=32))
);
CREATE INDEX presign_grants_owner ON presign_grants(org_id,grantor_user_id,id);

-- +goose StatementBegin
CREATE FUNCTION hash_presign_revision_tenant() RETURNS trigger AS $$
BEGIN
 IF TG_TABLE_NAME='presign_workflow_revisions' THEN
  IF NOT EXISTS (SELECT 1 FROM html_template_revisions r JOIN templates t ON t.id=r.template_id AND t.org_id=r.org_id
   WHERE r.org_id=NEW.org_id AND r.template_id=NEW.template_id AND r.version=NEW.template_version
    AND r.content_sha256=NEW.template_content_sha256 AND r.approved_by IS NOT NULL AND r.approved_at IS NOT NULL
    AND t.archived_at IS NULL AND t.source_kind='html') THEN
   RAISE EXCEPTION 'workflow requires same-tenant approved template' USING ERRCODE='23514';
  END IF;
 ELSIF TG_TABLE_NAME='presign_grant_revisions' THEN
  IF NOT EXISTS (SELECT 1 FROM presign_workflow_revisions r WHERE r.org_id=NEW.org_id AND r.policy_id=NEW.policy_id AND r.revision=NEW.policy_revision AND r.policy_sha256=NEW.policy_sha256) THEN
   RAISE EXCEPTION 'grant requires exact same-tenant policy' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_workflow_revision_tenant BEFORE INSERT ON presign_workflow_revisions FOR EACH ROW EXECUTE FUNCTION hash_presign_revision_tenant();
CREATE TRIGGER presign_grant_revision_tenant BEFORE INSERT ON presign_grant_revisions FOR EACH ROW EXECUTE FUNCTION hash_presign_revision_tenant();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_immutable() RETURNS trigger AS $$
BEGIN
 IF TG_OP='UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'pre-sign authority evidence is immutable' USING ERRCODE='23514';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_workflow_revisions_immutable BEFORE UPDATE OR DELETE ON presign_workflow_revisions FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_workflow_retirements_immutable BEFORE UPDATE OR DELETE ON presign_workflow_retirements FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_grant_revisions_immutable BEFORE UPDATE OR DELETE ON presign_grant_revisions FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_grant_revocations_immutable BEFORE UPDATE OR DELETE ON presign_grant_revocations FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();
CREATE TRIGGER presign_requests_immutable BEFORE UPDATE OR DELETE ON presign_mutation_requests FOR EACH ROW EXECUTE FUNCTION hash_presign_immutable();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_head_guard() RETURNS trigger AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'pre-sign authority heads are retained' USING ERRCODE='23514'; END IF;
 IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.id IS DISTINCT FROM OLD.id OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
  RAISE EXCEPTION 'pre-sign authority identity is immutable' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='presign_workflows' THEN
  IF OLD.archived_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'archived workflow is terminal' USING ERRCODE='23514'; END IF;
  IF NEW.current_revision<>OLD.current_revision AND NEW.current_revision<>OLD.current_revision+1 THEN RAISE EXCEPTION 'workflow revision must advance exactly once' USING ERRCODE='23514'; END IF;
 ELSE
  IF NEW.grantor_user_id IS DISTINCT FROM OLD.grantor_user_id THEN RAISE EXCEPTION 'named grantor is immutable' USING ERRCODE='23514'; END IF;
  IF OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN RAISE EXCEPTION 'revoked grant is terminal' USING ERRCODE='23514'; END IF;
  IF NEW.current_revision<>OLD.current_revision AND (NEW.current_revision<>OLD.current_revision+1 OR NEW.revoked_at IS NOT NULL) THEN RAISE EXCEPTION 'grant revision must advance exactly once while active' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER presign_workflow_heads_guard BEFORE UPDATE OR DELETE ON presign_workflows FOR EACH ROW EXECUTE FUNCTION hash_presign_head_guard();
CREATE TRIGGER presign_grant_heads_guard BEFORE UPDATE OR DELETE ON presign_grants FOR EACH ROW EXECUTE FUNCTION hash_presign_head_guard();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_revocation_complete() RETURNS trigger AS $$
DECLARE h presign_grants%ROWTYPE; r presign_grant_revocations%ROWTYPE; grant_identity UUID;
BEGIN
 IF TG_TABLE_NAME='presign_grants' THEN grant_identity:=NEW.id; ELSE grant_identity:=NEW.grant_id; END IF;
 SELECT * INTO STRICT h FROM presign_grants WHERE org_id=NEW.org_id AND id=grant_identity;
 SELECT * INTO r FROM presign_grant_revocations WHERE org_id=h.org_id AND grant_id=h.id;
 IF (h.revoked_at IS NULL AND FOUND) OR (h.revoked_at IS NOT NULL AND (NOT FOUND OR r.revoked_at IS DISTINCT FROM h.revoked_at OR r.reason IS DISTINCT FROM h.revoked_reason)) THEN
  RAISE EXCEPTION 'terminal grant revocation requires exact evidence' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_grant_head_revocation AFTER INSERT OR UPDATE ON presign_grants DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_revocation_complete();
CREATE CONSTRAINT TRIGGER presign_grant_revocation_head AFTER INSERT ON presign_grant_revocations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_revocation_complete();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_revoke_changed_member() RETURNS trigger AS $$
DECLARE why TEXT; at_time TIMESTAMPTZ;
BEGIN
 IF TG_OP='DELETE' THEN why:='member_removed';
 ELSIF NEW.org_id IS DISTINCT FROM OLD.org_id THEN why:='organization_changed';
 ELSIF NEW.name IS DISTINCT FROM OLD.name OR NEW.email IS DISTINCT FROM OLD.email THEN why:='identity_changed';
 ELSIF OLD.role IN ('owner','sender') AND NEW.role NOT IN ('owner','sender') THEN why:='authority_role_lost';
 ELSE RETURN NEW;
 END IF;
 at_time:=clock_timestamp();
 WITH revoked AS (
  UPDATE presign_grants SET revoked_at=at_time,revoked_reason=why
  WHERE org_id=OLD.org_id AND grantor_user_id=OLD.id AND revoked_at IS NULL RETURNING org_id,id
 ) INSERT INTO presign_grant_revocations(org_id,grant_id,revoked_at,reason)
 SELECT org_id,id,at_time,why FROM revoked;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE TRIGGER users_presign_authority_transition BEFORE UPDATE OR DELETE ON users FOR EACH ROW EXECUTE FUNCTION hash_presign_revoke_changed_member();

-- +goose StatementBegin
CREATE FUNCTION hash_presign_request_lineage() RETURNS trigger AS $$
BEGIN
 IF NEW.state='closed' THEN RETURN NULL; END IF;
 IF NEW.resource_kind='workflow' THEN
  IF NOT EXISTS (SELECT 1 FROM presign_workflow_revisions WHERE org_id=NEW.org_id AND workflow_id=NEW.resource_id AND revision=NEW.resource_revision AND definition_sha256=NEW.resource_sha256) THEN RAISE EXCEPTION 'workflow outcome requires exact approved revision' USING ERRCODE='23514'; END IF;
 ELSE
  IF NOT EXISTS (SELECT 1 FROM presign_grant_revisions WHERE org_id=NEW.org_id AND grant_id=NEW.resource_id AND revision=NEW.resource_revision AND grant_sha256=NEW.resource_sha256) THEN RAISE EXCEPTION 'grant outcome requires exact named revision' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NULL;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER presign_request_resource AFTER INSERT ON presign_mutation_requests DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_presign_request_lineage();

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM presign_workflows) OR EXISTS(SELECT 1 FROM presign_grants) OR EXISTS(SELECT 1 FROM presign_mutation_requests) THEN
  RAISE EXCEPTION 'cannot discard retained pre-sign authority';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER users_presign_authority_transition ON users;
DROP FUNCTION hash_presign_revoke_changed_member();
ALTER TABLE presign_grants DROP CONSTRAINT presign_grants_current_revision;
ALTER TABLE presign_workflows DROP CONSTRAINT presign_workflows_current_revision;
DROP TABLE presign_mutation_requests,presign_grant_revocations,presign_grant_revisions,presign_grants,presign_workflow_retirements,presign_workflow_revisions,presign_workflows;
DROP FUNCTION hash_presign_request_lineage();
DROP FUNCTION hash_presign_revocation_complete();
DROP FUNCTION hash_presign_head_guard();
DROP FUNCTION hash_presign_immutable();
DROP FUNCTION hash_presign_revision_tenant();
