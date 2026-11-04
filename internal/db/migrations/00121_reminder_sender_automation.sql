-- +goose Up
-- Explicit owner choices only. No existing schedule/preference/outbox is changed.
-- All old reminders retain their original schedule and manual-delay semantics.
-- +goose StatementBegin
CREATE FUNCTION hash_reminder_policy_valid_v1(m text,d integer,n integer,inherit_ok boolean)
RETURNS boolean LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT (m='legacy' AND d=0 AND n=2)
 OR (m='disabled' AND d=0 AND n=0)
 OR (inherit_ok AND m='inherit' AND d=0 AND n=0)
 OR (m='interval' AND d BETWEEN 1 AND 365 AND n BETWEEN 1 AND 365
     AND d::bigint*n::bigint<=365);
$$;
-- +goose StatementEnd

CREATE TABLE template_reminder_policies_v1 (
 template_id uuid PRIMARY KEY REFERENCES templates(id) ON DELETE CASCADE,
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 revision bigint NOT NULL CHECK(revision>0),
 mode text NOT NULL,interval_days integer NOT NULL,max_fires integer NOT NULL,
 updated_by uuid NOT NULL REFERENCES users(id),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(template_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(hash_reminder_policy_valid_v1(mode,interval_days,max_fires,false))
);
CREATE TABLE document_reminder_policies_v1 (
 document_id uuid PRIMARY KEY REFERENCES documents(id) ON DELETE CASCADE,
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 sender_user_id uuid NOT NULL REFERENCES users(id),
 revision bigint NOT NULL CHECK(revision>0),
 mode text NOT NULL,interval_days integer NOT NULL,max_fires integer NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(document_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(hash_reminder_policy_valid_v1(mode,interval_days,max_fires,true))
);
CREATE TABLE reminder_policy_snapshots_v1 (
 document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 sender_user_id uuid NOT NULL REFERENCES users(id),
 sent_at timestamptz NOT NULL,
 source text NOT NULL CHECK(source IN ('legacy','template','document')),
 template_policy_revision bigint NOT NULL CHECK(template_policy_revision>=0),
 document_policy_revision bigint NOT NULL CHECK(document_policy_revision>=0),
 mode text NOT NULL,interval_days integer NOT NULL,max_fires integer NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(document_id,sent_at),
 CHECK(document_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(hash_reminder_policy_valid_v1(mode,interval_days,max_fires,false))
);
CREATE TABLE sender_automation_preferences_v1 (
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 sender_user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 revision bigint NOT NULL CHECK(revision>0),
 notify_viewed boolean NOT NULL DEFAULT false,
 notify_signed boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(org_id,sender_user_id),
 CHECK(sender_user_id<>'00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE TABLE sender_event_notice_receipts_v1 (
 audit_event_id uuid PRIMARY KEY REFERENCES events(id) ON DELETE CASCADE,
 org_id uuid NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
 document_id uuid NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
 recipient_id uuid NOT NULL REFERENCES recipients(id) ON DELETE CASCADE,
 sender_user_id uuid NOT NULL REFERENCES users(id),
 sent_at timestamptz NOT NULL,
 event_kind text NOT NULL CHECK(event_kind IN ('document.viewed','document.signed')),
 signature_id uuid REFERENCES signatures(id),
 email_delivery_id uuid NOT NULL UNIQUE REFERENCES email_deliveries(id) DEFERRABLE INITIALLY DEFERRED,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((event_kind='document.viewed' AND signature_id IS NULL)
    OR (event_kind='document.signed' AND signature_id IS NOT NULL)),
 CHECK(audit_event_id<>'00000000-0000-0000-0000-000000000000'::uuid),
 CHECK(email_delivery_id<>'00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE UNIQUE INDEX sender_notice_first_view_v1
 ON sender_event_notice_receipts_v1(document_id,recipient_id,sent_at)
 WHERE event_kind='document.viewed';
CREATE UNIQUE INDEX sender_notice_signature_v1
 ON sender_event_notice_receipts_v1(signature_id)
 WHERE event_kind='document.signed';

-- Cross-tenant identities are checked independently of application predicates.
-- The app keeps its existing member/source locks and final credential recheck.
-- +goose StatementBegin
CREATE FUNCTION hash_automation_scope_v1() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actual_org uuid;actual_sender uuid;actual_at timestamptz;
BEGIN
 IF TG_TABLE_NAME='template_reminder_policies_v1' THEN
  SELECT org_id INTO actual_org FROM templates WHERE id=NEW.template_id FOR KEY SHARE;
 ELSIF TG_TABLE_NAME='sender_automation_preferences_v1' THEN
  SELECT org_id INTO actual_org FROM users WHERE id=NEW.sender_user_id FOR KEY SHARE;
 ELSE
  SELECT org_id,sender_id,sent_at INTO actual_org,actual_sender,actual_at
   FROM documents WHERE id=NEW.document_id FOR KEY SHARE;
  IF actual_sender IS DISTINCT FROM NEW.sender_user_id THEN
   RAISE EXCEPTION 'automation sender scope refused' USING ERRCODE='23514';
  END IF;
 END IF;
 IF actual_org IS DISTINCT FROM NEW.org_id THEN
  RAISE EXCEPTION 'automation organization scope refused' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='template_reminder_policies_v1' THEN
  PERFORM 1 FROM users WHERE id=NEW.updated_by AND org_id=NEW.org_id
   AND role IN ('owner','sender') FOR KEY SHARE;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'automation author scope refused' USING ERRCODE='23514';
  END IF;
 END IF;
 IF TG_TABLE_NAME IN ('reminder_policy_snapshots_v1','sender_event_notice_receipts_v1') THEN
  IF actual_at IS DISTINCT FROM NEW.sent_at THEN
   RAISE EXCEPTION 'automation send epoch refused' USING ERRCODE='23514';
  END IF;
 END IF;
 IF TG_TABLE_NAME='sender_event_notice_receipts_v1' THEN
  PERFORM 1 FROM events e JOIN recipients r ON r.id=e.recipient_id
   WHERE e.id=NEW.audit_event_id AND e.org_id=NEW.org_id
    AND e.document_id=NEW.document_id AND e.recipient_id=NEW.recipient_id
    AND r.document_id=NEW.document_id AND e.kind=NEW.event_kind
    AND e.created_at>=NEW.sent_at FOR KEY SHARE OF e,r;
  IF NOT FOUND THEN
   RAISE EXCEPTION 'automation event scope refused' USING ERRCODE='23514';
  END IF;
  IF NEW.event_kind='document.signed' THEN
   PERFORM 1 FROM signatures WHERE id=NEW.signature_id
    AND document_id=NEW.document_id AND recipient_id=NEW.recipient_id FOR KEY SHARE;
   IF NOT FOUND THEN
    RAISE EXCEPTION 'automation signature scope refused' USING ERRCODE='23514';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE FUNCTION hash_sender_notice_delivery_scope_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 -- Cascaded organization/event removal is not a retained receipt.
 IF NOT EXISTS(SELECT 1 FROM sender_event_notice_receipts_v1
  WHERE audit_event_id=NEW.audit_event_id) THEN RETURN NULL; END IF;
 PERFORM 1 FROM email_deliveries WHERE id=NEW.email_delivery_id
  AND smtp_org_id=NEW.org_id AND smtp_purpose='workspace'
  AND staff_auth_ciphertext IS NULL FOR KEY SHARE;
 IF NOT FOUND THEN
  RAISE EXCEPTION 'automation outbox scope refused' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END;
$$;
CREATE FUNCTION hash_automation_revision_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.revision<>OLD.revision+1 THEN
  RAISE EXCEPTION 'automation revision refused' USING ERRCODE='23514';
 END IF;
 IF TG_TABLE_NAME='template_reminder_policies_v1' THEN
  IF NEW.template_id IS DISTINCT FROM OLD.template_id THEN
   RAISE EXCEPTION 'automation identity refused' USING ERRCODE='23514';
  END IF;
 ELSE
  IF NEW.sender_user_id IS DISTINCT FROM OLD.sender_user_id THEN
   RAISE EXCEPTION 'automation identity refused' USING ERRCODE='23514';
  END IF;
  IF TG_TABLE_NAME='document_reminder_policies_v1' THEN
   IF NEW.document_id IS DISTINCT FROM OLD.document_id THEN
    RAISE EXCEPTION 'automation identity refused' USING ERRCODE='23514';
   END IF;
  END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE FUNCTION hash_automation_snapshot_immutable_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'retained automation snapshot is immutable' USING ERRCODE='23514';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER template_reminder_scope_v1 BEFORE INSERT OR UPDATE ON template_reminder_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_scope_v1();
CREATE TRIGGER document_reminder_scope_v1 BEFORE INSERT OR UPDATE ON document_reminder_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_scope_v1();
CREATE TRIGGER reminder_snapshot_scope_v1 BEFORE INSERT ON reminder_policy_snapshots_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_scope_v1();
CREATE TRIGGER sender_preference_scope_v1 BEFORE INSERT OR UPDATE ON sender_automation_preferences_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_scope_v1();
CREATE TRIGGER sender_notice_scope_v1 BEFORE INSERT ON sender_event_notice_receipts_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_scope_v1();
CREATE TRIGGER template_reminder_revision_v1 BEFORE UPDATE ON template_reminder_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_revision_v1();
CREATE TRIGGER document_reminder_revision_v1 BEFORE UPDATE ON document_reminder_policies_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_revision_v1();
CREATE TRIGGER sender_preference_revision_v1 BEFORE UPDATE ON sender_automation_preferences_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_revision_v1();
CREATE TRIGGER reminder_snapshot_immutable_v1 BEFORE UPDATE ON reminder_policy_snapshots_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_snapshot_immutable_v1();
CREATE TRIGGER sender_notice_immutable_v1 BEFORE UPDATE ON sender_event_notice_receipts_v1 FOR EACH ROW EXECUTE FUNCTION hash_automation_snapshot_immutable_v1();
CREATE CONSTRAINT TRIGGER sender_notice_delivery_scope_v1 AFTER INSERT ON sender_event_notice_receipts_v1
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_sender_notice_delivery_scope_v1();

-- +goose Down
LOCK TABLE template_reminder_policies_v1,document_reminder_policies_v1,
 reminder_policy_snapshots_v1,sender_automation_preferences_v1,
 sender_event_notice_receipts_v1 IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM template_reminder_policies_v1)
 OR EXISTS(SELECT 1 FROM document_reminder_policies_v1)
 OR EXISTS(SELECT 1 FROM reminder_policy_snapshots_v1)
 OR EXISTS(SELECT 1 FROM sender_automation_preferences_v1)
 OR EXISTS(SELECT 1 FROM sender_event_notice_receipts_v1) THEN
  RAISE EXCEPTION 'retained automation policy or notice forbids rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TABLE sender_event_notice_receipts_v1;
DROP TABLE sender_automation_preferences_v1;
DROP TABLE reminder_policy_snapshots_v1;
DROP TABLE document_reminder_policies_v1;
DROP TABLE template_reminder_policies_v1;
DROP FUNCTION hash_sender_notice_delivery_scope_v1();
DROP FUNCTION hash_automation_snapshot_immutable_v1();
DROP FUNCTION hash_automation_revision_v1();
DROP FUNCTION hash_automation_scope_v1();
DROP FUNCTION hash_reminder_policy_valid_v1(text,integer,integer,boolean);
