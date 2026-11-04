-- Scalar-only settings targets; no document/template JSON body is transferred.
-- name: GetTemplateReminderTargetForUpdateV1 :one
SELECT id,org_id,version FROM templates
WHERE id=sqlc.arg(template_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND archived_at IS NULL FOR UPDATE;

-- name: GetDocumentReminderTargetForUpdateV1 :one
SELECT id,org_id,sender_id,template_id,status,updated_at,sent_at,parent_envelope_id,
 (jsonb_typeof(metadata)='object')::boolean AS metadata_object,
 (metadata ? 'hash:document-purpose:v1')::boolean AS purpose_set,
 CASE WHEN octet_length((metadata->'hash:document-purpose:v1')::text)<=256
 THEN metadata->'hash:document-purpose:v1' ELSE NULL END::jsonb AS reserved_purpose
FROM documents WHERE id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND deleted_at IS NULL FOR UPDATE;

-- Native send already holds the document family lock. Locking this scalar
-- template row also protects the absent-default case from the settings writer.
-- Existing documents may keep a retained archived template association.
-- name: LockTemplateReminderSourceV1 :one
SELECT id,org_id FROM templates
WHERE id=sqlc.arg(template_id)::uuid AND org_id=sqlc.arg(org_id)::uuid FOR SHARE;

-- name: GetTemplateReminderPolicyV1 :one
SELECT revision,mode,interval_days,max_fires,updated_at FROM template_reminder_policies_v1
WHERE template_id=sqlc.arg(template_id)::uuid AND org_id=sqlc.arg(org_id)::uuid FOR SHARE;

-- name: GetDocumentReminderPolicyV1 :one
SELECT sender_user_id,revision,mode,interval_days,max_fires,updated_at FROM document_reminder_policies_v1
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid FOR SHARE;

-- name: SaveTemplateReminderPolicyV1 :one
WITH changed AS (
 UPDATE template_reminder_policies_v1 SET revision=revision+1,
 mode=sqlc.arg(mode)::text,interval_days=sqlc.arg(interval_days)::integer,
 max_fires=sqlc.arg(max_fires)::integer,updated_by=sqlc.arg(updated_by)::uuid,
 updated_at=clock_timestamp()
 WHERE template_id=sqlc.arg(template_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND revision=sqlc.arg(expected_revision)::bigint
 RETURNING revision,mode,interval_days,max_fires,updated_at
), fresh AS (
 INSERT INTO template_reminder_policies_v1
 (template_id,org_id,revision,mode,interval_days,max_fires,updated_by)
 SELECT sqlc.arg(template_id)::uuid,sqlc.arg(org_id)::uuid,1,
 sqlc.arg(mode)::text,sqlc.arg(interval_days)::integer,sqlc.arg(max_fires)::integer,sqlc.arg(updated_by)::uuid
 WHERE sqlc.arg(expected_revision)::bigint=0
 ON CONFLICT DO NOTHING RETURNING revision,mode,interval_days,max_fires,updated_at
)
SELECT * FROM changed UNION ALL SELECT * FROM fresh;

-- name: SaveDocumentReminderPolicyV1 :one
WITH changed AS (
 UPDATE document_reminder_policies_v1 SET revision=revision+1,
 mode=sqlc.arg(mode)::text,interval_days=sqlc.arg(interval_days)::integer,
 max_fires=sqlc.arg(max_fires)::integer,updated_at=clock_timestamp()
 WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND sender_user_id=sqlc.arg(sender_user_id)::uuid AND revision=sqlc.arg(expected_revision)::bigint
 RETURNING revision,mode,interval_days,max_fires,updated_at
), fresh AS (
 INSERT INTO document_reminder_policies_v1
 (document_id,org_id,sender_user_id,revision,mode,interval_days,max_fires)
 SELECT sqlc.arg(document_id)::uuid,sqlc.arg(org_id)::uuid,sqlc.arg(sender_user_id)::uuid,1,
 sqlc.arg(mode)::text,sqlc.arg(interval_days)::integer,sqlc.arg(max_fires)::integer
 WHERE sqlc.arg(expected_revision)::bigint=0
 ON CONFLICT DO NOTHING RETURNING revision,mode,interval_days,max_fires,updated_at
)
SELECT * FROM changed UNION ALL SELECT * FROM fresh;

-- name: GetOwnSenderAutomationPreferenceV1 :one
SELECT revision,notify_viewed,notify_signed,updated_at FROM sender_automation_preferences_v1
WHERE org_id=sqlc.arg(org_id)::uuid AND sender_user_id=sqlc.arg(sender_user_id)::uuid FOR SHARE;

-- name: SaveOwnSenderAutomationPreferenceV1 :one
WITH changed AS (
 UPDATE sender_automation_preferences_v1 SET revision=revision+1,
 notify_viewed=sqlc.arg(notify_viewed)::boolean,notify_signed=sqlc.arg(notify_signed)::boolean,
 updated_at=clock_timestamp()
 WHERE org_id=sqlc.arg(org_id)::uuid AND sender_user_id=sqlc.arg(sender_user_id)::uuid
 AND revision=sqlc.arg(expected_revision)::bigint
 RETURNING revision,notify_viewed,notify_signed,updated_at
), fresh AS (
 INSERT INTO sender_automation_preferences_v1
 (org_id,sender_user_id,revision,notify_viewed,notify_signed)
 SELECT sqlc.arg(org_id)::uuid,sqlc.arg(sender_user_id)::uuid,1,
 sqlc.arg(notify_viewed)::boolean,sqlc.arg(notify_signed)::boolean
 WHERE sqlc.arg(expected_revision)::bigint=0
 ON CONFLICT DO NOTHING RETURNING revision,notify_viewed,notify_signed,updated_at
)
SELECT * FROM changed UNION ALL SELECT * FROM fresh;

-- name: GetReminderPolicySnapshotV1 :one
SELECT sender_user_id,source,template_policy_revision,document_policy_revision,
 mode,interval_days,max_fires,created_at FROM reminder_policy_snapshots_v1
WHERE document_id=sqlc.arg(document_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND sent_at=sqlc.arg(sent_at)::timestamptz FOR SHARE;

-- name: InsertReminderPolicySnapshotV1 :one
INSERT INTO reminder_policy_snapshots_v1
 (document_id,org_id,sender_user_id,sent_at,source,template_policy_revision,document_policy_revision,mode,interval_days,max_fires)
VALUES (sqlc.arg(document_id)::uuid,sqlc.arg(org_id)::uuid,sqlc.arg(sender_user_id)::uuid,
 sqlc.arg(sent_at)::timestamptz,sqlc.arg(source)::text,
 sqlc.arg(template_policy_revision)::bigint,sqlc.arg(document_policy_revision)::bigint,
 sqlc.arg(mode)::text,sqlc.arg(interval_days)::integer,sqlc.arg(max_fires)::integer)
ON CONFLICT(document_id,sent_at) DO NOTHING RETURNING document_id;

-- One actual private schedule is admitted before this write. SQL independently
-- binds every offset/count and first-fire instant to the immutable snapshot.
-- name: InstallFrozenReminderScheduleV1 :one
INSERT INTO reminders(document_id,schedule_json,next_fire_at,fires_remaining)
SELECT d.id,sqlc.arg(schedule_json)::jsonb,
 d.sent_at+(CASE WHEN p.mode='legacy' THEN 3 ELSE p.interval_days END)*interval '24 hours',p.max_fires
FROM documents d JOIN reminder_policy_snapshots_v1 p
 ON p.document_id=d.id AND p.org_id=d.org_id AND p.sent_at=d.sent_at
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.status='sent' AND p.mode<>'disabled'
 AND sqlc.arg(schedule_json)::jsonb=(
  SELECT jsonb_agg(jsonb_build_object('days_after_send',
   CASE WHEN p.mode='legacy' THEN CASE WHEN n=1 THEN 3 ELSE 7 END ELSE n*p.interval_days END) ORDER BY n)
  FROM generate_series(1,p.max_fires) n)
ON CONFLICT(document_id) DO UPDATE SET schedule_json=EXCLUDED.schedule_json,
 next_fire_at=EXCLUDED.next_fire_at,fires_remaining=EXCLUDED.fires_remaining,
 last_fired_at=NULL
RETURNING document_id,next_fire_at,fires_remaining;

-- Manual reminders retain the original remaining count. New Sends use their
-- frozen interval; pre121 in-flight schedules retain legacy three-day delay.
-- No schedule is created or re-enabled here, even when a user clicks manually.
-- name: ResetFrozenReminderAfterManualV1 :exec
UPDATE reminders r SET next_fire_at=now()+COALESCE(
 (SELECT CASE WHEN p.mode='legacy' THEN 3 ELSE p.interval_days END
  FROM reminder_policy_snapshots_v1 p
  WHERE p.document_id=d.id AND p.org_id=d.org_id AND p.sent_at=d.sent_at),3)*interval '24 hours',
 last_fired_at=now()
FROM documents d WHERE d.id=r.document_id
 AND d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.status IN ('sent','in_progress') AND r.fires_remaining>0
 AND NOT EXISTS(SELECT 1 FROM reminder_policy_snapshots_v1 p
  WHERE p.document_id=d.id AND p.org_id=d.org_id AND p.sent_at=d.sent_at AND p.mode='disabled');
