-- name: LockPresignExecutionRequest :exec
-- Original session commitment is command provenance, not a readback identity.
-- Caller authenticates actual original user/credential and takes this lock
-- before grant/document locks; no network/storage work while holding it.
SELECT pg_advisory_xact_lock(hashtextextended(
 'hash:presign-execution-request:v1:' || sqlc.arg(org_id)::uuid::text || ':' ||
 sqlc.arg(executor_kind)::text || ':' || sqlc.arg(executor_user_id)::uuid::text || ':' ||
 sqlc.arg(executor_credential_id)::uuid::text || ':' || sqlc.arg(request_id)::uuid::text, 0));

-- name: GetPresignExecutionRequest :one
SELECT * FROM presign_execution_requests
WHERE org_id=$1 AND executor_kind=$2 AND executor_user_id=$3
 AND executor_credential_id=$4 AND request_id=$5;

-- name: GetPresignExecutionByID :one
SELECT * FROM presign_executions WHERE org_id=$1 AND id=$2;

-- name: GetPresignExecutionByDocument :one
SELECT * FROM presign_executions WHERE org_id=$1 AND document_id=$2;

-- name: ValidatePresignExecutionIntegrity :exec
-- Caller authenticates the original executor and owns the short transaction.
-- This acquires the document lock and checks the committed pair without
-- re-admitting a use after grant revocation or expiry.
SELECT hash_check_presign_execution(e.document_id,FALSE)
FROM presign_executions e WHERE e.org_id=$1 AND e.document_id=$2;

-- name: NextPresignExecutionUse :one
-- Caller must already hold users before selected grant-head FOR UPDATE.
-- Schema81 consumed_uses remains immutable zero; this exact revision's ledger
-- alone supplies the allowance. Under RR a stale contender fails, not reuses.
SELECT COALESCE(max(use_number),0)::bigint+1 AS next_use
FROM presign_execution_uses WHERE org_id=$1 AND grant_id=$2 AND grant_revision=$3;

-- name: InsertPresignExecution :one
WITH v AS (
 SELECT sqlc.arg(canonical_execution)::bytea AS raw,
        convert_from(sqlc.arg(canonical_execution)::bytea,'UTF8')::jsonb AS x
)
INSERT INTO presign_executions (
 org_id,id,document_id,grant_id,grant_revision,grant_sha256,policy_id,policy_revision,policy_sha256,
 executor_kind,executor_user_id,executor_credential_id,request_id,
 command_canonical,command_sha256,original_credential_sha256,
 canonical_execution,execution_sha256,admission_canonical,admission_sha256,audit_event_id,
 signature_id,provider_recipient_id,provider_field_id,materialization_id,source_commitment,
 ceremony_epoch,executed_at,use_number)
SELECT
 (x->>'org_id')::uuid,(x->>'id')::uuid,(x->'document'->>'id')::uuid,
 (x->'grant'->>'id')::uuid,(x->'grant'->>'revision')::bigint,decode(x->'grant'->>'sha256','hex'),
 (x->'policy'->>'id')::uuid,(x->'policy'->>'revision')::bigint,decode(x->'policy'->>'sha256','hex'),
 x->'executor'->>'kind',(x->'executor'->>'user_id')::uuid,(x->'executor'->>'credential_id')::uuid,
 sqlc.arg(request_id)::uuid,sqlc.arg(command_canonical)::bytea,sqlc.arg(command_sha256)::bytea,sqlc.arg(original_credential_sha256)::bytea,
 raw,sqlc.arg(execution_sha256)::bytea,sqlc.arg(admission_canonical)::bytea,sqlc.arg(admission_sha256)::bytea,sqlc.arg(audit_event_id)::uuid,
 (x->'signature'->>'id')::uuid,(x->'signature'->>'recipient_id')::uuid,(x->'signature'->>'field_id')::uuid,
 (x->'document'->'materialization'->>'id')::uuid,decode(x->'document'->'materialization'->>'source_commitment','hex'),
 (x->>'ceremony_epoch')::timestamptz,(x->>'executed_at')::timestamptz,(x->>'use_number')::bigint
FROM v RETURNING *;

-- name: InsertPresignExecutionUse :exec
-- No standalone allowance update. Deferred reciprocal FK requires this exact
-- execution/signature/request/intent atomically, even before retention begins.
INSERT INTO presign_execution_uses(org_id,grant_id,grant_revision,use_number,execution_id,execution_sha256)
SELECT e.org_id,e.grant_id,e.grant_revision,e.use_number,e.id,e.execution_sha256
FROM presign_executions e WHERE e.org_id=$1 AND e.id=$2;

-- name: InsertCommittedPresignExecutionRequest :one
INSERT INTO presign_execution_requests(
 org_id,executor_kind,executor_user_id,executor_credential_id,request_id,state,
 execution_id,execution_sha256,command_canonical,command_sha256,original_credential_sha256,audit_event_id,occurred_at)
SELECT e.org_id,e.executor_kind,e.executor_user_id,e.executor_credential_id,e.request_id,'committed',
 e.id,e.execution_sha256,e.command_canonical,e.command_sha256,e.original_credential_sha256,e.audit_event_id,e.executed_at
FROM presign_executions e WHERE e.org_id=$1 AND e.id=$2 RETURNING presign_execution_requests.*;

-- name: InsertClosedPresignExecutionRequest :one
INSERT INTO presign_execution_requests(
 org_id,executor_kind,executor_user_id,executor_credential_id,request_id,state,original_credential_sha256,audit_event_id,occurred_at)
VALUES($1,$2,$3,$4,$5,'closed',$6,$7,clock_timestamp()) RETURNING *;

-- name: InsertPresignDelegatedSignature :one
-- Intentional delegated evidence, never a fabricated manual portal visit.
INSERT INTO signatures(id,document_id,recipient_id,field_id,font,typed_name,
 image_storage_key,image_sha256,image_version_id,image_version_pin_required,
 signer_ip,signer_ua,signed_at,signature_kind,presign_execution_id)
SELECT e.signature_id,e.document_id,e.provider_recipient_id,e.provider_field_id,
 x->'signature'->'style'->>'font',x->'signature'->>'typed_name',
 x->'signature'->'image'->>'storage_key',decode(x->'signature'->'image'->>'sha256','hex'),
 x->'signature'->'image'->>'version_id',TRUE,NULL,NULL,e.executed_at,'delegated_grant_v1',e.id
FROM presign_executions e
CROSS JOIN LATERAL (SELECT convert_from(e.canonical_execution,'UTF8')::jsonb AS x) v
WHERE e.org_id=$1 AND e.id=$2 RETURNING signatures.*;

-- name: MarkPresignProviderSigned :one
-- Empty hash can never match a SHA256 token lookup; exact epoch is expired.
UPDATE recipients r SET status='signed',signed_at=e.executed_at,
 magic_token_hash=decode('','hex'),magic_token_expires_at=TIMESTAMPTZ '1970-01-01 00:00:00+00'
FROM presign_executions e WHERE e.org_id=$1 AND e.id=$2
 AND r.id=e.provider_recipient_id AND r.document_id=e.document_id
 AND r.status='pending' AND r.sent_at IS NULL AND r.first_viewed_at IS NULL AND r.signed_at IS NULL
RETURNING r.*;

-- name: BindPresignSealingIntent :one
-- Ordinary CreateSendSealingIntent allocates the real next ceremony first.
-- Exact epoch equality forbids adopting a new ceremony after preparation.
UPDATE send_sealing_intents i SET presign_execution_id=e.id
FROM presign_executions e WHERE e.org_id=$1 AND e.id=$2
 AND i.document_id=e.document_id AND i.org_id=e.org_id AND i.presign_execution_id IS NULL
 AND i.actor_user_id=e.executor_user_id AND i.article13_notice_epoch_at=e.ceremony_epoch
 AND i.retain_until=hash_evidence_retain_until(e.ceremony_epoch,7)
 AND i.retention_started_at IS NULL AND i.retention_completed_at IS NULL
RETURNING i.*;
