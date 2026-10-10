-- name: GetPresignWorkflowHeadForUpdate :one
SELECT * FROM presign_workflows WHERE org_id=$1 AND id=$2 FOR UPDATE;

-- name: GetPresignWorkflowHeadForShare :one
SELECT * FROM presign_workflows WHERE org_id=$1 AND id=$2 FOR SHARE;

-- name: GetPresignWorkflowRevisionForShare :one
SELECT * FROM presign_workflow_revisions WHERE org_id=$1 AND workflow_id=$2 AND revision=$3 FOR SHARE;

-- name: GetPresignPolicyRevisionForShare :one
SELECT * FROM presign_workflow_revisions WHERE org_id=$1 AND policy_id=$2 AND revision=$3 FOR SHARE;

-- name: ListPresignWorkflowHeads :many
SELECT * FROM presign_workflows WHERE org_id=$1 ORDER BY id LIMIT 100;

-- name: InsertPresignWorkflowHead :one
INSERT INTO presign_workflows(org_id,id,name,current_revision) VALUES($1,$2,$3,1) RETURNING *;

-- name: AdvancePresignWorkflowHead :one
UPDATE presign_workflows SET name=$3,current_revision=current_revision+1 WHERE org_id=$1 AND id=$2 AND current_revision=$4 AND archived_at IS NULL RETURNING *;

-- name: InsertPresignWorkflowRevision :one
INSERT INTO presign_workflow_revisions(org_id,workflow_id,revision,policy_id,canonical_definition,definition_sha256,canonical_policy,policy_sha256,template_id,template_version,template_content_sha256,approved_by,approved_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *;

-- name: IsPresignWorkflowRetired :one
SELECT EXISTS(SELECT 1 FROM presign_workflow_retirements WHERE org_id=$1 AND workflow_id=$2 AND revision=$3);

-- name: RetirePresignWorkflowRevision :execrows
INSERT INTO presign_workflow_retirements(org_id,workflow_id,revision,retired_by) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING;

-- name: ArchivePresignWorkflow :execrows
UPDATE presign_workflows SET archived_at=clock_timestamp() WHERE org_id=$1 AND id=$2 AND current_revision=$3 AND archived_at IS NULL;

-- name: GetPresignGrantHeadForUpdate :one
SELECT * FROM presign_grants WHERE org_id=$1 AND id=$2 FOR UPDATE;

-- name: GetPresignGrantHeadForShare :one
SELECT * FROM presign_grants WHERE org_id=$1 AND id=$2 FOR SHARE;

-- name: GetPresignGrantRevisionForShare :one
SELECT * FROM presign_grant_revisions WHERE org_id=$1 AND grant_id=$2 AND revision=$3 FOR SHARE;

-- name: ListOwnPresignGrantHeads :many
SELECT * FROM presign_grants WHERE org_id=$1 AND grantor_user_id=$2 ORDER BY id LIMIT 100;

-- name: InsertPresignGrantHead :one
INSERT INTO presign_grants(org_id,id,grantor_user_id,current_revision) VALUES($1,$2,$3,1) RETURNING *;

-- name: AdvanceOwnPresignGrantHead :execrows
UPDATE presign_grants SET current_revision=current_revision+1 WHERE org_id=$1 AND id=$2 AND grantor_user_id=$3 AND current_revision=$4 AND revoked_at IS NULL;

-- name: InsertPresignGrantRevision :one
INSERT INTO presign_grant_revisions(org_id,grant_id,revision,canonical_grant,grant_sha256,policy_id,policy_revision,policy_sha256,granted_at,not_before,expires_at,max_uses)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *;

-- name: RevokePresignGrant :execrows
UPDATE presign_grants SET revoked_at=$4,revoked_reason=$5 WHERE org_id=$1 AND id=$2 AND current_revision=$3 AND revoked_at IS NULL;

-- name: InsertPresignGrantRevocation :exec
INSERT INTO presign_grant_revocations(org_id,grant_id,revoked_at,reason,actor_user_id) VALUES($1,$2,$3,$4,$5);

-- name: GetOwnPresignMutationRequest :one
SELECT * FROM presign_mutation_requests WHERE org_id=$1 AND actor_user_id=$2 AND request_id=$3 FOR SHARE;

-- name: InsertPresignMutationRequest :one
INSERT INTO presign_mutation_requests(org_id,actor_user_id,request_id,state,operation,command_sha256,resource_kind,resource_id,resource_revision,resource_sha256,outcome_json,occurred_at)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *;

-- name: ListPresignGrantHeads :many
SELECT * FROM presign_grants WHERE org_id=$1 ORDER BY id LIMIT 100;

-- name: GetPresignClock :one
SELECT clock_timestamp()::timestamptz AS observed_at;

-- name: GetPresignGrantorIdentity :one
SELECT grantor_user_id FROM presign_grants WHERE org_id=$1 AND id=$2;

-- name: GetPresignExecutorAPIKeyForShare :one
SELECT scopes,expires_at FROM api_keys WHERE org_id=$1 AND user_id=$2 AND id=$3 FOR SHARE;
