-- name: CountEnvelopeTopologyChildrenV1 :one
-- Actual parent is already locked by native protected header; all membership
-- writers serialize on that same root. No JSON/model is expanded by this count.
SELECT count(*)::bigint FROM documents WHERE parent_envelope_id=$1 AND org_id=$2;

-- name: ListEnvelopeTopologyChildIDsV1 :many
SELECT id FROM documents WHERE parent_envelope_id=$1 AND org_id=$2 ORDER BY id;

-- name: GetEnvelopeTopologyChildParentV1 :one
-- Original detach preflight only needs these actual scoped scalar identities.
SELECT id,parent_envelope_id FROM documents WHERE id=$1 AND org_id=$2 AND deleted_at IS NULL;

-- name: ReorderEnvelopeTopologyChildV1 :one
-- Same parent-first eligibility and atomic mutation as ReorderEnvelopeChild.
-- Native owner retains the actual old body and funds this full returned row.
WITH locked_parent AS MATERIALIZED (
 SELECT parent.id FROM documents parent
 WHERE parent.id=sqlc.arg(parent_envelope_id)::uuid AND parent.org_id=sqlc.arg(org_id)::uuid
 AND parent.status='draft' AND parent.is_envelope=TRUE AND parent.parent_envelope_id IS NULL AND parent.deleted_at IS NULL
 FOR UPDATE OF parent
)
UPDATE documents child SET envelope_position=sqlc.arg(envelope_position),updated_at=now()
FROM locked_parent WHERE child.id=sqlc.arg(id)::uuid AND child.parent_envelope_id=locked_parent.id
 AND child.org_id=sqlc.arg(org_id)::uuid AND child.status='draft' AND child.is_envelope=FALSE AND child.deleted_at IS NULL
RETURNING child.*;
