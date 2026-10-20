-- SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
-- Controller staging only: receipt metadata is pending, never verification.
-- No READY/activate, credit, purge or generic caller-number debit API exists.

-- name: GetSigningResourceControlV1 :one
SELECT c.singleton,c.state,c.active_snapshot_id,c.controller_verification_receipt_id,
 a.db_capacity_bytes,a.db_retained_bytes,a.provider_reserved_bytes,a.provider_reserved_objects,
 a.db_capacity_limit,a.provider_bytes_limit,a.provider_objects_limit
FROM signing_resource_control c JOIN signing_resource_accounts a ON a.scope='global' WHERE c.singleton;

-- name: GetSigningResourceTenantAccountV1 :one
SELECT account_key,scope,org_id,state,baseline_snapshot_id,db_capacity_bytes,db_retained_bytes,
 provider_reserved_bytes,provider_reserved_objects,db_capacity_limit,provider_bytes_limit,provider_objects_limit
FROM signing_resource_accounts WHERE scope='tenant' AND org_id=sqlc.arg(org_id) AND account_key=sqlc.arg(org_id);

-- name: StageSigningResourceTenantAccountV1 :one
-- An uninitialized catalog row is not capacity or controller authorization.
INSERT INTO signing_resource_accounts(account_key,scope,org_id)
SELECT sqlc.arg(org_id),'tenant',o.id FROM orgs o WHERE o.id=sqlc.arg(org_id)
RETURNING account_key,scope,org_id,state,baseline_snapshot_id;

-- name: GetStagedSigningResourceInventoryV1 :one
SELECT id,inventory_scope,inventory_sha256,entry_count,document_count,known_db_bytes,
 known_provider_bytes,known_provider_objects,controller_receipt_id,receipt_storage_key,
 receipt_version_id,receipt_sha256,receipt_bytes,verification_state,unknown_provider_debt,captured_at
FROM signing_resource_inventory_snapshots WHERE id=sqlc.arg(id);

-- name: ListStagedSigningResourceInventoryEntriesV1 :many
-- Global controller knowledge, not signer/tenant API. Runtime must hold its
-- authenticated administrative scope and bounded DB/process permit first.
SELECT snapshot_id,org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,
 identity_sha256,db_bytes,provider_bytes,provider_objects
FROM signing_resource_inventory_entries WHERE snapshot_id=sqlc.arg(snapshot_id)
ORDER BY org_id,document_id,kind,operation_id,member_kind,page LIMIT 65537;

-- name: GetSigningResourceDebtV1 :one
SELECT org_id,document_id,ceremony_epoch,admission_id,kind,operation_id,member_kind,page,
 identity_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects,captured_at
FROM signing_resource_debts WHERE org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id)
 AND kind=sqlc.arg(kind) AND operation_id=sqlc.arg(operation_id) AND member_kind=sqlc.arg(member_kind) AND page=sqlc.arg(page);

-- name: ListSigningResourceDocumentDebtV1 :many
SELECT org_id,document_id,ceremony_epoch,admission_id,kind,operation_id,member_kind,page,
 identity_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects,captured_at
FROM signing_resource_debts WHERE org_id=sqlc.arg(org_id) AND document_id=sqlc.arg(document_id)
ORDER BY admission_id,kind,operation_id,member_kind,page LIMIT 65537;

-- name: GetSigningResourceFitTransferV1 :one
SELECT admission_id,org_id,document_id,recipient_id,preparation_id,captured_at
FROM signing_resource_fit_transfers WHERE admission_id=sqlc.arg(admission_id) AND org_id=sqlc.arg(org_id)
 AND document_id=sqlc.arg(document_id) AND recipient_id=sqlc.arg(recipient_id);

-- name: GetSigningResourceAccountsForUpdateV1 :many
-- LAST/NOWAIT after doc->ordered recipients->88/slots->85/87->86. Missing,
-- uninitialized or busy accounts refuse; callers never wait/retry under locks.
SELECT a.account_key,a.scope,a.org_id,a.state,a.baseline_snapshot_id,a.db_capacity_bytes,a.db_retained_bytes,
 a.provider_reserved_bytes,a.provider_reserved_objects,a.db_capacity_limit,a.provider_bytes_limit,a.provider_objects_limit
FROM signing_resource_accounts a
WHERE a.account_key IN('00000000-0000-0000-0000-000000000000'::uuid,sqlc.arg(org_id)::uuid)
ORDER BY a.account_key FOR UPDATE NOWAIT;

-- name: CaptureStagedSigningResourceInventoryV1 :one
-- Fixed SQL function derives every count/hash/byte total; no supplied amount.
-- Caller MUST hold global DB/process and authenticated controller staging scope
-- before this bounded metadata transaction. It performs no provider I/O and
-- leaves verification pending and all runtime admission unavailable.
SELECT id,inventory_scope,inventory_sha256,entry_count,document_count,known_db_bytes,
 known_provider_bytes,known_provider_objects,controller_receipt_id,receipt_storage_key,
 receipt_version_id,receipt_sha256,receipt_bytes,verification_state,unknown_provider_debt,captured_at
FROM hash_signing_resource_stage_inventory_v1(sqlc.arg(id)::uuid,sqlc.arg(controller_receipt_id)::uuid,
 sqlc.arg(receipt_storage_key)::text,sqlc.arg(receipt_version_id)::text,sqlc.arg(receipt_sha256)::bytea,sqlc.arg(receipt_bytes)::bigint);
