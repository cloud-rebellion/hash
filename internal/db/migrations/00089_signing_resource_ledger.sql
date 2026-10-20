-- +goose Up
-- Signing-scope logical debt only. No application policy is activated, no
-- physical disk/RSS/WAL claim is made, and no disposition/credit API exists.
-- Bootstrap is intentionally unavailable: staged inventory/pin metadata is NOT
-- controller verification. A real serialized collector and authenticated
-- administrative verifier must be wired before a later explicit activation.
-- Historical policy remains unchanged. All account acquisition is LAST/NOWAIT.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN
  RAISE EXCEPTION 'signing resource installation requires read committed' USING ERRCODE='23514';
 END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'signing resource rollback refuses active inventory' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

CREATE TABLE signing_resource_inventory_snapshots (
 id UUID PRIMARY KEY CHECK(id<>'00000000-0000-0000-0000-000000000000'),
 inventory_scope TEXT NOT NULL DEFAULT 'pdf-static-v1-signing' CHECK(inventory_scope='pdf-static-v1-signing'),
 inventory_sha256 BYTEA NOT NULL CHECK(octet_length(inventory_sha256)=32),
 entry_count BIGINT NOT NULL CHECK(entry_count BETWEEN 0 AND 65536),
 document_count BIGINT NOT NULL CHECK(document_count BETWEEN 0 AND 4096),
 known_db_bytes BIGINT NOT NULL CHECK(known_db_bytes BETWEEN 0 AND 1152921504606846976),
 known_provider_bytes BIGINT NOT NULL CHECK(known_provider_bytes BETWEEN 0 AND 1152921504606846976),
 known_provider_objects BIGINT NOT NULL CHECK(known_provider_objects BETWEEN 0 AND 1000000000),
 controller_receipt_id UUID NOT NULL CHECK(controller_receipt_id<>'00000000-0000-0000-0000-000000000000'),
 receipt_storage_key TEXT NOT NULL CHECK(octet_length(receipt_storage_key) BETWEEN 1 AND 2048 AND receipt_storage_key=btrim(receipt_storage_key) AND receipt_storage_key !~ '[[:cntrl:]]'),
 receipt_version_id TEXT NOT NULL CHECK(hash_signature_fit_version_valid(receipt_version_id)),
 receipt_sha256 BYTEA NOT NULL CHECK(octet_length(receipt_sha256)=32),
 receipt_bytes BIGINT NOT NULL CHECK(receipt_bytes BETWEEN 1 AND 8388608),
 verification_state TEXT NOT NULL DEFAULT 'pending' CHECK(verification_state='pending'),
 unknown_provider_debt BOOLEAN NOT NULL DEFAULT TRUE CHECK(unknown_provider_debt),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 captured_transaction_id XID8 NOT NULL DEFAULT pg_current_xact_id(),
 UNIQUE(controller_receipt_id)
);
CREATE TABLE signing_resource_inventory_entries (
 snapshot_id UUID NOT NULL REFERENCES signing_resource_inventory_snapshots(id) ON DELETE RESTRICT,
 org_id UUID NOT NULL,document_id UUID NOT NULL,ceremony_epoch TIMESTAMPTZ,
 kind TEXT NOT NULL,operation_id UUID NOT NULL,member_kind TEXT NOT NULL,page INTEGER NOT NULL,
 identity_sha256 BYTEA NOT NULL CHECK(octet_length(identity_sha256)=32),
 db_bytes BIGINT NOT NULL CHECK(db_bytes BETWEEN 0 AND 1152921504606846976),
 provider_bytes BIGINT NOT NULL CHECK(provider_bytes BETWEEN 0 AND 1152921504606846976),
 provider_objects BIGINT NOT NULL CHECK(provider_objects BETWEEN 0 AND 1000000000),
 PRIMARY KEY(snapshot_id,org_id,document_id,kind,operation_id,member_kind,page)
);
CREATE TABLE signing_resource_control (
 singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK(singleton),
 state TEXT NOT NULL DEFAULT 'uninitialized' CHECK(state IN('uninitialized','ready')),
 active_snapshot_id UUID REFERENCES signing_resource_inventory_snapshots(id) ON DELETE RESTRICT,
 controller_verification_receipt_id UUID,
 CHECK((state='uninitialized' AND active_snapshot_id IS NULL AND controller_verification_receipt_id IS NULL) OR
       (state='ready' AND active_snapshot_id IS NOT NULL AND controller_verification_receipt_id IS NOT NULL))
);
INSERT INTO signing_resource_control(singleton) VALUES(TRUE);
CREATE TABLE signing_resource_accounts (
 account_key UUID PRIMARY KEY,
 scope TEXT NOT NULL CHECK(scope IN('global','tenant')),
 org_id UUID REFERENCES orgs(id) ON DELETE RESTRICT,
 state TEXT NOT NULL DEFAULT 'uninitialized' CHECK(state IN('uninitialized','ready')),
 baseline_snapshot_id UUID REFERENCES signing_resource_inventory_snapshots(id) ON DELETE RESTRICT,
 baseline_db_capacity_bytes BIGINT NOT NULL DEFAULT 0 CHECK(baseline_db_capacity_bytes BETWEEN 0 AND 1152921504606846976),
 baseline_db_retained_bytes BIGINT NOT NULL DEFAULT 0 CHECK(baseline_db_retained_bytes BETWEEN 0 AND baseline_db_capacity_bytes),
 baseline_provider_bytes BIGINT NOT NULL DEFAULT 0 CHECK(baseline_provider_bytes BETWEEN 0 AND 1152921504606846976),
 baseline_provider_objects BIGINT NOT NULL DEFAULT 0 CHECK(baseline_provider_objects BETWEEN 0 AND 1000000000),
 db_capacity_bytes BIGINT NOT NULL DEFAULT 0 CHECK(db_capacity_bytes BETWEEN 0 AND 1152921504606846976),
 db_retained_bytes BIGINT NOT NULL DEFAULT 0 CHECK(db_retained_bytes BETWEEN 0 AND db_capacity_bytes),
 provider_reserved_bytes BIGINT NOT NULL DEFAULT 0 CHECK(provider_reserved_bytes BETWEEN 0 AND 1152921504606846976),
 provider_reserved_objects BIGINT NOT NULL DEFAULT 0 CHECK(provider_reserved_objects BETWEEN 0 AND 1000000000),
 db_capacity_limit BIGINT,provider_bytes_limit BIGINT,provider_objects_limit BIGINT,
 CHECK((scope='global' AND account_key='00000000-0000-0000-0000-000000000000' AND org_id IS NULL) OR (scope='tenant' AND org_id IS NOT NULL AND org_id=account_key)),
 CHECK(state='uninitialized' OR (baseline_snapshot_id IS NOT NULL AND db_capacity_limit IS NOT NULL AND provider_bytes_limit IS NOT NULL AND provider_objects_limit IS NOT NULL AND db_capacity_limit BETWEEN 1 AND 1152921504606846976 AND provider_bytes_limit BETWEEN 1 AND 1152921504606846976 AND provider_objects_limit BETWEEN 1 AND 1000000000 AND db_capacity_bytes<=db_capacity_limit AND provider_reserved_bytes<=provider_bytes_limit AND provider_reserved_objects<=provider_objects_limit))
);
CREATE UNIQUE INDEX signing_resource_account_org ON signing_resource_accounts(org_id) WHERE scope='tenant';
INSERT INTO signing_resource_accounts(account_key,scope) VALUES('00000000-0000-0000-0000-000000000000','global');

-- Capacity entitlements and measured retained bytes are separate. Materializing a
-- covered original adds retained bytes but never credits/reduces its reservation.
-- Future actor names are not recorded here. First preparation absorbs one slot's
-- conserved ceiling; every replacement preparation is ADDITIONAL debt.
CREATE TABLE signing_resource_fit_transfers (
 admission_id UUID NOT NULL,org_id UUID NOT NULL,document_id UUID NOT NULL,recipient_id UUID NOT NULL,
 preparation_id UUID NOT NULL UNIQUE,
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 PRIMARY KEY(admission_id,recipient_id),
 FOREIGN KEY(admission_id,recipient_id) REFERENCES document_signing_admission_slots(admission_id,recipient_id) ON DELETE RESTRICT,
 FOREIGN KEY(preparation_id,org_id,document_id,recipient_id) REFERENCES signature_fit_preparations(id,org_id,document_id,recipient_id) ON DELETE RESTRICT
);
CREATE TABLE signing_resource_finalization_transfers (
 admission_id UUID PRIMARY KEY,org_id UUID NOT NULL,document_id UUID NOT NULL,preparation_id UUID NOT NULL UNIQUE,
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 FOREIGN KEY(admission_id,org_id,document_id) REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT,
 FOREIGN KEY(preparation_id,org_id,document_id) REFERENCES document_finalization_preparations(id,org_id,document_id) ON DELETE RESTRICT
);
CREATE TABLE signing_resource_debts (
 org_id UUID NOT NULL,document_id UUID NOT NULL,ceremony_epoch TIMESTAMPTZ NOT NULL CHECK(isfinite(ceremony_epoch)),
 admission_id UUID NOT NULL,kind TEXT NOT NULL CHECK(kind IN('candidate','ordinary','fit','authority','payload','finalization','output','audit_input','certificate_input')),
 operation_id UUID NOT NULL,member_kind TEXT NOT NULL,page INTEGER NOT NULL CHECK(page BETWEEN 0 AND 500),
 identity_sha256 BYTEA NOT NULL CHECK(octet_length(identity_sha256)=32),
 db_capacity_bytes BIGINT NOT NULL CHECK(db_capacity_bytes BETWEEN 0 AND 1152921504606846976),
 db_retained_bytes BIGINT NOT NULL CHECK(db_retained_bytes BETWEEN 0 AND 1152921504606846976),
 provider_reserved_bytes BIGINT NOT NULL CHECK(provider_reserved_bytes BETWEEN 0 AND 1152921504606846976),
 provider_reserved_objects BIGINT NOT NULL CHECK(provider_reserved_objects BETWEEN 0 AND 1000000000),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 captured_transaction_id XID8 NOT NULL DEFAULT pg_current_xact_id(),
 PRIMARY KEY(org_id,document_id,kind,operation_id,member_kind,page),
 FOREIGN KEY(admission_id,org_id,document_id) REFERENCES document_signing_admissions(id,org_id,document_id) ON DELETE RESTRICT
);
CREATE INDEX signing_resource_debts_scope ON signing_resource_debts(org_id,document_id,admission_id);
-- One server-derived same-transaction/document batch owns the LAST account locks.
-- The batch guard derives every scalar from immutable debt rows; supplying this
-- row directly cannot provide a quota amount or forge a lock-completion marker.
CREATE TABLE signing_resource_debit_batches (
 captured_transaction_id XID8 PRIMARY KEY,
 org_id UUID NOT NULL,document_id UUID NOT NULL,
 debt_count BIGINT NOT NULL CHECK(debt_count BETWEEN 1 AND 65536),
 debt_sha256 BYTEA NOT NULL CHECK(octet_length(debt_sha256)=32),
 db_capacity_bytes BIGINT NOT NULL CHECK(db_capacity_bytes BETWEEN 0 AND 1152921504606846976),
 db_retained_bytes BIGINT NOT NULL CHECK(db_retained_bytes BETWEEN 0 AND 1152921504606846976),
 provider_reserved_bytes BIGINT NOT NULL CHECK(provider_reserved_bytes BETWEEN 0 AND 1152921504606846976),
 provider_reserved_objects BIGINT NOT NULL CHECK(provider_reserved_objects BETWEEN 0 AND 1000000000),
 captured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(captured_at)),
 FOREIGN KEY(document_id,org_id) REFERENCES documents(id,org_id) ON DELETE RESTRICT
);
CREATE INDEX signing_resource_debts_transaction ON signing_resource_debts(captured_transaction_id);


-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_immutable_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'signing resource inventory is immutable' USING ERRCODE='23514'; END $$;
CREATE FUNCTION hash_signing_resource_bootstrap_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 -- This unit deliberately has NO authenticated activation implementation. A
 -- metadata/pin/caller verification boolean cannot turn inventory into authority.
 IF TG_OP='DELETE' OR NEW.state<>'uninitialized' OR NEW.active_snapshot_id IS NOT NULL OR NEW.controller_verification_receipt_id IS NOT NULL THEN
  RAISE EXCEPTION 'signing resource controller activation unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION hash_signing_resource_account_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'signing resource accounts cannot be discarded' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.scope='tenant' THEN PERFORM 1 FROM signing_resource_control WHERE singleton FOR UPDATE NOWAIT; END IF;
   IF NEW.scope='tenant' AND (SELECT count(*) FROM signing_resource_accounts WHERE scope='tenant')>=4096 THEN RAISE EXCEPTION 'signing resource tenant catalog exceeds staged profile' USING ERRCODE='23514'; END IF;
  IF NEW.state<>'uninitialized' OR NEW.baseline_snapshot_id IS NOT NULL OR NEW.baseline_db_capacity_bytes<>0 OR NEW.baseline_db_retained_bytes<>0 OR NEW.baseline_provider_bytes<>0 OR NEW.baseline_provider_objects<>0 OR NEW.db_capacity_limit IS NOT NULL OR NEW.provider_bytes_limit IS NOT NULL OR NEW.provider_objects_limit IS NOT NULL OR NEW.db_capacity_bytes<>0 OR NEW.db_retained_bytes<>0 OR NEW.provider_reserved_bytes<>0 OR NEW.provider_reserved_objects<>0 THEN
   RAISE EXCEPTION 'signing resource verified baseline unavailable' USING ERRCODE='23514';
  END IF;
 ELSIF pg_trigger_depth()<2 THEN RAISE EXCEPTION 'signing resource counters require derived debit trigger' USING ERRCODE='23514';
 ELSIF ROW(NEW.account_key,NEW.scope,NEW.org_id,NEW.state,NEW.baseline_snapshot_id,NEW.baseline_db_capacity_bytes,NEW.baseline_db_retained_bytes,NEW.baseline_provider_bytes,NEW.baseline_provider_objects,NEW.db_capacity_limit,NEW.provider_bytes_limit,NEW.provider_objects_limit)
       IS DISTINCT FROM ROW(OLD.account_key,OLD.scope,OLD.org_id,OLD.state,OLD.baseline_snapshot_id,OLD.baseline_db_capacity_bytes,OLD.baseline_db_retained_bytes,OLD.baseline_provider_bytes,OLD.baseline_provider_objects,OLD.db_capacity_limit,OLD.provider_bytes_limit,OLD.provider_objects_limit)
       OR NEW.db_capacity_bytes<OLD.db_capacity_bytes OR NEW.db_retained_bytes<OLD.db_retained_bytes OR NEW.provider_reserved_bytes<OLD.provider_reserved_bytes OR NEW.provider_reserved_objects<OLD.provider_reserved_objects THEN
  RAISE EXCEPTION 'signing resource baseline/credit mutation unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION hash_signing_resource_require_accounts_v1(org UUID) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE global_account signing_resource_accounts%ROWTYPE; tenant_account signing_resource_accounts%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NOT EXISTS(SELECT 1 FROM signing_resource_control WHERE singleton AND state='ready') THEN
  RAISE EXCEPTION 'signing resources unavailable: verified inventory required' USING ERRCODE='23514';
 END IF;
 -- These are LAST after all relevant entity locks. Refuse immediately; never
 -- wait here while an existing permit owner needs those entity locks to finish.
 SELECT * INTO global_account FROM signing_resource_accounts WHERE account_key='00000000-0000-0000-0000-000000000000' FOR UPDATE NOWAIT;
 SELECT * INTO tenant_account FROM signing_resource_accounts WHERE account_key=org AND scope='tenant' AND org_id=org FOR UPDATE NOWAIT;
 IF global_account.state IS DISTINCT FROM 'ready' OR tenant_account.state IS DISTINCT FROM 'ready' THEN
  RAISE EXCEPTION 'signing resources unavailable: scoped baseline required' USING ERRCODE='23514';
 END IF;
EXCEPTION WHEN lock_not_available THEN
 RAISE EXCEPTION 'signing resources unavailable: account busy' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER signing_resource_control_guard BEFORE UPDATE OR DELETE ON signing_resource_control FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_bootstrap_guard_v1();
CREATE TRIGGER signing_resource_account_guard BEFORE INSERT OR UPDATE OR DELETE ON signing_resource_accounts FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_account_guard_v1();
CREATE TRIGGER signing_resource_snapshot_immutable BEFORE UPDATE OR DELETE ON signing_resource_inventory_snapshots FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();
CREATE TRIGGER signing_resource_entry_immutable BEFORE UPDATE OR DELETE ON signing_resource_inventory_entries FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();
CREATE TRIGGER signing_resource_fit_transfer_immutable BEFORE UPDATE OR DELETE ON signing_resource_fit_transfers FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();
CREATE TRIGGER signing_resource_final_transfer_immutable BEFORE UPDATE OR DELETE ON signing_resource_finalization_transfers FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();
CREATE TRIGGER signing_resource_debt_immutable BEFORE UPDATE OR DELETE ON signing_resource_debts FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();
CREATE TRIGGER signing_resource_batch_immutable BEFORE UPDATE OR DELETE ON signing_resource_debit_batches FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_immutable_v1();

-- Metadata-only inventory; no to_jsonb(whole bytea row) expansion. All retained
-- stale/cleaned/unknown rows in the opt-in signing scope are represented. The
-- fingerprint covers mutable checkpoints as well as immutable raw commitments.
-- This signing-scope floor is NOT the authenticated whole-bucket inventory.
CREATE VIEW signing_resource_current_inventory_v1 AS
SELECT d.org_id,d.id AS document_id,d.sent_at AS ceremony_epoch,'document'::text AS kind,d.id AS operation_id,''::text AS member_kind,0::integer AS page,
 digest(convert_to(jsonb_build_array(d.id,d.org_id,d.status,d.signing_admission_policy,d.signing_admission_active_id,d.signing_admission_sealed_id,d.pdf_storage_key,d.pdf_storage_version_id,encode(d.pdf_sha256,'hex'),hash_article13_canonical_sent_at(d.sent_at),d.deleted_at IS NOT NULL)::text,'UTF8'),'sha256') AS identity_sha256,
 (4096+octet_length(d.name)+COALESCE(octet_length(d.pdf_storage_key),0)+COALESCE(octet_length(d.pdf_storage_version_id),0))::bigint AS db_bytes,0::bigint AS provider_bytes,0::bigint AS provider_objects
FROM documents d WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'candidate',a.id,'',0,
 digest(convert_to(jsonb_build_array(a.id,encode(a.static_basis_sha256,'hex'),encode(a.static_basis_body_sha256,'hex'),encode(a.geometry_sha256,'hex'),encode(a.fields_sha256,'hex'),encode(a.parties_sha256,'hex'),encode(a.render_recipe_sha256,'hex'),a.status,a.owner_id,hash_article13_canonical_sent_at(a.lease_until),a.attempts)::text,'UTF8'),'sha256'),
 (octet_length(a.static_basis_payload)::bigint+octet_length(a.geometry_payload)+octet_length(a.geometry_pages_payload)+octet_length(a.fields_payload)+octet_length(a.parties_payload)+octet_length(a.render_recipe_payload)+octet_length(a.ordinary_recipe_payload)+octet_length(a.original_document_name)+octet_length(a.source_storage_key)+octet_length(a.source_version_id)+4096),(a.base_bytes_limit+a.final_pdf_bytes_limit+a.fits_index_bytes_limit+a.certificate_pdf_bytes_limit+a.certificate_payload_bytes_limit+a.certificate_signature_bytes_limit)::bigint,(cardinality(a.expected_ordinary_pages)+5)::bigint
FROM document_signing_admissions a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'ordinary',b.admission_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.page,encode(b.sha256,'hex'),b.bytes,encode(b.plan_sha256,'hex'),octet_length(b.plan_payload),encode(b.package_sha256,'hex'),encode(b.report_sha256,'hex'),encode(b.inspection_sha256,'hex'),b.captured_owner_id)::text,'UTF8'),'sha256'),
 (b.bytes+octet_length(b.plan_payload)+4096)::bigint,0::bigint,0::bigint
FROM document_signing_admission_bodies b JOIN document_signing_admissions a ON a.id=b.admission_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,p.recipient_id,encode(p.authority_sha256,'hex'),p.source_storage_key,p.source_version_id,encode(p.source_sha256,'hex'),p.source_bytes,encode(p.geometry_sha256,'hex'),encode(p.span_sha256,'hex'),p.reserved_bytes,p.expected_objects,p.status,p.owner_id,hash_article13_canonical_sent_at(p.lease_until),p.attempts,p.selection_commit_attempted_at IS NOT NULL,p.selection_not_committed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id))::bigint,p.reserved_bytes,p.expected_objects::bigint
FROM signature_fit_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'fit_object',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.cleanup_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM signature_fit_objects o JOIN signature_fit_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT a.org_id,a.document_id,a.ceremony_epoch,'authority',a.preparation_id,'',0,a.authority_sha256,(a.authority_bytes+4096+4*cardinality(a.occupied_pages))::bigint,0::bigint,0::bigint
FROM signature_fit_original_authorities a JOIN documents d ON d.id=a.document_id AND d.org_id=a.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT b.org_id,b.document_id,a.ceremony_epoch,'payload',b.preparation_id,b.kind,b.page,
 digest(convert_to(jsonb_build_array(b.kind,b.page,b.storage_key,encode(b.sha256,'hex'),b.bytes,b.content_type,b.captured_owner_id)::text,'UTF8'),'sha256'),(b.bytes+4096+octet_length(b.storage_key)+octet_length(b.content_type))::bigint,0::bigint,0::bigint
FROM signature_fit_original_payloads b JOIN signature_fit_original_authorities a ON a.preparation_id=b.preparation_id JOIN documents d ON d.id=b.document_id AND d.org_id=b.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'finalization',p.id,'',0,
 digest(convert_to(jsonb_build_array(p.id,encode(p.source_sha256,'hex'),p.source_version_id,encode(p.geometry_sha256,'hex'),encode(p.field_snapshot_sha256,'hex'),hash_article13_canonical_sent_at(p.completion_effective_at),p.status,p.expected_outputs,p.expected_references,encode(p.audit_snapshot_sha256,'hex'),encode(p.certificate_input_sha256,'hex'),p.publication_commit_attempted_at IS NOT NULL,p.published_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(p.geometry_pages_payload)+octet_length(p.field_snapshot_payload)+octet_length(p.original_document_name)+octet_length(p.source_storage_key)+octet_length(p.source_version_id)+COALESCE(octet_length(p.audit_snapshot_payload),0)+COALESCE(octet_length(p.certificate_input_payload),0))::bigint,
 (p.base_bytes_limit+p.final_pdf_bytes_limit+p.fits_index_bytes_limit+p.certificate_pdf_bytes_limit+p.certificate_payload_bytes_limit+p.certificate_signature_bytes_limit)::bigint,p.expected_outputs::bigint
FROM document_finalization_preparations p JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'output',p.id,o.kind,o.page,
 digest(convert_to(jsonb_build_array(o.kind,o.page,o.storage_key,encode(o.sha256,'hex'),o.bytes,o.content_type,o.version_id,o.upload_attempted_at IS NOT NULL,o.readback_verified_at IS NOT NULL,o.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (o.bytes+4096+octet_length(o.storage_key)+octet_length(o.content_type)+COALESCE(octet_length(o.version_id),0))::bigint,0::bigint,0::bigint
FROM document_finalization_outputs o JOIN document_finalization_preparations p ON p.id=o.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT sl.org_id,sl.document_id,a.ceremony_epoch,'slot',sl.admission_id,sl.recipient_id::text,0,
 digest(convert_to(jsonb_build_array(sl.recipient_id,sl.target_ids,sl.occupied_pages,sl.expected_objects,sl.fit_bytes_limit,sl.pdf_bytes_limit,sl.designated_preparation_id,sl.designated_owner_id)::text,'UTF8'),'sha256'),
 (4096+16*sl.target_count+4*sl.page_count)::bigint,sl.fit_bytes_limit,sl.expected_objects::bigint
FROM document_signing_admission_slots sl JOIN document_signing_admissions a ON a.id=sl.admission_id JOIN documents d ON d.id=sl.document_id AND d.org_id=sl.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT se.org_id,se.document_id,se.ceremony_epoch,'selection',se.id,'',0,
 digest(convert_to(jsonb_build_array(se.id,se.preparation_id,se.recipient_id,encode(se.authority_sha256,'hex'),se.span_storage_key,se.span_version_id,encode(se.span_sha256,'hex'),se.span_bytes,se.manifest_storage_key,se.manifest_version_id,encode(se.manifest_sha256,'hex'),se.manifest_bytes,hash_article13_canonical_sent_at(se.retain_until),se.retention_started_at IS NOT NULL,se.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(se.source_storage_key)+octet_length(se.source_version_id)+octet_length(se.span_storage_key)+octet_length(se.span_version_id)+octet_length(se.manifest_storage_key)+octet_length(se.manifest_version_id))::bigint,0::bigint,0::bigint
FROM signature_fit_selections se JOIN documents d ON d.id=se.document_id AND d.org_id=se.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT co.org_id,co.document_id,d.sent_at,'companion',co.signature_id,'',0,
 digest(convert_to(jsonb_build_array(co.signature_id,co.recipient_id,co.field_id,co.selection_id,encode(co.span_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_fit_companions co JOIN documents d ON d.id=co.document_id AND d.org_id=co.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT bi.org_id,bi.document_id,a.ceremony_epoch,'binding',bi.signature_id,'',0,
 digest(convert_to(jsonb_build_array(bi.signature_id,bi.admission_id,bi.recipient_id,bi.field_id,bi.selection_id,bi.signed_event_id,encode(bi.static_basis_sha256,'hex'),encode(bi.reviewed_basis_sha256,'hex'))::text,'UTF8'),'sha256'),4096::bigint,0::bigint,0::bigint
FROM signature_signing_admission_bindings bi JOIN document_signing_admissions a ON a.id=bi.admission_id JOIN documents d ON d.id=bi.document_id AND d.org_id=bi.org_id WHERE d.signing_admission_policy='pdf-static-v1'
UNION ALL
SELECT p.org_id,p.document_id,p.ceremony_epoch,'reference',p.id,r.kind||'/'||r.owner_key::text,r.page,
 digest(convert_to(jsonb_build_array(r.kind,r.owner_key,r.signature_id,r.selection_id,r.page,r.storage_key,r.version_id,encode(r.sha256,'hex'),r.bytes,r.content_type,r.retention_started_at IS NOT NULL,r.retention_completed_at IS NOT NULL)::text,'UTF8'),'sha256'),
 (4096+octet_length(r.storage_key)+octet_length(r.version_id)+octet_length(r.content_type))::bigint,0::bigint,0::bigint
FROM document_finalization_references r JOIN document_finalization_preparations p ON p.id=r.preparation_id JOIN documents d ON d.id=p.document_id AND d.org_id=p.org_id WHERE d.signing_admission_policy='pdf-static-v1';

-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_snapshot_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE rows_count BIGINT; docs_count BIGINT; db_total NUMERIC; provider_total NUMERIC; objects_total NUMERIC; fingerprint BYTEA;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NEW.verification_state<>'pending' OR NOT NEW.unknown_provider_debt THEN
  RAISE EXCEPTION 'signing resource staged snapshot is not verification' USING ERRCODE='23514';
 END IF;
 -- Take the serialized metadata snapshot ourselves, including direct SQL.
 -- Admission/collector resources MUST be held before dispatch. No provider I/O
 -- occurs under locks; active writers make staging refuse rather than wait.
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 PERFORM 1 FROM signing_resource_control WHERE singleton FOR UPDATE NOWAIT;
  IF (SELECT count(*) FROM signing_resource_inventory_snapshots)>=8 THEN
  RAISE EXCEPTION 'signing resource staged snapshot inventory full' USING ERRCODE='23514';
 END IF;

 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'signing resource snapshot transaction differs' USING ERRCODE='23514'; END IF;
 SELECT count(*),count(DISTINCT document_id) INTO rows_count,docs_count FROM signing_resource_current_inventory_v1;
 IF rows_count>65536 OR docs_count>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514'; END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
  digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_total,provider_total,objects_total,fingerprint FROM signing_resource_current_inventory_v1;
 IF db_total>1152921504606846976 OR provider_total>1152921504606846976 OR objects_total>1000000000 OR
  ROW(NEW.entry_count,NEW.document_count,NEW.known_db_bytes,NEW.known_provider_bytes,NEW.known_provider_objects,NEW.inventory_sha256)
  IS DISTINCT FROM ROW(rows_count,docs_count,db_total::bigint,provider_total::bigint,objects_total::bigint,fingerprint) THEN
  RAISE EXCEPTION 'signing resource snapshot differs from exact scoped inventory' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION hash_signing_resource_entry_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM signing_resource_inventory_snapshots sn WHERE sn.id=NEW.snapshot_id AND sn.captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource snapshot cannot be appended after capture' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM signing_resource_current_inventory_v1 inv WHERE
  ROW(inv.org_id,inv.document_id,inv.ceremony_epoch,inv.kind,inv.operation_id,inv.member_kind,inv.page,inv.identity_sha256,inv.db_bytes,inv.provider_bytes,inv.provider_objects)
  IS NOT DISTINCT FROM ROW(NEW.org_id,NEW.document_id,NEW.ceremony_epoch,NEW.kind,NEW.operation_id,NEW.member_kind,NEW.page,NEW.identity_sha256,NEW.db_bytes,NEW.provider_bytes,NEW.provider_objects)) THEN
  RAISE EXCEPTION 'signing resource baseline entry differs from inventory' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION hash_signing_resource_snapshot_pair_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE snapshot signing_resource_inventory_snapshots%ROWTYPE; snapshot_id_value UUID; n BIGINT;
BEGIN
 snapshot_id_value:=NEW.id;
 SELECT * INTO STRICT snapshot FROM signing_resource_inventory_snapshots WHERE id=snapshot_id_value;
 SELECT count(*) INTO n FROM signing_resource_inventory_entries WHERE snapshot_id=snapshot_id_value;
 IF n<>snapshot.entry_count OR EXISTS(
  (SELECT org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects FROM signing_resource_current_inventory_v1
   EXCEPT SELECT org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects FROM signing_resource_inventory_entries WHERE snapshot_id=snapshot_id_value)
  UNION ALL
  (SELECT org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects FROM signing_resource_inventory_entries WHERE snapshot_id=snapshot_id_value
   EXCEPT SELECT org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects FROM signing_resource_current_inventory_v1)) THEN
  RAISE EXCEPTION 'signing resource staged inventory is incomplete or raced' USING ERRCODE='23514';
 END IF;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER signing_resource_snapshot_guard BEFORE INSERT ON signing_resource_inventory_snapshots FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_snapshot_guard_v1();
CREATE TRIGGER signing_resource_entry_guard BEFORE INSERT ON signing_resource_inventory_entries FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_entry_guard_v1();
CREATE CONSTRAINT TRIGGER signing_resource_snapshot_pair AFTER INSERT ON signing_resource_inventory_snapshots DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_snapshot_pair_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_entities_v1(org UUID,doc UUID) RETURNS UUID LANGUAGE plpgsql AS $$
DECLARE document_row documents%ROWTYPE; admission_id_value UUID;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource scope requires read committed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT document_row FROM documents WHERE id=doc AND org_id=org FOR UPDATE;
 IF document_row.signing_admission_policy='historical' THEN RETURN NULL; END IF;
 IF document_row.signing_admission_policy<>'pdf-static-v1' THEN RAISE EXCEPTION 'signing resource policy unavailable' USING ERRCODE='23514'; END IF;
 -- Parent serialization also fences all guarded child writers. No body decoding
 -- or provider I/O, and no account is locked until these entity locks are owned.
 IF (SELECT count(*) FROM recipients WHERE document_id=doc)>100 OR (SELECT count(*) FROM signature_fit_preparations WHERE document_id=doc)>1024 OR (SELECT count(*) FROM document_signing_admissions WHERE document_id=doc)>8 THEN
  RAISE EXCEPTION 'signing resource entity inventory exceeds profile' USING ERRCODE='23514';
 END IF;
 PERFORM 1 FROM recipients WHERE document_id=doc ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admissions WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM document_signing_admission_slots WHERE document_id=doc AND org_id=org ORDER BY admission_id,recipient_id FOR UPDATE;
 PERFORM 1 FROM signature_fit_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 PERFORM 1 FROM signature_fit_original_authorities WHERE document_id=doc AND org_id=org ORDER BY preparation_id FOR UPDATE;
 PERFORM 1 FROM document_finalization_preparations WHERE document_id=doc AND org_id=org ORDER BY id FOR UPDATE;
 admission_id_value:=COALESCE(document_row.signing_admission_sealed_id,document_row.signing_admission_active_id);
 RETURN admission_id_value;
END $$;
CREATE FUNCTION hash_signing_resource_candidate_db_v1(a document_signing_admissions) RETURNS BIGINT LANGUAGE sql IMMUTABLE AS $$
 SELECT octet_length(a.static_basis_payload)::bigint+octet_length(a.geometry_payload)+octet_length(a.geometry_pages_payload)+octet_length(a.fields_payload)+octet_length(a.parties_payload)+octet_length(a.render_recipe_payload)+octet_length(a.ordinary_recipe_payload)+octet_length(a.original_document_name)+octet_length(a.source_storage_key)+octet_length(a.source_version_id)+4096;
$$;
CREATE FUNCTION hash_signing_resource_common_provider_v1(a document_signing_admissions) RETURNS BIGINT LANGUAGE sql IMMUTABLE AS $$
 SELECT a.base_bytes_limit+a.final_pdf_bytes_limit+a.fits_index_bytes_limit+a.certificate_pdf_bytes_limit+a.certificate_payload_bytes_limit+a.certificate_signature_bytes_limit;
$$;
CREATE FUNCTION hash_signing_resource_common_db_v1(a document_signing_admissions) RETURNS BIGINT LANGUAGE sql IMMUTABLE AS $$
 SELECT hash_signing_resource_common_provider_v1(a)+8388608+2097152+65536+2048+8192*(cardinality(a.expected_ordinary_pages)::bigint+9);
$$;
CREATE FUNCTION hash_signing_resource_fit_db_v1(bytes BIGINT,objects INTEGER) RETURNS BIGINT LANGUAGE sql IMMUTABLE AS $$
 SELECT bytes+1048576+8192*(objects::bigint+4);
$$;

-- The debit guard derives the entire row from immutable inventory. No public
-- query accepts arbitrary charge amounts. A rejected debit rolls back its source
-- row and all counters. No durable credit is inferred from materialization.
CREATE FUNCTION hash_signing_resource_debt_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; prep signature_fit_preparations%ROWTYPE;
 ordinary document_signing_admission_bodies%ROWTYPE; original signature_fit_original_payloads%ROWTYPE; authority signature_fit_original_authorities%ROWTYPE;
 finalization document_finalization_preparations%ROWTYPE; output document_finalization_outputs%ROWTYPE;
 expected_capacity BIGINT:=0; expected_retained BIGINT:=0; expected_provider BIGINT:=0; expected_objects BIGINT:=0; expected_identity BYTEA;
 fit_bytes NUMERIC; fit_db NUMERIC; fit_objects NUMERIC; slots_db NUMERIC; epoch TIMESTAMPTZ;
 account_global signing_resource_accounts%ROWTYPE; account_tenant signing_resource_accounts%ROWTYPE; account_key_value UUID;
BEGIN
 IF NEW.org_id='00000000-0000-0000-0000-000000000000' THEN RAISE EXCEPTION 'signing resource tenant is invalid' USING ERRCODE='23514'; END IF;
 IF NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() OR EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource transaction is already account-sealed' USING ERRCODE='23514'; END IF;
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=NEW.org_id AND document_id=NEW.document_id;
 epoch:=a.ceremony_epoch;
 IF NEW.kind='candidate' THEN
  IF NEW.operation_id<>a.id OR NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource candidate identity differs' USING ERRCODE='23514'; END IF;
  SELECT COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0)
   INTO fit_bytes,fit_db,fit_objects,slots_db FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_bytes>1152921504606846976 OR fit_db>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  expected_retained:=hash_signing_resource_candidate_db_v1(a)+slots_db::bigint;
  expected_capacity:=expected_retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_db::bigint;
  expected_provider:=hash_signing_resource_common_provider_v1(a)+fit_bytes::bigint;
  expected_objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;expected_identity:=a.static_basis_body_sha256;
 ELSIF NEW.kind='ordinary' THEN
  SELECT * INTO STRICT ordinary FROM document_signing_admission_bodies WHERE admission_id=a.id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  IF NEW.operation_id<>a.id THEN RAISE EXCEPTION 'signing resource ordinary identity differs' USING ERRCODE='23514'; END IF;
  expected_retained:=ordinary.bytes+octet_length(ordinary.plan_payload)+4096;expected_identity:=digest(ordinary.sha256||ordinary.plan_sha256||ordinary.package_sha256||ordinary.report_sha256||ordinary.inspection_sha256,'sha256');
 ELSIF NEW.kind='fit' THEN
  SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.member_kind<>'' OR NEW.page<>0 OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id AND sl.recipient_id=prep.recipient_id AND prep.expected_objects=sl.expected_objects AND prep.reserved_bytes<=sl.fit_bytes_limit) THEN RAISE EXCEPTION 'signing resource preparation differs from slot' USING ERRCODE='23514'; END IF;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=prep.recipient_id AND tr.preparation_id=prep.id) THEN
   expected_capacity:=hash_signing_resource_fit_db_v1(prep.reserved_bytes,prep.expected_objects);expected_provider:=prep.reserved_bytes;expected_objects:=prep.expected_objects;
  END IF;
  expected_retained:=4096+octet_length(prep.source_storage_key)+octet_length(prep.source_version_id);expected_identity:=prep.authority_sha256;
 ELSIF NEW.kind='authority' THEN
  IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource authority member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT authority FROM signature_fit_original_authorities WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  expected_retained:=authority.authority_bytes+4096+4*cardinality(authority.occupied_pages);expected_identity:=authority.authority_sha256;
 ELSIF NEW.kind='payload' THEN
  SELECT * INTO STRICT original FROM signature_fit_original_payloads WHERE preparation_id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND kind=NEW.member_kind AND page=NEW.page;
  expected_retained:=original.bytes+4096+octet_length(original.storage_key)+octet_length(original.content_type);expected_identity:=original.sha256;
 ELSIF NEW.kind IN('finalization','output','audit_input','certificate_input') THEN
  IF NEW.kind IN('audit_input','certificate_input') AND (NEW.member_kind<>'' OR NEW.page<>0) THEN RAISE EXCEPTION 'signing resource input member differs' USING ERRCODE='23514'; END IF;
  SELECT * INTO STRICT finalization FROM document_finalization_preparations WHERE id=NEW.operation_id AND org_id=a.org_id AND document_id=a.document_id AND ceremony_epoch=a.ceremony_epoch;
  IF NEW.kind='finalization' THEN
   IF NEW.member_kind<>'' OR NEW.page<>0 THEN RAISE EXCEPTION 'signing resource finalization identity differs' USING ERRCODE='23514'; END IF;
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=finalization.id) THEN
    expected_capacity:=hash_signing_resource_common_db_v1(a);expected_provider:=hash_signing_resource_common_provider_v1(a);expected_objects:=cardinality(a.expected_ordinary_pages)+5;
   END IF;
   expected_retained:=4096+octet_length(finalization.geometry_pages_payload)+octet_length(finalization.field_snapshot_payload)+octet_length(finalization.original_document_name)+octet_length(finalization.source_storage_key)+octet_length(finalization.source_version_id);expected_identity:=finalization.field_snapshot_sha256;
  ELSIF NEW.kind='output' THEN
   SELECT * INTO STRICT output FROM document_finalization_outputs WHERE preparation_id=finalization.id AND kind=NEW.member_kind AND page=NEW.page;
   expected_retained:=output.bytes+4096+octet_length(output.storage_key)+octet_length(output.content_type);expected_identity:=output.sha256;
  ELSIF NEW.kind='audit_input' THEN expected_retained:=octet_length(finalization.audit_snapshot_payload)+4096;expected_identity:=finalization.audit_snapshot_sha256;
  ELSE expected_retained:=octet_length(finalization.certificate_input_payload)+4096;expected_identity:=finalization.certificate_input_sha256;
  END IF;
 ELSE RAISE EXCEPTION 'signing resource inventory kind is invalid' USING ERRCODE='23514'; END IF;
 IF expected_identity IS NULL OR ROW(NEW.ceremony_epoch,NEW.identity_sha256,NEW.db_capacity_bytes,NEW.db_retained_bytes,NEW.provider_reserved_bytes,NEW.provider_reserved_objects)
   IS DISTINCT FROM ROW(epoch,expected_identity,expected_capacity,expected_retained,expected_provider,expected_objects) THEN
  RAISE EXCEPTION 'signing resource debit differs from derived inventory' USING ERRCODE='23514';
 END IF;
 -- Account application is deferred until the complete same-transaction tuple exists.
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER signing_resource_debt_guard BEFORE INSERT ON signing_resource_debts FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_debt_guard_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_batch_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE n BIGINT; orgs_count BIGINT; docs_count BIGINT; org_value UUID; doc_value UUID;
 capacity_sum NUMERIC; retained_sum NUMERIC; provider_sum NUMERIC; objects_sum NUMERIC; identity_value BYTEA; account_key_value UUID;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' OR NEW.captured_transaction_id IS DISTINCT FROM pg_current_xact_id() THEN RAISE EXCEPTION 'signing resource batch must own current transaction' USING ERRCODE='23514'; END IF;
 SELECT count(*),count(DISTINCT dr.org_id),count(DISTINCT dr.document_id),min(dr.org_id::text)::uuid,min(dr.document_id::text)::uuid
 INTO n,orgs_count,docs_count,org_value,doc_value FROM signing_resource_debts dr WHERE dr.captured_transaction_id=NEW.captured_transaction_id;
 IF n NOT BETWEEN 1 AND 65536 OR orgs_count<>1 OR docs_count<>1 OR ROW(NEW.org_id,NEW.document_id) IS DISTINCT FROM ROW(org_value,doc_value) THEN RAISE EXCEPTION 'signing resource batch requires one exact document transaction' USING ERRCODE='23514'; END IF;
 -- All source rows are now present. Acquire the complete entity set ONCE before
 -- accounts. Every later source/debt insert in this transaction is refused.
 PERFORM hash_signing_resource_entities_v1(org_value,doc_value);
 SELECT COALESCE(sum(dr.db_capacity_bytes::numeric),0),COALESCE(sum(dr.db_retained_bytes::numeric),0),COALESCE(sum(dr.provider_reserved_bytes::numeric),0),COALESCE(sum(dr.provider_reserved_objects::numeric),0),
 digest(convert_to(string_agg(dr.kind||'/'||dr.operation_id::text||'/'||dr.member_kind||'/'||dr.page::text||'/'||encode(dr.identity_sha256,'hex')||'/'||dr.db_capacity_bytes::text||'/'||dr.db_retained_bytes::text||'/'||dr.provider_reserved_bytes::text||'/'||dr.provider_reserved_objects::text,E'\n' ORDER BY dr.kind,dr.operation_id,dr.member_kind,dr.page),'UTF8'),'sha256')
 INTO capacity_sum,retained_sum,provider_sum,objects_sum,identity_value FROM signing_resource_debts dr WHERE dr.captured_transaction_id=NEW.captured_transaction_id;
 IF capacity_sum>1152921504606846976 OR retained_sum>1152921504606846976 OR provider_sum>1152921504606846976 OR objects_sum>1000000000 OR
 ROW(NEW.debt_count,NEW.debt_sha256,NEW.db_capacity_bytes,NEW.db_retained_bytes,NEW.provider_reserved_bytes,NEW.provider_reserved_objects)
 IS DISTINCT FROM ROW(n,identity_value,capacity_sum::bigint,retained_sum::bigint,provider_sum::bigint,objects_sum::bigint) THEN RAISE EXCEPTION 'signing resource batch differs from derived debts' USING ERRCODE='23514'; END IF;
 PERFORM hash_signing_resource_require_accounts_v1(org_value);
 -- The batch row has a fixed conservative 4096-byte logical metadata charge;
 -- this charge is additional and never receives a disposition/retry credit.
 FOREACH account_key_value IN ARRAY ARRAY['00000000-0000-0000-0000-000000000000'::uuid,org_value] LOOP
  UPDATE signing_resource_accounts ac SET db_capacity_bytes=(ac.db_capacity_bytes::numeric+capacity_sum+4096)::bigint,
   db_retained_bytes=(ac.db_retained_bytes::numeric+retained_sum+4096)::bigint,
   provider_reserved_bytes=(ac.provider_reserved_bytes::numeric+provider_sum)::bigint,
   provider_reserved_objects=(ac.provider_reserved_objects::numeric+objects_sum)::bigint
  WHERE ac.account_key=account_key_value AND ac.state='ready' AND ac.db_capacity_bytes::numeric+capacity_sum+4096<=ac.db_capacity_limit
   AND ac.db_retained_bytes::numeric+retained_sum+4096<=ac.db_capacity_bytes::numeric+capacity_sum+4096
   AND ac.provider_reserved_bytes::numeric+provider_sum<=ac.provider_bytes_limit AND ac.provider_reserved_objects::numeric+objects_sum<=ac.provider_objects_limit;
  IF NOT FOUND THEN RAISE EXCEPTION 'signing resource quota unavailable' USING ERRCODE='23514'; END IF;
 END LOOP;
 RETURN NEW;
END $$;
CREATE FUNCTION hash_signing_resource_commit_debts_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=NEW.captured_transaction_id) THEN RETURN NULL; END IF;
 INSERT INTO signing_resource_debit_batches(captured_transaction_id,org_id,document_id,debt_count,debt_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects)
 SELECT NEW.captured_transaction_id,min(dr.org_id::text)::uuid,min(dr.document_id::text)::uuid,count(*),
 digest(convert_to(string_agg(dr.kind||'/'||dr.operation_id::text||'/'||dr.member_kind||'/'||dr.page::text||'/'||encode(dr.identity_sha256,'hex')||'/'||dr.db_capacity_bytes::text||'/'||dr.db_retained_bytes::text||'/'||dr.provider_reserved_bytes::text||'/'||dr.provider_reserved_objects::text,E'\n' ORDER BY dr.kind,dr.operation_id,dr.member_kind,dr.page),'UTF8'),'sha256'),
 sum(dr.db_capacity_bytes::numeric)::bigint,sum(dr.db_retained_bytes::numeric)::bigint,sum(dr.provider_reserved_bytes::numeric)::bigint,sum(dr.provider_reserved_objects::numeric)::bigint
 FROM signing_resource_debts dr WHERE dr.captured_transaction_id=NEW.captured_transaction_id;
 RETURN NULL;
END $$;
-- +goose StatementEnd
CREATE TRIGGER signing_resource_batch_guard BEFORE INSERT ON signing_resource_debit_batches FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_batch_guard_v1();
CREATE CONSTRAINT TRIGGER zz_signing_resource_commit_debts AFTER INSERT ON signing_resource_debts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_commit_debts_v1();


-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_before_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID; policy_value TEXT;
BEGIN
 IF TG_TABLE_NAME IN('signature_fit_objects','document_finalization_outputs') THEN
  IF TG_TABLE_NAME='signature_fit_objects' THEN SELECT org_id,document_id INTO STRICT org_value,doc_value FROM signature_fit_preparations WHERE id=NEW.preparation_id;
  ELSE SELECT org_id,document_id INTO STRICT org_value,doc_value FROM document_finalization_preparations WHERE id=NEW.preparation_id; END IF;
 ELSE org_value:=NEW.org_id;doc_value:=NEW.document_id; END IF;
 SELECT signing_admission_policy INTO STRICT policy_value FROM documents WHERE id=doc_value AND org_id=org_value;
 IF policy_value='historical' THEN RETURN NEW; END IF;
 -- Fast unavailable refusal BEFORE existing JSON/BYTEA checks. This is not an
 -- account lock or grant. A future READY implementation still derives/debits
 -- AFTER all guarded entity rows/slots are present in this SAME transaction.
 IF NOT EXISTS(SELECT 1 FROM signing_resource_control WHERE singleton AND state='ready') THEN
  RAISE EXCEPTION 'signing resources unavailable: verified inventory required' USING ERRCODE='23514';
 END IF;
 IF EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource transaction already owns account locks' USING ERRCODE='23514'; END IF;
 PERFORM hash_signing_resource_entities_v1(org_value,doc_value);
 RETURN NEW;
END $$;

CREATE FUNCTION hash_signing_resource_record_v1(org UUID,doc UUID,admission UUID,resource_kind TEXT,operation UUID,member TEXT,member_page INTEGER) RETURNS VOID LANGUAGE plpgsql AS $$
DECLARE a document_signing_admissions%ROWTYPE; p signature_fit_preparations%ROWTYPE; b document_signing_admission_bodies%ROWTYPE;
 orig signature_fit_original_payloads%ROWTYPE; au signature_fit_original_authorities%ROWTYPE; fp document_finalization_preparations%ROWTYPE; outrow document_finalization_outputs%ROWTYPE;
 capacity BIGINT:=0; retained BIGINT:=0; provider BIGINT:=0; objects BIGINT:=0; identity BYTEA; fit_capacity NUMERIC; fit_provider NUMERIC; fit_objects NUMERIC; slot_retained NUMERIC;
BEGIN
 SELECT * INTO STRICT a FROM document_signing_admissions WHERE id=admission AND org_id=org AND document_id=doc;
 IF resource_kind='candidate' THEN
  SELECT COALESCE(sum(hash_signing_resource_fit_db_v1(sl.fit_bytes_limit,sl.expected_objects)::numeric),0),COALESCE(sum(sl.fit_bytes_limit::numeric),0),COALESCE(sum(sl.expected_objects::numeric),0),COALESCE(sum((4096+16*sl.target_count+4*sl.page_count)::numeric),0) INTO fit_capacity,fit_provider,fit_objects,slot_retained FROM document_signing_admission_slots sl WHERE sl.admission_id=a.id;
  IF fit_capacity>1152921504606846976 OR fit_provider>1152921504606846976 OR fit_objects>1000000000 THEN RAISE EXCEPTION 'signing resource entitlement overflow' USING ERRCODE='23514'; END IF;
  retained:=hash_signing_resource_candidate_db_v1(a)+slot_retained::bigint;
  capacity:=retained+a.base_bytes_limit+LEAST(8388608::bigint,cardinality(a.expected_ordinary_pages)::bigint*1048576)+8192*cardinality(a.expected_ordinary_pages)::bigint+hash_signing_resource_common_db_v1(a)+fit_capacity::bigint;
  provider:=hash_signing_resource_common_provider_v1(a)+fit_provider::bigint;objects:=cardinality(a.expected_ordinary_pages)+5+fit_objects::bigint;identity:=a.static_basis_body_sha256;
 ELSIF resource_kind='ordinary' THEN SELECT * INTO STRICT b FROM document_signing_admission_bodies WHERE admission_id=a.id AND kind=member AND page=member_page;retained:=b.bytes+octet_length(b.plan_payload)+4096;identity:=digest(b.sha256||b.plan_sha256||b.package_sha256||b.report_sha256||b.inspection_sha256,'sha256');
 ELSIF resource_kind='fit' THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=a.id AND tr.recipient_id=p.recipient_id AND tr.preparation_id=p.id) THEN capacity:=hash_signing_resource_fit_db_v1(p.reserved_bytes,p.expected_objects);provider:=p.reserved_bytes;objects:=p.expected_objects;END IF;
  retained:=4096+octet_length(p.source_storage_key)+octet_length(p.source_version_id);identity:=p.authority_sha256;
 ELSIF resource_kind='authority' THEN SELECT * INTO STRICT au FROM signature_fit_original_authorities WHERE preparation_id=operation AND org_id=org AND document_id=doc;retained:=au.authority_bytes+4096+4*cardinality(au.occupied_pages);identity:=au.authority_sha256;
 ELSIF resource_kind='payload' THEN SELECT * INTO STRICT orig FROM signature_fit_original_payloads WHERE preparation_id=operation AND org_id=org AND document_id=doc AND kind=member AND page=member_page;retained:=orig.bytes+4096+octet_length(orig.storage_key)+octet_length(orig.content_type);identity:=orig.sha256;
 ELSE
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation AND org_id=org AND document_id=doc;
  IF resource_kind='finalization' THEN
   IF NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=a.id AND tr.preparation_id=fp.id) THEN capacity:=hash_signing_resource_common_db_v1(a);provider:=hash_signing_resource_common_provider_v1(a);objects:=cardinality(a.expected_ordinary_pages)+5;END IF;
   retained:=4096+octet_length(fp.geometry_pages_payload)+octet_length(fp.field_snapshot_payload)+octet_length(fp.original_document_name)+octet_length(fp.source_storage_key)+octet_length(fp.source_version_id);identity:=fp.field_snapshot_sha256;
  ELSIF resource_kind='output' THEN SELECT * INTO STRICT outrow FROM document_finalization_outputs WHERE preparation_id=operation AND kind=member AND page=member_page;retained:=outrow.bytes+4096+octet_length(outrow.storage_key)+octet_length(outrow.content_type);identity:=outrow.sha256;
  ELSIF resource_kind='audit_input' THEN retained:=octet_length(fp.audit_snapshot_payload)+4096;identity:=fp.audit_snapshot_sha256;
  ELSIF resource_kind='certificate_input' THEN retained:=octet_length(fp.certificate_input_payload)+4096;identity:=fp.certificate_input_sha256;
  ELSE RAISE EXCEPTION 'signing resource kind unavailable' USING ERRCODE='23514';END IF;
 END IF;
 INSERT INTO signing_resource_debts(org_id,document_id,ceremony_epoch,admission_id,kind,operation_id,member_kind,page,identity_sha256,db_capacity_bytes,db_retained_bytes,provider_reserved_bytes,provider_reserved_objects)
 VALUES(org,doc,a.ceremony_epoch,a.id,resource_kind,operation,member,member_page,identity,capacity,retained,provider,objects);
END $$;

CREATE FUNCTION hash_signing_resource_after_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;admission UUID; policy_value TEXT; source_preparation UUID; p signature_fit_preparations%ROWTYPE; fp document_finalization_preparations%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signature_fit_objects' THEN RETURN NEW; END IF;
 IF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;
 ELSE org_value:=NEW.org_id;doc_value:=NEW.document_id; END IF;
 SELECT signing_admission_policy INTO STRICT policy_value FROM documents WHERE id=doc_value AND org_id=org_value;
 IF policy_value='historical' THEN RETURN NEW; END IF;
 admission:=hash_signing_resource_entities_v1(org_value,doc_value);
 IF TG_TABLE_NAME='document_signing_admissions' THEN admission:=NEW.id;PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'candidate',NEW.id,'',0);
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,NEW.admission_id,'ordinary',NEW.admission_id,NEW.kind,NEW.page);
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN
  IF admission IS NULL THEN RAISE EXCEPTION 'signing resource preparation requires current static admission' USING ERRCODE='23514';END IF;
  -- The first logical prep conserves the ENTIRE unknown-name slot ceiling.
  -- Later preparations add their own immutable ceiling; old debt is not freed.
  INSERT INTO signing_resource_fit_transfers(admission_id,org_id,document_id,recipient_id,preparation_id)
   SELECT admission,org_value,doc_value,NEW.recipient_id,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_fit_transfers tr WHERE tr.admission_id=admission AND tr.recipient_id=NEW.recipient_id);
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'fit',NEW.id,'',0);
 ELSIF TG_TABLE_NAME IN('signature_fit_original_authorities','signature_fit_original_payloads') THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='fit' AND debt.operation_id=NEW.preparation_id;
  IF TG_TABLE_NAME='signature_fit_original_authorities' THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'authority',NEW.preparation_id,'',0);
  ELSE PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'payload',NEW.preparation_id,NEW.kind,NEW.page);END IF;
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN
  IF TG_OP='INSERT' THEN
   INSERT INTO signing_resource_finalization_transfers(admission_id,org_id,document_id,preparation_id)
    SELECT admission,org_value,doc_value,NEW.id WHERE NOT EXISTS(SELECT 1 FROM signing_resource_finalization_transfers tr WHERE tr.admission_id=admission);
   PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'finalization',NEW.id,'',0);
  ELSE SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.id;END IF;
  IF NEW.audit_snapshot_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.audit_snapshot_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'audit_input',NEW.id,'',0);END IF;
  IF NEW.certificate_input_payload IS NOT NULL AND (TG_OP='INSERT' OR OLD.certificate_input_payload IS NULL) THEN PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'certificate_input',NEW.id,'',0);END IF;
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN
  SELECT debt.admission_id INTO STRICT admission FROM signing_resource_debts debt WHERE debt.org_id=org_value AND debt.document_id=doc_value AND debt.kind='finalization' AND debt.operation_id=NEW.preparation_id;
  PERFORM hash_signing_resource_record_v1(org_value,doc_value,admission,'output',NEW.preparation_id,NEW.kind,NEW.page);
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd

-- BEFORE names sort before protected85/87/88 guards; unavailable fails before
-- their bounded JSON decoding. AFTER names sort after88's slot construction.
CREATE TRIGGER aa_signing_resource_slot BEFORE INSERT OR UPDATE ON document_signing_admission_slots FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_selection BEFORE INSERT ON signature_fit_selections FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_companion BEFORE INSERT ON signature_fit_companions FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_binding BEFORE INSERT ON signature_signing_admission_bindings FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_reference BEFORE INSERT ON document_finalization_references FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_candidate BEFORE INSERT ON document_signing_admissions FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_candidate AFTER INSERT ON document_signing_admissions FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_ordinary BEFORE INSERT ON document_signing_admission_bodies FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_ordinary AFTER INSERT ON document_signing_admission_bodies FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_fit BEFORE INSERT ON signature_fit_preparations FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_fit AFTER INSERT ON signature_fit_preparations FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_authority BEFORE INSERT ON signature_fit_original_authorities FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_authority AFTER INSERT ON signature_fit_original_authorities FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_payload BEFORE INSERT ON signature_fit_original_payloads FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_payload AFTER INSERT ON signature_fit_original_payloads FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_object BEFORE INSERT ON signature_fit_objects FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_object_attempt BEFORE UPDATE ON signature_fit_objects FOR EACH ROW WHEN(OLD.upload_attempted_at IS NULL AND NEW.upload_attempted_at IS NOT NULL) EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER aa_signing_resource_final BEFORE INSERT ON document_finalization_preparations FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_final AFTER INSERT ON document_finalization_preparations FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_final_inputs BEFORE UPDATE ON document_finalization_preparations FOR EACH ROW WHEN((OLD.audit_snapshot_payload IS NULL AND NEW.audit_snapshot_payload IS NOT NULL) OR (OLD.certificate_input_payload IS NULL AND NEW.certificate_input_payload IS NOT NULL)) EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_final_inputs AFTER UPDATE ON document_finalization_preparations FOR EACH ROW WHEN((OLD.audit_snapshot_payload IS NULL AND NEW.audit_snapshot_payload IS NOT NULL) OR (OLD.certificate_input_payload IS NULL AND NEW.certificate_input_payload IS NOT NULL)) EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_output BEFORE INSERT ON document_finalization_outputs FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_before_v1();
CREATE TRIGGER zz_signing_resource_output AFTER INSERT ON document_finalization_outputs FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_after_v1();
CREATE TRIGGER aa_signing_resource_output_attempt BEFORE UPDATE ON document_finalization_outputs FOR EACH ROW WHEN(OLD.upload_attempted_at IS NULL AND NEW.upload_attempted_at IS NOT NULL) EXECUTE FUNCTION hash_signing_resource_before_v1();

-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_pair_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE org_value UUID;doc_value UUID;operation UUID;member TEXT:='';member_page INTEGER:=0;resource_kind TEXT;admission UUID;
 p signature_fit_preparations%ROWTYPE;fp document_finalization_preparations%ROWTYPE;debt signing_resource_debts%ROWTYPE;
BEGIN
 IF TG_TABLE_NAME='signing_resource_fit_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='fit';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_finalization_transfers' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='finalization';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signing_resource_debts' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.operation_id;member:=NEW.member_kind;member_page:=NEW.page;resource_kind:=NEW.kind;admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='document_signing_admissions' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='candidate';admission:=NEW.id;
 ELSIF TG_TABLE_NAME='document_signing_admission_bodies' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.admission_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='ordinary';admission:=NEW.admission_id;
 ELSIF TG_TABLE_NAME='signature_fit_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='fit';
 ELSIF TG_TABLE_NAME='signature_fit_original_authorities' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;resource_kind:='authority';
 ELSIF TG_TABLE_NAME='signature_fit_original_payloads' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.preparation_id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='payload';
 ELSIF TG_TABLE_NAME='document_finalization_preparations' THEN org_value:=NEW.org_id;doc_value:=NEW.document_id;operation:=NEW.id;resource_kind:='finalization';
 ELSIF TG_TABLE_NAME='document_finalization_outputs' THEN SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id;org_value:=fp.org_id;doc_value:=fp.document_id;operation:=fp.id;member:=NEW.kind;member_page:=NEW.page;resource_kind:='output';
 ELSE RETURN NULL;END IF;
 IF NOT EXISTS(SELECT 1 FROM documents WHERE id=doc_value AND org_id=org_value AND signing_admission_policy='pdf-static-v1') THEN RETURN NULL;END IF;
 SELECT * INTO STRICT debt FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind=resource_kind AND operation_id=operation AND member_kind=member AND page=member_page;
 IF admission IS NOT NULL AND debt.admission_id<>admission THEN RAISE EXCEPTION 'signing resource source/receipt admission differs' USING ERRCODE='23514';END IF;
 IF resource_kind IN('fit','authority','payload') THEN
  SELECT * INTO STRICT p FROM signature_fit_preparations WHERE id=operation AND org_id=org_value AND document_id=doc_value;
  IF NOT EXISTS(SELECT 1 FROM signature_fit_original_authorities oa WHERE oa.preparation_id=p.id AND oa.org_id=p.org_id AND oa.document_id=p.document_id AND oa.authority_sha256=p.authority_sha256)
   OR NOT EXISTS(SELECT 1 FROM signature_fit_original_payloads os WHERE os.preparation_id=p.id AND os.kind='span' AND os.page=0 AND os.sha256=p.span_sha256)
   OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=debt.admission_id AND sl.org_id=p.org_id AND sl.document_id=p.document_id AND sl.recipient_id=p.recipient_id AND sl.designated_preparation_id=p.id AND sl.designated_owner_id=p.owner_id) THEN
   RAISE EXCEPTION 'signing resource fit reservation requires atomic85/87/88 tuple' USING ERRCODE='23514';
  END IF;
 END IF;
 IF resource_kind='finalization' THEN
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=operation;
  IF fp.audit_snapshot_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='audit_input' AND operation_id=operation AND member_kind='' AND page=0)
   OR fp.certificate_input_payload IS NOT NULL AND NOT EXISTS(SELECT 1 FROM signing_resource_debts WHERE org_id=org_value AND document_id=doc_value AND kind='certificate_input' AND operation_id=operation AND member_kind='' AND page=0) THEN
   RAISE EXCEPTION 'signing resource final input lacks retained debt' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NULL;
EXCEPTION WHEN no_data_found THEN RAISE EXCEPTION 'signing resource inventory lacks exact debt receipt' USING ERRCODE='23514';
END $$;
CREATE FUNCTION hash_signing_resource_transfer_guard_v1() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE admission document_signing_admissions%ROWTYPE;prep signature_fit_preparations%ROWTYPE;fp document_finalization_preparations%ROWTYPE;
BEGIN
  IF NOT EXISTS(SELECT 1 FROM signing_resource_control WHERE singleton AND state='ready') THEN RAISE EXCEPTION 'signing resource transfer requires verified inventory' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM signing_resource_debit_batches WHERE captured_transaction_id=pg_current_xact_id()) THEN RAISE EXCEPTION 'signing resource transaction already owns account locks' USING ERRCODE='23514'; END IF;
 PERFORM hash_signing_resource_entities_v1(NEW.org_id,NEW.document_id);
 SELECT * INTO STRICT admission FROM document_signing_admissions WHERE id=NEW.admission_id AND org_id=NEW.org_id AND document_id=NEW.document_id;
 IF TG_TABLE_NAME='signing_resource_fit_transfers' THEN
  SELECT * INTO STRICT prep FROM signature_fit_preparations WHERE id=NEW.preparation_id AND org_id=NEW.org_id AND document_id=NEW.document_id AND recipient_id=NEW.recipient_id AND ceremony_epoch=admission.ceremony_epoch;
  IF prep.source_storage_key<>admission.source_storage_key OR prep.source_version_id<>admission.source_version_id OR prep.source_sha256<>admission.source_sha256 OR prep.source_bytes<>admission.source_bytes OR prep.geometry_sha256<>admission.geometry_sha256
   OR NOT EXISTS(SELECT 1 FROM document_signing_admission_slots sl WHERE sl.admission_id=admission.id AND sl.recipient_id=prep.recipient_id AND sl.expected_objects=prep.expected_objects AND sl.fit_bytes_limit>=prep.reserved_bytes) THEN
   RAISE EXCEPTION 'signing resource slot transfer differs from original source' USING ERRCODE='23514';END IF;
 ELSE
  SELECT * INTO STRICT fp FROM document_finalization_preparations WHERE id=NEW.preparation_id AND org_id=NEW.org_id AND document_id=NEW.document_id AND ceremony_epoch=admission.ceremony_epoch;
  IF admission.status<>'sealed' OR fp.source_storage_key<>admission.source_storage_key OR fp.source_version_id<>admission.source_version_id OR fp.source_sha256<>admission.source_sha256 OR fp.source_bytes<>admission.source_bytes OR fp.geometry_sha256<>admission.geometry_sha256 OR fp.base_bytes_limit>admission.base_bytes_limit OR fp.final_pdf_bytes_limit>admission.final_pdf_bytes_limit OR fp.fits_index_bytes_limit>admission.fits_index_bytes_limit OR fp.certificate_pdf_bytes_limit>admission.certificate_pdf_bytes_limit OR fp.certificate_payload_bytes_limit>admission.certificate_payload_bytes_limit OR fp.certificate_signature_bytes_limit>admission.certificate_signature_bytes_limit OR fp.expected_outputs<>cardinality(admission.expected_ordinary_pages)+5 THEN
   RAISE EXCEPTION 'signing resource final transfer exceeds conserved entitlement' USING ERRCODE='23514';END IF;
 END IF;
 RETURN NEW;
END $$;
-- +goose StatementEnd
CREATE TRIGGER signing_resource_fit_transfer_guard BEFORE INSERT ON signing_resource_fit_transfers FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_transfer_guard_v1();
CREATE TRIGGER signing_resource_final_transfer_guard BEFORE INSERT ON signing_resource_finalization_transfers FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_transfer_guard_v1();
CREATE CONSTRAINT TRIGGER signing_resource_fit_transfer_pair AFTER INSERT ON signing_resource_fit_transfers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_final_transfer_pair AFTER INSERT ON signing_resource_finalization_transfers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_debt_pair AFTER INSERT ON signing_resource_debts DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_candidate_pair AFTER INSERT ON document_signing_admissions DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_ordinary_pair AFTER INSERT ON document_signing_admission_bodies DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_fit_pair AFTER INSERT ON signature_fit_preparations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_authority_pair AFTER INSERT ON signature_fit_original_authorities DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_payload_pair AFTER INSERT ON signature_fit_original_payloads DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_final_pair AFTER INSERT OR UPDATE ON document_finalization_preparations DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();
CREATE CONSTRAINT TRIGGER signing_resource_output_pair AFTER INSERT ON document_finalization_outputs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION hash_signing_resource_pair_v1();


-- +goose StatementBegin
CREATE FUNCTION hash_signing_resource_stage_inventory_v1(snapshot_id UUID,receipt_id UUID,receipt_key TEXT,receipt_version TEXT,receipt_sha BYTEA,receipt_size BIGINT)
RETURNS signing_resource_inventory_snapshots LANGUAGE plpgsql AS $$
DECLARE n BIGINT; docs BIGINT; db_amount NUMERIC; provider_amount NUMERIC; object_amount NUMERIC; sha BYTEA; result signing_resource_inventory_snapshots%ROWTYPE;
BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource staging requires read committed' USING ERRCODE='23514';END IF;
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,document_finalization_preparations,document_finalization_outputs,document_finalization_references IN SHARE MODE NOWAIT;
 SELECT count(*),count(DISTINCT document_id) INTO n,docs FROM signing_resource_current_inventory_v1;
 IF n>65536 OR docs>4096 THEN RAISE EXCEPTION 'signing resource inventory exceeds staged profile' USING ERRCODE='23514';END IF;
 SELECT COALESCE(sum(db_bytes::numeric),0),COALESCE(sum(provider_bytes::numeric),0),COALESCE(sum(provider_objects::numeric),0),
 digest(convert_to(COALESCE(string_agg(org_id::text||'/'||document_id::text||'/'||kind||'/'||operation_id::text||'/'||member_kind||'/'||page::text||'/'||encode(identity_sha256,'hex')||'/'||db_bytes::text||'/'||provider_bytes::text||'/'||provider_objects::text,E'\n' ORDER BY org_id,document_id,kind,operation_id,member_kind,page),''),'UTF8'),'sha256')
 INTO db_amount,provider_amount,object_amount,sha FROM signing_resource_current_inventory_v1;
 IF db_amount>1152921504606846976 OR provider_amount>1152921504606846976 OR object_amount>1000000000 THEN RAISE EXCEPTION 'signing resource inventory overflow' USING ERRCODE='23514';END IF;
 INSERT INTO signing_resource_inventory_snapshots(id,inventory_sha256,entry_count,document_count,known_db_bytes,known_provider_bytes,known_provider_objects,controller_receipt_id,receipt_storage_key,receipt_version_id,receipt_sha256,receipt_bytes)
 VALUES(snapshot_id,sha,n,docs,db_amount::bigint,provider_amount::bigint,object_amount::bigint,receipt_id,receipt_key,receipt_version,receipt_sha,receipt_size) RETURNING * INTO result;
 INSERT INTO signing_resource_inventory_entries(snapshot_id,org_id,document_id,ceremony_epoch,kind,operation_id,member_kind,page,identity_sha256,db_bytes,provider_bytes,provider_objects)
 SELECT result.id,inv.org_id,inv.document_id,inv.ceremony_epoch,inv.kind,inv.operation_id,inv.member_kind,inv.page,inv.identity_sha256,inv.db_bytes,inv.provider_bytes,inv.provider_objects FROM signing_resource_current_inventory_v1 inv;
 RETURN result;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'signing resource inventory is busy' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd

-- +goose Down
-- No deinitialization, baseline replacement or inventory destruction is inferred.
-- Used inventories and policy reservations require explicit managed disposition.
-- +goose StatementBegin
DO $$ BEGIN
 IF current_setting('transaction_isolation')<>'read committed' THEN RAISE EXCEPTION 'signing resource rollback requires read committed' USING ERRCODE='23514';END IF;
 -- Fence stage writers BEFORE checking inventory; a snapshot committed while
 -- destructive DDL waits must never be erased by an earlier empty read.
 LOCK TABLE documents,document_signing_admissions,document_signing_admission_bodies,document_signing_admission_slots,signature_signing_admission_bindings,signature_fit_preparations,signature_fit_objects,signature_fit_selections,signature_fit_companions,signature_fit_original_authorities,signature_fit_original_payloads,document_finalization_preparations,document_finalization_outputs,document_finalization_references,signing_resource_inventory_snapshots,signing_resource_inventory_entries,signing_resource_control,signing_resource_accounts,signing_resource_debts,signing_resource_debit_batches,signing_resource_fit_transfers,signing_resource_finalization_transfers IN ACCESS EXCLUSIVE MODE NOWAIT;
 IF EXISTS(SELECT 1 FROM signing_resource_inventory_snapshots) OR EXISTS(SELECT 1 FROM signing_resource_inventory_entries) OR EXISTS(SELECT 1 FROM signing_resource_debts) OR EXISTS(SELECT 1 FROM signing_resource_debit_batches) OR EXISTS(SELECT 1 FROM signing_resource_fit_transfers) OR EXISTS(SELECT 1 FROM signing_resource_finalization_transfers) OR EXISTS(SELECT 1 FROM signing_resource_accounts WHERE scope='tenant' OR state<>'uninitialized' OR db_capacity_bytes<>0 OR db_retained_bytes<>0 OR provider_reserved_bytes<>0 OR provider_reserved_objects<>0) OR EXISTS(SELECT 1 FROM signing_resource_control WHERE state<>'uninitialized') THEN
  RAISE EXCEPTION 'signing resource rollback refuses used inventory' USING ERRCODE='23514';END IF;
EXCEPTION WHEN lock_not_available THEN RAISE EXCEPTION 'signing resource rollback refuses active inventory' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
DROP TRIGGER aa_signing_resource_reference ON document_finalization_references;
DROP TRIGGER aa_signing_resource_binding ON signature_signing_admission_bindings;
DROP TRIGGER aa_signing_resource_companion ON signature_fit_companions;
DROP TRIGGER aa_signing_resource_selection ON signature_fit_selections;
DROP TRIGGER aa_signing_resource_slot ON document_signing_admission_slots;
DROP TRIGGER signing_resource_fit_transfer_pair ON signing_resource_fit_transfers;
DROP TRIGGER signing_resource_final_transfer_pair ON signing_resource_finalization_transfers;
DROP TRIGGER signing_resource_output_pair ON document_finalization_outputs;
DROP TRIGGER signing_resource_final_pair ON document_finalization_preparations;
DROP TRIGGER signing_resource_payload_pair ON signature_fit_original_payloads;
DROP TRIGGER signing_resource_authority_pair ON signature_fit_original_authorities;
DROP TRIGGER signing_resource_fit_pair ON signature_fit_preparations;
DROP TRIGGER signing_resource_ordinary_pair ON document_signing_admission_bodies;
DROP TRIGGER signing_resource_candidate_pair ON document_signing_admissions;
DROP TRIGGER signing_resource_debt_pair ON signing_resource_debts;
DROP TRIGGER signing_resource_fit_transfer_guard ON signing_resource_fit_transfers;
DROP TRIGGER signing_resource_final_transfer_guard ON signing_resource_finalization_transfers;
DROP TRIGGER aa_signing_resource_output_attempt ON document_finalization_outputs;
DROP TRIGGER zz_signing_resource_output ON document_finalization_outputs;
DROP TRIGGER aa_signing_resource_output ON document_finalization_outputs;
DROP TRIGGER zz_signing_resource_final_inputs ON document_finalization_preparations;
DROP TRIGGER aa_signing_resource_final_inputs ON document_finalization_preparations;
DROP TRIGGER zz_signing_resource_final ON document_finalization_preparations;
DROP TRIGGER aa_signing_resource_final ON document_finalization_preparations;
DROP TRIGGER aa_signing_resource_object_attempt ON signature_fit_objects;
DROP TRIGGER aa_signing_resource_object ON signature_fit_objects;
DROP TRIGGER zz_signing_resource_payload ON signature_fit_original_payloads;
DROP TRIGGER aa_signing_resource_payload ON signature_fit_original_payloads;
DROP TRIGGER zz_signing_resource_authority ON signature_fit_original_authorities;
DROP TRIGGER aa_signing_resource_authority ON signature_fit_original_authorities;
DROP TRIGGER zz_signing_resource_fit ON signature_fit_preparations;
DROP TRIGGER aa_signing_resource_fit ON signature_fit_preparations;
DROP TRIGGER zz_signing_resource_ordinary ON document_signing_admission_bodies;
DROP TRIGGER aa_signing_resource_ordinary ON document_signing_admission_bodies;
DROP TRIGGER zz_signing_resource_candidate ON document_signing_admissions;
DROP TRIGGER aa_signing_resource_candidate ON document_signing_admissions;
DROP TRIGGER signing_resource_snapshot_pair ON signing_resource_inventory_snapshots;
DROP TRIGGER signing_resource_entry_guard ON signing_resource_inventory_entries;
DROP TRIGGER signing_resource_snapshot_guard ON signing_resource_inventory_snapshots;
DROP FUNCTION hash_signing_resource_stage_inventory_v1(UUID,UUID,TEXT,TEXT,BYTEA,BIGINT);
DROP FUNCTION hash_signing_resource_pair_v1();
DROP FUNCTION hash_signing_resource_transfer_guard_v1();
DROP FUNCTION hash_signing_resource_after_v1();
DROP FUNCTION hash_signing_resource_before_v1();
DROP FUNCTION hash_signing_resource_record_v1(UUID,UUID,UUID,TEXT,UUID,TEXT,INTEGER);
DROP TRIGGER zz_signing_resource_commit_debts ON signing_resource_debts;
DROP TRIGGER signing_resource_batch_guard ON signing_resource_debit_batches;
DROP FUNCTION hash_signing_resource_commit_debts_v1();
DROP FUNCTION hash_signing_resource_batch_guard_v1();
DROP TRIGGER signing_resource_debt_guard ON signing_resource_debts;
DROP FUNCTION hash_signing_resource_debt_guard_v1();
DROP FUNCTION hash_signing_resource_fit_db_v1(BIGINT,INTEGER);
DROP FUNCTION hash_signing_resource_common_db_v1(document_signing_admissions);
DROP FUNCTION hash_signing_resource_common_provider_v1(document_signing_admissions);
DROP FUNCTION hash_signing_resource_candidate_db_v1(document_signing_admissions);
DROP FUNCTION hash_signing_resource_entities_v1(UUID,UUID);
DROP FUNCTION hash_signing_resource_snapshot_pair_v1();
DROP FUNCTION hash_signing_resource_entry_guard_v1();
DROP FUNCTION hash_signing_resource_snapshot_guard_v1();
DROP VIEW signing_resource_current_inventory_v1;
DROP TABLE signing_resource_debit_batches;
DROP TABLE signing_resource_debts;
DROP TABLE signing_resource_finalization_transfers;
DROP TABLE signing_resource_fit_transfers;
DROP FUNCTION hash_signing_resource_require_accounts_v1(UUID);
DROP TABLE signing_resource_accounts;
DROP TABLE signing_resource_control;
DROP TABLE signing_resource_inventory_entries;
DROP TABLE signing_resource_inventory_snapshots;
DROP FUNCTION hash_signing_resource_account_guard_v1();
DROP FUNCTION hash_signing_resource_bootstrap_guard_v1();
DROP FUNCTION hash_signing_resource_immutable_v1();
