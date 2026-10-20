-- +goose Up
-- Frozen package members may outlive their live source documents. A linked
-- pending privacy request therefore needs a fence independent of that source
-- row's FK/document lock. The existing M72 org fence still covers global DSRs.
-- +goose StatementBegin
CREATE FUNCTION hash_try_document_package_privacy_fence_v1(tenant UUID,target UUID) RETURNS BOOLEAN AS $$
 SELECT pg_try_advisory_xact_lock_shared(hashtextextended('hash:document-package:privacy:'||tenant::text||':'||target::text,0));
$$ LANGUAGE sql VOLATILE STRICT;

CREATE FUNCTION hash_lock_linked_dsr_for_document_packages_v1() RETURNS trigger AS $$
BEGIN
 IF NEW.document_id IS NOT NULL AND NEW.status IN ('open','in_progress') THEN
  -- Refuse rather than acquire multiple exclusive keys in an arbitrary order
  -- or wait on an unbounded signer request. A retry is a new caller action.
  IF NOT pg_try_advisory_xact_lock(hashtextextended('hash:document-package:privacy:'||NEW.org_id::text||':'||NEW.document_id::text,0)) THEN
   RAISE EXCEPTION 'document privacy review is changing; retry the request' USING ERRCODE='55P03';
  END IF;
 END IF;
 RETURN NEW;
END;
$$ LANGUAGE plpgsql;
CREATE TRIGGER linked_dsr_document_package_fence_v1 BEFORE INSERT OR UPDATE ON data_subject_requests
 FOR EACH ROW EXECUTE FUNCTION hash_lock_linked_dsr_for_document_packages_v1();
-- +goose StatementEnd

-- +goose Down
-- No data is rewritten. Quiesce actual package/DSR transactions before removing
-- the guard. A new consumer on an older schema fails closed on its missing
-- shared-fence function; this is not a rolling binary compatibility promise.
-- +goose StatementBegin
LOCK TABLE documents,document_packages_v1,document_attachment_drafts_v1,data_subject_requests IN ACCESS EXCLUSIVE MODE NOWAIT;
DROP TRIGGER linked_dsr_document_package_fence_v1 ON data_subject_requests;
DROP FUNCTION hash_lock_linked_dsr_for_document_packages_v1();
DROP FUNCTION hash_try_document_package_privacy_fence_v1(UUID,UUID);
-- +goose StatementEnd
