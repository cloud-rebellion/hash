-- +goose Up
-- A design and its embedded, digest-verified logo belong to the SAME immutable
-- kind/revision as M119 content. Existing editions retain empty design exactly.
ALTER TABLE org_email_template_revisions_v1
 ADD COLUMN design_json TEXT NOT NULL DEFAULT '' CHECK(octet_length(design_json)<=131072),
 ADD COLUMN design_sha256 BYTEA;
ALTER TABLE org_email_template_revisions_v1 ADD CONSTRAINT email_design_digest_v1 CHECK(
 (design_json='' AND design_sha256 IS NULL)
 OR (design_json<>'' AND design_sha256 IS NOT NULL AND octet_length(design_sha256)=32
     AND design_sha256=sha256(convert_to(design_json,'UTF8'))));

-- Canned M120 owner tests remain all-NULL. Reviewed samples pin a native kind,
-- its current immutable edition (including design/logo), and final render bytes.
ALTER TABLE org_smtp_test_requests_v1
 ADD COLUMN template_kind TEXT,
 ADD COLUMN template_revision BIGINT,
 ADD COLUMN subject_sha256 BYTEA,
 ADD COLUMN html_sha256 BYTEA,
 ADD COLUMN text_sha256 BYTEA;
ALTER TABLE org_smtp_test_requests_v1 ADD CONSTRAINT smtp_sample_receipt_v1 CHECK(
 (template_kind IS NULL AND template_revision IS NULL AND subject_sha256 IS NULL AND html_sha256 IS NULL AND text_sha256 IS NULL)
 OR (template_kind IS NOT NULL AND octet_length(template_kind) BETWEEN 1 AND 80
     AND template_revision IS NOT NULL AND template_revision>=0
     AND subject_sha256 IS NOT NULL AND octet_length(subject_sha256)=32
     AND html_sha256 IS NOT NULL AND octet_length(html_sha256)=32
     AND text_sha256 IS NOT NULL AND octet_length(text_sha256)=32));
-- +goose StatementBegin
CREATE FUNCTION hash_smtp_sample_receipt_immutable_v1() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW IS DISTINCT FROM OLD THEN
  RAISE EXCEPTION 'SMTP test request commitment is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER smtp_sample_receipt_immutable_v1 BEFORE UPDATE ON org_smtp_test_requests_v1
FOR EACH ROW EXECUTE FUNCTION hash_smtp_sample_receipt_immutable_v1();

-- +goose Down
LOCK TABLE org_email_template_revisions_v1,org_smtp_test_requests_v1 IN SHARE ROW EXCLUSIVE MODE;
-- +goose StatementBegin
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM org_email_template_revisions_v1 WHERE design_json<>'' OR design_sha256 IS NOT NULL)
 OR EXISTS(SELECT 1 FROM org_smtp_test_requests_v1 WHERE template_kind IS NOT NULL) THEN
  RAISE EXCEPTION 'retained email design or reviewed sample forbids rollback' USING ERRCODE='23514';
 END IF;
END $$;
-- +goose StatementEnd
DROP TRIGGER smtp_sample_receipt_immutable_v1 ON org_smtp_test_requests_v1;
DROP FUNCTION hash_smtp_sample_receipt_immutable_v1();
ALTER TABLE org_smtp_test_requests_v1 DROP CONSTRAINT smtp_sample_receipt_v1,
 DROP COLUMN template_kind,DROP COLUMN template_revision,DROP COLUMN subject_sha256,DROP COLUMN html_sha256,DROP COLUMN text_sha256;
ALTER TABLE org_email_template_revisions_v1 DROP CONSTRAINT email_design_digest_v1,
 DROP COLUMN design_json,DROP COLUMN design_sha256;
