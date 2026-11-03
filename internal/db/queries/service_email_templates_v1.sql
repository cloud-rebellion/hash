-- name: GetServiceEmailTemplateHeaderV1 :one
SELECT h.org_id,h.kind,h.revision,
       octet_length(r.subject_template)::bigint AS subject_bytes,
       octet_length(r.html_template)::bigint AS html_bytes,
       octet_length(r.text_template)::bigint AS text_bytes,h.updated_at
FROM org_email_template_heads_v1 h
JOIN org_email_template_revisions_v1 r USING(org_id,kind,revision)
WHERE h.org_id=$1 AND h.kind=$2
FOR SHARE OF h,r;

-- name: CreateServiceEmailTemplateRevisionV1 :exec
INSERT INTO org_email_template_revisions_v1(org_id,kind,revision,subject_template,html_template,text_template)
VALUES($1,$2,$3,$4,$5,$6);

-- name: SetServiceEmailTemplateHeadV1 :exec
INSERT INTO org_email_template_heads_v1(org_id,kind,revision)
VALUES($1,$2,$3)
ON CONFLICT(org_id,kind) DO UPDATE SET revision=EXCLUDED.revision,updated_at=clock_timestamp();

-- name: GetServiceEmailTemplateV1 :one
-- Native caller must admit bounded source/SQL work before reading this row.
-- SHARE locks retain the chosen immutable revision through rendering/enqueue.
SELECT h.org_id,h.kind,h.revision,r.subject_template,r.html_template,r.text_template,h.updated_at
FROM org_email_template_heads_v1 h
JOIN org_email_template_revisions_v1 r USING(org_id,kind,revision)
WHERE h.org_id=$1 AND h.kind=$2
FOR SHARE OF h,r;
