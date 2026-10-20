-- name: ConfirmDocumentPackageLawfulBasisV1 :one
-- The sender explicitly submits the basis at Send. Record that instruction and
-- controller disclosure without UPDATEing the immutable measured draft clock.
-- A different basis requires a fresh document review; its default alone is not
-- confirmation. The native owner holds the actual root/user/organization locks.
INSERT INTO document_lawful_basis_confirmations (
 document_id,org_id,lawful_basis,confirmed_by,via,controller_name,controller_contact
)
SELECT d.id,d.org_id,d.lawful_basis,sqlc.narg(confirmed_by)::uuid,sqlc.arg(via)::text,btrim(o.name),btrim(u.email)
FROM documents d JOIN orgs o ON o.id=d.org_id
JOIN users u ON u.id=sqlc.narg(confirmed_by)::uuid AND u.org_id=d.org_id
WHERE d.id=sqlc.arg(document_id)::uuid AND d.org_id=sqlc.arg(org_id)::uuid
 AND d.status='draft' AND d.deleted_at IS NULL AND d.source_kind='pdf' AND NOT d.is_envelope AND d.parent_envelope_id IS NULL
 AND d.updated_at=sqlc.arg(expected_updated_at)::timestamptz
 AND sqlc.arg(lawful_basis)::text='contract' AND d.lawful_basis=sqlc.arg(lawful_basis)::text
 AND btrim(o.name)<>'' AND btrim(u.email)<>''
 AND EXISTS(SELECT 1 FROM document_packages_v1 p JOIN document_attachment_drafts_v1 a ON a.package_id=p.id AND a.org_id=p.org_id
  WHERE p.document_id=d.id AND p.org_id=d.org_id)
ON CONFLICT (document_id) DO UPDATE
SET lawful_basis=EXCLUDED.lawful_basis,confirmed_at=now(),confirmed_by=EXCLUDED.confirmed_by,
 via=EXCLUDED.via,controller_name=EXCLUDED.controller_name,controller_contact=EXCLUDED.controller_contact
WHERE document_lawful_basis_confirmations.org_id=EXCLUDED.org_id
RETURNING *;
