-- Only the actual native event producer reads this locked sender's preference.
-- Absence is opt-out; source/SQL loan must precede even this scalar projection.
-- name: GetSenderAutomationPreferenceV1 :one
SELECT p.org_id,p.sender_user_id,p.revision,p.notify_viewed,p.notify_signed
FROM sender_automation_preferences_v1 p JOIN users u
 ON u.id=p.sender_user_id AND u.org_id=p.org_id
WHERE p.org_id=sqlc.arg(org_id)::uuid
 AND p.sender_user_id=sqlc.arg(sender_user_id)::uuid
 AND u.role IN ('owner','sender')
FOR SHARE OF p;

-- Bounded real sender destination, never a caller-supplied address. The native
-- owner admits this scalar/email source and keeps the user lock through commit.
-- name: GetSenderAutomationRecipientV1 :one
SELECT id,org_id,email FROM users
WHERE id=sqlc.arg(sender_user_id)::uuid AND org_id=sqlc.arg(org_id)::uuid
 AND role IN ('owner','sender') AND octet_length(email) BETWEEN 3 AND 254
FOR SHARE;

-- The private native caller supplies the real pending audit UUID, never a DTO.
-- A signed receipt also binds the actual unique legal signature row.
-- name: GetSenderAutomationEventIdentityV1 :one
SELECT e.id AS audit_event_id,d.sent_at,
 COALESCE(CASE WHEN e.kind='document.signed' THEN s.id ELSE NULL END,
 '00000000-0000-0000-0000-000000000000'::uuid)::uuid AS signature_id
FROM events e JOIN documents d ON d.id=e.document_id AND d.org_id=e.org_id
LEFT JOIN signatures s ON s.document_id=d.id AND s.recipient_id=e.recipient_id
WHERE e.id=sqlc.arg(audit_event_id)::uuid
 AND e.org_id=sqlc.arg(org_id)::uuid
 AND e.document_id=sqlc.arg(document_id)::uuid
 AND e.recipient_id=sqlc.arg(recipient_id)::uuid
 AND e.kind=sqlc.arg(event_kind)::text
 AND d.sender_id=sqlc.arg(sender_user_id)::uuid
 AND d.sent_at IS NOT NULL AND e.created_at>=d.sent_at
FOR KEY SHARE OF e,d;

-- The email UUID is freshly generated privately before this claim. Its deferred
-- FK forbids committing a claimed receipt without that exact real outbox row.
-- Conflicts mean an already recorded first view/signature, never a new message.
-- name: TryClaimSenderEventNoticeV1 :one
INSERT INTO sender_event_notice_receipts_v1
 (audit_event_id,org_id,document_id,recipient_id,sender_user_id,sent_at,event_kind,signature_id,email_delivery_id)
VALUES (sqlc.arg(audit_event_id)::uuid,sqlc.arg(org_id)::uuid,
 sqlc.arg(document_id)::uuid,sqlc.arg(recipient_id)::uuid,
 sqlc.arg(sender_user_id)::uuid,sqlc.arg(sent_at)::timestamptz,
 sqlc.arg(event_kind)::text,sqlc.narg(signature_id)::uuid,
 sqlc.arg(email_delivery_id)::uuid)
ON CONFLICT DO NOTHING RETURNING audit_event_id;

-- Fixed new ordinary workspace notice. No staff-auth or test transport route.
-- name: EnqueueSenderEventNoticeV1 :one
INSERT INTO email_deliveries
 (id,smtp_org_id,smtp_purpose,to_email,subject,html_body,text_body,reply_to,from_name,headers_json)
VALUES (sqlc.arg(id)::uuid,sqlc.arg(org_id)::uuid,'workspace',
 sqlc.arg(to_email)::text,sqlc.arg(subject)::text,sqlc.arg(html_body)::text,
 sqlc.arg(text_body)::text,'',sqlc.arg(from_name)::text,'{}'::jsonb)
RETURNING *;
