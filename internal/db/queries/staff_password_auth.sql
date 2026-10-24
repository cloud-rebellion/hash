-- name: EnqueueStaffAuthEmail :exec
INSERT INTO email_deliveries (id, to_email, subject, html_body, text_body, staff_auth_ciphertext)
VALUES ($1, $2, $3, '', '', $4);

-- name: GetLatestStaffAuthEmail :one
SELECT * FROM email_deliveries
WHERE to_email = $1 AND staff_auth_ciphertext IS NOT NULL
ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: GetStaffPasswordCredential :one
SELECT u.id, u.org_id, u.email, u.name, u.role, u.session_generation, c.password_hash
FROM users u
JOIN staff_password_credentials c ON c.user_id = u.id
WHERE lower(u.email) = lower($1);

-- name: LockStaffPasswordEmail :exec
SELECT pg_advisory_xact_lock(hashtextextended('hash.staff-password:' || sqlc.arg(email)::text, 0));

-- name: LockStaffPasswordUserByEmail :one
SELECT * FROM users WHERE lower(email) = lower($1) FOR UPDATE;

-- name: LockStaffPasswordUser :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: GetStaffPasswordCredentialForUser :one
SELECT * FROM staff_password_credentials WHERE user_id = $1;

-- name: IssueStaffAuthRequest :exec
INSERT INTO staff_auth_requests (
    id, email, purpose, user_id, session_generation, name, company_name,
    password_hash, token_hash, expires_at
) VALUES (
    sqlc.arg(id), sqlc.arg(email), sqlc.arg(purpose),
    sqlc.narg(user_id), sqlc.narg(session_generation),
    sqlc.arg(name), sqlc.arg(company_name), sqlc.narg(password_hash),
    sqlc.arg(token_hash), now() + sqlc.arg(ttl_seconds)::int * interval '1 second'
);

-- name: DeleteStaffAuthRequestsByEmail :exec
DELETE FROM staff_auth_requests WHERE email = $1;

-- name: GetStaffAuthRequest :one
SELECT * FROM staff_auth_requests
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: GetStaffAuthRequestForUpdate :one
SELECT * FROM staff_auth_requests
WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
FOR UPDATE;

-- name: ConsumeStaffAuthRequest :execrows
UPDATE staff_auth_requests SET consumed_at = now()
WHERE id = $1 AND consumed_at IS NULL AND expires_at > now();

-- name: InvalidateStaffAuthRequestsByEmail :exec
UPDATE staff_auth_requests SET consumed_at = now()
WHERE email = $1 AND consumed_at IS NULL;

-- name: CreateStaffPasswordCredential :execrows
INSERT INTO staff_password_credentials (user_id, password_hash)
VALUES ($1, $2)
ON CONFLICT (user_id) DO NOTHING;

-- name: SetStaffPasswordCredential :exec
INSERT INTO staff_password_credentials (user_id, password_hash)
VALUES ($1, $2)
ON CONFLICT (user_id) DO UPDATE
SET password_hash = EXCLUDED.password_hash, updated_at = now();

-- name: RotateStaffPasswordSession :one
UPDATE users SET session_generation = session_generation + 1
WHERE id = $1 AND session_generation = $2
RETURNING *;

-- name: RefreshStaffPasswordLogin :one
SELECT u.* FROM users u
JOIN staff_password_credentials c ON c.user_id = u.id
WHERE u.id = sqlc.arg(user_id)
  AND u.session_generation = sqlc.arg(session_generation)
  AND c.password_hash = sqlc.arg(password_hash)
FOR SHARE OF u, c;

-- name: DeleteExpiredStaffAuthRequests :exec
WITH expired AS (
    SELECT id FROM staff_auth_requests WHERE expires_at < now() - interval '24 hours'
    ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 100
)
DELETE FROM staff_auth_requests WHERE id IN (SELECT id FROM expired);
