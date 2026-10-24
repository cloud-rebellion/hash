# Staff login

Hash staff sign in at `/login` with an email address and password. Google or
another OIDC provider is optional. Signing recipients use their document links
and do not need a staff account.

## Create or join a workspace

1. Use **Create workspace** to enter your name, company, email and password.
2. Open the verification email and confirm the password you chose. Hash creates
   a separate starter organization for a genuinely new verified identity and
   signs its owner in.
3. Invite colleagues through the workspace's Members settings. They use the
   password setup email to join with the organization and role already assigned.

Invite colleagues before they independently create another workspace. Email
verification never moves an existing account between organizations or grants
it a different role. SMTP acceptance and inbox delivery are separate outcomes;
the Members screen confirms the request was accepted. Eligible accounts receive
a password setup email.

Passwords support spaces and Unicode, with a minimum of 12 characters and a
maximum of 1024 UTF-8 bytes. Hash stores salted password hashes. It uses its
existing HttpOnly session cookie and rechecks current membership and session
generation; the browser does not receive a bearer token to persist.

## Recover access

Choose **Forgot password** and enter your email. The page gives the same response
whether an account exists. A valid account receives an expiring, one-use link.
Setting a new password invalidates prior sessions and outstanding account links;
sign in again afterward.

Verification and recovery links carry their token in the URL fragment. The
account page removes it from the address bar before posting it to Hash. Tokens
are stored as hashes; account-email bodies are encrypted in the durable mail
queue and cleared after delivery. Old or already used links cannot be replayed.

## Operator setup

- Set the intended HTTPS `HASH_PUBLIC_URL` and use Hash's existing strong session
  and encryption keys. Server and worker need the same configured encryption
  key and any retained previous key for queued account mail.
- Configure outbound SMTP before testing verification, invitations and password
  recovery. The normal development stack captures messages in MailHog.
- Include credentials, account-request state and the mail queue in PostgreSQL
  backup/restore qualification, together with the existing encryption keys.
- Leave OIDC settings blank for email/password only. Existing SSO accounts keep
  their identity binding and membership; password recovery proves mailbox
  ownership before adding or changing a password.

The native account routes require migration 117. A downgrade refuses while
credential, account-request or sealed account-mail data remains; use the
reviewed restore procedure rather than deleting authentication records.
