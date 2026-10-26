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

### First internal workspace

A fresh operator-mode installation needs a real organization before its
nonempty `HASH_OPERATOR_ENTITLEMENTS` binding can pass startup validation. Use
the exact release image's maintenance command to create the first workspace
and its pending owner atomically:

```sh
hash-bootstrapowner --org-id "$HASH_INITIAL_ORG_ID" --company 'Example Company' \
  --owner-name 'Example Owner' --owner-email owner@example.com \
  --review-ref approved-first-workspace
```

Select a new non-nil organization UUID for `HASH_INITIAL_ORG_ID` in the reviewed
installation request and bind that same identity in the planned operator
configuration. The command creates that real organization; it cannot take over
an unrelated existing identity. `HASH_INITIAL_ORG_ID` is a shell input for this
example, not an additional application setting.

Supply `HASH_DB_URL` through the managed private configuration, never command
arguments. This operation requires migration 117 and the existing maintenance,
source and physical database fences. During a managed first installation, run
it only after the genuine `exact-candidate-cutover` phase is persisted. The
earlier `schema-applied-empty-estate` phase requires an unused business estate.
The command alone does not establish those deployment prerequisites or start
the application.

Retain the returned organization, owner and audit identities and verify that
the created organization matches the planned operator binding. Server and
worker must use that real organization and the same approved finite plan.
Prepare the selected plan through the existing catalog maintenance process.
Do not change a validated environment snapshot in the middle of a deployment.

The owner then uses **Forgot password** on the intended HTTPS origin and follows
the setup email to choose their password. No password, verified mailbox claim,
OIDC subject, API key, session or subscription is created by the command.
An exact retry recognizes the original audited initialization and returns its
identities without replacing later account state. Unrelated existing workspaces
or a conflicting initialization refuse. SMTP and inbox delivery still require
the normal deployed acceptance checks.
