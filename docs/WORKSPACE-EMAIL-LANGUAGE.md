# Workspace email language and saved native editions

An owner can save English (`en`) or Swedish (`sv`) as the workspace email
language. It selects built-in copy for future scheduled staff/quota notices.
An absent setting preserves English at revision zero without creating a row.
The browser's staff UI language remains independent. Customer invitations,
reminders and other recipient messages retain their document/recipient language
rules. A decline notification retains the original locked document language,
including the native renderer's existing normalization and fallback behavior.

Saved subject, introduction and design source is literal content. Choosing a
language does not translate that source. The existing native content, action
links, issuer/security copy and mandatory material remain controlled by Hash.

## Owner settings contract

`GET /api/v1/email-preferences` returns:

```json
{
  "schema_version": 1,
  "org_id": "the-current-workspace-uuid",
  "revision": 0,
  "locale": "en",
  "updated_at": null
}
```

The nonzero organization identity comes from the admitted owner, never the
request body. A persisted row has a positive revision and an RFC3339Nano
`updated_at`. The revision is an exact JSON/JavaScript integer from zero through
9007199254740991. At that ceiling the setting is readable but no further save is
accepted.

`PUT /api/v1/email-preferences` takes only the two required fields:

```json
{"expected_revision":0,"locale":"sv"}
```

The expected revision must be an integer from zero through 9007199254740990.
Unknown or duplicate fields, nulls, fractional numbers, regional language tags,
unsupported languages and trailing JSON are refused. A successful save advances
the revision by exactly one, including an explicit save of the same language.
Both responses use `Cache-Control: no-store`.

Read and save retain the original owner session or key authorization and live
tenant membership through their transaction. Saves append an atomic
`email_preferences.updated` audit event with the new revision and locale. They
do not prepare or send an email. Invalid input returns 400; a stale revision
returns 409; missing or revoked authority returns 401/403. An unconfirmed write
outcome requires readback before retry. Keep local input while reconciling.

MCP exposes the same service and checks through
`get_workspace_email_preferences` with no arguments and
`save_workspace_email_preferences` with the PUT fields. Both require an owner
and an organization-wide key. Read needs `read`; save needs `write:authoring`.
Document-scoped credentials cannot access workspace preferences. These tools
grant no SMTP or workflow/send permission.

## Editions and synthetic previews

The nine-kind catalog now has eight editable kinds. `email.declined` and
`email.quota_warning_80` use the same immutable, exact-revision saved editions as
the six existing editable kinds. `email.voided` remains built-in-only. There is
no new voided-email producer.

Synthetic Preview and AI proposal Preview responses include `locale`. A quota
sample uses the saved workspace email preference at the preview transaction;
other samples retain their existing English context. The explicit sample
language is separate from custom literal source. A preference change invalidates
an old quota preview in the settings UI; reload the preference and preview again.
The existing explicit saved-template SMTP sample uses the same guarded quota
language selection in its original owner transaction. Other sample kinds retain
English. Its authenticated owner destination, SMTP/template CAS, rate fence,
synthetic notice and immutable queued-byte receipt remain unchanged. Changing
the preference does not request or deliver a sample.
Preview never sends or saves. AI proposal still requires the configured enabled
workspace provider, normal accounting and a separate human-reviewed save.

## Native delivery and rollout boundary

The two existing quota producers and decline producer select preference and
edition in their original transaction before freezing subject/HTML/text into the
existing outbox. Quota selects the saved workspace language; decline keeps its
document language. The original recipients, triggers, timing, deduplication,
status/token/notice checks and dispatch mechanism remain unchanged. Already
queued bodies remain immutable and are never rerendered by a worker.

Migration 128 (`00128_workspace_email_and_signing_languages.sql`) creates typed
workspace preferences and widens the template revision kind constraint for
decline/quota. It also freezes an English or Swedish incorporation statement in
each new package Send attempt. A new attempt follows the document's saved
language; later display and response validation follow that frozen version.
Retained English attempts, statements and evidence keep their original bytes.
The Article13 notice follows the recipient's saved language; its actual displayed
words remain committed by the existing notice snapshot and digest. Interface
labels identify the actual notice and frozen package languages independently.
The browser never translates canonical notices or authored document content.

This semantic package change requires lifecycle writer contract **10**. Reviewed
M117–M123 trees retain writer8 and M124–M127 retain writer9. The release identity
is used by deployment admission and rollback review; it does not fence SQL from
an already-running old process. **Quiesce every old Hash server, worker and
one-shot writer before applying M128.** An old writer9 artifact must not resume
over retained Swedish package state. The existing deployment compatibility gate
must compare the candidate's exact migration digest and writer10 identity;
maintenance or a verified restore is required where old-image rollback is
incompatible. Do not infer compatibility from unchanged outbox bytes.

Applied migrations119 and107 stay intact. M128 Down refuses while any workspace
preferences, new-kind editions, Swedish package attempts or Swedish package
responses remain; it never deletes that retained data. SQL generation, source
checks, native and real-PostgreSQL tests, exact CI, the reviewed Stage128 admission
update and release acceptance are separate steps before installation. No
already-deployed or fully Swedish live-ceremony claim follows from authored
source or test fixtures.

The process-resource contract is described in
[native email work ownership](WORKSPACE-EMAIL-RESOURCES.md).
