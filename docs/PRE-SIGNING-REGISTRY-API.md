# Signing workflow and self-grant registry API

This browser registry stores reviewed workflow policies and a named member's
own revocable authority. Registry mutations themselves do not consume a use,
produce a signature or send an invitation. The isolated implementation candidate
adds separate [execution, approved-data source and linked-draft routes](PRE-SIGNING-EXECUTION-API.md).
Their production switch is disabled by default; configured integration and
release acceptance remain separate from source and component qualification.

All paths start with `/api/v1/presign`. They require a current signed
`hash_session` cookie; an API key, MCP identity or generic actor callback cannot
grant a person's consent. Fresh confirmation must use the exact session captured
by preview. Recovery requires the original member and organization through a
current session; it does not require an expired preview cookie.
Mutations require the exact app `Origin`. Responses
are `no-store`. A member has 60 requests per minute on this tree, with an
additional shared 15-per-minute mutation budget. These are process-local
limits; multiple instances need measured deployment-level admission.

## Routes and permissions

| Method | Suffix | Permission and response |
| --- | --- | --- |
| GET | `/context` | Current member; actor witness, live own identity/role, bundled font hashes, app-owned disclosure text and `execution_available` (false by default). |
| GET | `/fonts/{font}` | Current member; exact bundled WOFF2 bytes for a supported, URL-encoded font name. Verify against the context hash before showing a signature preview. |
| GET | `/templates` | Owner; up to 20 recent approved schema-3 template revision descriptors, declarations, defaults and contract profile. `truncated` reports the count or byte window. Raw HTML/assets and storage identifiers are absent. |
| GET | `/workflows` | Current member; bounded current workflow views and original actor witness. |
| GET | `/workflows/{id}` | Current member; selected retained revision with policy reference and current archive/retirement state. |
| POST | `/workflows/preview` | Owner; normalized `WorkflowIntent`, readable rules/commitments and short-lived confirmation receipt. |
| POST | `/workflows/approve` | Owner; `ConfirmWorkflowInput`, actual approval time and durable mutation outcome. New revisions advance the expected head once. |
| POST | `/workflows/{id}/retire` | Owner; confirmed exact workflow definition reference; retire that revision. |
| POST | `/workflows/{id}/archive` | Owner; confirmed current workflow definition reference; terminal archive. |
| GET | `/self-grants` | Current member; own bounded current grant views. |
| GET | `/self-grants/{id}` | Current member; own selected retained grant revision and current state. |
| POST | `/self-grants/preview` | Sender/owner; `GrantIntent`, live named grantor, exact bundled style and app-owned disclosure pins, expiring confirmation receipt. |
| POST | `/self-grants/create` | Sender/owner; `ConfirmGrantInput`, actual consent time and durable mutation outcome. |
| POST | `/self-grants/{id}/revise` | Sender/owner; confirmed next own revision while the same logical grant remains active. A terminally revoked grant needs a fresh ID/consent. |
| POST | `/self-grants/{id}/revoke` | Current member; confirmed exact own grant reference. Sending-role loss does not prevent own revocation. |
| GET | `/grants`, `/grants/{id}` | Owner; bounded colleague grant discovery/detail for emergency revocation. |
| POST | `/grants/{id}/revoke` | Owner; confirmed exact colleague grant reference. This never grants authority on another person's behalf. |
| GET | `/requests/{request_id}` | Original current member; immutable `committed` or `closed` outcome, or unconfirmed 404. |
| POST | `/requests/{request_id}/close` | Original current member; explicit confirmation resolves the nonce as closed, or returns its existing committed/closed outcome. |

Collection envelopes are `{org_id,user_id,items}`. Detail reads optionally accept
one canonical positive `revision` query parameter; omission reads the current
locked head. Route UUIDs and body UUIDs use lowercase hyphenated canonical
spelling. Paths and body references must agree. Bodies reject unknown or
incorrectly cased keys, duplicates, malformed Unicode, deep nulls, trailing
values and more than 1 MiB. Optional rule members are omitted rather than null.
CRM `generation` is a canonical positive decimal string so JavaScript cannot
round a 64-bit generation. Revisions and finite usage/duration caps are bounded
by the service. [Go request/response types](../internal/presignregistry/types.go)
define the exact field names; the generated route inventory is not an OpenAPI
schema for this browser contract.

## API executor credentials

A workflow naming an API executor must select a regular API key belonging to the
exact named organization/user, with a non-null `expires_at` strictly after the
current database clock. A key without expiry is ineligible even if ordinary API
authentication accepts it. Both authoring and workflow privileges must remain
available (the explicit scopes are `write:authoring` and `write:workflow`;
existing broader `write`/`admin` privileges satisfy those checks). Credential
identity, scope, live membership and natural expiry are rechecked under the
actual authority transaction. Document-agent credentials and MCP identities do
not become pre-sign API executors. This finite-expiry rule is specific to
pre-sign workflow authority and does not impose a new global API-key rule.

## Review and recovery

Each write supplies a fresh `request_id`, `expected_org_id` and
`expected_user_id`. Preview is read-only. Approval/consent supplies the exact
normalized intent, original-session-bound preview receipt and `confirmed:true`.
Retire/archive/revoke supply an exact `{id,revision,sha256}` reference and explicit
confirmation. The workflow reference uses the definition hash; grant policy
selection uses the separately returned policy reference. A company/authority
declaration is not independent identity or representative-authority verification.

Before dispatching a confirmed mutation, retain only its opaque request/actor
metadata. A network failure, 503 or unconfirmed 404 is not a successful close or
permission to mint another request. Recover with the original authenticated
actor and request ID. A committed outcome retains its original operation,
command hash, exact resource reference and occurrence time, even after the
resource expires or is revoked. Read the resource's current state separately.
A closed outcome uses `operation:"request.close"`, a nil UUID/zero revision/empty
hash reference, and omits `command_sha256` and `resource_kind`. Explicitly
acknowledge the confirmed outcome before clearing the pending marker or adopting
another operation.

Approval, consent, terminal revocation, audit append and recovery outcome commit
in one bounded transaction. Original session and natural deadlines are rechecked
after audit waits. Role eligibility loss, name/email changes, organization moves
or removal terminally revoke affected grants; changing those values back cannot
revive them. Owner-to-sender changes and logout/session rotation alone preserve
eligible stored grants, while invalidating old browser admissions as applicable.
No standalone consumption endpoint exists. Retained authority rows restrict
organization deletion and migration rollback; general retention/disposal and
rights workflows still need the whole-application acceptance described in the
completion checklist.

401 indicates original-session expiry; 403 indicates permission/credential loss;
400 indicates invalid input; 409 indicates stale review/reference or conflicting
request reuse; 404 indicates scoped missing authority or an unconfirmed request;
503 indicates unavailable dependencies, failed stored-integrity checks or an
unknown commit result. Audit failures return redacted 500, including audit errors
wrapping a no-row/expired-credential condition. Refusals never fabricate an outcome.
