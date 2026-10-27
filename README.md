# Hash

Published by Cloud Rebellion.

Deployment-controlled, self-hosted document creation + e-signing platform. Agent-native
authoring via MCP. The name comes from the product's spine: every signing event
lands in a hash-chained audit timeline. Completed documents receive a final PDF
and audit certificate; plans with the `evidence_bundle` feature can also export
a bundle designed for independent verification against the instance's published
key. The bundled `/verify` web page is server-assisted and uploads
the supplied certificate or evidence bundle; it is not an offline verifier.

## Stack

- Go + chi + sqlc + goose (server + background worker, one image)
- SvelteKit + Svelte 5 + TipTap (block editor), embedded into the server binary
- PostgreSQL 16+
- An S3-compatible object store that implements the versioning, version-specific access, Object Lock
  retention, and legal-hold APIs Hash requires in non-local deployments
- An SMTP submission server that supports STARTTLS on a plain SMTP connection (implicit-TLS-only
  endpoints are not supported)
- Email/password staff accounts, using the existing secure session cookie
- An optional OIDC provider for staff SSO
- Gotenberg for HTML→PDF rendering
- pdfcpu for PDF signature/field stamping

Storage and mail providers must satisfy the runtime contracts above. Staff
email/password login does not require an OIDC application registration. Optional
SSO providers must satisfy Hash's verified-identity requirements.

Hetzner **Object Storage** can be evaluated as an S3 backend with Hash's `sse-c`
mode; a Hetzner **Storage Box** cannot be used as primary object storage because
it does not provide the S3 VersionId, exact-version read, and Object Lock APIs
that Hash's evidence model requires. Storage Box remains suitable only as a
separately verified encrypted backup target.

The built-in legal pages explain the instance operator's responsibilities; they
are not the operator's terms or privacy policy. Configure your actual operator
and privacy contact, and publish notices, any applicable DPA, sub-processor and
retention schedules for your deployment.

## Reusable HTML designs

In Templates, create an HTML design with its print CSS, declared values, saved
wording and local images/fonts. Save the design before previewing it. Preview
values and section samples are separate from saved defaults. An owner reviews every rendered page
and explicitly approves the saved revision; any saved edit requires new approval.

Use an approved design to populate a fresh document. Review that document's
actual PDF, confirm its signing parties and fields, then send it through the normal
signing workflow. Reviewed contract profiles derive the two named parties from
the printed values. A design with the approved branded signing-page option also
adds a fixed final page and places each party's protected signature field there.
Design approval does not approve a future contract's terms.

For manually placed fields, select the field type and recipient. On touch screens,
tap the PDF to place a field and swipe to scroll; with a mouse, click or drag a box.
Resizing the view retains the saved PDF coordinates. Generated signing-page fields
keep their protected layout. PDF history updates as the source changes; opening
an earlier revision is read-only and does not restore, approve or send it.
See [HTML design API](docs/API.md#html-design-draft-api)
and [readiness and limits](docs/READINESS.md) for contracts and remaining
release acceptance.

## Quick start

Hash runs independently. Reactor and CRM connections are optional integrations
configured through scoped APIs; see [API contracts](docs/API.md). Verify a connected
workflow's configuration before using that integration.

For the optional direct BrightCRM connector, organisation owners enroll and
explicitly confirm their own account in Settings → Integrations. Credentials are
encrypted with a dedicated operator key; fresh reads verify the remote account
and selected records. Changed CRM values require document review before sending.
See [CRM connector](docs/CRM-CONNECTOR.md) for setup, supported fields, migration
and acceptance limits.

```bash
cp .env.example .env
# configure SMTP, storage and the remaining operator settings, then:
make docker-up
# Hash at http://localhost:8080, Postgres at 5433, MinIO at 9000
```

`make dev` starts the same complete development stack. These commands explicitly
build local MinIO from its pinned official source and include the finite server
and worker work profile in `docker-compose.browser-e2e.yml`. The MinIO build
context contains no Hash application or environment files. This local profile is
not a production capacity allocation; production uses its separate storage and
per-process configuration contracts.

Open `/login` to sign in with email and password. Create a workspace through
`/register`, verify the emailed link, and invite colleagues into that workspace.
Password recovery is available from the login page. Development mail is captured
by the bundled MailHog service. Signing recipients continue to use their emailed
document links without creating staff accounts. See [staff login](docs/STAFF-LOGIN.md)
for setup and recovery.

Before creating documents, prepare the selected billing plans using
[catalog maintenance](docs/CATALOG-MAINTENANCE.md); a fresh database also needs
this preparation. Browser CI has a separate helper restricted to its synthetic
identity. See [work configuration](docs/WORK-RUNTIME.md) for the explicit local
resource profile and requirements for other deployments.

## Deploy

- **[docker-compose.selfhost.yml](./docker-compose.selfhost.yml)**: standalone
  production profile for your own domain and services; start with the
  [portable deployment guide](./DEPLOY.md#portable-production-compose).
- **[DEPLOY.md](./DEPLOY.md)**: generic, CI- and host-neutral deployment
  (Docker / Compose / Kubernetes; GitHub Actions, GitLab CI, or any pipeline).
- **[ops/BACKUP-RESTORE.md](./ops/BACKUP-RESTORE.md)**: coupled PostgreSQL + S3
  backup, restore, validation, RPO/RTO, and drill procedure.
- **[.env.example](./.env.example)**: every config var, annotated.

## License

Hash is fair-code, licensed under the Hash Sustainable Use License: self-host
free, use it commercially for your own business and your own clients, have
anyone sign on your instance; you may not resell it as a hosted e-sign service.
See [LICENSE](./LICENSE) and [LICENSING.md](./LICENSING.md).
