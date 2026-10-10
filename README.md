# Hash

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
- Any OIDC provider for sender SSO (Zitadel, Keycloak, Auth0, ...)
- Gotenberg for HTML→PDF rendering
- pdfcpu for PDF signature/field stamping

(The Bright Interaction instance uses MinIO, Postal, and Zitadel. Alternatives must satisfy the
runtime contracts above and the OIDC claim requirements enforced at boot/login.)

Hetzner **Object Storage** can be evaluated as an S3 backend with Hash's `sse-c`
mode; a Hetzner **Storage Box** cannot be used as primary object storage because
it does not provide the S3 VersionId, exact-version read, and Object Lock APIs
that Hash's evidence model requires. Storage Box remains suitable only as a
separately verified encrypted backup target.

The built-in legal pages are Bright Interaction draft templates, not reusable operator terms. A
self-hosting operator must replace or obtain approval for its own notices, DPA, sub-processor and
retention schedules before processing customer data.

## Reusable HTML designs

In Templates, create an HTML design with its print CSS, declared values, saved
wording and local images/fonts. Save the design before previewing it. Preview
values are separate from saved defaults. An owner reviews every rendered page
and explicitly approves the saved revision; any saved edit requires new approval.

Use an approved design to populate a fresh document. Review that document's
actual PDF, add its signing parties and fields, then send it through the normal
signing workflow. Design approval does not approve a future contract's terms or
signature placement. See [HTML design API](docs/API.md#html-design-draft-api)
and [completion status](docs/COMPLETION-STATUS.md) for contracts and remaining
release acceptance.

## Quick start

```bash
cp .env.example .env
# edit .env, then:
make docker-up
# Hash at http://localhost:8080, Postgres at 5432, MinIO at 9000
```

## Deploy

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
