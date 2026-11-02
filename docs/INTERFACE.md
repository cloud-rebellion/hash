# Using the Hash workspace

Documents holds your drafts and sent or completed documents. Start with a blank
block document or import a PDF or HTML design, then review the content, recipients
and signature fields before sending. The status badge shows where each document
is in its signing journey. Search and status filters narrow the visible library.

Templates are reusable starting points. Each customer receives a new document
created from the template; editing a template does not rewrite an existing
contract. An HTML design must be reviewed and approved at its saved revision
before use. Production instances do not offer the bundled development-only legal
starter. Create an editable HTML design, upload a PDF template, or save a fully
saved block document as a template. Every library card has separate Open template
and Use template actions. Opening an uploaded PDF shows its saved content and
details; editing its original PDF text requires your PDF authoring application.

Library cards show a verified first-page thumbnail for stored PDFs. Block and HTML
cards show an escaped content preview; that preview does not reproduce the final
print layout. Open and review the actual PDF before sending. Unavailable previews
leave the document link usable and provide a clear fallback.

Verify checks an audit certificate or evidence bundle against this installation's
verification service. The selected file is uploaded to the server for checking.
It does not verify an arbitrary ordinary PDF, determine a signer's authority to
represent a company, or provide legal approval of the contract's terms.

The profile menu in the upper-right corner contains Settings, API, documentation,
language and sign-out. Sun and moon controls immediately to the left of the
profile menu select light or dark appearance with one click. Appearance initially
follows your system until you choose a mode. Choose English or Swedish from the
profile menu for the staff interface. These preferences are
stored in your browser. Staff language does not change a document's wording or the
signer's configured ceremony language. Settings groups account and team, branding
and documents, connections and automation, and security and administration; access
still depends on your workspace role.

## Connecting an AI client

An owner can open API from the profile menu to create a scoped API key and copy
the installation's HTTPS MCP endpoint, normally `https://your-domain.example/mcp`.
Use an MCP client that supports HTTP transport and an `Authorization: Bearer`
header. Put the API key in the client's private credential/header configuration,
never in the endpoint URL or a shared document. The guide displays the actual
installation origin. Available tools still depend on the key's scopes, workspace
role, enabled features and plan; copying an endpoint does not grant access.

Hash's MCP connection supports AI-assisted document authoring and settings.
External products can independently use the [HTTP API](API.md) and webhooks to
create or retrieve documents, send eligible documents, and follow signing status.
No CRM or automation service is required to use Hash on its own.
