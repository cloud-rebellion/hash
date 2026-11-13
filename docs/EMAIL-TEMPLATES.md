# Service email design

Workspace owners can open **Settings → Email design** to change a message's
subject, introduction, layout, colors and embedded logo. Use the HTML and
plain-text introductions together, then preview the result before saving. The
preview uses sample names, documents and non-delivering `example.invalid` links;
it sends no email. Configure the workspace's sender name, sender address and own
SMTP server separately in **Settings → Email delivery**; see
[Workspace SMTP](WORKSPACE-SMTP.md).

The following messages support saved content:

| Message | API kind |
| --- | --- |
| Signature invitation | `email.invite` |
| Signing reminder | `email.reminder` |
| Completion sent to a signer | `email.completed_signer` |
| Completion sent to the sender | `email.completed_sender` |
| Requested document changes | `email.changes_requested` |
| New negotiation comment | `email.new_comment` |
| Declined document | `email.declined` |
| Quota warning | `email.quota_warning_80` |

Voided messages remain built-in-only: their previews are available, but saving
overrides is refused. Quota warnings use the saved workspace email language;
declined-document messages use the document's language. See
[workspace email language](WORKSPACE-EMAIL-LANGUAGE.md) for delivery and synthetic
preview language selection.

## Variables and formatting

Insert `{{document_name}}`, `{{sender_name}}`, `{{sender_email}}`,
`{{recipient_name}}` or `{{org_name}}`. Values are escaped when rendered; other
variables and malformed tokens are refused.

The subject accepts up to 256 UTF-8 bytes, HTML up to 16,384 bytes and plain text
up to 8,192 bytes. HTML supports paragraphs, line breaks, emphasis, headings,
lists, block quotes and simple tables. Attributes, styles, images, custom links
and scripts are unavailable in the introduction. The separate design controls
provide the overall layout, colors and logo without changing SMTP or the sender.

Hash adds the message's action links, expiry and required service information
after the introductory content. These remain controlled by Hash. An empty
override keeps the built-in subject or content for that field.

## Layout, logo and AI proposals

Use the design controls for colors and a local PNG/JPEG logo, or edit the safe
HTML layout around its required `{{native_content}}` slot. The native signing
actions, deadlines and security information remain visible and unchanged. A logo
is embedded in the email; the design does not fetch remote images. Logos must fit
32 KiB and 512 pixels per dimension. Arbitrary links, scripts, hidden actions and
remote resources are refused. Document theme settings are separate from email
design.

**Design with AI** uses the enabled provider in workspace AI settings. The
proposal is an unsaved draft with a synthetic preview. Review it, choose
**Use proposal in draft**, then **Save changes** separately. Generating or
accepting a proposal sends no email. There is no provider-key entry in a
document or email template.

The API's optional `design_json` string preserves the saved design when omitted;
an empty string explicitly clears it. See [the design schema](API.md#email-content-design-and-synthetic-previews)
for the layout, logo and byte-limit contract.

## Saving and delivery

Each save creates an immutable workspace-specific revision. If someone else has
changed the template, reload and review the newer revision before saving again.
Changing content affects newly prepared messages. A message already queued keeps
the content selected when it was prepared. Newly prepared recipient messages use
the send-frozen company presentation or a neutral footer; already queued messages
keep their original bytes. Service and evidence identities are retained.

After saving, use the saved-template test to queue a synthetic email to your own
signed-in address through the configured workspace SMTP server. It tests the
observed template and SMTP revisions, with non-delivering sample action links.
Queued or SMTP-accepted status does not confirm inbox delivery. This test does
not simulate an actual customer negotiation or signature; test those separately
with a clearly labelled document and controlled recipients.

Content editing does not enable email-open tracking, change notification
preferences or change the reminder schedule. SMTP delivery and recipient-room
testing are separate from the synthetic preview.

## HTTP endpoints

These endpoints require an authenticated owner session. Mutating requests use
the same CSRF protection as other workspace settings.

- `GET /api/v1/email-templates` lists content, revisions, editable capabilities,
  supported variables and byte limits.
- `POST /api/v1/email-templates/{kind}/preview` renders synthetic content.
- `PUT /api/v1/email-templates/{kind}` saves a new revision.
- `POST /api/v1/email-templates/{kind}/propose` returns an unsaved AI proposal.
- `POST /api/v1/email-templates/{kind}/test` queues a saved-template test to the
  current owner, using `expected_smtp_revision` and `expected_template_revision`.

Preview and save require all four fields. Use the revision returned by the list
response, including `0` for a template without a saved override:

```json
{
  "expected_revision": 0,
  "subject_template": "Please review {{document_name}}",
  "html_template": "<p>Hello {{recipient_name}},</p><p>Please review our agreement.</p>",
  "text_template": "Hello {{recipient_name}},\nPlease review our agreement."
}
```

Invalid content returns `400`; a stale revision returns `409`. After a save
timeout, reload the saved revision before retrying: the first save may have
completed. Templates and previews are returned with `Cache-Control: no-store`.
