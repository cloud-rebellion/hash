# Service email content

Workspace owners can open **Settings → Email content** to change a message's
subject and introductory content. Use the HTML and plain-text fields together,
then preview the result before saving. The preview uses sample names, documents
and non-delivering `example.invalid` links; it sends no email.

The following messages support saved content:

| Message | API kind |
| --- | --- |
| Signature invitation | `email.invite` |
| Signing reminder | `email.reminder` |
| Completion sent to a signer | `email.completed_signer` |
| Completion sent to the sender | `email.completed_sender` |
| Requested document changes | `email.changes_requested` |
| New negotiation comment | `email.new_comment` |

Declined, voided and quota-warning messages currently use their built-in content.
Their previews are available; saving overrides for them is refused.

## Variables and formatting

Insert `{{document_name}}`, `{{sender_name}}`, `{{sender_email}}`,
`{{recipient_name}}` or `{{org_name}}`. Values are escaped when rendered; other
variables and malformed tokens are refused.

The subject accepts up to 256 UTF-8 bytes, HTML up to 16,384 bytes and plain text
up to 8,192 bytes. HTML supports paragraphs, line breaks, emphasis, headings,
lists, block quotes and simple tables. Attributes, styles, images, custom links
and scripts are unavailable in this content editor. This editor does not change
SMTP configuration, the sender address, the email's overall layout or its logo.

Hash adds the message's action links, expiry and required service information
after the introductory content. These remain controlled by Hash. An empty
override keeps the built-in subject or content for that field.

## Saving and delivery

Each save creates an immutable workspace-specific revision. If someone else has
changed the template, reload and review the newer revision before saving again.
Changing content affects newly prepared messages. A message already queued keeps
the content selected when it was prepared.

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
