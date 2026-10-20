# Negotiation message history

Authenticated staff read `GET /api/v1/documents/{document_id}/comments`.
Recipients read `GET /sign/{token}/comments` using their current signing link.
Both endpoints return a window of at most 50 messages, in chronological order:

```json
{
  "comments": [
    {
      "id": "message UUID",
      "author_name": "Name",
      "author_side": "sender",
      "body": "Full message text",
      "created_at": "2026-10-16T10:00:00.123456Z"
    }
  ],
  "older_cursor": null,
  "newer_cursor": null
}
```

`author_side` is `sender` or `signer`. Timestamps retain the database's
microsecond precision; clients must preserve their strings rather than sorting
messages by JavaScript's millisecond clock. Historical text is returned whole,
including messages longer than the current POST text limit.

Omit the query for the latest window. Pass `?before=<older_cursor>` for an older
window or `?after=<newer_cursor>` for a newer one. A null cursor marks the end
in that direction. Cursors are opaque, fixed-length selections bound to the
organisation and document. They grant no access; every request repeats current
authorisation and document/recipient policy checks. Do not decode, construct or
reuse a cursor with another document. Invalid, duplicated, unknown, foreign or
simultaneous before/after parameters return HTTP 400. Offset and custom limit
parameters are unsupported. Responses use Cache-Control: no-store.

The two portals replace the displayed window on a successful read. Older and
Newer wait for any current read or send to finish; Latest can supersede a read.
A confirmed POST releases the send controls before its follow-up GET finishes,
so Latest can replace a stalled refresh. Paging preserves the editable draft. A failed read retains the previous window
and offers Retry for precisely that failed GET. It never retries POST.

Sending remains a separate POST to the same path. A confirmed send clears only
the exact submitted draft and then fetches Latest. Text entered while sending
is retained. If the subsequent GET fails, Retry fetches history without sending
the message again. Recipient POST requires acknowledgement of the current
privacy notice; GET does not require that acknowledgement.
