# Hash agent rules

Go module root is this directory. Run `go build ./... && go vet ./... && go test ./...`
and `go vet -tags=e2e ./internal/handler/...` before committing. Report the numeric
exit code of each, captured to a file, never through a pipe.

## Source guards (internal/sourceguard)

Four AST checks run with `go test ./...`. Each pins a defect class from the PR 5
audits. A failure names the function; fix the code, do not widen an allowlist
without a written reason.

1. **Unmeasured document audit events.** `audit.Logger` measures every event that
   names a document (`measureDocumentEventV1`, called from `Logger.append`, so both
   `Log` and `LogTx` are covered), in the caller's transaction. An HTML document
   with an unmeasured event can never be revised (permanent 503). Do not add a
   second event writer: the guard fails on any use of `InsertEvent` outside
   `Logger.append`, on `InsertEventIdentityV1` outside `pdfadmission` and
   `ownedaudit`, and on any new sqlc statement that inserts into `events`.
2. **Gate before session.** In an error mapping, classify the review gate
   (`reviewgate.Message`, `sendReviewGateMessageV1`, `writePDFRevisionDBRefusalV1`)
   before testing `ErrApplicationSessionV1`. The session wrapper keeps the cause,
   so testing it first turns a permanent 409 refusal into "503 retry later". A
   function that tests `ErrApplicationSessionV1` with no classifier at all must be
   in `sessionCheckWithoutGateClassifier`; that list only shrinks.
3. **Human review in e2e fixtures.** Do not call `MarkDocumentHTMLReviewed` in a
   `*_e2e_test.go` file. Use `markHTMLReviewedHumanE2E`, which also records the
   human reviewer kind that the signing gate requires.
4. **One DSR error mapping.** Map a database error on the DSR transition path only
   through `classifyDSRDBErrorV1`. `writeDSRRetryableV1` and
   `writeDSRPrivacyContentionV1` are called from nowhere else; the guard fails on any
   other caller. A failed `tx.Commit` in `handleTransitionDSR` goes through
   `classifyDSRCommitErrorV1` and never through `fail`: it gives a retry hint only
   for a deadline that passed before COMMIT was sent, or a server rollback (40001,
   40P01, 55P03). A lost connection and 57014 can follow an applied commit and are
   "outcome unknown". The guard fails if any Commit error branch in `dsr.go` calls
   `fail`, or if one in `handleTransitionDSR` does not call the commit classifier.

## Frontend route classification

Whether a SPA path is public, an auth screen, the verify page or a staff page
is decided only in `frontend/src/lib/routeSurface.ts`. The root layout, the
session-expiry guard, the login return path and Flare telemetry all read it. Do
not write a `path.startsWith('/sign')` style check anywhere else. Adding a
directory under `frontend/src/routes` needs an entry there; `routeSurface.test.ts`
fails until it has one.
