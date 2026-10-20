// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

//go:build e2e

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/billing"
	"github.com/bright-interaction/hash/internal/blocks"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/dispatch"
	"github.com/bright-interaction/hash/internal/send"
	"github.com/bright-interaction/hash/internal/templatepin"
)

func TestAutomationSignatureRequestIsAtomicConcurrentAndReplaySafeE2E(t *testing.T) {
	owned := newOwnedAutomationAuthorizationFixtureV1(t)
	ownedCreationPrepareProPlanV1(t, owned)
	ownedAutomationAuthorizationPrepareFreePlanV1(t, owned)
	base := owned.f
	ctx, pool, q, server := base.ctx, base.pool, base.q, base.s
	user := base.user
	org, err := q.GetOrg(ctx, base.org)
	if err != nil {
		t.Fatal(err)
	}
	ctx = automationCredentialContextE2E(t, ctx, q, user)
	sendEngine := server.Send
	// Preserve this original regression's nil billing and no-op mail policy;
	// concrete storage, restricted renderer and native runtime remain genuine.
	server.Billing = nil
	sendEngine.Billing = nil
	sendEngine.Mailer = dispatch.NoopMailer{}
	tree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "intro", Type: blocks.TypeParagraph, Text: "Agreement for {{customer.name}}"},
		{ID: "signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	blocksJSON, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	template, err := originalAutomationTemplateCreateV1(t, owned, "Partner agreement", blocksJSON, json.RawMessage(`{"customer.name":"Template default","company.name":"Example AB"}`))
	if err != nil {
		t.Fatal(err)
	}
	templateContent, err := templatepin.Canonicalize(template.BlocksJson, template.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	baseRequestInput := automationSignatureRequestInput{
		TemplateID: template.ID.String(), TemplateVersion: template.Version,
		TemplateContentSHA256: templateContent.SHA256Hex(),
		Name:                  "Ada partner agreement", LawfulBasis: "contract",
		Variables:  map[string]string{"customer.name": "Ada"},
		Recipients: []automationSignatureRecipientInput{{Email: "ada@example.test", Name: "Ada", Locale: "en"}},
	}
	prepared, requestHash, err := prepareAutomationSignatureRequest(baseRequestInput)
	if err != nil {
		t.Fatal(err)
	}
	processInput := automationSignatureRequestProcessInput{
		User:    auth.SessionUser{UserID: user.ID, OrgID: org.ID, Role: user.Role, Email: user.Email},
		Request: prepared, IdempotencyKeyHash: automationIdempotencyKeyHash("e2e-send-" + uuid.NewString()),
		RequestHash: requestHash, IP: "127.0.0.1", UserAgent: "hash-e2e",
	}
	type durableCounts struct {
		Requests, Documents, Recipients, Versions, Audits, Emails, Webhooks int
	}
	readDurableCounts := func(email string) durableCounts {
		t.Helper()
		var counts durableCounts
		if err := pool.QueryRow(ctx, `SELECT
			(SELECT count(*) FROM automation_signature_requests WHERE org_id = $1),
			(SELECT count(*) FROM documents WHERE org_id = $1),
			(SELECT count(*) FROM recipients r JOIN documents d ON d.id = r.document_id WHERE d.org_id = $1),
			(SELECT count(*) FROM document_versions WHERE org_id = $1),
			(SELECT count(*) FROM events WHERE org_id = $1),
			(SELECT count(*) FROM email_deliveries WHERE to_email = $2),
			(SELECT count(*) FROM webhook_deliveries wd JOIN events e ON e.id = wd.event_id WHERE e.org_id = $1)`,
			org.ID, email,
		).Scan(&counts.Requests, &counts.Documents, &counts.Recipients, &counts.Versions, &counts.Audits, &counts.Emails, &counts.Webhooks); err != nil { //nolint:rawsql
			t.Fatal(err)
		}
		return counts
	}
	differentDigest := func(value string) string {
		first := byte('0')
		if value[0] == first {
			first = '1'
		}
		return string(first) + value[1:]
	}
	for _, test := range []struct {
		name                string
		mutate              func(*automationSignatureRequestInput)
		wantContentMismatch bool
		wantExpectedVersion int32
	}{
		{
			name: "version mismatch", wantExpectedVersion: template.Version + 1,
			mutate: func(in *automationSignatureRequestInput) { in.TemplateVersion++ },
		},
		{
			name: "content mismatch", wantContentMismatch: true, wantExpectedVersion: template.Version,
			mutate: func(in *automationSignatureRequestInput) {
				in.TemplateContentSHA256 = differentDigest(in.TemplateContentSHA256)
			},
		},
	} {
		t.Run("pin "+test.name+" leaves no durable state", func(t *testing.T) {
			mismatched := baseRequestInput
			mismatched.Recipients = []automationSignatureRecipientInput{{
				Email: uuid.NewString() + "@pin-mismatch.test", Name: "Mismatch", Locale: "en",
			}}
			test.mutate(&mismatched)
			mismatchedPrepared, mismatchedHash, err := prepareAutomationSignatureRequest(mismatched)
			if err != nil {
				t.Fatal(err)
			}
			mismatchedProcess := processInput
			mismatchedProcess.Request = mismatchedPrepared
			mismatchedProcess.RequestHash = mismatchedHash
			mismatchedProcess.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-pin-mismatch-" + uuid.NewString())
			before := readDurableCounts(mismatched.Recipients[0].Email)
			_, _, callErr, callLease := originalAutomationMaterializeV1(t, server, ctx, mismatchedProcess)
			defer callLease.closeV1()
			var precondition *automationTemplatePreconditionError
			if !errors.As(callErr, &precondition) || precondition.ActualVersion != template.Version ||
				precondition.ExpectedVersion != test.wantExpectedVersion ||
				precondition.ContentDigestMismatch != test.wantContentMismatch {
				t.Fatalf("precondition error = %#v/%v", precondition, callErr)
			}
			after := readDurableCounts(mismatched.Recipients[0].Email)
			callErr = nil
			callLease.closeV1()
			if after != before {
				t.Fatalf("pin mismatch leaked durable state: before=%#v after=%#v", before, after)
			}
		})
	}

	first, err, firstLease := originalAutomationProcessV1(t, server, ctx, processInput)
	defer firstLease.closeV1()
	if err != nil {
		t.Fatalf("first composite request: %v", err)
	}
	if first.Replayed || first.Status != "sent" || first.AutomationRequestID == uuid.Nil || first.DocumentID == uuid.Nil {
		t.Fatalf("first response = %#v", first)
	}
	replayed, err, replayLease := originalAutomationProcessV1(t, server, ctx, processInput)
	defer replayLease.closeV1()
	if err != nil {
		t.Fatalf("replay composite request: %v", err)
	}
	if !replayed.Replayed || replayed.AutomationRequestID != first.AutomationRequestID || replayed.DocumentID != first.DocumentID || replayed.Status != "sent" {
		t.Fatalf("replay response = %#v, first = %#v", replayed, first)
	}
	first.Status = ""
	replayed.Status = ""
	firstLease.closeV1()
	replayLease.closeV1()
	document, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: first.DocumentID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	variables, err := blocks.ParseVariableValues(document.VariablesJson)
	if err != nil || variables["customer.name"] != "Ada" || variables["company.name"] != "Example AB" {
		t.Fatalf("frozen variables = %#v/%v", variables, err)
	}
	copiedTemplateContent, err := templatepin.Canonicalize(document.BlocksJson, template.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	if copiedTemplateContent.SHA256 != templateContent.SHA256 {
		t.Fatalf("document copied content digest = %s, want pinned %s", copiedTemplateContent.SHA256Hex(), templateContent.SHA256Hex())
	}
	versions, err := q.CountDocumentVersions(ctx, document.ID)
	if err != nil || versions != 1 {
		t.Fatalf("document versions = %d/%v, want 1", versions, err)
	}
	var versionBlocksMatch, versionVariablesMatch bool
	if err := pool.QueryRow(ctx, `SELECT
		v.block_tree_json = d.blocks_json,
		v.variables_json = d.variables_json
		FROM document_versions v
		JOIN documents d ON d.id = v.document_id
		WHERE v.document_id = $1 AND v.version_no = 1`, document.ID,
	).Scan(&versionBlocksMatch, &versionVariablesMatch); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if !versionBlocksMatch || !versionVariablesMatch {
		t.Fatalf("initial version did not exactly snapshot copied blocks/variables: %v/%v", versionBlocksMatch, versionVariablesMatch)
	}
	var documentCount, recipientCount int
	if err := pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM documents WHERE org_id = $1 AND template_id = $2),
		(SELECT count(*) FROM recipients WHERE document_id = $3)`, org.ID, template.ID, document.ID).Scan(&documentCount, &recipientCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if documentCount != 1 || recipientCount != 1 {
		t.Fatalf("replay created documents/recipients = %d/%d, want 1/1", documentCount, recipientCount)
	}
	// Every later Hash lifecycle callback carries a durable Hash-owned
	// correlation back to this command. The producer can persist the composite
	// response once, then update CRM state from signed callbacks without Hash
	// retaining the producer's raw idempotency key.
	var sentEventID uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM events WHERE document_id = $1 AND kind = 'document.sent' ORDER BY created_at LIMIT 1`, first.DocumentID).Scan(&sentEventID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	lifecycleEvent, err := dispatch.LoadEvent(ctx, q, sentEventID)
	if err != nil {
		t.Fatal(err)
	}
	if lifecycleEvent.AutomationRequestID != first.AutomationRequestID.String() {
		t.Fatalf("lifecycle automation_request_id = %q, want %q",
			lifecycleEvent.AutomationRequestID, first.AutomationRequestID)
	}
	var createPayloadJSON []byte
	if err := pool.QueryRow(ctx, `SELECT payload_hashed FROM events WHERE document_id = $1 AND kind = 'document.created' ORDER BY created_at LIMIT 1`, first.DocumentID).Scan(&createPayloadJSON); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	var createProvenance struct {
		TemplateID            uuid.UUID `json:"template_id"`
		TemplateVersion       int32     `json:"template_version"`
		TemplateContentSHA256 string    `json:"template_content_sha256"`
	}
	if err := json.Unmarshal(createPayloadJSON, &createProvenance); err != nil {
		t.Fatal(err)
	}
	if createProvenance.TemplateID != template.ID || createProvenance.TemplateVersion != template.Version ||
		createProvenance.TemplateContentSHA256 != templateContent.SHA256Hex() {
		t.Fatalf("immutable create provenance = %#v", createProvenance)
	}

	collision := processInput
	collision.RequestHash[0] ^= 0xff
	_, collisionErr, collisionLease := originalAutomationProcessV1(t, server, ctx, collision)
	defer collisionLease.closeV1()
	if err := collisionErr; !errors.Is(err, errAutomationIdempotencyConflict) {
		t.Fatalf("same key/different request error = %v", err)
	}
	collisionErr = nil
	collisionLease.closeV1()
	for _, test := range []struct {
		name   string
		mutate func(*automationSignatureRequestInput)
	}{
		{name: "changed template version", mutate: func(in *automationSignatureRequestInput) { in.TemplateVersion++ }},
		{name: "changed template digest", mutate: func(in *automationSignatureRequestInput) {
			in.TemplateContentSHA256 = differentDigest(in.TemplateContentSHA256)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := baseRequestInput
			test.mutate(&changed)
			changedPrepared, changedHash, err := prepareAutomationSignatureRequest(changed)
			if err != nil {
				t.Fatal(err)
			}
			changedInput := processInput
			changedInput.Request = changedPrepared
			changedInput.RequestHash = changedHash
			_, changedErr, changedLease := originalAutomationProcessV1(t, server, ctx, changedInput)
			defer changedLease.closeV1()
			if err := changedErr; !errors.Is(err, errAutomationIdempotencyConflict) {
				t.Fatalf("same idempotency key/changed pin error = %v", err)
			}
			changedErr = nil
			changedLease.closeV1()
		})
	}

	// A command can materialize successfully and then sit in a retry queue. The
	// replay must re-check the persisted absolute deadline instead of sending a
	// draft whose signing links are already too close to expiry.
	expiringPrepared, expiringHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: template.ID.String(), TemplateVersion: template.Version,
		TemplateContentSHA256: templateContent.SHA256Hex(),
		Name:                  "Expiring partner agreement", LawfulBasis: "contract",
		Variables:  map[string]string{"customer.name": "Grace"},
		Recipients: []automationSignatureRecipientInput{{Email: "grace@example.test", Name: "Grace", Locale: "en"}},
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatal(err)
	}
	expiringInput := automationSignatureRequestProcessInput{
		User: processInput.User, Request: expiringPrepared,
		IdempotencyKeyHash: automationIdempotencyKeyHash("e2e-expiring-" + uuid.NewString()),
		RequestHash:        expiringHash, IP: "127.0.0.1", UserAgent: "hash-e2e",
	}
	expiringRequest, _, err, expiringLease := originalAutomationMaterializeV1(t, server, ctx, expiringInput)
	defer expiringLease.closeV1()
	if err != nil {
		t.Fatal(err)
	}
	expiringDocumentID := uuid.UUID(expiringRequest.DocumentID.Bytes)
	expiringRequest = nil
	expiringLease.closeV1()
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '4 minutes' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	_, expiryErr, expiryLease := originalAutomationProcessV1(t, server, ctx, expiringInput)
	defer expiryLease.closeV1()
	if err := expiryErr; !errors.Is(err, errAutomationExpiryTooSoon) {
		t.Fatalf("delayed replay expiry error = %v, want ErrAutomationExpiryTooSoon", err)
	}
	expiryErr = nil
	expiryLease.closeV1()
	var expiringStatus string
	var expiringInviteEvents int
	if err := pool.QueryRow(ctx, `SELECT status FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, expiringDocumentID).Scan(&expiringInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "draft" || expiringInviteEvents != 0 {
		t.Fatalf("delayed replay status/invites = %s/%d, want draft/0", expiringStatus, expiringInviteEvents)
	}

	stageExpiringSealing := func() {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '10 minutes' WHERE id = $1 AND status = 'draft'`, expiringDocumentID); err != nil {
			t.Fatal(err)
		} //nolint:rawsql -- original controlled recovery deadline stimulus
		if err := originalAutomationStageSealingV1(ctx, server.HTMLCreationSessions, org.ID, expiringDocumentID, user.ID); err != nil {
			t.Fatal("genuine controlled pre-retention stage", err)
		}
		ownedPlainAssertDrainedV1(t, owned)
	}

	// Before retention begins, a now-too-close deadline unwinds sealing back to
	// a truthful editable draft and consumes the intent atomically.
	stageExpiringSealing()
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() + interval '4 minutes' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	reversible, reversibleErr := sendEngine.ResumeSendSealing(ctx, expiringDocumentID, org.ID)
	defer reversible.CloseConsumerV1()
	if err := reversibleErr; !errors.Is(err, send.ErrExpiryTooSoon) {
		t.Fatalf("reversible expired sealing error = %v, want ErrExpiryTooSoon", err)
	}
	reversible.Links = nil
	reversible.CloseConsumerV1()
	reversibleErr = nil
	var expiringIntentCount int
	if err := pool.QueryRow(ctx, `SELECT status, (SELECT count(*) FROM send_sealing_intents WHERE document_id = $1) FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus, &expiringIntentCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "draft" || expiringIntentCount != 0 {
		t.Fatalf("reversible sealing status/intents = %s/%d, want draft/0", expiringStatus, expiringIntentCount)
	}

	// Once the retention-start marker is durable, recovery must never return to
	// draft. If the absolute deadline elapsed meanwhile, finish the evidence
	// epoch and land atomically in expired without invitations or born-expired
	// links.
	stageExpiringSealing()
	if rows, err := q.MarkSendSealingRetentionStarted(ctx, generated.MarkSendSealingRetentionStartedParams{DocumentID: expiringDocumentID, OrgID: org.ID}); err != nil || rows != 1 {
		t.Fatalf("mark retention started rows/error = %d/%v", rows, err)
	}
	if rows, err := q.MarkSendSealingRetentionComplete(ctx, generated.MarkSendSealingRetentionCompleteParams{DocumentID: expiringDocumentID, OrgID: org.ID}); err != nil || rows != 1 {
		t.Fatalf("mark retention complete rows/error = %d/%v", rows, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE documents SET expires_at = clock_timestamp() - interval '1 minute' WHERE id = $1`, expiringDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	expiredRecovery, err := sendEngine.ResumeSendSealing(ctx, expiringDocumentID, org.ID)
	defer expiredRecovery.CloseConsumerV1()
	if err != nil {
		t.Fatalf("irreversible expired sealing recovery: %v", err)
	}
	if expiredRecovery.Status != "expired" || len(expiredRecovery.Links) != 0 {
		t.Fatalf("irreversible expired recovery = %#v, want expired with no links", expiredRecovery)
	}
	expiredRecovery.Links = nil
	expiredRecovery.CloseConsumerV1()
	var expiredEvents int
	if err := pool.QueryRow(ctx, `SELECT status,
		(SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'),
		(SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'document.expired')
		FROM documents WHERE id = $1`, expiringDocumentID).Scan(&expiringStatus, &expiringInviteEvents, &expiredEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if expiringStatus != "expired" || expiringInviteEvents != 0 || expiredEvents != 1 {
		t.Fatalf("irreversible recovery status/invites/expired-events = %s/%d/%d, want expired/0/1", expiringStatus, expiringInviteEvents, expiredEvents)
	}

	// Race the complete materialize + sealing + send path. Both calls must
	// recover one durable command result rather than enqueueing two ceremonies.
	completeConcurrent := processInput
	completeConcurrent.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-complete-concurrent-" + uuid.NewString())
	type completeAutomationResultV1 struct {
		response automationSignatureRequestResponse
		err      error
		lease    *originalAutomationCallLeaseV1
	}
	completeResponses := make(chan completeAutomationResultV1, 2)
	completeStart := make(chan struct{})
	var completeReady sync.WaitGroup
	completeReady.Add(2)
	for range 2 {
		go func() {
			completeReady.Done()
			<-completeStart
			response, callErr, lease := originalAutomationProcessV1(t, server, ctx, completeConcurrent)
			completeResponses <- completeAutomationResultV1{response: response, err: callErr, lease: lease}
		}()
	}
	completeReady.Wait()
	close(completeStart)
	// Join both actual calls before an assertion can stop their consumer. The
	// deferred close covers errors/status/divergence as well as the happy path.
	completeJoined := [2]completeAutomationResultV1{<-completeResponses, <-completeResponses}
	defer func() {
		for i := range completeJoined {
			lease := completeJoined[i].lease
			completeJoined[i] = completeAutomationResultV1{}
			lease.closeV1()
		}
	}()
	var completeRequestID, completeDocumentID uuid.UUID
	for i := range completeJoined {
		result := &completeJoined[i]
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.response.Status != "sent" {
			t.Fatalf("complete concurrent status = %q, want sent", result.response.Status)
		}
		if completeRequestID == uuid.Nil {
			completeRequestID = result.response.AutomationRequestID
			completeDocumentID = result.response.DocumentID
		} else if result.response.AutomationRequestID != completeRequestID || result.response.DocumentID != completeDocumentID {
			t.Fatalf("complete concurrent commands diverged: %#v", result.response)
		}
		lease := result.lease
		*result = completeAutomationResultV1{}
		lease.closeV1()
	}
	var completeDocumentCount, completeInviteEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE id = $1`, completeDocumentID).Scan(&completeDocumentCount); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, completeDocumentID).Scan(&completeInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if completeDocumentCount != 1 || completeInviteEvents != 1 {
		t.Fatalf("complete concurrency docs/invite events = %d/%d, want 1/1", completeDocumentCount, completeInviteEvents)
	}
	// A recovery worker can race a successful completion after selecting the
	// now-consumed intent. It must converge from the authoritative send proof
	// without recreating bearer links or reporting a false retry failure.
	alreadyCompleted, err := sendEngine.ResumeSendSealing(ctx, completeDocumentID, org.ID)
	defer alreadyCompleted.CloseConsumerV1()
	if err != nil || alreadyCompleted.Status != "sent" || len(alreadyCompleted.Links) != 0 {
		t.Fatalf("post-completion recovery = %#v/%v, want sent without reconstructed links", alreadyCompleted, err)
	}
	alreadyCompleted.Links = nil
	alreadyCompleted.CloseConsumerV1()
	if _, err := q.RequestChangesOnDocument(ctx, generated.RequestChangesOnDocumentParams{ID: completeDocumentID, OrgID: org.ID}); err != nil {
		t.Fatal(err)
	}
	revised, err := server.Sign.Revise(ctx, org.ID, completeDocumentID)
	if err != nil {
		t.Fatal(err)
	}
	revised.CloseConsumerV1()
	_, revisedErr, revisedLease := originalAutomationProcessV1(t, server, ctx, completeConcurrent)
	defer revisedLease.closeV1()
	if err := revisedErr; !errors.Is(err, errAutomationCeremonySuperseded) {
		t.Fatalf("revised ceremony replay error = %v, want superseded conflict", err)
	}
	revisedErr = nil
	revisedLease.closeV1()
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE document_id = $1 AND kind = 'recipient.invited'`, completeDocumentID).Scan(&completeInviteEvents); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if completeInviteEvents != 1 {
		t.Fatalf("revised replay added invite events: got %d, want 1", completeInviteEvents)
	}

	// Exercise the claim race separately from Send: both callers must converge
	// on the same prepared draft and exactly one may report first materialization.
	concurrent := processInput
	concurrent.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-concurrent-" + uuid.NewString())
	type materializedAutomationResultV1 struct {
		request  *generated.AutomationSignatureRequest
		replayed bool
		err      error
		lease    *originalAutomationCallLeaseV1
	}
	responses := make(chan materializedAutomationResultV1, 2)
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(2)
	for range 2 {
		go func() {
			ready.Done()
			<-start
			request, wasReplay, callErr, lease := originalAutomationMaterializeV1(t, server, ctx, concurrent)
			responses <- materializedAutomationResultV1{request: request, replayed: wasReplay, err: callErr, lease: lease}
		}()
	}
	ready.Wait()
	close(start)
	materializedJoined := [2]materializedAutomationResultV1{<-responses, <-responses}
	defer func() {
		for i := range materializedJoined {
			lease := materializedJoined[i].lease
			materializedJoined[i] = materializedAutomationResultV1{}
			lease.closeV1()
		}
	}()
	var concurrentID, concurrentDocumentID uuid.UUID
	firstCount, replayCount := 0, 0
	for i := range materializedJoined {
		result := &materializedJoined[i]
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.replayed {
			replayCount++
		} else {
			firstCount++
		}
		if concurrentID == uuid.Nil {
			concurrentID = result.request.ID
			concurrentDocumentID = uuid.UUID(result.request.DocumentID.Bytes)
		} else if result.request.ID != concurrentID || uuid.UUID(result.request.DocumentID.Bytes) != concurrentDocumentID {
			t.Fatalf("concurrent claims diverged: %#v", result.request)
		}
		lease := result.lease
		*result = materializedAutomationResultV1{}
		lease.closeV1()
	}
	if firstCount != 1 || replayCount != 1 {
		t.Fatalf("concurrent first/replay = %d/%d, want 1/1", firstCount, replayCount)
	}

	// Hold materialization immediately after it validates a FOR SHARE snapshot,
	// then race an in-place template update. The edit must wait until the old
	// block/default pair has been copied and committed; a document may never
	// combine columns from different template revisions.
	raceTree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "race-body", Type: blocks.TypeParagraph, Text: "Old approved {{customer.name}}"},
		{ID: "race-signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	raceBlocksJSON, err := json.Marshal(raceTree)
	if err != nil {
		t.Fatal(err)
	}
	raceTemplate, err := originalAutomationTemplateCreateV1(t, owned, "Concurrent approved template", raceBlocksJSON, json.RawMessage(`{"customer.name":"Old default"}`))
	if err != nil {
		t.Fatal(err)
	}
	raceContent, err := templatepin.Canonicalize(raceTemplate.BlocksJson, raceTemplate.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	racePrepared, raceHash, err := prepareAutomationSignatureRequest(automationSignatureRequestInput{
		TemplateID: raceTemplate.ID.String(), TemplateVersion: raceTemplate.Version,
		TemplateContentSHA256: raceContent.SHA256Hex(), Name: "Pinned concurrent agreement", LawfulBasis: "contract",
		Recipients: []automationSignatureRecipientInput{{Email: "concurrent@example.test", Name: "Concurrent", Locale: "en"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	raceInput := processInput
	raceInput.Request = racePrepared
	raceInput.RequestHash = raceHash
	raceInput.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-template-update-race-" + uuid.NewString())
	snapshotReady := make(chan struct{})
	releaseSnapshot := make(chan struct{})
	releasedSnapshot := false
	server.automationTemplateSnapshotHook = func() {
		close(snapshotReady)
		<-releaseSnapshot
	}
	materializedRead := false
	var joinTemplateUpdate func()
	materialized := make(chan struct {
		request *generated.AutomationSignatureRequest
		err     error
		lease   *originalAutomationCallLeaseV1
	}, 1)
	go func() {
		request, _, callErr, lease := originalAutomationMaterializeV1(t, server, ctx, raceInput)
		materialized <- struct {
			request *generated.AutomationSignatureRequest
			err     error
			lease   *originalAutomationCallLeaseV1
		}{request: request, err: callErr, lease: lease}
	}()
	defer func() {
		if !releasedSnapshot {
			close(releaseSnapshot)
		}
		if !materializedRead {
			result := <-materialized
			result.request = nil
			result.err = nil
			result.lease.closeV1()
		}
		if joinTemplateUpdate != nil {
			joinTemplateUpdate()
		}
		server.automationTemplateSnapshotHook = nil
	}()
	select {
	case <-snapshotReady:
	case <-time.After(5 * time.Second):
		t.Fatal("materialization did not reach the pinned template snapshot")
	}
	updatedTree := blocks.Tree{Version: blocks.SchemaVersion, Blocks: []blocks.Block{
		{ID: "race-body", Type: blocks.TypeParagraph, Text: "New unapproved {{customer.name}}"},
		{ID: "race-signature", Type: blocks.TypeSignatureField, Attrs: map[string]any{"recipient_role": "signer"}},
	}}
	updatedBlocksJSON, err := json.Marshal(updatedTree)
	if err != nil {
		t.Fatal(err)
	}
	updateStarted := make(chan struct{})
	updated := make(chan struct {
		template *generated.Template
		err      error
	}, 1)
	updatedRead := false
	joinTemplateUpdate = func() {
		if !updatedRead {
			result := <-updated
			result.template = nil
			result.err = nil
		}
	}
	go func() {
		close(updateStarted)
		value, callErr := originalAutomationTemplateUpdateV1(owned, raceTemplate, updatedBlocksJSON, json.RawMessage(`{"customer.name":"New default"}`))
		updated <- struct {
			template *generated.Template
			err      error
		}{template: value, err: callErr}
	}()
	<-updateStarted
	select {
	case result := <-updated:
		updatedRead = true
		t.Fatalf("concurrent template update escaped the pinned snapshot lock: %#v/%v", result.template, result.err)
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseSnapshot)
	releasedSnapshot = true
	materializeResult := <-materialized
	materializedRead = true
	defer func() {
		materializeResult.request = nil
		materializeResult.err = nil
		materializeResult.lease.closeV1()
	}()
	if materializeResult.err != nil {
		t.Fatalf("materialize pinned concurrent snapshot: %v", materializeResult.err)
	}
	updateResult := <-updated
	updatedRead = true
	if updateResult.err != nil || updateResult.template.Version != raceTemplate.Version+1 {
		t.Fatalf("concurrent template update = %#v/%v", updateResult.template, updateResult.err)
	}
	server.automationTemplateSnapshotHook = nil
	raceDocumentID := uuid.UUID(materializeResult.request.DocumentID.Bytes)
	materializeResult.request = nil
	materializeResult.lease.closeV1()
	raceDocument, err := q.GetDocument(ctx, generated.GetDocumentParams{ID: raceDocumentID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	copiedRaceContent, err := templatepin.Canonicalize(raceDocument.BlocksJson, raceTemplate.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	copiedRaceVariables, err := blocks.ParseVariableValues(raceDocument.VariablesJson)
	if err != nil {
		t.Fatal(err)
	}
	if copiedRaceContent.SHA256 != raceContent.SHA256 || copiedRaceVariables["customer.name"] != "Old default" {
		t.Fatalf("concurrent document mixed template revisions: digest=%s variables=%#v", copiedRaceContent.SHA256Hex(), copiedRaceVariables)
	}

	// Simulate the existing hard purge of an abandoned draft. ON DELETE SET
	// NULL must retain the key/request digest so a late retry can only return a
	// tombstone, never create another document.
	if _, err := pool.Exec(ctx, `DELETE FROM documents WHERE id = $1 AND status = 'draft'`, concurrentDocumentID); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	tombstone, err := q.GetAutomationSignatureRequest(ctx, generated.GetAutomationSignatureRequestParams{ID: concurrentID, OrgID: org.ID})
	if err != nil {
		t.Fatal(err)
	}
	if tombstone.DocumentID.Valid {
		t.Fatalf("hard-deleted draft still bound to document %s", uuid.UUID(tombstone.DocumentID.Bytes))
	}

	// A quota rejection must roll back the claimed idempotency row, document,
	// recipients, version, and audits. Otherwise 402 responses silently strand
	// PII-bearing drafts which themselves consume more quota.
	billingEngine := billing.New(q, billing.MockProvider{}, "", "")
	plan, _, err := billingEngine.PlanForOrg(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if plan.DocumentQuotaMonthly <= 0 {
		t.Fatal("fixture free plan must have a document quota")
	}
	var documentsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE org_id = $1`, org.ID).Scan(&documentsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	for documentsBefore < int(plan.DocumentQuotaMonthly) {
		raw, err := json.Marshal(map[string]any{"name": "quota fixture", "source_kind": "blocks", "blocks_json": json.RawMessage(blocksJSON), "variables_json": map[string]string{"customer.name": "fixture"}})
		if err != nil {
			t.Fatal(err)
		}
		response := submitSessionOperationE2E(server, http.MethodPost, "/api/v1/documents", string(raw), owned.cookie)
		if response.Code != http.StatusCreated {
			t.Fatalf("actual quota fixture document=%d %s", response.Code, response.Body.String())
		}
		ownedPlainAssertDrainedV1(t, owned)
		documentsBefore++
	}
	var requestsBefore, recipientsBefore, eventsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM automation_signature_requests WHERE org_id = $1`, org.ID).Scan(&requestsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id = $1`, org.ID).Scan(&recipientsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1`, org.ID).Scan(&eventsBefore); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	server.Billing = billingEngine
	quotaInput := processInput
	quotaInput.IdempotencyKeyHash = automationIdempotencyKeyHash("e2e-quota-" + uuid.NewString())
	_, _, quotaErr, quotaLease := originalAutomationMaterializeV1(t, server, ctx, quotaInput)
	if err := quotaErr; !errors.Is(err, billing.ErrQuotaExceeded) {
		t.Fatalf("quota materialization error = %v, want ErrQuotaExceeded", err)
	}
	quotaErr = nil
	quotaLease.closeV1()
	var documentsAfter, requestsAfter, recipientsAfter, eventsAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM documents WHERE org_id = $1`, org.ID).Scan(&documentsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM automation_signature_requests WHERE org_id = $1`, org.ID).Scan(&requestsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM recipients r JOIN documents d ON d.id=r.document_id WHERE d.org_id = $1`, org.ID).Scan(&recipientsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE org_id = $1`, org.ID).Scan(&eventsAfter); err != nil { //nolint:rawsql
		t.Fatal(err)
	}
	if documentsAfter != documentsBefore || requestsAfter != requestsBefore || recipientsAfter != recipientsBefore || eventsAfter != eventsBefore {
		t.Fatalf("quota rollback leaked rows docs %d/%d requests %d/%d recipients %d/%d events %d/%d",
			documentsBefore, documentsAfter, requestsBefore, requestsAfter,
			recipientsBefore, recipientsAfter, eventsBefore, eventsAfter)
	}
	ownedPlainAssertDrainedV1(t, owned)
}
