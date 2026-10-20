//go:build e2e

// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/article13"
	"github.com/bright-interaction/hash/internal/audit"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// These are actual-PG database constraint tests after a genuinely prepared and
// retained main-only Send. M99 stays enabled. Response rows below deliberately
// use the real audit logger but direct SQL status/signature primitives: this
// does not claim the HTTP consent ceremony, provider signature-image storage,
// attachment Send, participant report, or legal enforceability is qualified.
type packageResponseSQLFixture247 struct {
	q         *ownedPublicReadFixtureV1
	m         pdfadmission.HTMLSendPackageIntentMetadataV1
	recipient uuid.UUID
	notice    article13.Evidence
}

func packageResponseSQLBirth247(t *testing.T, signed bool) packageResponseSQLFixture247 {
	t.Helper()
	q := inspectionFixturePG236(t)
	m, recipient := packageCompletionPreparedBirth241(t, q, 1, signed)
	peer := &packageRetentionNativePeer240{base: q.storagePeer, until: make(map[string]time.Time), entered: make(chan struct{}), getDone: make(chan struct{})}
	client := packageRetentionNativeClient240(t, q, peer)
	packageCompletionRun241(t, q, client, m, "sent")
	t.Cleanup(func() {
		peer.mu.Lock()
		failure := peer.failure
		peer.mu.Unlock()
		if failure != nil {
			t.Error("actual response-constraint Send peer", failure)
		}
	})
	token := signerPackageToken242(t, q, recipient)
	rc := q.lookupV1(t, token)
	notice, err := q.f.s.signerPrivacyNotice(signerReadRequestE2E(token, ""), rc)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := signerArticle13NoticeEvidence(rc, notice)
	if err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseReadV1(); err != nil {
		t.Fatal(err)
	}
	q.assertObserversOnlyV1(t)
	return packageResponseSQLFixture247{q: q, m: m, recipient: recipient, notice: evidence}
}

func (f packageResponseSQLFixture247) params247(eid uuid.UUID, sid pgtype.UUID) generated.RecordDocumentPackageResponseV1Params {
	return generated.RecordDocumentPackageResponseV1Params{OrgID: f.m.Capture.OrgID, DocumentID: f.m.Capture.DocumentID, RecipientID: f.recipient,
		AttemptID: f.m.AttemptID, ExpectedManifestSha256: f.m.Capture.CanonicalSHA256[:], ExpectedLegalCommitmentSha256: f.m.Capture.CommitmentSHA256[:],
		ResponseEventID: eid, SignatureID: sid}
}

func (f packageResponseSQLFixture247) state247(t *testing.T) string {
	t.Helper()
	var receipt string
	if err := f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY recipient_id),'[]'::jsonb)::text FROM document_package_responses_v1 x WHERE attempt_id=$1", f.m.AttemptID).Scan(&receipt); err != nil {
		t.Fatal(err)
	}
	return packageCompletionNativeState241(t, f.q, f.m) + receipt
}

func (f packageResponseSQLFixture247) stage247(t *testing.T, tx pgx.Tx, signed bool, mutate func(map[string]any)) (uuid.UUID, pgtype.UUID, error) {
	t.Helper()
	db := generated.New(tx)
	if _, err := db.GetDocumentForUpdate(f.q.f.ctx, generated.GetDocumentForUpdateParams{ID: f.m.Capture.DocumentID, OrgID: f.m.Capture.OrgID}); err != nil {
		return uuid.Nil, pgtype.UUID{}, err
	}
	kind := "accepted"
	if signed {
		kind = "signed"
	}
	if err := db.SetRecipientStatus(f.q.f.ctx, generated.SetRecipientStatusParams{ID: f.recipient, DocumentID: f.m.Capture.DocumentID, Status: kind}); err != nil {
		return uuid.Nil, pgtype.UUID{}, err
	}
	copyText := "I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments."
	copySHA := sha256.Sum256([]byte(copyText))
	payload := map[string]any{"package_response_schema": "hash-package-response-v1", "package_send_attempt_id": f.m.AttemptID.String(),
		"package_id": f.m.Capture.PackageID.String(), "capture_revision": strconv.FormatInt(f.m.Capture.Revision, 10),
		"manifest_sha256": hex.EncodeToString(f.m.Capture.CanonicalSHA256[:]), "legal_commitment_sha256": hex.EncodeToString(f.m.Capture.CommitmentSHA256[:]),
		"incorporation_version": "hash-package-incorporation-v1", "incorporation_sha256": hex.EncodeToString(copySHA[:]), "package_consent": true, "response_kind": kind}
	if err := f.notice.BindAuditPayload(payload); err != nil {
		return uuid.Nil, pgtype.UUID{}, err
	}
	var sid pgtype.UUID
	if signed {
		fields, err := db.ListFieldsByDocument(f.q.f.ctx, f.m.Capture.DocumentID)
		if err != nil {
			return uuid.Nil, sid, err
		}
		var field uuid.UUID
		for _, v := range fields {
			if v.Type == "signature" && v.RecipientID.Valid && uuid.UUID(v.RecipientID.Bytes) == f.recipient {
				field = v.ID
			}
		}
		if field == uuid.Nil {
			t.Fatal("actual prepared package signature field is absent")
		}
		sig, err := db.InsertSignature(f.q.f.ctx, generated.InsertSignatureParams{DocumentID: f.m.Capture.DocumentID, RecipientID: f.recipient, FieldID: field,
			Font: "Caveat", TypedName: "Synthetic SQL response constraint", ImageStorageKey: "org/" + f.m.Capture.OrgID.String() + "/sql-response-test/" + uuid.NewString() + ".png",
			ImageSha256: bytes.Repeat([]byte{7}, 32), ImageVersionID: pgtype.Text{String: "synthetic-sql-response-v1", Valid: true}})
		if err != nil {
			return uuid.Nil, sid, err
		}
		sid = pgtype.UUID{Bytes: sig.ID, Valid: true}
		payload["signature_id"], payload["image_sha256"], payload["font"], payload["typed_name"] = sig.ID.String(), hex.EncodeToString(sig.ImageSha256), sig.Font, sig.TypedName
	}
	if mutate != nil {
		mutate(payload)
	}
	event, err := f.q.f.s.Audit.LogTx(f.q.f.ctx, tx, audit.Entry{OrgID: f.m.Capture.OrgID, DocumentID: &f.m.Capture.DocumentID, RecipientID: &f.recipient,
		Kind: "document." + kind, Payload: payload})
	if err == nil {
		stored, e := db.GetEventByID(f.q.f.ctx, event.ID)
		if e != nil || stored == nil {
			t.Fatal("actual emitted audit row unavailable", e)
		}
		var sqlHash []byte
		if e := tx.QueryRow(f.q.f.ctx, "SELECT hash_package_response_audit_row_sha256_v1($1)", event.ID).Scan(&sqlHash); e != nil {
			t.Fatal(e)
		}
		// This crosses the independently implemented SQL/Go wire formats before
		// exercising association guards. A shared refusal must not hide a hash
		// implementation that rejects every genuine response.
		if !bytes.Equal(sqlHash, stored.RowHash) {
			t.Fatal("SQL response audit wire format differs from actual Go audit row")
		}
	}
	return event.ID, sid, err
}

func TestDocumentPackageResponseConstraintRefusalsV1E2E(t *testing.T) {
	f := packageResponseSQLBirth247(t, false)
	cases := []struct {
		name    string
		payload func(map[string]any)
		params  func(*generated.RecordDocumentPackageResponseV1Params)
		noRows  bool
	}{
		{name: "wrong tenant", params: func(p *generated.RecordDocumentPackageResponseV1Params) { p.OrgID = uuid.New() }, noRows: true},
		{name: "wrong root", params: func(p *generated.RecordDocumentPackageResponseV1Params) { p.DocumentID = uuid.New() }, noRows: true},
		{name: "wrong recipient", params: func(p *generated.RecordDocumentPackageResponseV1Params) { p.RecipientID = uuid.New() }, noRows: true},
		{name: "wrong attempt", params: func(p *generated.RecordDocumentPackageResponseV1Params) { p.AttemptID = uuid.New() }, noRows: true},
		{name: "stale observed commitment", params: func(p *generated.RecordDocumentPackageResponseV1Params) {
			p.ExpectedLegalCommitmentSha256 = bytes.Repeat([]byte{9}, 32)
		}, noRows: true},
		{name: "unrelated audit event", params: func(p *generated.RecordDocumentPackageResponseV1Params) { p.ResponseEventID = uuid.New() }, noRows: true},
		{name: "wrong captured revision", payload: func(p map[string]any) { p["capture_revision"] = "999999" }},
		{name: "wrong manifest", payload: func(p map[string]any) { p["manifest_sha256"] = hex.EncodeToString(bytes.Repeat([]byte{9}, 32)) }},
		{name: "missing explicit consent", payload: func(p map[string]any) { delete(p, "package_consent") }},
		{name: "false explicit consent", payload: func(p map[string]any) { p["package_consent"] = false }},
		{name: "wrong incorporation copy", payload: func(p map[string]any) { p["incorporation_sha256"] = hex.EncodeToString(bytes.Repeat([]byte{9}, 32)) }},
		{name: "signature on acknowledgement", params: func(p *generated.RecordDocumentPackageResponseV1Params) {
			p.SignatureID = pgtype.UUID{Bytes: uuid.New(), Valid: true}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := f.state247(t)
			func() {
				tx := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
				defer rollbackHTMLQueryFixtureV1(t, tx)
				eid, sid, err := f.stage247(t, tx, false, c.payload)
				if err != nil {
					t.Fatal(err)
				}
				params := f.params247(eid, sid)
				if c.params != nil {
					c.params(&params)
				}
				_, err = generated.New(tx).RecordDocumentPackageResponseV1(f.q.f.ctx, params)
				if c.noRows {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatal("wrong scoped response selector did not refuse", err)
					}
					return
				}
				if err == nil {
					err = tx.Commit(f.q.f.ctx)
				}
				packageExpectPG218(t, err, "23514")
			}()
			if f.state247(t) != before {
				t.Fatal("refused response changed the genuine completed Send or response state")
			}
		})
	}
}

func TestDocumentPackageResponseOldBinaryAndRollbackV1E2E(t *testing.T) {
	f := packageResponseSQLBirth247(t, false)
	for _, name := range []string{"old binary terminal status only", "old binary response audit only", "exact receipt explicit transaction rollback"} {
		t.Run(name, func(t *testing.T) {
			before := f.state247(t)
			func() {
				tx := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
				defer rollbackHTMLQueryFixtureV1(t, tx)
				if name == "old binary terminal status only" {
					if err := generated.New(tx).SetRecipientStatus(f.q.f.ctx, generated.SetRecipientStatusParams{ID: f.recipient, DocumentID: f.m.Capture.DocumentID, Status: "accepted"}); err != nil {
						t.Fatal(err)
					}
				} else {
					eid, sid, err := f.stage247(t, tx, false, nil)
					if err != nil {
						t.Fatal(err)
					}
					if name == "exact receipt explicit transaction rollback" {
						if _, err := generated.New(tx).RecordDocumentPackageResponseV1(f.q.f.ctx, f.params247(eid, sid)); err != nil {
							t.Fatal(err)
						}
						if _, err := tx.Exec(f.q.f.ctx, "SET CONSTRAINTS ALL IMMEDIATE"); err != nil {
							t.Fatal("exact uncommitted response pair does not validate", err)
						}
						return
					}
				}
				packageExpectPG218(t, tx.Commit(f.q.f.ctx), "23514")
			}()
			if f.state247(t) != before {
				t.Fatal("aborted response transaction leaked receipt, status, signature or audit effects")
			}
		})
	}
}

func TestDocumentPackageResponseAppendOnlyV1E2E(t *testing.T) {
	for _, signed := range []bool{false, true} {
		name := "accepted"
		if signed {
			name = "signed"
		}
		t.Run(name, func(t *testing.T) {
			f := packageResponseSQLBirth247(t, signed)
			if signed {
				for _, refusal := range []string{"missing signature association", "wrong signature association", "wrong canonical event hash", "wrong audit signature payload", "old binary signature without receipt"} {
					t.Run(refusal, func(t *testing.T) {
						before := f.state247(t)
						func() {
							tx := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
							defer rollbackHTMLQueryFixtureV1(t, tx)
							var mutate func(map[string]any)
							if refusal == "wrong audit signature payload" {
								mutate = func(p map[string]any) { p["signature_id"] = uuid.NewString() }
							}
							eid, sid, err := f.stage247(t, tx, true, mutate)
							if err != nil {
								t.Fatal(err)
							}
							switch refusal {
							case "missing signature association":
								sid = pgtype.UUID{}
							case "wrong signature association":
								sid = pgtype.UUID{Bytes: uuid.New(), Valid: true}
							case "wrong canonical event hash":
								if _, err := tx.Exec(f.q.f.ctx, "UPDATE events SET row_hash=decode(repeat('11',32),'hex') WHERE id=$1", eid); err != nil {
									t.Fatal(err)
								}
							}
							if refusal != "old binary signature without receipt" {
								_, err = generated.New(tx).RecordDocumentPackageResponseV1(f.q.f.ctx, f.params247(eid, sid))
							}
							if err == nil {
								err = tx.Commit(f.q.f.ctx)
							}
							packageExpectPG218(t, err, "23514")
						}()
						if f.state247(t) != before {
							t.Fatal("invalid signature association leaked atomic response effects")
						}
					})
				}
			}
			tx := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
			defer rollbackHTMLQueryFixtureV1(t, tx)
			eid, sid, err := f.stage247(t, tx, signed, nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = generated.New(tx).RecordDocumentPackageResponseV1(f.q.f.ctx, f.params247(eid, sid)); err != nil {
				t.Fatal(err)
			}
			if err = tx.Commit(f.q.f.ctx); err != nil {
				t.Fatal("exact SQL response receipt did not commit", err)
			}
			before := f.state247(t)
			mutations := []struct {
				name, sql string
				id        uuid.UUID
			}{
				{"receipt update", "UPDATE document_package_responses_v1 SET incorporation_sha256=decode(repeat('11',32),'hex') WHERE attempt_id=$1", f.m.AttemptID},
				{"receipt delete", "DELETE FROM document_package_responses_v1 WHERE attempt_id=$1", f.m.AttemptID},
				{"audit delete", "DELETE FROM events WHERE id=$1", eid},
				{"canonical payload mutation", "UPDATE events SET payload_hashed=convert_to('{}','UTF8') WHERE id=$1", eid},
				{"audit hash mutation", "UPDATE events SET row_hash=decode(repeat('11',32),'hex') WHERE id=$1", eid},
				{"recipient status mutation", "UPDATE recipients SET status='viewed' WHERE id=$1", f.recipient},
				{"recipient role mutation", "UPDATE recipients SET role=CASE WHEN role='signer' THEN 'approver' ELSE 'signer' END WHERE id=$1", f.recipient},
				{"recipient routing mutation", "UPDATE recipients SET order_index=order_index+1 WHERE id=$1", f.recipient},
				{"recipient delete", "DELETE FROM recipients WHERE id=$1", f.recipient},
			}
			if signed {
				mutations = append(mutations, struct {
					name, sql string
					id        uuid.UUID
				}{"signature mutation", "UPDATE signatures SET typed_name='replacement' WHERE id=$1", uuid.UUID(sid.Bytes)}, struct {
					name, sql string
					id        uuid.UUID
				}{"signature delete", "DELETE FROM signatures WHERE id=$1", uuid.UUID(sid.Bytes)})
			}
			for _, c := range mutations {
				t.Run(c.name, func(t *testing.T) {
					_, err := f.q.f.pool.Exec(f.q.f.ctx, c.sql, c.id)
					packageExpectPG218(t, err, "23514")
					if f.state247(t) != before {
						t.Fatal("forbidden mutation changed retained response evidence")
					}
				})
			}
			t.Run("occupied exact migration Down", func(t *testing.T) {
				raw, err := os.ReadFile("../db/migrations/00107_document_package_responses.sql")
				if err != nil {
					t.Fatal(err)
				}
				parts := strings.SplitN(string(raw), "-- +goose Down", 2)
				if len(parts) != 2 {
					t.Fatal("package response migration has no explicit Down")
				}
				func() {
					tx := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
					defer rollbackHTMLQueryFixtureV1(t, tx)
					_, err := tx.Exec(f.q.f.ctx, parts[1]) //nolint:rawsql -- exact occupied Down in disposable rolled-back transaction only
					packageExpectPG218(t, err, "23514")
				}()
				if f.state247(t) != before {
					t.Fatal("occupied migration rollback changed package response evidence")
				}
			})
			// Display redaction is deliberately separate from canonical evidence.
			if _, err := f.q.f.pool.Exec(f.q.f.ctx, "UPDATE events SET payload_json='{}'::jsonb WHERE id=$1", eid); err != nil {
				t.Fatal("display payload redaction was blocked", err)
			}
			var exact bool
			if err := f.q.f.pool.QueryRow(f.q.f.ctx, "SELECT hash_package_response_matches_v1($1,$2)", f.m.AttemptID, f.recipient).Scan(&exact); err != nil || !exact {
				t.Fatal("display redaction changed exact canonical response association", err)
			}
			// A later terminal root may still expire its credentials without
			// erasing or re-signing the earlier immutable participant response.
			terminal := beginHTMLQueryFixtureV1(t, f.q.f.ctx, f.q.f)
			defer rollbackHTMLQueryFixtureV1(t, terminal)
			if _, err := terminal.Exec(f.q.f.ctx, "UPDATE documents SET status='voided' WHERE id=$1 AND org_id=$2", f.m.Capture.DocumentID, f.m.Capture.OrgID); err != nil {
				t.Fatal(err)
			}
			if err := generated.New(terminal).InvalidateRecipientTokens(f.q.f.ctx, f.m.Capture.DocumentID); err != nil {
				t.Fatal(err)
			}
			if err := terminal.Commit(f.q.f.ctx); err != nil {
				t.Fatal("later terminal credential expiry broke historical package response", err)
			}
		})
	}
}
