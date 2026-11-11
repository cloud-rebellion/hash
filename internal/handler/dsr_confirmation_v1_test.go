// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package handler

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/google/uuid"
)

func dsrConfirmationFixtureV1(t *testing.T) (*Server, dsrConfirmationScopeV1) {
	t.Helper()
	cookies, err := auth.NewSignedCookie(strings.Repeat("32", 32))
	if err != nil {
		t.Fatal(err)
	}
	return &Server{Cookies: cookies}, dsrConfirmationScopeV1{RequestID: uuid.New(), OrgID: uuid.New(), ActorID: uuid.New(), RecipientID: uuid.New(), DocumentID: uuid.New(), DocumentStatus: "draft",
		SessionSHA256: strings.Repeat("a", 64), RequestSHA256: strings.Repeat("b", 64), SubjectSHA256: strings.Repeat("c", 64), DocumentsSHA256: strings.Repeat("d", 64), PDFRevisionDocuments: 2, PDFRevisions: 3}
}

func TestDSRConfirmationBindsActorSessionRequestAndExactScopeV1(t *testing.T) {
	s, scope := dsrConfirmationFixtureV1(t)
	now := time.Now().UTC()
	token, err := s.mintDSRConfirmationV1(scope, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.verifyDSRConfirmationV1(token, scope, now); err != nil {
		t.Fatal("fresh exact receipt refused", err)
	}
	for name, change := range map[string]func(*dsrConfirmationScopeV1){
		"request":        func(p *dsrConfirmationScopeV1) { p.RequestID = uuid.New() },
		"tenant":         func(p *dsrConfirmationScopeV1) { p.OrgID = uuid.New() },
		"actor":          func(p *dsrConfirmationScopeV1) { p.ActorID = uuid.New() },
		"recipient":      func(p *dsrConfirmationScopeV1) { p.RecipientID = uuid.New() },
		"document":       func(p *dsrConfirmationScopeV1) { p.DocumentID = uuid.New() },
		"status":         func(p *dsrConfirmationScopeV1) { p.DocumentStatus = "completed" },
		"session":        func(p *dsrConfirmationScopeV1) { p.SessionSHA256 = strings.Repeat("e", 64) },
		"request state":  func(p *dsrConfirmationScopeV1) { p.RequestSHA256 = strings.Repeat("e", 64) },
		"subject":        func(p *dsrConfirmationScopeV1) { p.SubjectSHA256 = strings.Repeat("e", 64) },
		"revision set":   func(p *dsrConfirmationScopeV1) { p.DocumentsSHA256 = strings.Repeat("e", 64) },
		"document count": func(p *dsrConfirmationScopeV1) { p.PDFRevisionDocuments++ },
		"revision count": func(p *dsrConfirmationScopeV1) { p.PDFRevisions++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := scope
			change(&changed)
			if _, err := s.verifyDSRConfirmationV1(token, changed, now); err == nil {
				t.Fatal("changed confirmation scope accepted")
			}
		})
	}
	if _, err := s.verifyDSRConfirmationV1(token, scope, now.Add(dsrConfirmationTTLV1)); err == nil {
		t.Fatal("expired confirmation accepted")
	}
	if _, err := s.verifyDSRConfirmationV1("", scope, now); err == nil {
		t.Fatal("missing confirmation accepted")
	}
	if _, err := s.verifyDSRConfirmationV1(strings.Repeat("x", maxDSRConfirmationReceiptV1+1), scope, now); err == nil {
		t.Fatal("oversized confirmation accepted")
	}
	if _, err := s.verifyDSRConfirmationV1(token+"x", scope, now); err == nil {
		t.Fatal("tampered confirmation accepted")
	}
	ordinary := s.Cookies.Mint([]byte(`{"user_id":"`+scope.ActorID.String()+`"}`), time.Hour)
	if _, err := s.verifyDSRConfirmationV1(ordinary, scope, now); err == nil {
		t.Fatal("ordinary session cookie accepted as erasure consent")
	}
	other, err := s.Cookies.MintPurpose("hash.other-confirmation.v1", []byte(`{}`), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.verifyDSRConfirmationV1(other, scope, now); err == nil {
		t.Fatal("wrong-purpose receipt accepted")
	}
}

func TestDSRConfirmationRefusesMalformedSignedPayloadV1(t *testing.T) {
	s, scope := dsrConfirmationFixtureV1(t)
	now := time.Now().UTC()
	for name, mutate := range map[string]func(*dsrConfirmationReceiptV1){
		"future":       func(p *dsrConfirmationReceiptV1) { p.IssuedAt = now.Add(time.Second) },
		"overlong TTL": func(p *dsrConfirmationReceiptV1) { p.ExpiresAt = now.Add(dsrConfirmationTTLV1 + time.Second) },
		"expired": func(p *dsrConfirmationReceiptV1) {
			p.IssuedAt = now.Add(-time.Hour)
			p.ExpiresAt = now.Add(-time.Second)
		},
		"schema": func(p *dsrConfirmationReceiptV1) { p.SchemaVersion = 2 },
	} {
		t.Run(name, func(t *testing.T) {
			p := dsrConfirmationReceiptV1{SchemaVersion: 1, Scope: scope, IssuedAt: now, ExpiresAt: now.Add(dsrConfirmationTTLV1)}
			mutate(&p)
			raw, _ := json.Marshal(p)
			token, err := s.Cookies.MintPurpose(dsrConfirmationPurposeV1, raw, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.verifyDSRConfirmationV1(token, scope, now); err == nil {
				t.Fatal("malformed signed receipt accepted")
			}
		})
	}
}
