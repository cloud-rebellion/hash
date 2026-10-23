// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package presignregistry

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestDataAdmissionPreservesActualContactFullNameTransformationV1(t *testing.T) {
	d, g, in, doc := admissionFixture(t)
	in.Values["customer_name"] = "Åsa Öberg"
	rebuildAdmissionSource(t, &in, doc)
	token := strings.Repeat("ab", 32)
	accounts, records := 0, 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("original credential changed")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/auth/me":
			accounts++
			_, _ = w.Write([]byte(`{"id":"crm_user","team_id":"crm_team","is_active":true}`))
		case "/api/v1/contacts/contact_1":
			records++
			_, _ = w.Write([]byte(`{"id":"contact_1","team_id":"crm_team","updated_at":"2026-10-01T10:00:00Z","anonymized_at":null,"first_name":"  Åsa ","last_name":" Öberg  ","email":"customer@example.test"}`))
		default:
			t.Error("unexpected provider path")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()
	client, err := crmconnection.NewClient(upstream.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crmconnection.NewKeyring(strings.Repeat("1234", 16), "")
	if err != nil {
		t.Fatal(err)
	}
	id := crmconnection.Identity{ID: uuid.New(), OrgID: doc.OrgID, Generation: 2, Origin: upstream.URL, CRMTeamID: "crm_team", CRMUserID: "crm_user"}
	ciphertext, err := keys.Seal(id, token)
	if err != nil {
		t.Fatal(err)
	}
	store := &admissionCRMStore{connection: &generated.CrmConnection{ID: id.ID, OrgID: id.OrgID, Generation: id.Generation, Origin: id.Origin, CrmTeamID: id.CRMTeamID, CrmUserID: id.CRMUserID, Status: "active", CredentialCiphertext: ciphertext, VerifiedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}},
		bindings: []*generated.DocumentVariableBinding{{DocumentID: doc.ID, VariableName: "customer_name", SourceKind: "crm.contact", SourceRef: "contact_1", SourcePath: "full_name"}}}
	engine := resolver.New(nil)
	engine.Q = store
	engine.CRM = &resolver.CRMRecords{Store: store, Client: client, Keys: keys, Origin: upstream.URL}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, reports, err := engine.FreezeForSend(ctx, doc)
	if err != nil {
		t.Fatal(err)
	}
	if accounts != 2 || records != 1 {
		t.Fatal("genuine protected account bookends/record read missing")
	}
	for i, rule := range d.DataRules.Values {
		if rule.Variable == "customer_name" {
			d.DataRules.Values[i] = ValueRule{Variable: rule.Variable, Mode: ModeCRM, SourceKind: "crm.contact", SourcePath: "full_name"}
		}
	}
	d.DataRules.CRM = &CRMScope{ConnectionID: id.ID, Generation: id.Generation, Origin: id.Origin, TeamID: id.CRMTeamID, UserID: id.CRMUserID, Selection: "fixed_record_set", Records: []RecordRule{{Kind: "crm.contact", ID: "contact_1"}}}
	at := time.Now()
	admission, err := EvaluateExecutionData(d, g, doc, reports, at)
	if err != nil {
		t.Fatal("genuine resolver full_name refused", err)
	}
	snapshot := admission.Snapshot()
	if len(snapshot.CRMValues) != 1 || snapshot.CRMValues[0].Observation.Transformation != "trim-first-and-last-name-v1" || !bytes.Contains(admission.CanonicalJSON(), []byte(`"transformation":"trim-first-and-last-name-v1"`)) {
		t.Fatal("native transformation stripped from canonical evidence")
	}
	round, err := DecodeDataAdmission(admission.CanonicalJSON())
	if err != nil || round.Commitment() != admission.Commitment() || !bytes.Equal(round.CanonicalJSON(), admission.CanonicalJSON()) {
		t.Fatal("exact transformed evidence failed readback", err)
	}
	if admission.Commitment() != sha(append([]byte(DataAdmissionDomain), admission.CanonicalJSON()...)) {
		t.Fatal("existing commitment domain changed")
	}
	var actual resolver.ResolveReport
	for _, entry := range reports {
		if entry.Variable == "customer_name" {
			actual = entry
		}
	}
	if actual.Value != "Åsa Öberg" || actual.CRMObservation == nil || actual.CRMObservation.Transformation != "trim-first-and-last-name-v1" {
		t.Fatal("actual trim/compose witness changed")
	}
	for _, transformation := range []string{"", "arbitrary-v1", "trim-first-and-last-name-v2"} {
		t.Run("constructor_"+transformation, func(t *testing.T) {
			entry := actual
			proof := *entry.CRMObservation
			entry.CRMObservation = &proof
			entry.CRMObservation.Transformation = transformation
			if _, err := EvaluateExecutionData(d, g, doc, []resolver.ResolveReport{entry}, at); err == nil {
				t.Fatal("altered private observation accepted")
			}
		})
	}
	for _, fault := range []string{"missing", "unknown", "wrong_version", "wrong_path", "wrong_kind"} {
		t.Run("decoder_"+fault, func(t *testing.T) {
			s := admission.Snapshot()
			v := &s.CRMValues[0]
			switch fault {
			case "missing":
				v.Observation.Transformation = ""
			case "unknown":
				v.Observation.Transformation = "arbitrary-v1"
			case "wrong_version":
				v.Observation.Transformation = "trim-first-and-last-name-v2"
			case "wrong_path":
				v.SourcePath = "first_name"
			case "wrong_kind":
				v.SourceKind = "crm.company"
				v.SourcePath = "name"
				s.CRMRecords[0].Kind = "crm.company"
			}
			raw, err := canonical(s)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = DecodeDataAdmission(raw); err == nil {
				t.Fatal("wrong transformation/source pairing accepted")
			}
		})
	}
}

func TestDataAdmissionNativeScalarTransformationScopeRemainsClosedV1(t *testing.T) {
	for _, source := range []struct{ kind, path string }{{"crm.contact", "first_name"}, {"crm.contact", "email"}, {"crm.deal", "title"}, {"crm.company", "name"}} {
		if !dataAdmissionCRMTransformationV1(source.kind, source.path, "") {
			t.Fatal("unchanged native scalar refused")
		}
		for _, transform := range []string{"trim-first-and-last-name-v1", "arbitrary-v1"} {
			if dataAdmissionCRMTransformationV1(source.kind, source.path, transform) {
				t.Fatal("transform admitted on another native scalar")
			}
		}
	}
	if !dataAdmissionCRMTransformationV1("crm.contact", "full_name", "trim-first-and-last-name-v1") || dataAdmissionCRMTransformationV1("crm.contact", "full_name", "") {
		t.Fatal("derived scalar lost exact transformation requirement")
	}
}
