// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package resolver

import (
	"context"
	"errors"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type crmSendProviderStoreV1 struct {
	row                *generated.CrmConnection
	deny               bool
	holds, releases    atomic.Int32
	calls              *atomic.Int32
	releasedAfterCalls int32
}

func (s *crmSendProviderStoreV1) GetCRMConnectionByOrg(_ context.Context, org uuid.UUID) (*generated.CrmConnection, error) {
	if s.row.OrgID != org {
		return nil, errors.New("foreign org")
	}
	return s.row, nil
}
func (s *crmSendProviderStoreV1) HoldCRMRecordReadV1(_ context.Context, org uuid.UUID) (func(), error) {
	s.holds.Add(1)
	if org != s.row.OrgID || s.deny {
		return nil, errors.New("synthetic provider unavailable")
	}
	return func() { s.releasedAfterCalls = s.calls.Load(); s.releases.Add(1) }, nil
}

// The real protected Client verifies account twice, reads the actual requested
// record, joins its response bodies and decodes before the native span ends.
func TestProtectedCRMReadNativeProviderSpanV1(t *testing.T) {
	for _, deny := range []bool{true, false} {
		t.Run(map[bool]string{true: "denied-no-network", false: "release-after-actual-client"}[deny], func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/v1/auth/me":
					_, _ = w.Write([]byte("{\"id\":\"crm_user\",\"team_id\":\"crm_team\",\"is_active\":true}"))
				case "/api/v1/deals/deal_1":
					_, _ = w.Write([]byte("{\"id\":\"deal_1\",\"team_id\":\"crm_team\",\"updated_at\":\"2026-10-01T10:00:00Z\",\"title\":\"Reviewed title\"}"))
				default:
					w.WriteHeader(404)
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
			org, doc := uuid.New(), uuid.New()
			id := crmconnection.Identity{ID: uuid.New(), OrgID: org, Generation: 1, Origin: upstream.URL, CRMTeamID: "crm_team", CRMUserID: "crm_user"}
			cipher, err := keys.Seal(id, strings.Repeat("ab", 32))
			if err != nil {
				t.Fatal(err)
			}
			store := &crmSendProviderStoreV1{row: &generated.CrmConnection{ID: id.ID, OrgID: org, Generation: id.Generation, Status: "active", Origin: id.Origin, CrmTeamID: id.CRMTeamID, CrmUserID: id.CRMUserID, CredentialCiphertext: cipher, VerifiedAt: pgtype.Timestamptz{Time: time.Now().Add(-time.Minute), Valid: true}}, deny: deny, calls: &calls}
			reader := &CRMRecords{Store: store, Client: client, Keys: keys, Origin: id.Origin}
			out, err := reader.observe(context.Background(), &generated.Document{ID: doc, OrgID: org}, []*generated.DocumentVariableBinding{{DocumentID: doc, SourceKind: "crm.deal", SourceRef: "deal_1", SourcePath: "title"}})
			if deny {
				if !errors.Is(err, ErrSourceFreshness) || out != nil || calls.Load() != 0 || store.holds.Load() != 1 || store.releases.Load() != 0 {
					t.Fatalf("denied protected CRM dispatched network: calls=%d holds=%d releases=%d err=%v", calls.Load(), store.holds.Load(), store.releases.Load(), err)
				}
				return
			}
			if err != nil || out == nil || len(out.Records) != 1 || calls.Load() != 3 || store.holds.Load() != 1 || store.releases.Load() != 1 || store.releasedAfterCalls != 3 {
				t.Fatalf("protected call did not join original three requests before release: calls=%d holds=%d releases=%d joined=%d err=%v", calls.Load(), store.holds.Load(), store.releases.Load(), store.releasedAfterCalls, err)
			}
		})
	}
}
