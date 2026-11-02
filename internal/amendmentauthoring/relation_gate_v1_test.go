// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
package amendmentauthoring

import (
	"context"
	"errors"
	"testing"

	"github.com/bright-interaction/hash/internal/amendments"
	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/authoring"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type relationGateRow700 struct {
	value any
	err   error
}

func (r relationGateRow700) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("unexpected scalar scan")
	}
	switch out := dest[0].(type) {
	case *bool:
		*out = r.value.(bool)
	case *uuid.UUID:
		*out = r.value.(uuid.UUID)
	default:
		return errors.New("unexpected scalar type")
	}
	return nil
}

type relationGateDB700 struct {
	rows    []relationGateRow700
	queries []string
	args    [][]any
}

func (d *relationGateDB700) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	d.queries = append(d.queries, query)
	d.args = append(d.args, args)
	if len(d.rows) == 0 {
		return relationGateRow700{err: errors.New("unexpected query")}
	}
	r := d.rows[0]
	d.rows = d.rows[1:]
	return r
}
func (*relationGateDB700) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("body reads are not scalar relation proof")
}
func (*relationGateDB700) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errors.New("scalar relation gate must not write")
}

func TestRelationAbsenceIsProvedAfterPrivacyAndFinalCredential(t *testing.T) {
	ctx := context.Background()
	org, user, doc := uuid.New(), uuid.New(), uuid.New()
	calls := 0
	db := &relationGateDB700{rows: []relationGateRow700{{value: true}, {value: false}, {err: pgx.ErrNoRows}}}
	actor := authoring.Actor{OrgID: org, UserID: user, Authorize: func(_ context.Context, _ pgx.Tx, u *generated.User) error {
		calls++
		if u.ID != user || u.OrgID != org {
			t.Fatal("actor changed")
		}
		if calls == 1 && len(db.queries) != 0 {
			t.Fatal("relation queried before original credential")
		}
		if calls == 2 && len(db.queries) != 3 {
			t.Fatal("final credential preceded the absence proof")
		}
		return nil
	}}
	gate, guard := relationReadGateV1(ctx, db, actor)
	err := gate(pdfadmission.HTMLRevisionReadAccessV1{DocumentID: doc, OrgID: org, SenderID: user, Draft: true}, &generated.User{ID: user, OrgID: org, Role: "owner"})
	if !errors.Is(err, pgx.ErrNoRows) || calls != 2 || *guard == nil || len(db.rows) != 0 {
		t.Fatal("genuine absence did not retain all original read guards")
	}
	if len(db.args[2]) != 2 || db.args[2][0] != doc || db.args[2][1] != org {
		t.Fatal("relation lookup lost document or tenant binding")
	}
}
func TestRelationGateNeverTurnsUnknownOrRefusedAuthorityIntoAbsence(t *testing.T) {
	unknown := errors.New("database unavailable")
	for _, tc := range []struct {
		name               string
		rows               []relationGateRow700
		first, final, want error
		queries            int
	}{
		{"permission", nil, auth.ErrMutationPermissionRevoked, nil, auth.ErrMutationPermissionRevoked, 0},
		{"privacy fence", []relationGateRow700{{value: false}}, nil, nil, authoring.ErrPrivacyReviewChanging, 1},
		{"privacy request", []relationGateRow700{{value: true}, {value: true}}, nil, nil, authoring.ErrPendingPrivacyReview, 2},
		{"unknown relation", []relationGateRow700{{value: true}, {value: false}, {err: unknown}}, nil, nil, unknown, 3},
		{"expired after absence", []relationGateRow700{{value: true}, {value: false}, {err: pgx.ErrNoRows}}, nil, auth.ErrMutationCredentialExpired, auth.ErrMutationCredentialExpired, 3},
		{"invalid relation identity", []relationGateRow700{{value: true}, {value: false}, {value: uuid.Nil}}, nil, nil, amendments.ErrUnavailableV1, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			org, user, doc := uuid.New(), uuid.New(), uuid.New()
			db := &relationGateDB700{rows: tc.rows}
			calls := 0
			actor := authoring.Actor{OrgID: org, UserID: user, Authorize: func(context.Context, pgx.Tx, *generated.User) error {
				calls++
				if calls == 1 {
					return tc.first
				}
				return tc.final
			}}
			gate, _ := relationReadGateV1(context.Background(), db, actor)
			err := gate(pdfadmission.HTMLRevisionReadAccessV1{DocumentID: doc, OrgID: org, SenderID: user}, &generated.User{ID: user, OrgID: org, Role: "owner"})
			if !errors.Is(err, tc.want) || errors.Is(err, pgx.ErrNoRows) || len(db.queries) != tc.queries {
				t.Fatalf("authority refusal changed: %v", err)
			}
		})
	}
}
func TestLinkedRelationStillRequiresTheExistingFullBodyPath(t *testing.T) {
	org, user, doc, link := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	db := &relationGateDB700{rows: []relationGateRow700{{value: true}, {value: false}, {value: link}}}
	calls := 0
	gate, guard := relationReadGateV1(context.Background(), db, authoring.Actor{OrgID: org, UserID: user, Authorize: func(context.Context, pgx.Tx, *generated.User) error { calls++; return nil }})
	err := gate(pdfadmission.HTMLRevisionReadAccessV1{DocumentID: doc, OrgID: org, SenderID: user}, &generated.User{ID: user, OrgID: org, Role: "owner"})
	if err != nil || calls != 1 || *guard == nil {
		t.Fatal("linked source did not continue to original native full read")
	}
}

func TestRelationAbsenceNeverMasksUnknownNativeCleanup(t *testing.T) {
	unknown := errors.New("native cleanup remains unknown")
	if got := relationFailureAfterCleanupV1(pgx.ErrNoRows, nil); !errors.Is(got, pgx.ErrNoRows) {
		t.Fatal("proved clean absence lost its ordinary missing response")
	}
	if got := relationFailureAfterCleanupV1(pgx.ErrNoRows, unknown); errors.Is(got, pgx.ErrNoRows) || !errors.Is(got, amendments.ErrUnavailableV1) || !errors.Is(got, unknown) {
		t.Fatal("unknown cleanup was hidden as ordinary absence")
	}
}
