// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CommentPageResultV1 struct {
	JSON    []byte
	self    *CommentPageResultV1
	once    sync.Once
	release func()
}

func (r *CommentPageResultV1) CloseConsumerV1() {
	if r != nil && r.self == r {
		r.once.Do(func() {
			r.JSON = nil
			if r.release != nil {
				r.release()
				r.release = nil
			}
		})
	}
}

// Public scope comes only from the immutable borrowed Active admission. The
// cursor and mutable exposed RecipientContext cannot replace that authority.
func (e *Engine) SignerCommentPageV1(ctx context.Context, rc *RecipientContext, rawQuery string, check func(*RecipientContext) error) (*CommentPageResultV1, error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || rc == nil || rc.readLease == nil || check == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finish, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	input, err := e.WorkRuntime.SessionsV1().NewSignerCommentPageInputV1(ctx, rc.readLease.reader, rawQuery)
	if err != nil {
		finish()
		return nil, commentPageFailureV1(err)
	}
	return e.readCommentPageV1(input, rc, original, uuid.Nil, nil, check, finish)
}

func (e *Engine) StaffCommentPageV1(ctx context.Context, org, document, user uuid.UUID, rawQuery string, authorize func(context.Context, *generated.User) error) (*CommentPageResultV1, error) {
	if authorize == nil || user == uuid.Nil {
		return nil, ErrSenderCommentNotAuthorized
	}
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	input, err := e.WorkRuntime.SessionsV1().NewStaffCommentPageInputV1(ctx, org, document, rawQuery)
	if err != nil {
		return nil, commentPageFailureV1(err)
	}
	return e.readCommentPageV1(input, nil, nil, user, authorize, nil, nil)
}

func commentPageFailureV1(err error) error {
	if errors.Is(err, pdfadmission.ErrCommentPageV1) {
		return errors.Join(ErrSigningAdmissionUnavailableV1, err)
	}
	return blockSignatureFailureV1(err)
}

func (e *Engine) readCommentPageV1(input *pdfadmission.ApplicationCommentPageInputV1, public, original *RecipientContext, user uuid.UUID, authorize func(context.Context, *generated.User) error, check func(*RecipientContext) error, finishOriginal func()) (result *CommentPageResultV1, failure error) {
	var native *pdfadmission.ApplicationHTMLSendOperationV1
	var finishInput, finishPage func()
	transferred := false
	defer func() {
		if native != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			failure = errors.Join(failure, native.CloseV1(cleanup))
			stop()
		}
		input.CloseConsumerV1()
		if !transferred {
			if finishPage != nil {
				finishPage()
			}
			if finishInput != nil {
				finishInput()
			}
			if finishOriginal != nil {
				finishOriginal()
			}
		}
		if failure != nil && result != nil {
			result.CloseConsumerV1()
			result = nil
		}
		failure = commentPageFailureV1(failure)
	}()
	var err error
	native, selection, release, err := e.WorkRuntime.SessionsV1().NewCommentPageOperationV1(input)
	if err != nil {
		return nil, err
	}
	finishInput = release
	request := input.ContextV1()
	purpose := pdfadmission.HTMLStaffCommentReadV1
	if original != nil {
		purpose = pdfadmission.HTMLSignerCommentReadV1
	}
	stage, err := native.OpenSQLV1(purpose)
	if err != nil {
		return nil, err
	}
	call, session := stage.ContextV1(), stage.SessionV1()
	if call == nil || session == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	if _, err = session.NewAdmissionV1(call); err != nil {
		return nil, err
	}
	var body []byte
	var actor *generated.User
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		state, err := w.StateV1(actual)
		if errors.Is(err, pgx.ErrNoRows) {
			if original != nil {
				return ErrMagicLinkExpired
			}
			return ErrCommentDocumentNotFound
		}
		if err != nil {
			return err
		}
		var access pdfadmission.ApplicationSignerReadAccessV1
		if original != nil {
			if state.ID != original.Document.ID || state.OrgID != original.Document.OrgID || state.SentAt != original.Document.SentAt || state.Article13NoticeEpochAt != original.Document.Article13NoticeEpochAt || state.Article13NoticeEpochV61Committed != original.Document.Article13NoticeEpochV61Committed || !state.HasSupportedArticle13NoticeSchema || len(original.Recipient.MagicTokenHash) != sha256.Size {
				return ErrMagicLinkExpired
			}
			var hash [sha256.Size]byte
			copy(hash[:], original.Recipient.MagicTokenHash)
			access, err = w.ReadCommentPageCredentialV1(actual, original.Recipient.ID, hash)
			if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, pdfadmission.ErrSignerReadCredentialV1) {
				return ErrMagicLinkExpired
			}
			if err != nil {
				return err
			}
			if err = ValidateRecipientReadCredential(original, original, time.Now()); err != nil {
				return err
			}
			if err = signerReadPreflightV1(pdfadmission.SignerReadActiveV1, time.Now(), access); err != nil {
				return err
			}
		} else {
			actor, err = w.ReadActorV1(actual, user)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSenderCommentNotAuthorized
			}
			if err != nil {
				return err
			}
			if actor.Role != string(auth.RoleViewer) && actor.Role != string(auth.RoleSender) && actor.Role != string(auth.RoleOwner) {
				return ErrSenderCommentNotAuthorized
			}
			if err = authorize(actual, actor); err != nil {
				return err
			}
		}
		body, finishPage, err = w.ReadCommentPageV1(actual, selection)
		if err != nil {
			return err
		}
		// Serialization has finished, while parent/recipient/member locks remain.
		if original != nil {
			if err = ValidateRecipientReadCredential(original, original, time.Now()); err != nil {
				return err
			}
			return signerReadPreflightV1(pdfadmission.SignerReadActiveV1, time.Now(), access)
		}
		return authorize(actual, actor)
	})
	if err != nil {
		return nil, err
	}
	if err = session.CommitV1(call); err != nil {
		return nil, err
	}
	if err = stage.CloseSQLV1(); err != nil {
		return nil, err
	}
	// CloseSQL cancels only the SQL stage. Final policy uses the captured
	// original request context, with no renewed credential or request deadline.
	if original != nil {
		// The JSON owns its own retained grant. Retire this completed producer
		// before opening the mandatory full policy recheck. A failed close stays
		// quarantined in the factory; do not renew its original cleanup deadline.
		producer := native
		native = nil
		producer.EndConsumerV1()
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		err = producer.CloseV1(cleanup)
		stop()
		if err != nil {
			return nil, err
		}
		if err = e.RecheckRecipientReadV1(request, public, check); err != nil {
			return nil, err
		}
	} else if err = authorize(request, actor); err != nil {
		return nil, err
	}
	if err = request.Err(); err != nil {
		return nil, err
	}
	r := &CommentPageResultV1{JSON: body, release: func() {
		if finishPage != nil {
			finishPage()
		}
		if finishInput != nil {
			finishInput()
		}
		if finishOriginal != nil {
			finishOriginal()
		}
	}}
	r.self = r
	transferred = true
	return r, nil
}
