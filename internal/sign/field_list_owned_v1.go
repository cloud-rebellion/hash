// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package sign

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/pdfadmission"
	"github.com/jackc/pgx/v5"
)

type SignerFieldListResultV1 struct {
	JSON    []byte
	self    *SignerFieldListResultV1
	once    sync.Once
	release func()
}

func (r *SignerFieldListResultV1) CloseConsumerV1() {
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

// The original opaque read admission supplies identity and original deadlines.
// The native field producer adds resource/coherence ownership only; the full
// final credential/source/notice recheck remains mandatory before any output.
func (e *Engine) SignerFieldListV1(ctx context.Context, rc *RecipientContext, check func(*RecipientContext) error) (result *SignerFieldListResultV1, failure error) {
	if e == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || rc == nil || rc.readLease == nil || check == nil {
		return nil, ErrSigningAdmissionUnavailableV1
	}
	original, _, finishOriginal, err := rc.readLease.borrowOriginalV1(e, rc, pdfadmission.SignerReadActiveV1)
	if err != nil {
		return nil, err
	}
	var native *pdfadmission.ApplicationHTMLSendOperationV1
	var input *pdfadmission.ApplicationSignerFieldListInputV1
	var finishInput, finishBody func()
	transferred := false
	defer func() {
		if native != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			failure = errors.Join(failure, native.CloseV1(cleanup))
			stop()
		}
		if input != nil {
			input.CloseConsumerV1()
		}
		if !transferred {
			if finishBody != nil {
				finishBody()
			}
			if finishInput != nil {
				finishInput()
			}
			finishOriginal()
		}
		if failure != nil && result != nil {
			result.CloseConsumerV1()
			result = nil
		}
		if errors.Is(failure, pdfadmission.ErrSignerFieldListV1) {
			failure = errors.Join(ErrSigningAdmissionUnavailableV1, failure)
		}
		failure = blockSignatureFailureV1(failure)
	}()
	input, err = e.WorkRuntime.SessionsV1().NewSignerFieldListInputV1(ctx, rc.readLease.reader)
	if err != nil {
		return nil, err
	}
	native, finishInput, err = e.WorkRuntime.SessionsV1().NewSignerFieldListOperationV1(input)
	if err != nil {
		return nil, err
	}
	request := input.ContextV1()
	stage, err := native.OpenSQLV1(pdfadmission.HTMLSignerFieldListReadV1)
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
	err = stage.WithTxV1(func(actual context.Context, _ generated.DBTX) error {
		w, err := session.NewHTMLSendWorkV1(actual, stage)
		if err != nil {
			return err
		}
		state, err := w.StateV1(actual)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMagicLinkExpired
		}
		if err != nil {
			return err
		}
		if state.ID != original.Document.ID || state.OrgID != original.Document.OrgID || state.SentAt != original.Document.SentAt || state.Article13NoticeEpochAt != original.Document.Article13NoticeEpochAt || state.Article13NoticeEpochV61Committed != original.Document.Article13NoticeEpochV61Committed || !state.HasSupportedArticle13NoticeSchema {
			return ErrMagicLinkExpired
		}
		access, err := w.ReadSignerFieldListCredentialV1(actual)
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
		body, finishBody, err = w.ReadSignerFieldListV1(actual)
		if err != nil {
			return err
		}
		// Serialization is complete and all original locks are still held.
		if err = ValidateRecipientReadCredential(original, original, time.Now()); err != nil {
			return err
		}
		return signerReadPreflightV1(pdfadmission.SignerReadActiveV1, time.Now(), access)
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
	if err = e.RecheckRecipientReadV1(request, rc, check); err != nil {
		return nil, err
	}
	if err = request.Err(); err != nil {
		return nil, err
	}
	r := &SignerFieldListResultV1{JSON: body, release: func() {
		if finishBody != nil {
			finishBody()
		}
		if finishInput != nil {
			finishInput()
		}
		finishOriginal()
	}}
	r.self = r
	transferred = true
	return r, nil
}
