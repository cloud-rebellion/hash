// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

package sign

import "context"

// InitializeWorkRuntimeV1 installs exactly one private journal for this Engine
// lifetime. It binds only the configured actual pool/runtime and performs no
// SQL, rendering, credential issuance, READY activation or signing dispatch.
// Call during startup after assigning the process runtime, before serving work.
func (e *Engine) InitializeWorkRuntimeV1() error {
	if e == nil {
		return ErrSigningAdmissionUnavailableV1
	}
	e.applicationJournalMu.Lock()
	defer e.applicationJournalMu.Unlock()
	if e.applicationJournalClosed || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) {
		return ErrSigningAdmissionUnavailableV1
	}
	if e.applicationJournal != nil {
		if e.applicationJournal.engine != e || e.applicationJournal.factory != e.WorkRuntime.SessionsV1() {
			return ErrSigningAdmissionUnavailableV1
		}
		return nil
	}
	journal, err := newApplicationRequestJournalV1(e)
	if err != nil {
		return ErrSigningAdmissionUnavailableV1
	}
	e.applicationJournal = journal
	return nil
}

// applicationWorkJournalV1 returns the SAME installed instance. A missing,
// replaced, differently bound or closed runtime cannot mint a new per-request
// journal or discard ownership of an unknown mutation. Full driver permission
// remains a separate genuine gate; obtaining this object is not admission.
func (e *Engine) applicationWorkJournalV1() (*applicationRequestJournalV1, error) {
	if e == nil {
		return nil, errApplicationBoundRequestV1
	}
	e.applicationJournalMu.Lock()
	defer e.applicationJournalMu.Unlock()
	journal := e.applicationJournal
	if e.applicationJournalClosed || journal == nil || e.WorkRuntime == nil || !e.WorkRuntime.MatchesPoolV1(e.Pool) || journal.engine != e || journal.factory != e.WorkRuntime.SessionsV1() {
		return nil, errApplicationBoundRequestV1
	}
	return journal, nil
}

// CloseWorkRuntimeRequestsV1 drains only this Engine's retained owners. It
// permanently fences new journal dispatch, including subsequent initializer
// calls. It retains the same journal for fresh-context cleanup retries and does
// not close or transfer ownership of the shared process session factory.
func (e *Engine) CloseWorkRuntimeRequestsV1(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.applicationJournalMu.Lock()
	e.applicationJournalClosed = true
	journal := e.applicationJournal
	e.applicationJournalMu.Unlock()
	if journal == nil {
		return nil
	}
	return journal.CloseV1(ctx)
}
