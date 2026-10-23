// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
package pdfadmission

import (
	"context"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bright-interaction/hash/internal/auth"
	"github.com/bright-interaction/hash/internal/crmconnection"
	"github.com/bright-interaction/hash/internal/crmreview"
	"github.com/bright-interaction/hash/internal/db/generated"
	"github.com/bright-interaction/hash/internal/presign"
	"github.com/bright-interaction/hash/internal/presignregistry"
	"github.com/bright-interaction/hash/internal/resolver"
	"github.com/bright-interaction/hash/internal/workguard"
)

// Selection supplies record IDs only. Every kind/account/path comes from the
// actual approved definition; fixed selections cannot be overridden. Order is
// canonical at the API digest boundary and duplicate kinds never collapse.
func preSignCRMRefsV1(d presignregistry.WorkflowDefinition, selected []presignregistry.RecordRule) ([]crmconnection.RecordRef, error) {
	c := d.DataRules.CRM
	if d.Kind != presignregistry.KindApprovedData || c == nil || len(c.Records) < 1 || len(c.Records) > 3 {
		return nil, presignregistry.ErrInvalid
	}
	records := c.Records
	switch c.Selection {
	case "fixed_record_set":
		if len(selected) != 0 {
			return nil, presignregistry.ErrInvalid
		}
	case "execution_record_set":
		if len(selected) != len(c.Records) {
			return nil, presignregistry.ErrInvalid
		}
		records = selected
	default:
		return nil, presignregistry.ErrInvalid
	}
	kinds := map[string]bool{}
	for _, r := range c.Records {
		if kinds[r.Kind] {
			return nil, presignregistry.ErrInvalid
		}
		kinds[r.Kind] = true
	}
	refs := make([]crmconnection.RecordRef, 0, len(records))
	seen := map[string]bool{}
	for _, r := range records {
		ref := crmconnection.RecordRef{Kind: crmconnection.RecordKind(r.Kind), ID: r.ID}
		if !kinds[r.Kind] || seen[r.Kind] || crmconnection.ValidateRecordRef(ref) != nil {
			return nil, presignregistry.ErrInvalid
		}
		seen[r.Kind] = true
		refs = append(refs, ref)
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].Kind < refs[j].Kind })
	return refs, nil
}

// The original native reader supplies authority, current account and bounded
// inputs. This separate joined consumer owns its own parent loan: closing or
// retiring SQL cannot return credit while the real protected read is active.
type ApplicationPreSignCRMSourceV1 struct {
	mu          sync.Mutex
	activity    applicationJoinedActivityV1
	closed      atomic.Bool
	self        *ApplicationPreSignCRMSourceV1
	initial     *ApplicationSessionV1
	original    context.Context
	admission   auth.PreSignAPIAdmissionV1
	command     PreSignAPISourceCommandV1
	template    presign.TemplatePin
	definition  presignregistry.WorkflowDefinition
	grantor     presign.NamedRepresentative
	connection  crmconnection.Connection
	refs        []crmconnection.RecordRef
	client      *crmconnection.Client
	keys        *crmconnection.Keyring
	coordinator *workguard.CoordinatorV1
	body        *workguard.GrantV1
	observation *resolver.ApprovedCRMSourceV1
	values      map[string]string
	attempted   bool
}

func (r *ApplicationHTMLAuthoringReaderV1) StartPreSignCRMSourceV1(call, original context.Context, a auth.PreSignAPIAdmissionV1, c PreSignAPISourceCommandV1, selected []presignregistry.RecordRule, client *crmconnection.Client, keys *crmconnection.Keyring, origin string) (*ApplicationPreSignCRMSourceV1, error) {
	if r == nil || r.self != r || client == nil || keys == nil || !applicationContextV1(original) {
		return nil, ErrHTMLAuthoringReadV1
	}
	actualDeadline, ok := call.Deadline()
	deadline, _ := original.Deadline()
	if !ok || actualDeadline != deadline || original.Value(applicationSessionCallbackKeyV1{}) != nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	authority, err := r.LockPreSignAPIBirthAuthorityV1(call, a, c.Policy, c.Grant)
	if err != nil {
		return nil, err
	}
	d := authority.Definition()
	scope := d.DataRules.CRM
	refs, err := preSignCRMRefsV1(d, selected)
	if err != nil {
		return nil, err
	}
	row, err := r.ReadCRMConnectionV1(call)
	if err != nil {
		return nil, err
	}
	if row == nil || scope == nil || row.Status != "active" || !row.VerifiedAt.Valid || row.Origin != origin || row.ID != scope.ConnectionID || row.OrgID != a.OrgID() || row.Generation != scope.Generation || row.Origin != scope.Origin || row.CrmTeamID != scope.TeamID || row.CrmUserID != scope.UserID {
		return nil, presignregistry.ErrConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) {
		return nil, ErrHTMLAuthoringReadV1
	}
	factory := r.session.state.factory
	factory.mu.Lock()
	var coordinator *workguard.CoordinatorV1
	if !factory.closing && factory.work != nil {
		coordinator = factory.work.coordinator
	}
	factory.mu.Unlock()
	if coordinator == nil {
		return nil, ErrHTMLAuthoringReadV1
	}
	// At most three exact selected records plus both account reads, each with
	// the existing protected-client response ceiling. Eightfold parent allowance
	// plus the existing authoring scratch precedes decoding/maps/projections.
	body, err := coordinator.TryAcquireV1(original, a.OrgID(), workguard.VectorV1{ParentBytes: 8*int64(5*crmconnection.MaxResponseBytes) + htmlAuthoringOtherWorkV1})
	if err != nil {
		return nil, err
	}
	h := &ApplicationPreSignCRMSourceV1{initial: r.session, original: original, admission: a, command: c, template: authority.Policy().Snapshot().Template, definition: d, grantor: authority.Grant().Snapshot().Grantor,
		connection: crmconnection.Connection{Identity: crmconnection.Identity{ID: row.ID, OrgID: row.OrgID, Generation: row.Generation, Origin: row.Origin, CRMTeamID: row.CrmTeamID, CRMUserID: row.CrmUserID}, Enabled: true, VerifiedAt: row.VerifiedAt.Time, Ciphertext: row.CredentialCiphertext},
		refs:       refs, client: client, keys: keys, coordinator: coordinator, body: body}
	h.self = h
	return h, nil
}

func (h *ApplicationPreSignCRMSourceV1) lockV1() bool {
	if h == nil || h.self != h || !h.activity.enterV1() {
		return false
	}
	h.mu.Lock()
	return true
}
func (h *ApplicationPreSignCRMSourceV1) unlockV1() {
	h.mu.Unlock()
	if h.activity.leaveV1() {
		h.retireV1()
	}
}
func (h *ApplicationPreSignCRMSourceV1) retireV1() {
	h.observation = nil
	h.values = nil
	h.definition = presignregistry.WorkflowDefinition{}
	h.grantor = presign.NamedRepresentative{}
	h.connection = crmconnection.Connection{}
	h.refs = nil
	h.admission = auth.PreSignAPIAdmissionV1{}
	h.initial = nil
	h.client = nil
	h.keys = nil
	h.original = nil
	h.coordinator = nil
	if h.body != nil {
		h.body.Close()
		h.body = nil
	}
}
func (h *ApplicationPreSignCRMSourceV1) CloseConsumerV1() {
	if h == nil || h.self != h {
		return
	}
	h.closed.Store(true)
	if h.activity.closeV1() {
		h.retireV1()
	}
}

func (h *ApplicationPreSignCRMSourceV1) ReadV1() error {
	if !h.lockV1() {
		return ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	if h.closed.Load() || h.attempted || !preSignKnownCommitV1(h.initial) || !applicationContextV1(h.original) {
		return ErrHTMLAuthoringReadV1
	}
	h.attempted = true
	stream, err := h.coordinator.TryAcquireV1(h.original, h.admission.OrgID(), workguard.VectorV1{ProviderStreams: 1})
	if err != nil {
		return err
	}
	defer stream.Close()
	observation, err := resolver.ReadApprovedCRMSourceV1(h.original, h.client, h.keys, h.connection, h.refs)
	if err != nil {
		return err
	}
	values := map[string]string{}
	selected := map[string]string{}
	for _, r := range h.refs {
		selected[string(r.Kind)] = r.ID
	}
	for _, rule := range h.definition.DataRules.Values {
		if rule.Mode != presignregistry.ModeCRM {
			continue
		}
		value, err := observation.ScalarV1(rule.SourceKind, selected[rule.SourceKind], rule.SourcePath)
		if err != nil {
			return err
		}
		values[rule.Variable] = value
	}
	if h.closed.Load() || h.original.Err() != nil || observation.CheckDeadlineV1() != nil {
		return resolver.ErrSourceFreshness
	}
	h.observation = observation
	h.values = values
	return nil
}

// A borrowed producer map, not an independently minted CRM witness. Callers
// keep the native consumer alive through their actual map/body last use.
func (h *ApplicationPreSignCRMSourceV1) ValuesV1() (map[string]string, error) {
	if !h.lockV1() {
		return nil, ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	if h.closed.Load() || h.observation == nil || h.observation.CheckDeadlineV1() != nil {
		return nil, resolver.ErrSourceFreshness
	}
	return h.values, nil
}
func (h *ApplicationPreSignCRMSourceV1) CheckDeadlineV1() error {
	if !h.lockV1() {
		return ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	if h.closed.Load() || h.observation == nil || h.original.Err() != nil {
		return resolver.ErrSourceFreshness
	}
	return h.observation.CheckDeadlineV1()
}

func (h *ApplicationPreSignCRMSourceV1) CheckLockedV1(call context.Context, r *ApplicationHTMLAuthoringReaderV1) error {
	if !h.lockV1() {
		return ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	return h.checkLockedV1(call, r)
}
func (h *ApplicationPreSignCRMSourceV1) checkLockedV1(call context.Context, r *ApplicationHTMLAuthoringReaderV1) error {
	if h.closed.Load() || h.observation == nil || h.original.Err() != nil || h.observation.CheckDeadlineV1() != nil || r == nil || r.self != r {
		return resolver.ErrSourceFreshness
	}
	// The original author callback locks/rechecks the actual policy/grant in
	// this transaction. This repeated population check adds the actual current
	// account lock and deadline without duplicating canonical registry scans.
	row, err := r.ReadCRMConnectionV1(call)
	if err != nil {
		return err
	}
	id := h.observation.IdentityV1()
	if row == nil || row.Status != "active" || !row.VerifiedAt.Valid || row.ID != id.ID || row.OrgID != id.OrgID || row.Generation != id.Generation || row.Origin != id.Origin || row.CrmTeamID != id.CRMTeamID || row.CrmUserID != id.CRMUserID {
		return presignregistry.ErrConflict
	}
	return h.observation.CheckDeadlineV1()
}

// The original creation transaction persists only policy-selected bindings.
// It does not write an interactive mapping-review row or invent human consent.
func (h *ApplicationPreSignCRMSourceV1) PersistBindingsV1(call context.Context, r *ApplicationHTMLAuthoringReaderV1, doc *generated.Document) (string, error) {
	if !h.lockV1() {
		return "", ErrHTMLAuthoringReadV1
	}
	defer h.unlockV1()
	if err := h.checkLockedV1(call, r); err != nil {
		return "", err
	}
	authority, err := r.LockPreSignAPIBirthAuthorityV1(call, h.admission, h.command.Policy, h.command.Grant)
	if err != nil {
		return "", err
	}
	if authority.Policy().Snapshot().Template != h.template || authority.Definition().DataRules.CRM == nil || authority.Grant().Snapshot().Grantor.UserID != h.admission.UserID() {
		return "", presignregistry.ErrConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.valid(call) || doc == nil || doc.ID != r.session.state.document || doc.OrgID != h.admission.OrgID() || doc.SenderID != h.admission.UserID() {
		return "", ErrHTMLAuthoringReadV1
	}
	if err := r.acquire(call, 64*4096, 64*4096); err != nil {
		return "", err
	}
	bindings, err := r.queries.ListCRMMappingBindingsForShare(call, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return "", err
	}
	if len(bindings) != 0 {
		return "", presignregistry.ErrConflict
	}
	selected := map[string]string{}
	for _, ref := range h.refs {
		selected[string(ref.Kind)] = ref.ID
	}
	for _, rule := range h.definition.DataRules.Values {
		if rule.Mode != presignregistry.ModeCRM {
			continue
		}
		if _, err = r.queries.UpsertVariableBinding(call, generated.UpsertVariableBindingParams{DocumentID: doc.ID, VariableName: rule.Variable, SourceKind: rule.SourceKind, SourceRef: selected[rule.SourceKind], SourcePath: rule.SourcePath, Fallback: ""}); err != nil {
			return "", err
		}
	}
	_, digest, err := h.reportsLockedV1(call, r, doc)
	return digest, err
}

// Caller holds both native handle and reader. Every final report comes from
// this same concrete provider read and the actual newly persisted rows.
func (h *ApplicationPreSignCRMSourceV1) reportsLockedV1(call context.Context, r *ApplicationHTMLAuthoringReaderV1, doc *generated.Document) ([]resolver.ResolveReport, string, error) {
	owned, tx, done, err := applicationSessionSQLBorrowV1(call, r.session.state, true)
	if err != nil {
		return nil, "", err
	}
	defer done()
	reports, err := h.observation.ReportsForDocumentV1(owned, tx, doc)
	if err != nil {
		return nil, "", err
	}
	q := generated.New(tx)
	bindings, err := q.ListCRMMappingBindingsForShare(owned, generated.ListCRMMappingBindingsForShareParams{DocumentID: doc.ID, OrgID: doc.OrgID})
	if err != nil {
		return nil, "", err
	}
	want := map[string]presignregistry.ValueRule{}
	selected := map[string]string{}
	for _, ref := range h.refs {
		selected[string(ref.Kind)] = ref.ID
	}
	for _, rule := range h.definition.DataRules.Values {
		if rule.Mode == presignregistry.ModeCRM {
			want[rule.Variable] = rule
		}
	}
	if len(bindings) != len(want) || len(reports) != len(want) {
		return nil, "", presignregistry.ErrConflict
	}
	for _, b := range bindings {
		if b == nil {
			return nil, "", presignregistry.ErrConflict
		}
		rule, ok := want[b.VariableName]
		if !ok || b.SourceKind != rule.SourceKind || b.SourcePath != rule.SourcePath || b.SourceRef != selected[rule.SourceKind] || b.Fallback != "" {
			return nil, "", presignregistry.ErrConflict
		}
	}
	digest, err := crmreview.CRMSemanticDigest(bindings)
	if err != nil {
		return nil, "", err
	}
	// This verifies exact stored values, approved template/materialization and
	// every private report fence; no permissive static-value substitute exists.
	if _, err = presignregistry.EvaluateExecutionData(h.definition, h.grantor, doc, reports, time.Now()); err != nil {
		return nil, "", err
	}
	return reports, digest, h.observation.CheckDeadlineV1()
}
