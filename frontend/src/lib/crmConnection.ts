// Owner enrollment only. A connection approval is not a contract/PDF approval.
export interface CRMOwnerIdentity { user_id: string; org_id: string; role: string }
export interface CRMConnection {
  id: string;
  generation: string;
  status: 'candidate' | 'active' | 'revoked';
  crm_team_id: string;
  crm_user_id: string;
  verified_at: string | null;
  updated_at: string;
}
export interface CRMConnectionResponse {
  org_id: string;
  user_id: string;
  available: boolean;
  configured: boolean;
  requires_reconfiguration: boolean;
  origin: string;
  connection: CRMConnection | null;
}
const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const nilUUID = '00000000-0000-0000-0000-000000000000';
const int64Max = '9223372036854775807';
const invalidResponse = 'The connection response could not be verified. Refresh before continuing.';
const unavailableOwner = 'The original owner session could not be verified. Return to settings in the correct organisation.';
class CRMOwnerMismatch extends Error { constructor() { super(unavailableOwner); } }
export function crmGeneration(value: unknown, allowZero = false): value is string {
  return typeof value === 'string' && ((allowZero && value === '0') || (/^[1-9][0-9]{0,18}$/.test(value)
    && (value.length < int64Max.length || value <= int64Max)));
}
export function crmOpaqueID(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{1,256}$/.test(value);
}
export function crmToken(value: unknown): value is string {
  return typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
}
function object(value: unknown, keys: string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).length !== keys.length || !keys.every((key) => Object.hasOwn(value, key))) throw new Error(invalidResponse);
  return value as Record<string, unknown>;
}
function timestamp(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 40
    && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value) && Number.isFinite(Date.parse(value));
}
function usableUUID(value: unknown): value is string {
  return typeof value === 'string' && uuid.test(value) && value.toLowerCase() !== nilUUID;
}
export function checkedCRMOwner(value: unknown): CRMOwnerIdentity {
  const identity = value as CRMOwnerIdentity | null;
  if (!identity || !usableUUID(identity.user_id) || !usableUUID(identity.org_id) || identity.role !== 'owner') throw new CRMOwnerMismatch();
  return { user_id: identity.user_id, org_id: identity.org_id, role: 'owner' };
}
export function checkedCRMConnection(value: unknown): CRMConnectionResponse {
  const raw = object(value, ['org_id', 'user_id', 'available', 'configured', 'requires_reconfiguration', 'origin', 'connection']);
  if (!usableUUID(raw.org_id) || !usableUUID(raw.user_id) || typeof raw.available !== 'boolean' || typeof raw.configured !== 'boolean' || typeof raw.requires_reconfiguration !== 'boolean'
      || typeof raw.origin !== 'string' || raw.origin.length > 2048) throw new Error(invalidResponse);
  if (raw.origin) {
    let origin: URL;
    try { origin = new URL(raw.origin); } catch { throw new Error(invalidResponse); }
    if (!['https:', 'http:'].includes(origin.protocol) || origin.origin !== raw.origin
        || origin.username || origin.password || origin.search || origin.hash) throw new Error(invalidResponse);
  } else if (raw.available) throw new Error(invalidResponse);
  if (!raw.configured) {
    if (raw.connection !== null || raw.requires_reconfiguration) throw new Error(invalidResponse);
    return { org_id: raw.org_id, user_id: raw.user_id, available: raw.available, configured: false, requires_reconfiguration: false, origin: raw.origin, connection: null };
  }
  const connection = object(raw.connection, ['id', 'generation', 'status', 'crm_team_id', 'crm_user_id', 'verified_at', 'updated_at']);
  if (!usableUUID(connection.id) || !crmGeneration(connection.generation)
      || !['candidate', 'active', 'revoked'].includes(connection.status as string)
      || !crmOpaqueID(connection.crm_team_id) || !crmOpaqueID(connection.crm_user_id)
      || !(connection.verified_at === null || timestamp(connection.verified_at)) || !timestamp(connection.updated_at)
      || (connection.status !== 'revoked' && connection.generation === int64Max)
      || (connection.status !== 'revoked' && connection.verified_at === null)) throw new Error(invalidResponse);
  return { org_id: raw.org_id, user_id: raw.user_id, available: raw.available, configured: true, requires_reconfiguration: raw.requires_reconfiguration, origin: raw.origin, connection: {
    id: connection.id, generation: connection.generation, status: connection.status as CRMConnection['status'],
    crm_team_id: connection.crm_team_id, crm_user_id: connection.crm_user_id,
    verified_at: connection.verified_at, updated_at: connection.updated_at,
  } as CRMConnection };
}
export function crmConnectionPin(response: CRMConnectionResponse | null): string {
  if (!response) return '';
  return JSON.stringify([response.org_id, response.user_id, response.origin, response.requires_reconfiguration, response.connection?.id ?? '', response.connection?.generation ?? '0',
    response.connection?.status ?? '', response.connection?.crm_team_id ?? '', response.connection?.crm_user_id ?? '']);
}
// Reserve candidate -> enabled -> revoked increments; never save an account
// that cannot subsequently be enabled and safely revoked.
export function crmConnectionCapacity(response: CRMConnectionResponse | null): { configure: boolean; enable: boolean; revoke: boolean } {
  if (!response) return { configure: false, enable: false, revoke: false };
  const connection = response.connection, generation = BigInt(connection?.generation ?? '0');
  return { configure: generation < BigInt(int64Max) - 2n,
    enable: !response.requires_reconfiguration && connection?.status === 'candidate' && generation < BigInt(int64Max) - 1n,
    revoke: !!connection && connection.status !== 'revoked' && generation < BigInt(int64Max) };
}
export interface CRMActorExpectation { expected_org_id: string; expected_user_id: string }
export interface CRMConnectionTransport {
  identity(signal: AbortSignal): Promise<unknown>;
  read(signal: AbortSignal): Promise<unknown>;
  configure(input: CRMActorExpectation & { expected_generation: string; token: string }, signal: AbortSignal): Promise<unknown>;
  enable(input: CRMActorExpectation & { expected_generation: string; crm_team_id: string; crm_user_id: string }, signal: AbortSignal): Promise<unknown>;
  revoke(input: CRMActorExpectation & { expected_generation: string }, signal: AbortSignal): Promise<unknown>;
}
export interface CRMConnectionState {
  owner: CRMOwnerIdentity | null;
  response: CRMConnectionResponse | null;
  busy: 'refresh' | 'configure' | 'enable' | 'revoke' | null;
  fresh: boolean;
  confirmation: string;
  needsReadback: boolean;
  error: string | null;
  notice: string | null;
}
export function initialCRMConnectionState(): CRMConnectionState {
  return { owner: null, response: null, busy: null, fresh: false, confirmation: '', needsReadback: false, error: null, notice: null };
}
function statusOf(error: unknown): number | undefined {
  return error && typeof error === 'object' && 'status' in error && typeof error.status === 'number' ? error.status : undefined;
}
// All messages are local: provider/error bodies must not echo a submitted key.
export function crmConnectionError(error: unknown): string {
  if (error instanceof CRMOwnerMismatch) return unavailableOwner;
  switch (statusOf(error)) {
    case 400: return 'The connection request was refused. Refresh and check the key before trying again.';
    case 401: return 'Your session has expired. Sign in again before changing the connection.';
    case 403: return 'Only a current organisation owner can manage this connection.';
    case 409: return 'The connection or CRM account changed. Refresh and review the returned account.';
    case 503: return 'The CRM connector is temporarily unavailable. Refresh its saved state before trying again.';
    default: return 'The connection request could not be confirmed. Refresh its saved state before trying again.';
  }
}
export class CRMConnectionController {
  state = initialCRMConnectionState();
  private actor: CRMOwnerIdentity | null = null;
  private operation = 0;
  private abort: AbortController | null = null;
  private disposed = false;
  constructor(private transport: CRMConnectionTransport, private changed: (state: CRMConnectionState) => void) {}
  private update(patch: Partial<CRMConnectionState>) {
    if (this.disposed) return;
    this.state = { ...this.state, ...patch }; this.changed(this.state);
  }
  private current(operation: number) { return !this.disposed && operation === this.operation && !this.abort?.signal.aborted; }
  private verifyActor(raw: unknown): CRMOwnerIdentity {
    const actor = checkedCRMOwner(raw);
    if (this.actor && (actor.user_id !== this.actor.user_id || actor.org_id !== this.actor.org_id)) throw new CRMOwnerMismatch();
    this.actor ??= actor; return actor;
  }
  private verifyResponseActor(response: CRMConnectionResponse, actor: CRMOwnerIdentity) {
    if (response.org_id !== actor.org_id || response.user_id !== actor.user_id) throw new CRMOwnerMismatch();
  }
  interrupt() {
    this.operation++; this.abort?.abort(); this.abort = null;
    this.update({ owner: null, response: null, busy: null, fresh: false, confirmation: '', needsReadback: true,
      error: 'Refresh the connection after returning to this page.', notice: null });
  }
  dispose() { this.interrupt(); this.disposed = true; }
  confirmAccount(pin: string, confirmed: boolean) {
    if (this.state.busy || !this.state.fresh || this.state.needsReadback || this.state.response?.connection?.status !== 'candidate') return;
    this.update({ confirmation: confirmed && pin === crmConnectionPin(this.state.response) ? pin : '' });
  }
  async refresh() {
    if (this.disposed || this.state.busy) return;
    this.abort?.abort(); this.abort = new AbortController();
    const signal = this.abort.signal, selected = ++this.operation;
    this.update({ busy: 'refresh', fresh: false, confirmation: '', error: null, notice: null });
    try {
      const rawActor = await this.transport.identity(signal); if (!this.current(selected)) return;
      const owner = this.verifyActor(rawActor);
      const raw = await this.transport.read(signal); if (!this.current(selected)) return;
      const response = checkedCRMConnection(raw);
      this.verifyResponseActor(response, owner);
      const finalActor = await this.transport.identity(signal); if (!this.current(selected)) return;
      this.verifyActor(finalActor);
      this.update({ owner, response, fresh: true, needsReadback: false });
    } catch (error) {
      if (this.current(selected)) this.update({ owner: null, response: null, fresh: false, needsReadback: true, error: crmConnectionError(error) });
    } finally { if (this.current(selected)) this.update({ busy: null }); }
  }
  async configure(token: string) {
    if (!crmToken(token)) { this.update({ error: 'Enter the exact 64-character lowercase BrightCRM API key.' }); return; }
    await this.mutate('configure', token);
  }
  async enable() {
    if (!this.state.confirmation || this.state.confirmation !== crmConnectionPin(this.state.response)
        || this.state.response?.connection?.status !== 'candidate') return;
    await this.mutate('enable');
  }
  async revoke(pin: string) {
    if (pin !== crmConnectionPin(this.state.response) || !this.state.response?.connection || this.state.response.connection.status === 'revoked') return;
    await this.mutate('revoke');
  }
  private async mutate(kind: 'configure' | 'enable' | 'revoke', token?: string) {
    const previous = this.state.response, owner = this.state.owner;
    if (this.disposed || this.state.busy || !this.state.fresh || this.state.needsReadback || !owner || !previous
        || (kind !== 'revoke' && !previous.available)) return;
    if (!crmConnectionCapacity(previous)[kind]) {
      this.update({ error: 'This connection has reached its revision limit. Revoke it if available and ask your operator for help.' });
      return;
    }
    const pin = crmConnectionPin(previous), connection = previous.connection, generation = connection?.generation ?? '0';
    const expectedActor = { expected_org_id: owner.org_id, expected_user_id: owner.user_id };
    this.abort?.abort(); this.abort = new AbortController();
    const signal = this.abort.signal, selected = ++this.operation;
    let dispatched = false;
    this.update({ busy: kind, confirmation: '', error: null, notice: null });
    try {
      const rawActor = await this.transport.identity(signal); if (!this.current(selected)) return;
      this.verifyActor(rawActor);
      if (crmConnectionPin(this.state.response) !== pin) throw new Error(invalidResponse);
      dispatched = true;
      const raw = kind === 'configure' ? await this.transport.configure({ ...expectedActor, expected_generation: generation, token: token! }, signal)
        : kind === 'enable' ? await this.transport.enable({ ...expectedActor, expected_generation: generation, crm_team_id: connection!.crm_team_id, crm_user_id: connection!.crm_user_id }, signal)
        : await this.transport.revoke({ ...expectedActor, expected_generation: generation }, signal);
      if (!this.current(selected)) return;
      const response = checkedCRMConnection(raw), next = response.connection;
      this.verifyResponseActor(response, owner);
      if (!next || (kind !== 'revoke' && response.requires_reconfiguration) || response.origin !== previous.origin || (connection && next.id !== connection.id)
          || BigInt(next.generation) !== BigInt(generation) + 1n
          || next.status !== (kind === 'configure' ? 'candidate' : kind === 'enable' ? 'active' : 'revoked')
          || (kind !== 'configure' && (next.crm_team_id !== connection!.crm_team_id || next.crm_user_id !== connection!.crm_user_id))) throw new Error(invalidResponse);
      const finalActor = await this.transport.identity(signal); if (!this.current(selected)) return;
      this.verifyActor(finalActor);
      this.update({ owner, response, fresh: true, needsReadback: false, notice: kind === 'configure'
        ? 'Key saved as a disabled candidate. Review and confirm the returned CRM account before enabling it.'
        : kind === 'enable' ? 'Connection enabled for this organisation.' : 'Connection revoked. The stored credential has been removed.' });
    } catch (error) {
      if (this.current(selected)) this.update({ owner: null, fresh: false, needsReadback: true, confirmation: '',
        error: crmConnectionError(error) + (dispatched ? ' A previous request may have completed; read back before another change.' : '') });
    } finally { if (this.current(selected)) this.update({ busy: null }); }
  }
}
