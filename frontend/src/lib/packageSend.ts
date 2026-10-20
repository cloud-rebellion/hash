// Public observations only. The server derives permissions and frozen pins.
export type PackageSendObservation = { expected_updated_at: string; package_id: string; generation: string };
export type PackageSendReceipt = { attempt_id: string; outcome: 'active' | 'completed' | 'unknown'; reconciliation_required: boolean };
const uuid = (v: unknown): v is string => typeof v === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(v) && v !== '00000000-0000-0000-0000-000000000000';
const invalid = 'The package Send result could not be verified. Inspect the saved document before continuing.';
function record(v: unknown, keys: string[]): Record<string, unknown> { if (!v || typeof v !== 'object' || Array.isArray(v) || Object.keys(v).length !== keys.length || !keys.every(k => Object.hasOwn(v,k))) throw new Error(invalid); return v as Record<string,unknown>; }
export function checkedPackageSendObservation(v: unknown): PackageSendObservation {
 const a=record(v,['expected_updated_at','package_id','generation']);
 if (typeof a.expected_updated_at!=='string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z$/.test(a.expected_updated_at) || !Number.isFinite(Date.parse(a.expected_updated_at)) || new Date(a.expected_updated_at).toISOString().slice(0,19)!==a.expected_updated_at.slice(0,19) || !uuid(a.package_id) || typeof a.generation!=='string' || !/^[1-9][0-9]{0,18}$/.test(a.generation) || BigInt(a.generation)>=9223372036854775807n) throw new Error(invalid);
 return {...a} as PackageSendObservation;
}
export function checkedPackageSendReceipt(v: unknown, status?: string): PackageSendReceipt {
 const a=record(v,['attempt_id','outcome','reconciliation_required']);
 if (!uuid(a.attempt_id) || !['active','completed','unknown'].includes(a.outcome as string) || a.reconciliation_required!==(a.outcome!=='completed') || (status!==undefined && (a.outcome==='unknown' || (a.outcome==='active' ? status!=='sealing' : !['sent','in_progress','changes_requested','finalizing','completed','declined','voided','expired'].includes(status))))) throw new Error(invalid);
 return {...a} as PackageSendReceipt;
}
export function checkedPackageSendInspection(v: unknown, attempt: string): 'active'|'completed'|'aborted'|'not_recorded' {
 const a=record(v,['attempt_id','outcome','retry_authorized']);
 if (!uuid(attempt) || a.attempt_id!==attempt || !['active','completed','aborted','not_recorded'].includes(a.outcome as string) || a.retry_authorized!==false) throw new Error(invalid);
 return a.outcome as 'active'|'completed'|'aborted'|'not_recorded';
}
