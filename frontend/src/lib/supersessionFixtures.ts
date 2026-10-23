import type { SupersessionMarker, SupersessionReady } from './supersession';
export const ids = Array.from({ length: 9 }, (_, n) => `00000000-0000-4000-8000-${String(n + 1).padStart(12, '0')}`);
export function supersessionFixture() {
  const actor = { org_id: ids[0], user_id: ids[1] };
  const ready: SupersessionReady = { schema_version: 1, state: 'ready', ...actor, creation_available: true, prior: { execution_id: ids[2], execution_sha256: 'a'.repeat(64), document_id: ids[3], source_commitment: 'b'.repeat(64), materialization_id: ids[4], materialization_revision: 1, template: { id: ids[5], version: 1, content_sha256: 'c'.repeat(64), approved_by: ids[1], approved_at: '2026-10-10T08:00:00.123456789Z' } }, template: { id: ids[5], version: 2, content_sha256: 'd'.repeat(64), values: [{ name: 'customer_name', required: true, max_chars: 80 }], defaults: { customer_name: 'Current approved default' }, sections: [{ name: 'scope', default_text: 'Current approved wording', max_chars: 500 }] } };
  const marker: SupersessionMarker = { schema_version: 1, ...actor, prior_document_id: ids[3], prior_execution_id: ids[2], template_id: ids[5], request_id: ids[6] };
  const result = { schema_version: 1, request_id: marker.request_id, state: 'committed', prior_execution_id: ids[2], prior_document_id: ids[3], document_id: ids[7], source_commitment: 'e'.repeat(64) };
  return { actor, ready, marker, result };
}
