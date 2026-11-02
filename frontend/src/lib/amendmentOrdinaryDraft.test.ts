import { afterEach, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { AmendmentWorkflow } from './amendmentWorkflow';
import { amendmentTransport } from './api/amendments';
import { actor, candidateID, clone, document, inventory, originalID, record } from './amendmentFixtures';

const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });

const panel = readFileSync(new URL('./components/DocumentAmendmentsPanel.svelte', import.meta.url), 'utf8');
const ast: any = parse(panel, { modern: true });
const condition = ast.fragment.nodes.find((node: any) => node.type === 'IfBlock' && panel.slice(node.test.start, node.test.end).includes('view.inventory'))?.test;
if (!condition) throw new Error('Actual amendment panel freshness condition is missing');
const panelVisible = new Function('view', `return !!(${panel.slice(condition.start, condition.end)});`) as (view: unknown) => boolean;

function workflow(status: number) {
 const calls: string[] = [];
 globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
  const path = String(input); calls.push(path);
  expect(init?.credentials).toBe('include'); expect(init?.cache).toBe('no-store'); expect(init?.redirect).toBe('error');
  if (path === '/api/v1/me') return Response.json(clone(actor));
  if (path === `/api/v1/documents/${candidateID}/amendment`) return Response.json({ error: 'Synthetic native response' }, { status });
  throw new Error('Ordinary draft must not load agreement history, choices or write');
 }) as typeof fetch;
 const draft = { ...document(candidateID), source_kind: 'blocks' as const, status: 'draft' };
 return { calls, workflow: new AmendmentWorkflow(draft, actor, amendmentTransport, () => {}) };
}

test('a genuine native404 clears only the ordinary block-draft relation lookup and hides its irrelevant panel', async () => {
 const f = workflow(404);
 expect(f.workflow.ordinarySendBlocked()).toBe(true);
 await f.workflow.refresh();
 expect(f.calls).toEqual(['/api/v1/me', `/api/v1/documents/${candidateID}/amendment`, '/api/v1/me']);
 expect(f.workflow.state.fresh).toBe(true); expect(f.workflow.state.link).toBeNull(); expect(f.workflow.state.inventory).toBeNull();
 expect(f.workflow.state.error).toBeNull(); expect(f.workflow.ordinarySendBlocked()).toBe(false); expect(f.workflow.canWrite()).toBe(false);
 expect(panelVisible(f.workflow.state)).toBe(false);
 f.workflow.dispose();
});

test('permission, privacy conflict and unavailable authority stay visible and keep ordinary Send blocked', async () => {
 for (const status of [401, 403, 409, 429, 500, 503]) {
  const f = workflow(status); await f.workflow.refresh();
  expect(f.workflow.state.fresh).toBe(false); expect(f.workflow.state.error).toBeTruthy();
  expect(f.workflow.ordinarySendBlocked()).toBe(true); expect(panelVisible(f.workflow.state)).toBe(true);
  f.workflow.dispose();
 }
});

test('a genuine linked notice still loads its original inventory and blocks ordinary signature Send', async () => {
 const saved = inventory([record('agreed_notice')]);
 globalThis.fetch = (async (input: string | URL | Request) => {
  const path = String(input);
  if (path === '/api/v1/me') return Response.json(clone(actor));
  if (path.endsWith(`/${candidateID}/amendment`)) return Response.json({ schema: 'hash-later-amendments-v1', original_document_id: originalID, amendment: saved.amendments[0] });
  if (path.endsWith(`/${originalID}/amendments`)) return Response.json(saved);
  throw new Error('Unexpected linked workflow request');
 }) as typeof fetch;
 const value = new AmendmentWorkflow(document(candidateID, false), actor, amendmentTransport, () => {});
 await value.refresh(); expect(value.state.fresh).toBe(true); expect(value.state.link?.amendment.mode).toBe('agreed_notice');
 expect(value.ordinarySendBlocked()).toBe(true); expect(panelVisible(value.state)).toBe(true); value.dispose();
});
