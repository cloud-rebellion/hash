import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { translateStaffText } from './staffPreferences';

const paths = [
  'routes/settings/ai/+page.svelte', 'routes/settings/audit-chain/+page.svelte', 'routes/settings/billing/+page.svelte',
  'routes/settings/branding/+page.svelte', 'routes/settings/compliance/+page.svelte', 'routes/settings/dsr/+page.svelte',
  'routes/settings/eidas-rules/+page.svelte', 'routes/settings/webhooks/+page.svelte',
  'lib/components/CRMConnectionSettings.svelte', 'lib/components/SigningAuthoritySettings.svelte',
  'lib/components/SigningPolicySettings.svelte', 'lib/components/BlockEditor/Editor.svelte',
  'lib/components/BlockEditor/RecoveryPanel.svelte', 'routes/documents/[id]/+page.svelte', 'lib/components/HtmlTemplateEditor.svelte',
];
const unchanged = new Set(['AES', 'QES', 'SES', 'P', 'H1', 'H2', 'HTML', 'Markdown', 'Anthropic', 'Mistral (EU)', 'URL', 'Status', 'Version', 'Index', 'Model', 'Code', 'API', 'SE',
  'Inter, system-ui, sans-serif', 'Geist, Inter, sans-serif', 'Acme Inc.', 'subject@example.com', 'https://your.cdn/logo.png', 'https://yoursaas.com/webhooks/hash',
  '2026-10-10T12:00:00Z', '2026-11-10T12:00:00Z', 'var.name', 'KiB', 'SHA-256', 'PDF SHA-256:',
  'Policy:', 'Status:', 'Webhooks', '· version', 'document.changes_requested', 'document.comment_posted', 'document.completed', 'document.declined', 'document.expired', 'document.sent', 'document.signed', 'document.viewed', 'document.voided', 'recipient.bounced', 'absent', 'active_room', 'approved_default', 'crm_scalar', 'grantor_field', 'literal', 'reviewed_value']);
function strings(node: any): string[] {
  if (node?.type === 'Literal' && typeof node.value === 'string') return [node.value];
  if (node?.type === 'ConditionalExpression') return [...strings(node.consequent), ...strings(node.alternate)];
  return [];
}
function walk(node: any, callback: (node: any, ancestors: any[]) => void, ancestors: any[] = []) {
  if (!node || typeof node !== 'object') return;
  callback(node, ancestors);
  for (const value of Object.values(node)) if (Array.isArray(value)) value.forEach(child => walk(child, callback, [...ancestors, node])); else if (value && typeof value === 'object') walk(value, callback, [...ancestors, node]);
}
function source(path: string) { return readFileSync(new URL('../' + path, import.meta.url), 'utf8'); }

test('all human literal staff labels in selected settings and editors have Swedish rendering', () => {
  const missing = new Set<string>();
  for (const path of paths) walk(parse(source(path), { modern: true }), node => {
    if (node.type === 'CallExpression' && node.callee?.name === '$ui') for (const text of strings(node.arguments[0])) {
      if (/[A-Za-z]/.test(text) && !unchanged.has(text.trim()) && translateStaffText('sv', text) === text) missing.add(text);
    }
  });
  expect([...missing].sort()).toEqual([]);
});

test('visible prose fragments are localized while source code, field values and business data stay separate', () => {
  const raw: string[] = [];
  for (const path of paths) walk(parse(source(path), { modern: true }), (node, ancestors) => {
    if (node.type !== 'Text' || !/[A-Za-z]/.test(node.data ?? '')) return;
    if (ancestors.some(parent => parent.type === 'Attribute' || parent.type?.endsWith('Directive') || ['code', 'pre', 'script', 'style'].includes(parent.name))) return;
    raw.push(path + ': ' + node.data.trim());
  });
  expect(raw).toEqual([]);
});

test('optional technical tools are collapsed without hiding core editing, required review or sending', () => {
  const panels = new Map<string, any[][]>();
  walk(parse(source('routes/documents/[id]/+page.svelte'), { modern: true }), (node, ancestors) => {
    if (node.type === 'Component' && ['CRMDocumentPanel', 'RiskPanel', 'EnvelopePanel', 'AgentTokensPanel', 'SenderPanel', 'BlockEditor', 'TimelinePanel', 'DocumentAttachmentsPanel', 'HtmlPDFReview', 'DocumentAmendmentsPanel'].includes(node.name)) {
      panels.set(node.name, [...(panels.get(node.name) ?? []), ancestors.filter(parent => parent.name === 'details')]);
    }
  });
  for (const name of ['CRMDocumentPanel', 'RiskPanel', 'EnvelopePanel']) expect(panels.get(name)?.every(ancestors => ancestors.length > 0)).toBe(true);
  expect(panels.has('AgentTokensPanel')).toBe(false);
  const settingsPanels: string[] = [];
  walk(parse(source('routes/settings/api-keys/+page.svelte'), { modern: true }), node => { if (node.type === 'Component') settingsPanels.push(node.name); });
  expect(settingsPanels.filter(name => name === 'DocumentAIAccessSettings')).toHaveLength(1);
  const scopedAccess: string[] = [];
  walk(parse(source('lib/components/DocumentAIAccessSettings.svelte'), { modern: true }), node => { if (node.type === 'Component') scopedAccess.push(node.name); });
  expect(scopedAccess.filter(name => name === 'AgentTokensPanel')).toHaveLength(1);
  for (const name of ['SenderPanel', 'BlockEditor', 'TimelinePanel', 'DocumentAttachmentsPanel', 'HtmlPDFReview', 'DocumentAmendmentsPanel']) expect(panels.get(name)?.every(ancestors => ancestors.length === 0)).toBe(true);
});

test('CRM review requests reveal the existing guarded feature and an existing envelope remains expanded', () => {
  const tree: any = parse(source('routes/documents/[id]/+page.svelte'), { modern: true }); let reveal = false, envelopeExpanded = false;
  walk(tree, (node, ancestors) => {
    if (node.type === 'Attribute' && node.name === 'onCRMReviewRequired') {
      let opens = false, invokes = false;
      walk(node, item => { if (item.type === 'AssignmentExpression' && item.left?.name === 'crmDetailsOpen' && item.right?.value === true) opens = true; if (item.type === 'CallExpression' && item.callee?.name === 'requestCRMReview') invokes = true; });
      reveal = opens && invokes;
    }
    if (node.type === 'Component' && node.name === 'EnvelopePanel') envelopeExpanded = ancestors.some(parent => parent.name === 'details' && parent.attributes.some((attribute: any) => attribute.name === 'open'));
  });
  expect(reveal).toBe(true); expect(envelopeExpanded).toBe(true);
});
