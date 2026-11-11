import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parse } from 'svelte/compiler';
import { swedishDocumentStaffMessages } from './staffDocumentMessages';
import { swedishStaffMessages } from './staffMessages';
import { translateStaffText } from './staffPreferences';

const components = ['SenderPanel', 'PdfFieldDesigner', 'PreSignSend', 'PreSignSupersession', 'DocumentAttachmentsPanel', 'DocumentAmendmentsPanel', 'TimelinePanel', 'AgentTokensPanel', 'EnvelopePanel', 'RiskPanel', 'HtmlPDFReview', 'SavePDFTemplate', 'HtmlDocumentRevision', 'HtmlDocumentHistory', 'HtmlTemplatePopulate', 'CRMDocumentPanel', 'CRMTemplatePopulationPanel'];
const protectedCopy = new Set(['Hash', 'I confirm this exact document, provider identity, authority and customer. Apply the provider signature and send only the customer’s invitation.']);

function placeholders(text: string) { return [...text.matchAll(/\{([a-zA-Z][\w]*)\}/g)].map(match => match[1]).sort(); }

test('document UI translations retain placeholders and distinguish signature, acknowledgement and unavailable language support', () => {
  for (const [key, value] of Object.entries(swedishDocumentStaffMessages)) {
    expect(value.trim().length).toBeGreaterThan(0);
    expect(placeholders(value)).toEqual(placeholders(key));
  }
  expect(translateStaffText('sv', 'Send for signature')).toBe('Skicka för signering');
  expect(translateStaffText('sv', 'Send for acknowledgement')).toBe('Skicka för bekräftelse');
  expect(translateStaffText('en', 'Send for signature')).toBe('Send for signature');
  expect(translateStaffText('sv', 'Lifecycle email language. The legal/signing page is currently English pending reviewed localization.')).toContain('på engelska');
  for (const technical of ['read', 'write:authoring', 'write:workflow']) expect(translateStaffText('sv', technical)).toBe(technical);
});

function outputStrings(node: any): string[] {
  if (!node) return [];
  if (node.type === 'Literal' && typeof node.value === 'string') return [node.value];
  if (node.type === 'ConditionalExpression') return [...outputStrings(node.consequent), ...outputStrings(node.alternate)];
  return [];
}

test('all staff document text and explicit UI labels are localized while protected copy and document data stay outside translation', () => {
  for (const name of components) {
    const source = readFileSync(new URL(`./components/${name}.svelte`, import.meta.url), 'utf8');
    const tree: any = parse(source, { modern: true });
    const seen = new WeakSet<object>();
    function walk(node: any, inCode = false) {
      if (!node || typeof node !== 'object' || seen.has(node) || node.type?.endsWith('Directive')) return;
      seen.add(node);
      const code = inCode || ['code', 'pre', 'script', 'style'].includes(node.name);
      if (!code && node.type === 'Text' && /[A-Za-z]/.test(node.data ?? '')) {
        const text = node.data.trim().replace(/\s+/g, ' ');
        expect(protectedCopy.has(text)).toBe(true);
      }
      if (!code && node.type === 'CallExpression' && node.callee?.name === '$ui') {
        for (const key of outputStrings(node.arguments[0])) {
          if (/[A-Za-z]/.test(key)) expect(Object.hasOwn(swedishStaffMessages, key)).toBe(true);
        }
      }
      if (node.type === 'Attribute') {
        if (!['placeholder', 'title', 'alt', 'aria-label'].includes(node.name)) return;
        for (const value of Array.isArray(node.value) ? node.value : [node.value]) {
          if (value?.type === 'Text' && /[A-Za-z]/.test(value.data ?? '')) throw new Error(`Untranslated UI attribute in ${name}`);
        }
      }
      for (const value of Object.values(node)) {
        if (Array.isArray(value)) value.forEach(child => walk(child, code));
        else if (value && typeof value === 'object') walk(value, code);
      }
    }
    walk(tree.fragment);
    expect(source).not.toContain('$ui(executionState.preview.disclosure)');
  }
});

test('attachment errors shown in the panel have Swedish translations', () => {
  expect(translateStaffText('sv', 'The saved attachments could not be verified. Refresh and inspect the saved state before continuing.')).toBe('De sparade bilagorna kunde inte verifieras. Uppdatera och granska det sparade läget innan du fortsätter.');
  expect(translateStaffText('sv', 'Select a saved attachment.')).toBe('Välj en sparad bilaga.');
});
