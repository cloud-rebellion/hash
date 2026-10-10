import { expect, test } from 'bun:test';
import { pdfTemplateParties } from './pdfTemplate';

function layout() {
  return { version: 1, parties: [{ role: 'provider', label: 'Provider' }, { role: 'client', label: 'Client' }],
    fields: [{ party_role: 'provider', type: 'signature', required: true }, { party_role: 'client', type: 'signature', required: true }] };
}

test('versioned PDF layout requests fresh identities for every named party', () => {
  expect(pdfTemplateParties(layout())).toEqual([{ role: 'provider', label: 'Provider' }, { role: 'client', label: 'Client' }]);
  expect(pdfTemplateParties([])).toEqual([]);
});

test('unknown or inconsistent layouts cannot silently become a blank contract', () => {
  const unknown = { ...layout(), version: 2 };
  const duplicate = { ...layout(), parties: [{ role: 'client', label: 'Client' }, { role: 'client', label: 'Other' }] };
  const orphan = { ...layout(), fields: [{ party_role: 'stranger', type: 'signature', required: true }] };
  const missing = { ...layout(), fields: [{ party_role: 'provider', type: 'signature', required: true }] };
  const editable = { ...layout(), fields: [{ party_role: 'provider', type: 'text', required: true }] };
  const optional = { ...layout(), fields: [{ party_role: 'provider', type: 'signature', required: false }] };
  for (const value of [unknown, duplicate, orphan, missing, editable, optional, 'malformed']) {
    expect(() => pdfTemplateParties(value)).toThrow();
  }
});
