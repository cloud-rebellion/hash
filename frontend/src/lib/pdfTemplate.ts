export interface PDFTemplateParty {
  role: string;
  label: string;
}

// A versioned layout requires fresh parties. An empty legacy PDF template can
// still start a blank designer, but an unknown layout cannot be silently lost.
export function pdfTemplateParties(layout: unknown): PDFTemplateParty[] {
  if (Array.isArray(layout)) return [];
  if (layout === null || layout === undefined) return [];
  if (typeof layout !== 'object') throw new Error('This PDF signing layout is not supported.');
  const value = layout as Record<string, unknown>;
  if (value.version !== 1 || !Array.isArray(value.parties) || value.parties.length === 0 || !Array.isArray(value.fields) || value.fields.length === 0) {
    throw new Error('This PDF signing layout is not supported.');
  }
  const seen = new Set<string>();
  const parties = value.parties.map((raw): PDFTemplateParty => {
    if (!raw || typeof raw !== 'object') throw new Error('This PDF signing layout has an invalid party.');
    const party = raw as Record<string, unknown>;
    if (typeof party.role !== 'string' || !/^[a-z][a-z0-9_-]{0,63}$/.test(party.role) || seen.has(party.role)
      || typeof party.label !== 'string' || !party.label.trim() || ['viewer', 'cc'].includes(party.role)) {
      throw new Error('This PDF signing layout has an invalid party.');
    }
    seen.add(party.role);
    return { role: party.role, label: party.label };
  });
  const assigned = new Set<string>();
  for (const raw of value.fields) {
    if (!raw || typeof raw !== 'object') throw new Error('This PDF signing layout has an invalid field.');
    const field = raw as Record<string, unknown>;
    if (field.type !== 'signature' || field.required !== true || typeof field.party_role !== 'string' || !seen.has(field.party_role)) {
      throw new Error('This PDF signing layout has an invalid field.');
    }
    assigned.add(field.party_role);
  }
  if (assigned.size !== parties.length) throw new Error('Every party needs a required signature field.');
  return parties;
}
