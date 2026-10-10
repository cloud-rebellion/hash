import type { TemplateResponse } from './api/client';

export interface HTMLValueDefinition {
  name: string;
  required: boolean;
  max_chars: number;
}
export interface HTMLSectionDefinition {
  name: string;
  default_text: string;
  max_chars: number;
}
export interface HTMLAsset {
  name: string;
  media_type: 'image/png' | 'image/jpeg' | 'font/woff' | 'font/woff2';
  data_base64: string;
  sha256: string;
}
export type HTMLPartySlot = 'provider' | 'customer';
export interface HTMLContractParty {
  slot: HTMLPartySlot;
  company_name: string;
  company_id: string;
  representative_name: string;
  representative_email: string;
  representative_authority: string;
}
export interface HTMLContractTerm { name: string; value?: string; section?: string }
export interface HTMLContractProfile {
  id: string;
  version: number;
  kind: 'proposal' | 'b2b_services';
  parties: HTMLContractParty[];
  terms: HTMLContractTerm[];
}
export interface HTMLMaster {
  schema_version: 1 | 2;
  html: string;
  css: string;
  values?: HTMLValueDefinition[];
  sections?: HTMLSectionDefinition[];
  assets?: HTMLAsset[];
  contract_profile?: HTMLContractProfile;
}
export interface HTMLFormField extends HTMLValueDefinition { defaultValue: string; label: string }

const namePattern = /^[a-z][a-z0-9_]{0,63}$/;
export const htmlPartyBindings = ['company_name', 'company_id', 'representative_name', 'representative_email', 'representative_authority'] as const;
export const htmlPartyLabels: Record<typeof htmlPartyBindings[number], string> = {
  company_name: 'Company name', company_id: 'Company or registration identifier', representative_name: 'Representative name',
  representative_email: 'Representative email', representative_authority: 'Declared representative authority',
};
export function requiredHTMLContractTerms(kind: HTMLContractProfile['kind']): string[] {
  const common = ['scope', 'price', 'currency', 'tax', 'payment_terms'];
  return kind === 'proposal' ? [...common, 'valid_until'] : [...common, 'effective_date', 'duration', 'termination'];
}
function onlyKeys(object: object, keys: string[]): boolean { return Object.keys(object).every((key) => keys.includes(key)); }

// These are explicit owner-reviewed engineering checks. They do not establish
// legal sufficiency, independent identity verification or representative authority.
export function htmlContractProfile(master: HTMLMaster): HTMLContractProfile | null {
  const profile = master.contract_profile;
  if (master.schema_version === 1 && profile === undefined) return null;
  if (master.schema_version !== 2 || !profile || typeof profile !== 'object' || Array.isArray(profile)
      || !onlyKeys(profile, ['id', 'version', 'kind', 'parties', 'terms']) || typeof profile.id !== 'string' || !namePattern.test(profile.id)
      || !Number.isSafeInteger(profile.version) || profile.version < 1 || profile.version > 1_000_000 || !['proposal', 'b2b_services'].includes(profile.kind)
      || !Array.isArray(profile.parties) || profile.parties.length !== 2 || !Array.isArray(profile.terms) || profile.terms.length > 16) {
    throw new Error('A version 2 design needs a valid reviewed contract profile with both parties. Version 1 designs cannot contain a contract profile.');
  }
  const declarations = new Map((master.values ?? []).map((field) => [field.name, field]));
  const sections = new Map((master.sections ?? []).map((section) => [section.name, section]));
  const slots = new Set<string>(), bindings = new Set<string>();
  for (const party of profile.parties) {
    if (!party || typeof party !== 'object' || Array.isArray(party) || !onlyKeys(party, ['slot', ...htmlPartyBindings])
        || !['provider', 'customer'].includes(party.slot) || slots.has(party.slot)) throw new Error('The profile needs exactly one provider and one customer.');
    slots.add(party.slot);
    for (const binding of htmlPartyBindings) {
      const name = party[binding], field = declarations.get(name);
      if (typeof name !== 'string' || !namePattern.test(name) || !field?.required || bindings.has(`value:${name}`)) {
        throw new Error(`Map ${party.slot} ${htmlPartyLabels[binding].toLowerCase()} to its own required printed value.`);
      }
      bindings.add(`value:${name}`);
    }
  }
  const terms = new Set<string>();
  for (const term of profile.terms) {
    if (!term || typeof term !== 'object' || Array.isArray(term) || !onlyKeys(term, ['name', 'value', 'section']) || typeof term.name !== 'string' || !namePattern.test(term.name)
        || terms.has(term.name) || (term.value !== undefined && typeof term.value !== 'string') || (term.section !== undefined && typeof term.section !== 'string')
        || (typeof term.value === 'string') === (typeof term.section === 'string')) throw new Error('Each contract term needs a unique lowercase name and one printed value or wording section.');
    terms.add(term.name);
    const key = typeof term.value === 'string' ? `value:${term.value}` : `section:${term.section}`;
    if (bindings.has(key)) throw new Error(`Map ${term.name.replaceAll('_', ' ')} to its own printed value or wording section.`);
    if (typeof term.value === 'string' && (!namePattern.test(term.value) || !declarations.get(term.value)?.required)) throw new Error(`Map ${term.name.replaceAll('_', ' ')} to a required printed value.`);
    if (typeof term.section === 'string' && (!namePattern.test(term.section) || !sections.has(term.section))) throw new Error(`Map ${term.name.replaceAll('_', ' ')} to a declared wording section.`);
    bindings.add(key);
  }
  const missing = requiredHTMLContractTerms(profile.kind).filter((name) => !terms.has(name));
  if (missing.length) throw new Error(`This ${profile.kind === 'proposal' ? 'proposal' : 'services'} profile needs: ${missing.map((name) => name.replaceAll('_', ' ')).join(', ')}.`);
  return { id: profile.id, version: profile.version, kind: profile.kind,
    parties: profile.parties.map((party) => ({ slot: party.slot, company_name: party.company_name, company_id: party.company_id,
      representative_name: party.representative_name, representative_email: party.representative_email, representative_authority: party.representative_authority })),
    terms: profile.terms.map((term) => typeof term.value === 'string' ? { name: term.name, value: term.value } : { name: term.name, section: term.section! }) };
}

export interface HTMLFormSection extends HTMLSectionDefinition { label: string }
export interface HTMLFormGroup { id: string; label: string; fields: HTMLFormField[]; sections: HTMLFormSection[] }
export function htmlTemplateGroups(template: TemplateResponse): HTMLFormGroup[] {
  const fields = htmlTemplateFields(template), master = template.html_master_json!, profile = htmlContractProfile(master);
  if (!profile) return [{ id: 'values', label: 'Document information', fields, sections: [] }];
  const used = new Set<string>();
  const groups: HTMLFormGroup[] = ['provider', 'customer'].map((slot) => {
    const party = profile.parties.find((candidate) => candidate.slot === slot)!;
    return { id: slot, label: slot === 'provider' ? 'Our company' : 'Customer', sections: [], fields: htmlPartyBindings.map((binding) => {
      const field = fields.find((candidate) => candidate.name === party[binding])!; used.add(field.name);
      return { ...field, label: htmlPartyLabels[binding] };
    }) };
  });
  const termFields: HTMLFormField[] = [], termSections: HTMLFormSection[] = [];
  for (const term of profile.terms) {
    if (term.value) {
      const field = fields.find((candidate) => candidate.name === term.value)!;
      if (!used.has(field.name)) termFields.push({ ...field, label: term.name.replaceAll('_', ' ') });
      used.add(field.name);
    } else if (term.section) {
      const section = master.sections!.find((candidate) => candidate.name === term.section)!;
      termSections.push({ ...section, label: term.name.replaceAll('_', ' ') });
    }
  }
  groups.push({ id: 'terms', label: 'Commercial terms', fields: termFields, sections: termSections });
  const remaining = fields.filter((field) => !used.has(field.name));
  if (remaining.length) groups.push({ id: 'other', label: 'Other document information', fields: remaining, sections: [] });
  return groups;
}
export function htmlProfileSectionValues(master: HTMLMaster, sections: Record<string, string>): Record<string, string> | undefined {
  const profile = htmlContractProfile(master), result: Record<string, string> = {};
  if (!profile) return undefined;
  for (const term of profile.terms) {
    if (!term.section) continue;
    const declaration = master.sections!.find((section) => section.name === term.section)!, text = sections[term.section];
    if (typeof text !== 'string' || !text.trim() || Array.from(text).length > declaration.max_chars
        || /[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(text)) {
      throw new Error(`Enter ${term.name.replaceAll('_', ' ')} wording within ${declaration.max_chars} characters.`);
    }
    result[term.section] = text;
  }
  return Object.keys(result).length ? result : undefined;
}
export function htmlProfileIssues(profile: HTMLContractProfile, values: Record<string, string>, sections: Record<string, string> = {}): string[] {
  const issues: string[] = [], emails = new Set<string>(), encoder = new TextEncoder();
  for (const party of profile.parties) {
    for (const binding of htmlPartyBindings) if (!values[party[binding]]?.trim()) issues.push(`Enter ${party.slot} ${htmlPartyLabels[binding].toLowerCase()}.`);
    const printedEmail = values[party.representative_email] ?? '', email = printedEmail.trim();
    if (email && (printedEmail !== email || !/^[^\s<>@]+@[^\s<>@]+$/.test(email) || /\p{Cc}/u.test(email) || encoder.encode(email).length > 254)) issues.push(`Enter a plain valid ${party.slot} representative email without surrounding spaces.`);
    else if (email && emails.has(email.toLowerCase())) issues.push('Provider and customer need different representative email addresses.');
    if (email) emails.add(email.toLowerCase());
    const name = values[party.representative_name] ?? '';
    if (name && (name !== name.trim() || Array.from(name).length > 200 || encoder.encode(name).length > 800 || /\p{Cc}/u.test(name))) issues.push(`Keep ${party.slot} representative name within 200 characters without surrounding spaces or control characters.`);
  }
  if (profile.parties.length === 2) {
    const [provider, customer] = profile.parties, left = values[provider.company_id]?.trim(), right = values[customer.company_id]?.trim();
    if (left && right && left.toLowerCase() === right.toLowerCase()) issues.push('Provider and customer company identifiers conflict.');
  }
  for (const term of profile.terms) if (term.value && !values[term.value]?.trim()) issues.push(`Enter ${term.name.replaceAll('_', ' ')}.`);
  for (const term of profile.terms) if (term.section && !sections[term.section]?.trim()) issues.push(`Enter ${term.name.replaceAll('_', ' ')} wording.`);
  return issues;
}

export function htmlTemplateFields(template: TemplateResponse): HTMLFormField[] {
  const master = template.html_master_json;
  if (template.source_kind !== 'html' || !master || ![1, 2].includes(master.schema_version) || !Number.isInteger(template.version)
      || template.version < 1 || !/^[a-f0-9]{64}$/.test(template.content_sha256 ?? '')) {
    throw new Error('This design is unavailable. Refresh the library before using it.');
  }
  const definitions = master.values ?? [];
  const defaults = template.variables_json;
  if (!Array.isArray(definitions) || definitions.length > 64 || defaults === null || typeof defaults !== 'object' || Array.isArray(defaults)) {
    throw new Error('The design has invalid value definitions. Ask its owner to review it.');
  }
  const seen = new Set<string>();
  const fields = definitions.map((field) => {
    if (!field || typeof field.name !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/.test(field.name) || seen.has(field.name)
        || typeof field.required !== 'boolean' || !Number.isInteger(field.max_chars) || field.max_chars < 1 || field.max_chars > 8192) {
      throw new Error('The design has invalid value definitions. Ask its owner to review it.');
    }
    seen.add(field.name);
    const value = Object.hasOwn(defaults, field.name) ? (defaults as Record<string, unknown>)[field.name] : '';
    if (typeof value !== 'string' || Array.from(value).length > field.max_chars) {
      throw new Error('The design has invalid approved defaults. Ask its owner to review it.');
    }
    return { ...field, defaultValue: value, label: field.name.replaceAll('_', ' ') };
  });
  if (Object.keys(defaults).some((name) => !seen.has(name))) throw new Error('The design contains undeclared defaults. Ask its owner to review it.');
  htmlContractProfile(master);
  return fields;
}

export function isApprovedHTMLTemplate(template: TemplateResponse): boolean {
  const approval = template.html_approval;
  return template.source_kind === 'html' && !!approval?.approved_by && !!approval.approved_at
    && Number.isFinite(Date.parse(approval.approved_at))
    && approval.version === template.version && approval.content_sha256 === template.content_sha256;
}

export function htmlValuesForSubmission(fields: HTMLFormField[], values: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const field of fields) {
    const value = values[field.name];
    if (typeof value !== 'string' || (field.required && !value.trim()) || Array.from(value).length > field.max_chars) {
      throw new Error(`Enter ${field.label}${field.required ? ' (required)' : ''}, within ${field.max_chars} characters.`);
    }
    result[field.name] = value;
  }
  return result;
}
