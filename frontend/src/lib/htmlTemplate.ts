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
export type HTMLAmendmentMode = 'signature' | 'acknowledgement' | 'agreed_notice';
export interface HTMLAmendmentPolicy { term: string; clause_reference: string; allowed_modes: HTMLAmendmentMode[]; allowed_channels: 'email'[]; effective_condition: string }
export interface HTMLContractProfile {
  id: string;
  version: number;
  kind: 'proposal' | 'b2b_services';
  parties: HTMLContractParty[];
  terms: HTMLContractTerm[];
  amendment_policy?: HTMLAmendmentPolicy;
}
export const htmlSigningPagePolicy = 'hash-branded-signing-page-a4-v1' as const;
export const htmlSigningPageFontSHA256 = '3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62' as const;
export interface HTMLSigningPageBranding {
  primary_hex: string; accent_hex: string; surface_hex: string; text_hex: string; muted_hex: string;
  logo_url: string; logo_alt: string; font_heading: string; font_body: string; signature_color: string;
}
export interface HTMLSigningPage {
  version: 1;
  policy: typeof htmlSigningPagePolicy;
  font_sha256: typeof htmlSigningPageFontSHA256;
  branding: HTMLSigningPageBranding;
  logo_asset: string;
  logo_sha256: string;
  logo_alt: string;
}
export const htmlSigningPageColours = ['primary_hex', 'accent_hex', 'surface_hex', 'text_hex', 'muted_hex', 'signature_color'] as const;
export const htmlSigningPagePartyLimits = { company_name: 80, company_id: 40, representative_name: 80, representative_email: 128, representative_authority: 80 } as const;
export const htmlSigningPageColourLabels: Record<typeof htmlSigningPageColours[number], string> = {
  primary_hex: 'Primary colour', accent_hex: 'Accent colour', surface_hex: 'Page background',
  text_hex: 'Text colour', muted_hex: 'Secondary text colour', signature_color: 'Signature colour',
};
export interface HTMLMaster {
  schema_version: 1 | 2 | 3;
  html: string;
  css: string;
  values?: HTMLValueDefinition[];
  sections?: HTMLSectionDefinition[];
  assets?: HTMLAsset[];
  contract_profile?: HTMLContractProfile;
  signing_page?: HTMLSigningPage;
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

// Required profile text needs a base character. Preserve exact international
// content rather than applying the separate schema-3 font policy here.
function hasContractText(value: unknown): value is string {
  return typeof value === 'string' && /[\p{L}\p{N}\p{P}\p{S}]/u.test(value);
}

export function htmlSigningPagePlainText(text: unknown, limit: number): text is string {
  if (typeof text !== 'string' || !text || text !== text.trim()) return false;
  const characters = Array.from(text);
  if (characters.length > limit || /^\p{M}/u.test(text) || !/^[\p{L}\p{M}\p{N}\p{P}\p{S}\p{Zs}]+$/u.test(text)
      || characters.some((character) => !htmlSigningPageFontCovers(character.codePointAt(0)!))) return false;
  const units = characters.reduce((sum, character) => sum + (/\p{M}/u.test(character) ? 0 : character.codePointAt(0)! <= 0x024f ? 1 : 2), 0);
  return units <= limit;
}
// Exact Unicode cmap ranges of the SHA-pinned bundled Inter Latin subset.
// Invisible mapped characters are still refused by the plain-text checks.
export function htmlSigningPageFontCovers(point: number): boolean {
  return [[0, 0], [0x20, 0x7e], [0xa0, 0xac], [0xae, 0xff], [0x131, 0x131], [0x152, 0x153],
    [0x2bb, 0x2bc], [0x2c6, 0x2c6], [0x2da, 0x2da], [0x2dc, 0x2dc], [0x300, 0x301], [0x303, 0x304],
    [0x308, 0x309], [0x323, 0x323], [0x2002, 0x2002], [0x2009, 0x2009], [0x200b, 0x200b],
    [0x2013, 0x2014], [0x2018, 0x201a], [0x201c, 0x201e], [0x2022, 0x2022], [0x2026, 0x2026],
    [0x2032, 0x2033], [0x2039, 0x203a], [0x2044, 0x2044], [0x20ac, 0x20ac], [0x2122, 0x2122],
    [0x2191, 0x2191], [0x2193, 0x2193], [0x2212, 0x2212], [0xfeff, 0xfeff]]
    .some(([first, last]) => point >= first && point <= last);
}
export function htmlSigningPageIssues(profile: HTMLContractProfile, values: Record<string, string>): string[] {
  return profile.parties.flatMap((party) => htmlPartyBindings.flatMap((binding) => {
    const limit = htmlSigningPagePartyLimits[binding];
    return htmlSigningPagePlainText(values[party[binding]], limit) ? []
      : [`Keep ${party.slot} ${htmlPartyLabels[binding].toLowerCase()} to one printable line in the bundled Latin font, within ${limit} characters and display units, without surrounding spaces. Wide supported characters use two units.`];
  }));
}
export function htmlSigningPageContrast(foreground: string, background: string): number {
  const luminance = (hex: string) => {
    const channels = [1, 3, 5].map((start) => parseInt(hex.slice(start, start + 2), 16) / 255)
      .map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
    return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
  };
  const a = luminance(foreground), b = luminance(background);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

export function validateHTMLSigningPage(page: HTMLSigningPage): HTMLSigningPage {
  const branding = page?.branding;
  if (!page || typeof page !== 'object' || Array.isArray(page)
      || !onlyKeys(page, ['version', 'policy', 'font_sha256', 'branding', 'logo_asset', 'logo_sha256', 'logo_alt'])
      || page.version !== 1 || page.policy !== htmlSigningPagePolicy || page.font_sha256 !== htmlSigningPageFontSHA256 || !branding || typeof branding !== 'object' || Array.isArray(branding)
      || !onlyKeys(branding, [...htmlSigningPageColours, 'logo_url', 'logo_alt', 'font_heading', 'font_body'])
      || htmlSigningPageColours.some((key) => typeof branding[key] !== 'string' || !/^#[a-f0-9]{6}$/i.test(branding[key]))
      || branding.logo_url !== '' || branding.logo_alt !== '' || branding.font_heading !== 'Inter' || branding.font_body !== 'Inter'
      || typeof page.logo_asset !== 'string' || typeof page.logo_sha256 !== 'string' || typeof page.logo_alt !== 'string'
      || (page.logo_asset === '' ? page.logo_sha256 !== '' || page.logo_alt !== ''
        : !namePattern.test(page.logo_asset) || !/^[a-f0-9]{64}$/.test(page.logo_sha256) || !htmlSigningPagePlainText(page.logo_alt, 80))) {
    throw new Error('The signing page needs its approved policy, complete saved colours, Inter fonts and an explicit no-logo or local-image choice.');
  }
  if (htmlSigningPageContrast(branding.text_hex, branding.surface_hex) < 4.5 || htmlSigningPageContrast(branding.muted_hex, branding.surface_hex) < 4.5
      || htmlSigningPageContrast(branding.primary_hex, branding.surface_hex) < 3 || htmlSigningPageContrast(branding.signature_color, branding.surface_hex) < 3) {
    throw new Error('Choose readable signing-page colours: text and secondary text need at least 4.5:1 contrast with the background; headings and signatures need 3:1.');
  }
  return { version: 1, policy: htmlSigningPagePolicy, font_sha256: htmlSigningPageFontSHA256, branding: {
    primary_hex: branding.primary_hex, accent_hex: branding.accent_hex, surface_hex: branding.surface_hex,
    text_hex: branding.text_hex, muted_hex: branding.muted_hex, logo_url: '', logo_alt: '',
    font_heading: 'Inter', font_body: 'Inter', signature_color: branding.signature_color,
  }, logo_asset: page.logo_asset, logo_sha256: page.logo_sha256, logo_alt: page.logo_alt };
}
export function htmlSigningPage(master: HTMLMaster): HTMLSigningPage | null {
  if (master.schema_version !== 3) {
    if (master.signing_page !== undefined) throw new Error('An appended signing page requires an explicitly approved version 3 design.');
    return null;
  }
  const page = validateHTMLSigningPage(master.signing_page!);
  if (page.logo_asset) {
    const asset = master.assets?.find((candidate) => candidate.name === page.logo_asset);
    if (!asset || !['image/png', 'image/jpeg'].includes(asset.media_type) || asset.sha256 !== page.logo_sha256) {
      throw new Error('The signing-page logo must match an image asset saved in this exact design. Choose that local asset again.');
    }
  }
  return page;
}

// These are explicit owner-reviewed engineering checks. They do not establish
// legal sufficiency, independent identity verification or representative authority.
export function htmlContractProfile(master: HTMLMaster): HTMLContractProfile | null {
  htmlSigningPage(master);
  const profile = master.contract_profile;
  if (master.schema_version === 1 && profile === undefined) return null;
  if (![2, 3].includes(master.schema_version) || !profile || typeof profile !== 'object' || Array.isArray(profile)
      || !onlyKeys(profile, ['id', 'version', 'kind', 'parties', 'terms', 'amendment_policy']) || typeof profile.id !== 'string' || !namePattern.test(profile.id)
      || !Number.isSafeInteger(profile.version) || profile.version < 1 || profile.version > 1_000_000 || !['proposal', 'b2b_services'].includes(profile.kind)
      || !Array.isArray(profile.parties) || profile.parties.length !== 2 || !Array.isArray(profile.terms) || profile.terms.length > 16) {
    throw new Error('A version 2 or 3 design needs a valid reviewed contract profile with both parties. Version 1 designs cannot contain a contract profile.');
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
  const amendmentPolicy = checkedHTMLAmendmentPolicy(profile);
  return { id: profile.id, version: profile.version, kind: profile.kind,
    ...(amendmentPolicy ? { amendment_policy: amendmentPolicy } : {}),
    parties: profile.parties.map((party) => ({ slot: party.slot, company_name: party.company_name, company_id: party.company_id,
      representative_name: party.representative_name, representative_email: party.representative_email, representative_authority: party.representative_authority })),
    terms: profile.terms.map((term) => typeof term.value === 'string' ? { name: term.name, value: term.value } : { name: term.name, section: term.section! }) };
}

// Match the native optional policy declaration. Permission is explicitly owner
// selected; no legal permission is inferred from a term name or its wording.
export const htmlAmendmentModes = ['signature', 'acknowledgement', 'agreed_notice'] as const;
export const htmlAmendmentModeLabels: Record<HTMLAmendmentMode, string> = { signature: 'New signature', acknowledgement: 'Explicit acknowledgement', agreed_notice: 'Agreed notice' };
export function htmlAmendmentText(value: unknown, maxBytes: number): value is string {
 return typeof value === 'string' && value.trim() === value && hasContractText(value) && new TextEncoder().encode(value).length <= maxBytes && !/[\p{Cc}\p{Cf}\p{Cs}]/u.test(value.replace(/[\t\n]/g, ''));
}
export function checkedHTMLAmendmentPolicy(profile: HTMLContractProfile): HTMLAmendmentPolicy | null {
 const policy = profile.amendment_policy;
 if (policy === undefined) return null;
 if (!policy || typeof policy !== 'object' || Array.isArray(policy) || !onlyKeys(policy, ['term', 'clause_reference', 'allowed_modes', 'allowed_channels', 'effective_condition']) || Object.keys(policy).length !== 5 || typeof policy.term !== 'string' || !namePattern.test(policy.term) || profile.terms.filter(term => term.name === policy.term).length !== 1 || !htmlAmendmentText(policy.clause_reference, 512) || !htmlAmendmentText(policy.effective_condition, 2048) || !Array.isArray(policy.allowed_modes) || !policy.allowed_modes.length || policy.allowed_modes.length > 3 || policy.allowed_modes.some(mode => !htmlAmendmentModes.includes(mode)) || new Set(policy.allowed_modes).size !== policy.allowed_modes.length || !Array.isArray(policy.allowed_channels) || (policy.allowed_modes.includes('agreed_notice') ? policy.allowed_channels.length !== 1 || policy.allowed_channels[0] !== 'email' : policy.allowed_channels.length !== 0)) throw new Error('Choose a printed agreement term, permitted processes, required email channel and exact wording references for later changes.');
 return { term: policy.term, clause_reference: policy.clause_reference, allowed_modes: [...policy.allowed_modes].sort(), allowed_channels: [...policy.allowed_channels], effective_condition: policy.effective_condition };
}
export function htmlAmendmentClause(profile: HTMLContractProfile, values: Record<string, string>, sections: Record<string, string>): string | null {
 const policy = profile.amendment_policy; if (!policy) return null; const matches = profile.terms.filter(term => term.name === policy.term); if (matches.length !== 1) return null; const term = matches[0]; return term.value !== undefined ? values[term.value] ?? null : term.section !== undefined ? sections[term.section] ?? null : null;
}
export function htmlAmendmentPolicyIssues(profile: HTMLContractProfile, values: Record<string, string>, sections: Record<string, string>): string[] {
 if (profile.amendment_policy === undefined) return [];
 let policy: HTMLAmendmentPolicy | null; try { policy = checkedHTMLAmendmentPolicy(profile); } catch { return ['Review the later-change policy in this design.']; }
 const clause = htmlAmendmentClause(profile, values, sections);
 if (!policy || !htmlAmendmentText(clause, 8192)) return ['Enter the actual printed later-change clause within 8192 bytes, without hidden formatting controls.'];
 if (!clause.includes(policy.clause_reference) || !clause.includes(policy.effective_condition)) return ['The later-change reference and timing conditions must be exact quotations from the selected printed clause.'];
 return [];
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
export function htmlProfileSectionValues(master: HTMLMaster, sections: Record<string, string>, deferRequired = false): Record<string, string> | undefined {
  const profile = htmlContractProfile(master), result: Record<string, string> = {};
  if (!profile) return undefined;
  for (const term of profile.terms) {
    if (!term.section) continue;
    const declaration = master.sections!.find((section) => section.name === term.section)!, text = sections[term.section];
    if (typeof text !== 'string' || (!deferRequired && !hasContractText(text)) || Array.from(text).length > declaration.max_chars
        || /[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(text)) {
      throw new Error(`Enter ${term.name.replaceAll('_', ' ')} wording within ${declaration.max_chars} characters.`);
    }
    result[term.section] = text;
  }
  return Object.keys(result).length ? result : undefined;
}
export function htmlPreviewSections(master: HTMLMaster, sections: Record<string, string>): Record<string, string> {
  const definitions = master.sections ?? [], result: Record<string, string> = {};
  if (Object.keys(sections).some((name) => !definitions.some((section) => section.name === name))) throw new Error('Preview only declared wording sections.');
  for (const definition of definitions) {
    const text = sections[definition.name];
    if (typeof text !== 'string' || Array.from(text).length > definition.max_chars
        || /[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(text)) throw new Error(`Keep preview ${definition.name.replaceAll('_', ' ')} within ${definition.max_chars} characters.`);
    result[definition.name] = text;
  }
  htmlProfileSectionValues(master, result);
  return result;
}
export function htmlProfileIssues(profile: HTMLContractProfile, values: Record<string, string>, sections: Record<string, string> = {}): string[] {
  const issues: string[] = [], emails = new Set<string>(), encoder = new TextEncoder();
  for (const party of profile.parties) {
    for (const binding of htmlPartyBindings) if (!hasContractText(values[party[binding]])) issues.push(`Enter ${party.slot} ${htmlPartyLabels[binding].toLowerCase()}.`);
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
  for (const term of profile.terms) if (term.value && !hasContractText(values[term.value])) issues.push(`Enter ${term.name.replaceAll('_', ' ')}.`);
  for (const term of profile.terms) if (term.section && !hasContractText(sections[term.section])) issues.push(`Enter ${term.name.replaceAll('_', ' ')} wording.`);
  issues.push(...htmlAmendmentPolicyIssues(profile, values, sections));
  return issues;
}

export function htmlTemplateFields(template: TemplateResponse): HTMLFormField[] {
  const master = template.html_master_json;
  if (template.source_kind !== 'html' || !master || ![1, 2, 3].includes(master.schema_version) || !Number.isInteger(template.version)
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

export function htmlValuesForSubmission(fields: HTMLFormField[], values: Record<string, string>, deferRequired = false): Record<string, string> {
  const result: Record<string, string> = {};
  for (const field of fields) {
    const value = values[field.name];
    if (typeof value !== 'string' || (!deferRequired && field.required && !value.trim()) || Array.from(value).length > field.max_chars) {
      throw new Error(`Enter ${field.label}${field.required ? ' (required)' : ''}, within ${field.max_chars} characters.`);
    }
    result[field.name] = value;
  }
  return result;
}
