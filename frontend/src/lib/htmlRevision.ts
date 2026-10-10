import type { DocumentField, DocumentResponse, HTMLDocumentRevisionInput, HTMLDocumentRevisionResult, HTMLDocumentSource, HTMLHistoryEntry, HTMLSigningArtifact, Recipient } from './api/client';
import { htmlContractProfile, htmlProfileIssues, htmlPartyBindings, htmlPartyLabels, htmlSigningPageIssues, htmlSigningPagePolicy, validateHTMLSigningPage } from './htmlTemplate';

const namePattern = /^[a-z][a-z0-9_]{0,63}$/;
export const htmlSHA256 = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const htmlUUID = (value: unknown): value is string => typeof value === 'string' && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(value) && value !== '00000000-0000-0000-0000-000000000000';
const textWithin = (text: unknown, max: number): text is string => typeof text === 'string' && Array.from(text).length <= max
  && !/[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(text);
const exactKeys = (value: unknown, keys: string[]): value is Record<string, unknown> => !!value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && Object.keys(value).every((key) => keys.includes(key));

export function validateHTMLSigningArtifact(artifact: HTMLSigningArtifact, pdfSHA: string, pageCount: number): HTMLSigningArtifact {
  const composition = artifact?.composition, page = composition?.signing_page;
  if (!exactKeys(artifact, ['version', 'policy', 'plan_sha256', 'composition', 'fields']) || artifact.version !== 1 || artifact.policy !== htmlSigningPagePolicy
      || !htmlSHA256(artifact.plan_sha256) || !exactKeys(composition, ['schema_version', 'policy', 'body_sha256', 'signing_page_sha256', 'merged_sha256', 'merged_bytes', 'output_sha256', 'body_pages', 'final_pages', 'body_geometry_sha256', 'geometry_sha256', 'signing_page'])
      || composition.schema_version !== 1 || composition.policy !== 'hash-pdf-signing-page-a4-v1'
      || !['body_sha256', 'signing_page_sha256', 'merged_sha256', 'output_sha256', 'body_geometry_sha256', 'geometry_sha256'].every((key) => htmlSHA256(composition[key as keyof typeof composition]))
      || composition.output_sha256 !== pdfSHA || !Number.isSafeInteger(composition.merged_bytes) || composition.merged_bytes < 1 || composition.merged_bytes > 50 * 1024 * 1024
      || !Number.isSafeInteger(composition.body_pages) || composition.body_pages < 1 || composition.body_pages > 499
      || composition.final_pages !== composition.body_pages + 1 || composition.final_pages !== pageCount
      || !exactKeys(page, ['boxes_milli_points', 'rotation', 'user_unit_milli']) || page.rotation !== 0 || page.user_unit_milli !== 1000
      || !Array.isArray(page.boxes_milli_points) || page.boxes_milli_points.length !== 5
      || page.boxes_milli_points.some((box) => !Array.isArray(box) || box.length !== 4 || box.some((coordinate, index) => coordinate !== [0, 0, 594960, 841920][index]))
      || !Array.isArray(artifact.fields) || artifact.fields.length !== 2) {
    throw new Error('The saved signing page does not match this PDF. Refresh the document before reviewing or sending.');
  }
  for (const [index, slot] of (['customer', 'provider'] as const).entries()) {
    const field = artifact.fields[index];
    if (!exactKeys(field, ['slot', 'page', 'x', 'y', 'w', 'h']) || field.slot !== slot || field.page !== pageCount
        || field.x !== 100000 || field.y !== (slot === 'customer' ? 420000 : 790000) || field.w !== 800000 || field.h !== 70000) {
      throw new Error('The saved signing locations do not match the approved page. Refresh this document.');
    }
  }
  return artifact;
}

export function validateHTMLSource(source: HTMLDocumentSource, documentID: string, orgID: string): HTMLDocumentSource {
  if (!source || !htmlUUID(documentID) || !htmlUUID(orgID) || source.document_id !== documentID || source.org_id !== orgID
      || !htmlSHA256(source.html_source_commitment) || !htmlSHA256(source.pdf_sha256) || !htmlUUID(source.template_id)
      || !htmlSHA256(source.template_content_sha256) || !Number.isInteger(source.template_version) || source.template_version < 1
      || !Number.isInteger(source.materialization_revision) || source.materialization_revision < 1
      || typeof source.updated_at !== 'string' || !Number.isFinite(Date.parse(source.updated_at)) || !Number.isInteger(source.page_count) || source.page_count < 1 || source.page_count > 500
      || typeof source.can_edit !== 'boolean' || !Array.isArray(source.values) || source.values.length > 64
      || !Array.isArray(source.sections) || source.sections.length > 64 || !Array.isArray(source.changed_sections) || source.changed_sections.length > 64) {
    throw new Error('The retained HTML document source could not be verified. Refresh this document.');
  }
  const names = new Set<string>();
  for (const field of source.values) {
    if (!field || typeof field.name !== 'string' || !namePattern.test(field.name) || names.has(field.name) || typeof field.required !== 'boolean'
        || !Number.isInteger(field.max_chars) || field.max_chars < 1 || field.max_chars > 8192 || !textWithin(field.text, field.max_chars)) throw new Error('The retained document has invalid declared values.');
    names.add(field.name);
  }
  names.clear();
  for (const section of source.sections) {
    if (!section || typeof section.name !== 'string' || !namePattern.test(section.name) || names.has(section.name) || !Number.isInteger(section.max_chars)
        || section.max_chars < 1 || section.max_chars > 32768 || !textWithin(section.text, section.max_chars) || !textWithin(section.default_text, section.max_chars)) throw new Error('The retained document has invalid wording sections.');
    names.add(section.name);
  }
  if (new Set(source.changed_sections).size !== source.changed_sections.length || source.changed_sections.some((name) => !names.has(name))
      || source.sections.some((section) => source.changed_sections.includes(section.name) !== (section.text !== section.default_text))) throw new Error('The retained wording changes could not be verified.');
  if (source.contract_profile !== undefined) {
    const profile = htmlContractProfile({ schema_version: 2, html: '', css: '', contract_profile: source.contract_profile,
      values: source.values, sections: source.sections });
    const values = Object.fromEntries(source.values.map((field) => [field.name, field.text]));
    const sections = Object.fromEntries(source.sections.map((section) => [section.name, section.text]));
    if (!profile || !htmlSHA256(source.contract_profile_digest) || !Array.isArray(source.contract_parties) || source.contract_parties.length !== 2
        || htmlProfileIssues(profile, values, sections).length) throw new Error('The declared contract parties and terms could not be verified against this document.');
    const ids = new Set<string>();
    for (const mapping of profile.parties) {
      const matching = source.contract_parties.filter((party) => party?.slot === mapping.slot), party = matching[0];
      if (matching.length !== 1 || !party || party.role !== mapping.slot || !htmlUUID(party.recipient_id) || ids.has(party.recipient_id)
          || party.name !== values[mapping.representative_name] || party.email !== values[mapping.representative_email]
          || party.company_name !== values[mapping.company_name] || party.company_id !== values[mapping.company_id]
          || party.representative_authority !== values[mapping.representative_authority]) throw new Error('The intended signers do not match this document’s printed party information.');
      ids.add(party.recipient_id);
    }
  } else if (source.contract_profile_digest !== undefined || (source.contract_parties !== undefined && (!Array.isArray(source.contract_parties) || source.contract_parties.length))) {
    throw new Error('This document contains party bindings without a reviewed contract profile.');
  }
  if (source.source_schema_version !== undefined && ![1, 2, 3].includes(source.source_schema_version)) {
    throw new Error('This retained source version is unsupported. Refresh this document.');
  }
  if ((source.source_schema_version === 1 && source.contract_profile) || (source.source_schema_version === 2 && !source.contract_profile)) {
    throw new Error('The retained source version conflicts with its reviewed contract profile. Refresh this document.');
  }
  if (source.source_schema_version === 3) {
    if (!source.contract_profile || !source.contract_parties) throw new Error('The signing page requires both printed contract parties.');
    validateHTMLSigningPage(source.signing_page!);
    validateHTMLSigningArtifact(source.signing_artifact!, source.pdf_sha256, source.page_count);
    if (htmlSigningPageIssues(source.contract_profile, Object.fromEntries(source.values.map((field) => [field.name, field.text]))).length) throw new Error('The printed party details do not fit the approved signing page. Refresh this document.');
  } else if (source.signing_page !== undefined || source.signing_artifact !== undefined) {
    throw new Error('The retained signing-page source is incomplete. Refresh this document; signature placement remains locked.');
  }
  return source;
}

export function verifiedHTMLGeneratedFields(source: HTMLDocumentSource, fields: DocumentField[], recipients: Recipient[]): DocumentField[] {
  validateHTMLSource(source, source.document_id, source.org_id);
  if (source.source_schema_version !== 3 || !source.signing_artifact || !source.contract_parties
      || !Array.isArray(fields) || fields.length !== 2 || !Array.isArray(recipients) || recipients.length !== 2) {
    throw new Error('The generated signing locations could not be verified. Refresh the document before sending.');
  }
  const ids = new Set<string>();
  for (const expected of source.signing_artifact.fields) {
    const party = source.contract_parties.find((candidate) => candidate.slot === expected.slot)!;
    const signer = recipients.filter((candidate) => candidate.id === party.recipient_id);
    const matched = fields.filter((candidate) => candidate.recipient_id === party.recipient_id);
    const field = matched[0];
    if (signer.length !== 1 || signer[0].document_id !== source.document_id || signer[0].role !== party.role
        || signer[0].name !== party.name || signer[0].email !== party.email || matched.length !== 1 || !field || !htmlUUID(field.id) || ids.has(field.id)
        || field.document_id !== source.document_id || field.type !== 'signature' || field.required !== true || field.page !== expected.page
        || !([['x_pct', 'x'], ['y_pct', 'y'], ['w_pct', 'w'], ['h_pct', 'h']] as const).every(([actual, pinned]) =>
          typeof field[actual] === 'number' && Number.isFinite(field[actual]) && field[actual] === expected[pinned] / 10000)) {
      throw new Error('The generated signature fields or intended signers differ from this PDF. Refresh the document before sending.');
    }
    ids.add(field.id);
  }
  return fields;
}
export function htmlRevisionGroups(source: HTMLDocumentSource) {
  const profile = source.contract_profile, used = new Set<string>();
  if (!profile) return [{ id: 'values', label: 'Document information', values: source.values.map((field) => ({ ...field, label: field.name.replaceAll('_', ' ') })) }];
  const groups = (['provider', 'customer'] as const).map((slot) => {
    const party = profile.parties.find((candidate) => candidate.slot === slot)!;
    return { id: slot as string, label: slot === 'provider' ? 'Our company' : 'Customer', values: htmlPartyBindings.map((binding) => {
      const field = source.values.find((candidate) => candidate.name === party[binding])!; used.add(field.name);
      return { ...field, label: htmlPartyLabels[binding] };
    }) };
  });
  const terms = profile.terms.filter((term) => term.value).map((term) => {
    const field = source.values.find((candidate) => candidate.name === term.value)!; used.add(field.name);
    return { ...field, label: term.name.replaceAll('_', ' ') };
  });
  groups.push({ id: 'terms', label: 'Commercial terms', values: terms });
  const other = source.values.filter((field) => !used.has(field.name));
  if (other.length) groups.push({ id: 'other', label: 'Other document information', values: other.map((field) => ({ ...field, label: field.name.replaceAll('_', ' ') })) });
  return groups;
}
export function currentHTMLSource(source: HTMLDocumentSource, document: DocumentResponse): HTMLDocumentSource {
  validateHTMLSource(source, document.id, document.org_id);
  if (!document.has_html_source || document.source_kind !== 'pdf' || source.updated_at !== document.updated_at
      || source.html_source_commitment !== document.html_source_commitment || source.pdf_sha256 !== document.pdf_sha256
      || source.materialization_revision !== document.html_materialization_revision || source.template_id !== document.template_id) {
    throw new Error('The document changed before its source was loaded. Refresh and review the current revision; local inputs are retained.');
  }
  return source;
}
export function advanceCleanHTMLObservation(source: HTMLDocumentSource, document: DocumentResponse, unresolved: boolean): HTMLDocumentSource | null {
  if (unresolved || document.status !== 'draft') return null;
  // Review and field metadata may change the document timestamp without
  // changing the immutable source. Never adopt content or resolve local work.
  const next = { ...source, updated_at: document.updated_at };
  try { return currentHTMLSource(next, document); }
  catch { return null; }
}
export function revisionDraft(source: HTMLDocumentSource) {
  return { values: Object.fromEntries(source.values.map((field) => [field.name, field.text])),
    sections: Object.fromEntries(source.sections.map((section) => [section.name, section.text])), summary: '' };
}
export function htmlRevisionInput(source: HTMLDocumentSource, values: Record<string, string>, sections: Record<string, string>, summary: string): HTMLDocumentRevisionInput {
  validateHTMLSource(source, source.document_id, source.org_id);
  if (!values || typeof values !== 'object' || Array.isArray(values) || !sections || typeof sections !== 'object' || Array.isArray(sections)
      || Object.keys(values).some((name) => !source.values.some((field) => field.name === name))
      || Object.keys(sections).some((name) => !source.sections.some((section) => section.name === name))) throw new Error('Only declared document values and wording sections may change.');
  const nextValues: Record<string, string> = {}, nextSections: Record<string, string> = {};
  for (const field of source.values) {
    const value = values[field.name];
    if (!textWithin(value, field.max_chars) || (field.required && !value.trim())) throw new Error(`Enter ${field.name.replaceAll('_', ' ')}, within ${field.max_chars} characters${field.required ? ' (required)' : ''}.`);
    nextValues[field.name] = value;
  }
  for (const section of source.sections) {
    const text = sections[section.name];
    if (!textWithin(text, section.max_chars)) throw new Error(`Enter ${section.name.replaceAll('_', ' ')} wording within ${section.max_chars} characters.`);
    nextSections[section.name] = text;
  }
  if (source.contract_profile) {
    const issues = [...htmlProfileIssues(source.contract_profile, nextValues, nextSections),
      ...(source.source_schema_version === 3 ? htmlSigningPageIssues(source.contract_profile, nextValues) : [])];
    if (issues.length) throw new Error(issues[0]);
  }
  if (!textWithin(summary, 500)) throw new Error('Keep the revision summary within 500 characters.');
  const input = { expected_updated_at: source.updated_at, expected_html_source_commitment: source.html_source_commitment, values: nextValues, sections: nextSections, summary };
  if (new TextEncoder().encode(JSON.stringify(input)).length > 1024 * 1024) throw new Error('These document changes exceed the 1 MiB request limit. Shorten the declared text before saving.');
  return input;
}
export function verifiedHTMLRevision(result: HTMLDocumentRevisionResult, before: DocumentResponse, source: HTMLDocumentSource): DocumentResponse {
  const doc = result?.document;
  if (!doc || doc.id !== before.id || doc.org_id !== before.org_id || doc.template_id !== before.template_id || doc.sender_id !== before.sender_id
      || doc.source_kind !== 'pdf' || doc.status !== 'draft' || !doc.has_html_source || !doc.html_review_required || !htmlSHA256(doc.pdf_sha256)
      || !htmlSHA256(doc.html_source_commitment) || doc.html_source_commitment === source.html_source_commitment
      || doc.html_materialization_revision !== source.materialization_revision + 1 || result.materialization_revision !== doc.html_materialization_revision
      || typeof doc.updated_at !== 'string' || !Number.isFinite(Date.parse(doc.updated_at)) || doc.updated_at === before.updated_at || !Number.isInteger(result.page_count) || result.page_count < 1 || result.page_count > 500
      || result.review_required !== true || result.placement_reset !== true) throw new Error('The rendered revision could not be confirmed. Inspect the saved document before another write; your local inputs are retained.');
  return doc;
}
export function validateHTMLHistory(entries: HTMLHistoryEntry[]): HTMLHistoryEntry[] {
  if (!Array.isArray(entries) || entries.length > 200) throw new Error('Document history could not be verified.');
  const sequences = new Set<number>();
  for (const entry of entries) {
    if (!entry || !Number.isInteger(entry.sequence) || entry.sequence < 1 || sequences.has(entry.sequence) || !htmlUUID(entry.id) || !htmlUUID(entry.created_by)
        || !htmlSHA256(entry.source_commitment) || !htmlSHA256(entry.pdf_sha256) || !Number.isInteger(entry.page_count) || entry.page_count < 1 || entry.page_count > 500
        || typeof entry.created_at !== 'string' || !Number.isFinite(Date.parse(entry.created_at)) || !textWithin(entry.summary, 500) || typeof entry.current !== 'boolean') throw new Error('Document history contains an invalid revision.');
    sequences.add(entry.sequence);
  }
  if (entries.filter((entry) => entry.current).length > 1) throw new Error('Document history contains conflicting current revisions.');
  return entries;
}
export function htmlPlacementPins(hasHTMLSource: boolean, pdfSHA256?: string, sourceCommitment?: string) {
  if (!hasHTMLSource) return undefined;
  if (!htmlSHA256(pdfSHA256) || !htmlSHA256(sourceCommitment)) throw new Error('The current PDF and HTML source pins are unavailable. Refresh before placing fields.');
  return { expected_pdf_sha256: pdfSHA256, expected_html_source_commitment: sourceCommitment };
}
