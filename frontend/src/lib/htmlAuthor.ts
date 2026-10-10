import type { HTMLTemplateInput, TemplateResponse } from './api/client';
import { htmlContractProfile, htmlTemplateFields, requiredHTMLContractTerms, type HTMLAsset, type HTMLContractProfile, type HTMLSectionDefinition, type HTMLValueDefinition } from './htmlTemplate';

export interface AuthorValue extends HTMLValueDefinition { key: number; default_value: string }
export interface AuthorSection extends HTMLSectionDefinition { key: number }
export interface HTMLAuthorDraft {
  schema_version: 1 | 2;
  contract_profile: HTMLContractProfile | null;
  name: string;
  html: string;
  css: string;
  values: AuthorValue[];
  sections: AuthorSection[];
  assets: HTMLAsset[];
}
const namePattern = /^[a-z][a-z0-9_]{0,63}$/;
const shaPattern = /^[a-f0-9]{64}$/;
const textEncoder = new TextEncoder();
const MAX_ASSET = 2 * 1024 * 1024;
const MAX_ASSETS_TOTAL = 8 * 1024 * 1024;

export function blankHTMLAuthorDraft(): HTMLAuthorDraft {
  return { schema_version: 1, contract_profile: null, name: '', html: '', css: '', values: [], sections: [], assets: [] };
}
export function blankHTMLContractProfile(kind: HTMLContractProfile['kind'] = 'proposal'): HTMLContractProfile {
  return { id: 'sales_proposal', version: 1, kind, parties: ['provider', 'customer'].map((slot) => ({
    slot: slot as 'provider' | 'customer', company_name: '', company_id: '', representative_name: '', representative_email: '', representative_authority: '',
  })), terms: requiredHTMLContractTerms(kind).map((name) => ({ name, value: '' })) };
}
export function draftFromHTMLTemplate(template: TemplateResponse): HTMLAuthorDraft {
  const fields = htmlTemplateFields(template);
  const master = template.html_master_json!;
  const draft: HTMLAuthorDraft = {
    schema_version: master.schema_version, contract_profile: htmlContractProfile(master),
    name: template.name, html: master.html, css: master.css,
    values: fields.map((field, key) => ({ name: field.name, required: field.required, max_chars: field.max_chars, default_value: field.defaultValue, key })),
    sections: (master.sections ?? []).map((section, key) => ({ ...section, key })),
    assets: (master.assets ?? []).map((asset) => ({ ...asset })),
  };
  htmlAuthorInput(draft);
  return draft;
}
// This is local dirty-state comparison, not the server's canonical commitment.
export function htmlAuthorFingerprint(draft: HTMLAuthorDraft): string {
  return JSON.stringify({ schema_version: draft.schema_version, contract_profile: draft.contract_profile, name: draft.name, html: draft.html, css: draft.css,
    values: draft.values.map((value) => ({ name: value.name, required: value.required, max_chars: value.max_chars, default_value: value.default_value })),
    sections: draft.sections.map((section) => ({ name: section.name, default_text: section.default_text, max_chars: section.max_chars })),
    assets: draft.assets.map((asset) => ({ name: asset.name, media_type: asset.media_type, data_base64: asset.data_base64, sha256: asset.sha256 })) });
}
function validText(text: string, maxChars: number): boolean {
  return typeof text === 'string' && Array.from(text).length <= maxChars
    && !/[\uD800-\uDFFF\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/u.test(text);
}
export function assetByteLength(asset: HTMLAsset): number {
  const value = asset.data_base64;
  if (typeof value !== 'string' || !value.length || value.length % 4 !== 0 || value.length > Math.ceil(MAX_ASSET / 3) * 4) {
    throw new Error('An asset has invalid base64 data. Replace it with a supported local file.');
  }
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0;
  let last = 0;
  for (let i = 0; i < value.length - padding; i++) {
    const code = value.charCodeAt(i);
    last = code >= 65 && code <= 90 ? code - 65 : code >= 97 && code <= 122 ? code - 71
      : code >= 48 && code <= 57 ? code + 4 : code === 43 ? 62 : code === 47 ? 63 : -1;
    if (last < 0) throw new Error('An asset has invalid base64 data. Replace it with a supported local file.');
  }
  if ((padding === 2 && (last & 15) !== 0) || (padding === 1 && (last & 3) !== 0)) throw new Error('An asset has noncanonical base64 padding.');
  return value.length / 4 * 3 - padding;
}
export function htmlAuthorInput(draft: HTMLAuthorDraft): HTMLTemplateInput {
  if (!validText(draft.name, 200) || !draft.name.trim()) throw new Error('Enter a design name within 200 characters.');
  if (!validText(draft.html, 256 * 1024) || !draft.html.trim() || textEncoder.encode(draft.html).length > 256 * 1024
      || !validText(draft.css, 128 * 1024) || textEncoder.encode(draft.css).length > 128 * 1024) {
    throw new Error('Enter an HTML body fragment within 256 KiB and CSS within 128 KiB.');
  }
  if (draft.values.length > 64 || draft.sections.length > 64 || draft.assets.length > 16) throw new Error('The design exceeds the declaration or asset limit.');
  const defaults: Record<string, string> = {};
  const names = new Set<string>();
  const values = draft.values.map((value) => {
    if (!namePattern.test(value.name) || names.has(value.name) || typeof value.required !== 'boolean'
        || !Number.isInteger(value.max_chars) || value.max_chars < 1 || value.max_chars > 8192 || !validText(value.default_value, value.max_chars)) {
      throw new Error('Values need unique lowercase names, valid defaults and a character limit from 1 to 8192.');
    }
    names.add(value.name); defaults[value.name] = value.default_value;
    return { name: value.name, required: value.required, max_chars: value.max_chars };
  });
  names.clear();
  const sections = draft.sections.map((section) => {
    if (!namePattern.test(section.name) || names.has(section.name) || !Number.isInteger(section.max_chars)
        || section.max_chars < 1 || section.max_chars > 32768 || !validText(section.default_text, section.max_chars)) {
      throw new Error('Wording sections need unique lowercase names, valid text and a character limit from 1 to 32768.');
    }
    names.add(section.name);
    return { name: section.name, default_text: section.default_text, max_chars: section.max_chars };
  });
  names.clear(); let total = 0;
  const assets = draft.assets.map((asset) => {
    const size = assetByteLength(asset);
    if (!namePattern.test(asset.name) || names.has(asset.name) || !shaPattern.test(asset.sha256)
        || !['image/png', 'image/jpeg', 'font/woff', 'font/woff2'].includes(asset.media_type) || size > MAX_ASSET) {
      throw new Error('Assets need unique lowercase names, a valid SHA and supported image/font bytes within 2 MiB.');
    }
    total += size; names.add(asset.name);
    return { name: asset.name, media_type: asset.media_type, data_base64: asset.data_base64, sha256: asset.sha256 };
  });
  if (total > MAX_ASSETS_TOTAL) throw new Error('The design exceeds the 8 MiB asset total.');
  const master: HTMLTemplateInput['html_master_json'] = { schema_version: draft.schema_version, html: draft.html, css: draft.css, values, sections, assets };
  if (draft.contract_profile !== null) master.contract_profile = draft.contract_profile;
  const profile = htmlContractProfile(master);
  if (profile) master.contract_profile = profile;
  const input: HTMLTemplateInput = { name: draft.name, html_master_json: master, variables_json: defaults };
  if (textEncoder.encode(JSON.stringify(input)).length > 12 * 1024 * 1024) throw new Error('The encoded design exceeds 12 MiB.');
  return input;
}

// No browser image/font parser or remote fetch: only bounded bytes and metadata.
// Backend validation, malware scanning and isolated PDF rendering remain authoritative.
export async function htmlAssetFromFile(file: File, name: string, existing: HTMLAsset[]): Promise<HTMLAsset> {
  if (!namePattern.test(name) || existing.some((asset) => asset.name === name)) throw new Error('Enter a unique lowercase asset name.');
  if (existing.length >= 16 || !file.size || file.size > MAX_ASSET || existing.reduce((sum, asset) => sum + assetByteLength(asset), 0) + file.size > MAX_ASSETS_TOTAL) {
    throw new Error('Choose a file within 2 MiB and the design’s 16-file / 8 MiB limits.');
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (bytes.length !== file.size) throw new Error('The local asset changed while reading. Choose it again.');
  const signature = String.fromCharCode(...bytes.subarray(0, 4));
  let media_type: HTMLAsset['media_type'];
  if (bytes[0] === 0x89 && signature.slice(1) === 'PNG' && bytes[4] === 13 && bytes[5] === 10 && bytes[6] === 26 && bytes[7] === 10 && /\.png$/i.test(file.name)) media_type = 'image/png';
  else if (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff && /\.jpe?g$/i.test(file.name)) media_type = 'image/jpeg';
  else if (signature === 'wOFF' && /\.woff$/i.test(file.name)) media_type = 'font/woff';
  else if (signature === 'wOF2' && /\.woff2$/i.test(file.name)) media_type = 'font/woff2';
  else throw new Error('Choose a PNG, JPEG, WOFF or WOFF2 file with matching content. SVG and remote assets are unsupported.');
  const sha256 = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.buffer)), (byte) => byte.toString(16).padStart(2, '0')).join('');
  let binary = '';
  for (let i = 0; i < bytes.length; i += 32768) binary += String.fromCharCode(...bytes.subarray(i, i + 32768));
  return { name, media_type, data_base64: btoa(binary), sha256 };
}
