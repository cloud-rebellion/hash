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
export interface HTMLMaster {
  schema_version: 1;
  html: string;
  css: string;
  values?: HTMLValueDefinition[];
  sections?: HTMLSectionDefinition[];
  assets?: HTMLAsset[];
}
export interface HTMLFormField extends HTMLValueDefinition { defaultValue: string; label: string }

export function htmlTemplateFields(template: TemplateResponse): HTMLFormField[] {
  const master = template.html_master_json;
  if (template.source_kind !== 'html' || !master || master.schema_version !== 1 || !Number.isInteger(template.version)
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
    if (!field || !/^[a-z][a-z0-9_]{0,63}$/.test(field.name) || seen.has(field.name)
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
