// The server owns HTML safety, contrast, image decoding and revision validation.
// These bounds also protect the editor before a request or returned JSON is used.
export const emailDesignLimits = { source: 131072, layout: 16384, logo: 32768, dimension: 512, rendered: 262144 } as const;
export interface EmailLogo { name: 'logo'; media_type: 'image/png' | 'image/jpeg'; data_base64: string; sha256: string }
export interface EmailDesign {
  schema_version: 1; layout_html: string; background: string; surface: string; primary: string; text: string;
  logo: EmailLogo | null; logo_alt: string;
}
export const designBytes = (value: string) => new TextEncoder().encode(value).byteLength;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
export function defaultEmailDesign(): EmailDesign {
  return { schema_version: 1, layout_html: '<div style="padding:24px;">{{logo}}</div><div>{{native_content}}</div>', background: '#f3f4f6', surface: '#ffffff', primary: '#111111', text: '#111111', logo: null, logo_alt: '' };
}
export function readEmailDesign(source: string | undefined): EmailDesign | null {
  if (!source) return null;
  if (typeof source !== 'string' || designBytes(source) > emailDesignLimits.source) throw new Error('The email design is too large.');
  let value: unknown;
  try { value = JSON.parse(source); } catch { throw new Error('The email design must be valid JSON.'); }
  const keys = ['schema_version', 'layout_html', 'background', 'surface', 'primary', 'text', 'logo', 'logo_alt'];
  if (!record(value) || Object.keys(value).some(key => !keys.includes(key)) || value.schema_version !== 1
      || typeof value.layout_html !== 'string' || !value.layout_html || designBytes(value.layout_html) > emailDesignLimits.layout
      || value.layout_html.split('{{native_content}}').length !== 2 || value.layout_html.split('{{logo}}').length > 2
      || !['background', 'surface', 'primary', 'text'].every(key => typeof value[key] === 'string' && /^#[0-9a-f]{6}$/.test(value[key] as string))
      || typeof value.logo_alt !== 'string' || designBytes(value.logo_alt) > 200 || /[\u0000-\u001f\u007f]/.test(value.logo_alt)
      || !Object.hasOwn(value, 'logo')) throw new Error('Check the email layout, colours and required content slot.');
  if (value.logo !== null) {
    const logo = value.logo;
    if (!record(logo) || Object.keys(logo).length !== 4 || logo.name !== 'logo' || !['image/png', 'image/jpeg'].includes(String(logo.media_type))
        || typeof logo.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(logo.sha256)
        || typeof logo.data_base64 !== 'string' || logo.data_base64.length > 4 * Math.ceil(emailDesignLimits.logo / 3)
        || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(logo.data_base64)
        || !logo.data_base64 || value.layout_html.split('{{logo}}').length !== 2) throw new Error('Use a local PNG or JPEG logo up to 32 KiB and 512 pixels.');
    const decoded = atob(logo.data_base64);
    if (decoded.length > emailDesignLimits.logo || btoa(decoded) !== logo.data_base64) throw new Error('Use a local PNG or JPEG logo up to 32 KiB and 512 pixels.');
  }
  return value as unknown as EmailDesign;
}
export function emailDesignProblem(source: string | undefined): string | null {
  try { readEmailDesign(source); return null; } catch (error) { return (error as Error).message; }
}
export async function localEmailLogo(file: File): Promise<EmailLogo> {
  if (!['image/png', 'image/jpeg'].includes(file.type) || file.size < 1 || file.size > emailDesignLimits.logo) throw new Error('Use a local PNG or JPEG logo up to 32 KiB and 512 pixels.');
  const buffer = await file.arrayBuffer();
  // Decode the selected local file only. No URL or remote image is accepted.
  const bitmap = await createImageBitmap(new Blob([buffer], { type: file.type }));
  try {
    if (bitmap.width < 1 || bitmap.height < 1 || bitmap.width > emailDesignLimits.dimension || bitmap.height > emailDesignLimits.dimension) throw new Error('Use a local PNG or JPEG logo up to 32 KiB and 512 pixels.');
  } finally { bitmap.close(); }
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  const data = new Uint8Array(buffer); let binary = '';
  for (const byte of data) binary += String.fromCharCode(byte);
  return { name: 'logo', media_type: file.type as EmailLogo['media_type'], data_base64: btoa(binary), sha256: Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('') };
}
// Editing may temporarily remove a required slot. Keep that source visible so
// validation can explain it; never fall back to a different layout or throw.
export function emailDesignDraft(source: string | undefined): EmailDesign {
  if (!source) return defaultEmailDesign();
  try {
    const value = JSON.parse(source);
    if (record(value) && typeof value.layout_html === 'string' && typeof value.logo_alt === 'string'
        && ['background', 'surface', 'primary', 'text'].every(key => typeof value[key] === 'string')) return value as unknown as EmailDesign;
  } catch { /* Returned sources are validated before reaching the draft. */ }
  return defaultEmailDesign();
}
