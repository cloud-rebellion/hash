import { signerRoomEnglish, signerRoomSwedish, type SignerRoomText } from './signerRoomUiMessages';

// The caller supplies the already-selected recipient interface locale. This
// module never infers, reads, persists or submits a language preference.
export function signerRoomText(locale: unknown, text: SignerRoomText, values: Record<string, string | number> = {}): string {
  const translated: string = locale === 'sv' ? signerRoomSwedish[text] : signerRoomEnglish[text];
  return translated.replace(/\{([a-zA-Z]+)\}/g, (placeholder, key: string) => Object.hasOwn(values, key) ? String(values[key]) : placeholder);
}

function knownText(value: string): value is SignerRoomText {
  return Object.hasOwn(signerRoomEnglish, value);
}

// Display only: keep the original exception/state for scope and proof handling.
// Unknown server/renderer details are never translated or echoed as UI copy.
export function signerRoomError(locale: unknown, value: unknown, fallback: SignerRoomText = 'The request failed.'): string {
  const message = typeof value === 'string' ? value : value instanceof Error ? value.message : '';
  if (knownText(message)) return signerRoomText(locale, message);
  const status = /^(?:The request failed|request failed) \(([1-5][0-9]{2})\)\.?$/.exec(message);
  if (status) return signerRoomText(locale, 'The request failed ({status}).', { status: status[1] });
  for (const [prefix, key] of [
    ['Unable to load document fields: ', 'Unable to load document fields: {reason}'],
    ['Unable to load document: ', 'Unable to load document: {reason}'],
  ] as const) {
    if (message.startsWith(prefix)) return signerRoomText(locale, key, { reason: signerRoomError(locale, message.slice(prefix.length)) });
  }
  if (message.startsWith('The server did not confirm field ')) return signerRoomText(locale, 'The server did not confirm the saved field.');
  return signerRoomText(locale, fallback);
}

// Existing PDF viewer seam accepts labels as well as exceptions. Only known
// application strings are localized; PDF content and its proof are untouched.
export function signerRoomViewerText(locale: unknown, text: string): string {
  return knownText(text) ? signerRoomText(locale, text) : signerRoomError(locale, text);
}

export function signerRoomFieldType(locale: unknown, type: string): string {
  return ['text', 'date', 'checkbox', 'dropdown', 'initial', 'signature'].includes(type)
    ? signerRoomText(locale, type as SignerRoomText) : signerRoomText(locale, 'field');
}

export function signerRoomPages(locale: unknown, count: number): string {
  return signerRoomText(locale, count === 1 ? '{count} page' : '{count} pages', { count });
}
