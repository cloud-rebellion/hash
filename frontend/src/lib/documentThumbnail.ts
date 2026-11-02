// Library previews stay in memory and never change the source document.
export type ThumbnailItem = { id: string; name: string; source_kind: string; version?: number; pdf_sha256?: string; content_sha256?: string; updated_at?: string; blocks_json?: unknown; html_master_json?: unknown };

export function previewLines(value: unknown, html = false): string[] {
  if (html) {
    const raw = value && typeof value === 'object' && 'html' in value ? (value as { html: unknown }).html : '';
    if (typeof raw !== 'string') return [];
    // Plain text only: never mount HTML, CSS, assets, URLs or active content.
    return raw.slice(0, 64_000).replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
      .replace(/<\/(?:p|div|h[1-6]|li|tr)\s*>|<br\s*\/?>/gi, '\n').replace(/<[^>]{0,2048}>/g, ' ')
      .replace(/&(nbsp|amp|lt|gt|quot|apos);/g, (_, name: string) => ({ nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" }[name] ?? ' '))
      .split('\n').map(line => line.replace(/\s+/g, ' ').trim().slice(0, 180)).filter(Boolean).slice(0, 12);
  }
  const out: string[] = [], pending: unknown[] = [value];
  let visited = 0;
  while (pending.length && out.length < 12 && visited++ < 1000) {
    const node = pending.pop();
    if (!node || typeof node !== 'object') continue;
    if (Array.isArray(node)) { pending.push(...node.slice(0, 100).reverse()); continue; }
    const block = node as Record<string, unknown>;
    if (typeof block.text === 'string' && block.text.trim()) out.push(block.text.replace(/\s+/g, ' ').trim().slice(0, 180));
    if (Array.isArray(block.rows)) for (const row of block.rows.slice(0, 8)) {
      if (Array.isArray(row)) out.push(row.filter(cell => typeof cell === 'string').join(' · ').slice(0, 180));
      if (out.length >= 12) break;
    }
    if (block.content) pending.push(block.content);
    if (block.blocks) pending.push(block.blocks);
  }
  return out.slice(0, 12);
}

let active = 0;
const waiters: Array<() => void> = [];
// Two visible thumbnail jobs at a time; PDF.js retains its existing canvas budget.
export function thumbnailTurn(signal: AbortSignal): Promise<() => void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const abort = () => {
      if (settled) return;
      settled = true;
      const index = waiters.indexOf(start); if (index >= 0) waiters.splice(index, 1);
      signal.removeEventListener('abort', abort);
      reject(new DOMException('Preview closed', 'AbortError'));
    };
    const start = () => {
      if (settled) return;
      if (signal.aborted) { abort(); return; }
      settled = true; signal.removeEventListener('abort', abort); active++;
      let released = false;
      resolve(() => { if (released) return; released = true; active--; waiters.shift()?.(); });
    };
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort(); else if (active < 2) start(); else waiters.push(start);
  });
}
