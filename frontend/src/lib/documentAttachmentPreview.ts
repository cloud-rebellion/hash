import { attachmentPreviewKey, checkedAttachmentInventory, type AttachmentInventory, type AttachmentMember } from './documentAttachments';
export type AttachmentPreviewSelection = { key: string; bytes: Uint8Array; pages: number; title: string };
export type AttachmentPreviewState = { selection: AttachmentPreviewSelection | null; opening: boolean; closing: boolean; blocked: boolean; error: string | null };
export const initialAttachmentPreview = (): AttachmentPreviewState => ({ selection: null, opening: false, closing: false, blocked: false, error: null });
// This barrier covers attachment preview instances, including route disposal.
// It does not claim global admission for unrelated PDF consumers.
function joined(previous: Promise<void>, retirement: Promise<void>): Promise<void> {
 const result=Promise.allSettled([previous,retirement]).then(results=>{for(const r of results)if(r.status==='rejected')throw r.reason;});void result.catch(()=>{});return result;
}
export class AttachmentPreviewFamily {
 private barrier:Promise<void>=Promise.resolve();
 current(){return this.barrier;}
 join(retirement:Promise<void>){this.barrier=joined(this.barrier,retirement);return this.barrier;}
}
const attachmentPreviewFamily=new AttachmentPreviewFamily();
export class AttachmentPreviewController {
 state = initialAttachmentPreview(); private revision = 0; private abort: AbortController | null = null; private work: Promise<void> = Promise.resolve(); private retirement:Promise<void>=Promise.resolve(); private disposed = false;
 constructor(private fetchPDF: (v: AttachmentInventory, m: AttachmentMember, signal: AbortSignal) => Promise<Uint8Array>, private retireView: () => Promise<void>, private changed: (state: AttachmentPreviewState) => void, private family=attachmentPreviewFamily) {}
 observeRetirement(retirement:Promise<void>){this.retirement=joined(this.retirement,retirement);this.family.join(retirement); }
 private update(value: Partial<AttachmentPreviewState>) { this.state = { ...this.state, ...value }; if (!this.disposed) this.changed(this.state); }
 private queue(v: AttachmentInventory | null, m?: AttachmentMember, org = ''): Promise<void> {
  const predecessor = this.family.current();
  const revision = ++this.revision; this.abort?.abort(); this.update({ opening: !!v, closing: !v, error: this.state.blocked ? this.state.error : null });
  const request = this.work.then(async () => {
   if (this.state.blocked) { this.update({ opening: false, closing: false }); return; }
   // The preceding transition includes actual fetch/body/hash settlement.
   try { await predecessor; await this.retirement; await this.retireView(); await this.retirement; } catch (error) {
    void this.family.join(Promise.reject(error)); this.update({ blocked: true, opening: false, closing: false, error: 'The attachment preview could not be closed. Refresh this page before opening another PDF.' }); return; }
   this.state.selection?.bytes.fill(0); this.update({ selection: null });
   if (revision !== this.revision || this.disposed || !v || !m) { if (revision === this.revision) this.update({ opening: false, closing: false }); return; }
   const abort = new AbortController(); this.abort = abort;
   try { const bytes = await this.fetchPDF(v, m, abort.signal);
    if (this.disposed || revision !== this.revision || abort.signal.aborted) { bytes.fill(0); return; }
    this.update({ selection: { key: attachmentPreviewKey(org, v, m), bytes, pages: m.pdf_pages, title: m.title }, opening: false, closing: false });
   } catch { if (revision === this.revision && !this.disposed) this.update({ opening: false, closing: false, error: 'The selected attachment could not be verified. Refresh attachments before opening it again.' }); }
  });
  this.work = request.catch(() => {}); return request;
 }
 open(org: string, inventory: AttachmentInventory, member: AttachmentMember): Promise<void> { const v = checkedAttachmentInventory(inventory), m = v.members.find(x => x.document_id === member.document_id); if (!m) return Promise.reject(new Error('Select a saved attachment.')); return this.queue(v, m, org); }
 close(): Promise<void> { return this.queue(null); }
 dispose(): Promise<void> { const joined = this.close(); this.disposed = true; return this.family.join(joined); }
}
