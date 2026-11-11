import { readonly, writable } from 'svelte/store';
import type { StaffLocale } from './staffPreferences';

export type PreviewMode = 'signature' | 'acceptance';
export type PreviewOutcome = 'review' | 'changes' | 'declined' | 'signed' | 'accepted';
export type PreviewPoint = { x: number; y: number };
export type PreviewEvent = 'opened' | 'message' | 'changes' | 'declined' | 'signed' | 'accepted';
export type PreviewProblem = 'messageRequired' | 'messageLimit' | 'reasonRequired' | 'signatureRequired' | 'confirmationRequired' | null;
export interface RoomPreviewState {
  mode: PreviewMode;
  outcome: PreviewOutcome;
  page: 1 | 2;
  panel: 'discussion' | 'activity';
  messages: { id: number; kind: 'message' | 'changes'; text: string }[];
  events: PreviewEvent[];
  signatureMode: 'type' | 'draw';
  signatureName: string;
  strokes: PreviewPoint[][];
  confirmed: boolean;
  problem: PreviewProblem;
  declineReason: string;
}

function initial(mode: PreviewMode = 'signature'): RoomPreviewState {
  return { mode, outcome: 'review', page: 1, panel: 'discussion', messages: [], events: ['opened'],
    signatureMode: 'type', signatureName: '', strokes: [], confirmed: false, problem: null, declineReason: '' };
}

/** A disposable local simulation. No API, storage, document, recipient or token is accepted. */
export function createRoomPreview() {
  const state = writable<RoomPreviewState>(initial());
  let current = initial();
  const update = (value: RoomPreviewState) => { current = value; state.set(value); };
  const editable = () => current.outcome === 'review';
  const point = (p: PreviewPoint): PreviewPoint | null => Number.isFinite(p.x) && Number.isFinite(p.y)
    ? { x: Math.min(1, Math.max(0, p.x)), y: Math.min(1, Math.max(0, p.y)) } : null;
  function message(raw: string, kind: 'message' | 'changes' = 'message') {
    const text = raw.trim().slice(0, 1000);
    if (!text) { update({ ...current, problem: kind === 'changes' ? 'reasonRequired' : 'messageRequired' }); return false; }
    if (current.messages.length >= 30) { update({ ...current, problem: 'messageLimit' }); return false; }
    if (kind === 'changes' && !editable()) return false;
    update({ ...current, panel: 'discussion', problem: null,
      outcome: kind === 'changes' ? 'changes' : current.outcome,
      messages: [...current.messages, { id: current.messages.length + 1, kind, text }],
      events: [...current.events, kind === 'changes' ? 'changes' : 'message'] });
    return true;
  }
  return {
    subscribe: readonly(state).subscribe,
    reset() { update(initial()); },
    setMode(mode: PreviewMode) { if (mode === 'signature' || mode === 'acceptance') update(initial(mode)); },
    setPage(page: number) { if (page === 1 || page === 2) update({ ...current, page }); },
    setPanel(panel: 'discussion' | 'activity') { update({ ...current, panel }); },
    message,
    requestChanges(text: string) { return message(text, 'changes'); },
    decline(raw: string) {
      if (!editable()) return false;
      const text = raw.trim().slice(0, 1000);
      if (!text) { update({ ...current, problem: 'reasonRequired' }); return false; }
      update({ ...current, outcome: 'declined', declineReason: text, problem: null, panel: 'activity', events: [...current.events, 'declined'] });
      return true;
    },
    setSignatureMode(signatureMode: 'type' | 'draw') { if (editable()) update({ ...current, signatureMode, problem: null }); },
    setSignatureName(signatureName: string) { if (editable()) update({ ...current, signatureName: signatureName.slice(0, 100), problem: null }); },
    setConfirmed(confirmed: boolean) { if (editable()) update({ ...current, confirmed, problem: null }); },
    startStroke(p: PreviewPoint) {
      const next = point(p);
      if (!editable() || !next || current.strokes.length >= 64 || current.strokes.reduce((n, s) => n + s.length, 0) >= 2048) return;
      update({ ...current, strokes: [...current.strokes, [next]], problem: null });
    },
    extendStroke(p: PreviewPoint) {
      const next = point(p);
      if (!editable() || !next || !current.strokes.length || current.strokes.reduce((n, s) => n + s.length, 0) >= 2048) return;
      const last = current.strokes.length - 1;
      update({ ...current, strokes: current.strokes.map((stroke, i) => i === last ? [...stroke, next] : stroke), problem: null });
    },
    clearSignature() { if (editable()) update({ ...current, strokes: [], signatureName: '', problem: null }); },
    finish() {
      if (!editable()) return false;
      if (!current.confirmed) { update({ ...current, problem: 'confirmationRequired' }); return false; }
      if (current.mode === 'signature' && (current.signatureMode === 'type' ? current.signatureName.trim().length < 2 : !current.strokes.some(s => s.length > 1))) {
        update({ ...current, problem: 'signatureRequired' }); return false;
      }
      const outcome = current.mode === 'signature' ? 'signed' : 'accepted';
      update({ ...current, outcome, page: 2, panel: 'activity', problem: null, events: [...current.events, outcome] });
      return true;
    },
  };
}

export interface RoomPreviewBrand {
  name: string;
  primary: string;
  foreground: string;
  logo: string | null;
}
const hex = (value: unknown) => typeof value === 'string' && /^#[0-9a-f]{6}$/i.test(value) ? value : null;
export function roomPreviewBrand(input?: { primary_hex?: string; logo_alt?: string; logo_url?: string }): RoomPreviewBrand {
  const primary = hex(input?.primary_hex) ?? '#4055a8';
  const rgb = [1, 3, 5].map(i => parseInt(primary.slice(i, i + 2), 16) / 255)
    .map(x => x <= 0.04045 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4);
  const luminance = 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
  // Only existing embedded image data is used. A preview never loads an external logo URL.
  const logo = typeof input?.logo_url === 'string' && input.logo_url.length <= 65536
    && /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/]+={0,2}$/.test(input.logo_url) ? input.logo_url : null;
  return { primary, foreground: luminance > 0.179 ? '#000000' : '#ffffff', logo,
    name: typeof input?.logo_alt === 'string' ? input.logo_alt.trim().slice(0, 100) : '' };
}

/** Session/branding reads only; authorization is checked before the preview is revealed. */
export function createRoomPreviewAccess(reads: {
  identity: () => Promise<{ user_id: string; org_id: string; role: string }>;
  branding: () => Promise<{ primary_hex?: string; logo_alt?: string; logo_url?: string }>;
}) {
  const state = writable<{ status: 'loading' | 'ready' | 'signed-out' | 'error'; brand: RoomPreviewBrand; fallback: boolean }>({ status: 'loading', brand: roomPreviewBrand(), fallback: false });
  let generation = 0, disposed = false, loading = false, ready = false;
  async function load() {
    if (disposed || loading || ready) return;
    const ticket = ++generation;
    loading = true;
    state.set({ status: 'loading', brand: roomPreviewBrand(), fallback: false });
    const current = () => !disposed && ticket === generation;
    try {
      const identity = await reads.identity();
      if (!identity.user_id || !identity.org_id || !identity.role) throw new Error('Staff session required');
      if (!current()) return;
      let brand = roomPreviewBrand(), fallback = false;
      try { brand = roomPreviewBrand(await reads.branding()); }
      catch (cause) {
        if (typeof cause === 'object' && cause !== null && 'status' in cause && cause.status === 401) throw cause;
        fallback = true;
      }
      if (current()) { ready = true; state.set({ status: 'ready', brand, fallback }); }
    } catch (cause) {
      const status = typeof cause === 'object' && cause !== null && 'status' in cause ? cause.status : 0;
      if (current()) state.set({ status: status === 401 || status === 403 ? 'signed-out' : 'error', brand: roomPreviewBrand(), fallback: false });
    } finally { if (current()) loading = false; }
  }
  return { subscribe: readonly(state).subscribe, load, dispose() { disposed = true; generation++; } };
}

const en = {
  entryTitle: 'Try the recipient room', entryDescription: 'Explore the document, chat and signing steps with a local example. Test emails keep their links inactive.',
  entryAction: 'Open room preview', back: 'Email design', title: 'Recipient room preview', eyebrow: 'Workspace · Preview',
  intro: 'See the room as a customer would, without inviting anyone.', reset: 'Restart preview',
  demoBadge: 'Test only', demoNotice: 'Synthetic example. Nothing here sends email, changes a document or creates a real signature, certificate or audit event.',
  loading: 'Checking your staff session…', signedOut: 'Sign in with a staff account to open the room preview.', signIn: 'Sign in',
  failed: 'The staff session could not be checked. Try again.', retry: 'Try again', brandFallback: 'Workspace branding could not be loaded. A neutral preview is shown.',
  workspace: 'Your workspace', mode: 'Room mode', signatureMode: 'Signature', acceptanceMode: 'Acceptance', modeHelp: 'Changing mode starts a fresh example.',
  recipient: 'Alex Example', company: 'Example Studio', email: 'alex@example.invalid', recipientLabel: 'Example recipient',
  documentTitle: 'Website project · example', documentType: 'Synthetic proposal', documentSubtitle: 'A small example, made for exploring the room.',
  overview: 'A clear plan for the next step', overviewBody: 'This sample combines a short delivery plan with a simple decision. Its content, people and amounts are fictional.',
  scope: 'What is included', scopeOne: 'A discovery session and a shared plan', scopeTwo: 'A first design with one review round', scopeThree: 'Delivery and a short handover',
  amount: '12,000 SEK', amountLabel: 'Example project amount', amountHelp: 'Sample only · not an offer',
  working: 'Working together', workingBody: 'Use the discussion to ask a question or request a change before making a decision.',
  delivery: 'Example delivery', deliveryBody: 'A four-week project with a shared review before delivery. This is demonstration wording, not contractual terms.',
  signatureArea: 'Preview signature', signatureEmpty: 'Your local test signature appears here.', acceptedArea: 'Preview acceptance', acceptanceEmpty: 'Your local test acceptance appears here.', acceptedText: 'The example has been accepted in this browser tab.',
  page: 'Page', of: 'of', pageOne: 'Overview', pageTwo: 'Details & decision', pages: 'Example pages', previous: 'Previous page', next: 'Next page',
  discussion: 'Discussion', activity: 'Preview activity', discussionEmpty: 'Start a conversation', discussionHelp: 'Try a question as the example recipient. Messages stay in this tab.',
  messageLabel: 'Test message', messagePlaceholder: 'For example: can we review the timeline?', sendMessage: 'Add test message', localOnly: 'Local example · not sent',
  decision: 'Try a decision', decisionHelp: 'Explore the final step, or ask for a change first.',
  type: 'Type signature', draw: 'Draw signature', signatureLabel: 'Test signature name', signaturePlaceholder: 'Type a fictional name',
  drawLabel: 'Draw a test signature with a pointer. Choose Type signature to use the keyboard.', drawHelp: 'Draw in the box, or use Type signature.', clear: 'Clear signature',
  confirmSignature: 'I have reviewed this example and want to try the signing step.', confirmAcceptance: 'I have reviewed this example and want to try acceptance.',
  sign: 'Try signing', accept: 'Try acceptance', changeTitle: 'Request a change', changeLabel: 'Proposed change', changePlaceholder: 'Describe a change to the example…', changeAction: 'Add test change request',
  declineTitle: 'Decline the example', declineLabel: 'Reason for declining', declinePlaceholder: 'Add a short example reason…', declineAction: 'Try declining',
  reviewStatus: 'Ready for review', changesStatus: 'Changes requested · preview', declinedStatus: 'Declined · preview', signedStatus: 'Signed · preview', acceptedStatus: 'Accepted · preview',
  signedNotice: 'Test signature added locally. No document was signed or saved.', acceptedNotice: 'Acceptance simulated locally. No agreement was accepted or saved.',
  changesNotice: 'The test change request is visible in the discussion. No sender was notified.', declinedNotice: 'Decline simulated locally. No recipient or document status changed.',
  endingHelp: 'Restart the preview to try another ending.', activityHelp: 'These are local demonstration steps, not a saved evidence log.',
  openedEvent: 'Example room opened', messageEvent: 'Test message added', changesEvent: 'Test change requested', declinedEvent: 'Example declined', signedEvent: 'Test signature added', acceptedEvent: 'Example accepted',
  messageRequired: 'Write a test message first.', messageLimit: 'This preview has 30 messages. Restart to clear it.', reasonRequired: 'Add a short example reason first.',
  signatureRequired: 'Type a name or draw a test signature first.', confirmationRequired: 'Confirm that you reviewed the example first.',
};
export type RoomPreviewCopy = typeof en;
const sv: RoomPreviewCopy = {
  entryTitle: 'Prova mottagarrummet', entryDescription: 'Utforska dokument, chatt och signering med ett lokalt exempel. Länkar i testmejl är fortfarande inaktiva.',
  entryAction: 'Öppna förhandsvisningen', back: 'E-postdesign', title: 'Förhandsvisa mottagarrummet', eyebrow: 'Arbetsyta · Förhandsvisning',
  intro: 'Se rummet som en kund skulle göra, utan att bjuda in någon.', reset: 'Börja om',
  demoBadge: 'Endast test', demoNotice: 'Ett påhittat exempel. Inget här skickar mejl, ändrar dokument eller skapar en riktig signatur, ett certifikat eller en logghändelse.',
  loading: 'Kontrollerar din inloggning…', signedOut: 'Logga in med ett personalkonto för att öppna förhandsvisningen.', signIn: 'Logga in',
  failed: 'Inloggningen kunde inte kontrolleras. Försök igen.', retry: 'Försök igen', brandFallback: 'Arbetsytans varumärke kunde inte hämtas. En neutral förhandsvisning visas.',
  workspace: 'Din arbetsyta', mode: 'Läge i rummet', signatureMode: 'Signering', acceptanceMode: 'Acceptans', modeHelp: 'Ett byte av läge startar ett nytt exempel.',
  recipient: 'Alex Exempel', company: 'Exempelstudio', email: 'alex@example.invalid', recipientLabel: 'Exempelmottagare',
  documentTitle: 'Webbprojekt · exempel', documentType: 'Påhittad offert', documentSubtitle: 'Ett litet exempel för att utforska rummet.',
  overview: 'En tydlig plan för nästa steg', overviewBody: 'Exemplet kombinerar en kort leveransplan med ett enkelt beslut. Innehåll, personer och belopp är påhittade.',
  scope: 'Det här ingår', scopeOne: 'Ett uppstartsmöte och en gemensam plan', scopeTwo: 'En första design med en granskningsrunda', scopeThree: 'Leverans och en kort överlämning',
  amount: '12 000 kr', amountLabel: 'Exempel på projektbelopp', amountHelp: 'Endast exempel · ingen offert',
  working: 'Så arbetar vi tillsammans', workingBody: 'Använd chatten för att ställa en fråga eller be om en ändring innan du bestämmer dig.',
  delivery: 'Exempel på leverans', deliveryBody: 'Ett fyraveckorsprojekt med gemensam granskning före leverans. Det här är demonstrationstext, inga avtalsvillkor.',
  signatureArea: 'Testsignatur', signatureEmpty: 'Din lokala testsignatur visas här.', acceptedArea: 'Testacceptans', acceptanceEmpty: 'Din lokala testacceptans visas här.', acceptedText: 'Exemplet har accepterats i den här webbläsarfliken.',
  page: 'Sida', of: 'av', pageOne: 'Översikt', pageTwo: 'Detaljer och beslut', pages: 'Exempelsidor', previous: 'Föregående sida', next: 'Nästa sida',
  discussion: 'Chatt', activity: 'Testaktivitet', discussionEmpty: 'Starta ett samtal', discussionHelp: 'Prova att ställa en fråga som exempelmottagare. Meddelanden stannar i den här fliken.',
  messageLabel: 'Testmeddelande', messagePlaceholder: 'Till exempel: kan vi gå igenom tidsplanen?', sendMessage: 'Lägg till testmeddelande', localOnly: 'Lokalt exempel · inte skickat',
  decision: 'Prova ett beslut', decisionHelp: 'Utforska det sista steget eller be om en ändring först.',
  type: 'Skriv signatur', draw: 'Rita signatur', signatureLabel: 'Namn för testsignatur', signaturePlaceholder: 'Skriv ett påhittat namn',
  drawLabel: 'Rita en testsignatur med pekdon. Välj Skriv signatur för att använda tangentbordet.', drawHelp: 'Rita i rutan eller välj Skriv signatur.', clear: 'Rensa signatur',
  confirmSignature: 'Jag har granskat exemplet och vill prova signeringssteget.', confirmAcceptance: 'Jag har granskat exemplet och vill prova acceptans.',
  sign: 'Testsignera', accept: 'Prova acceptans', changeTitle: 'Begär en ändring', changeLabel: 'Föreslagen ändring', changePlaceholder: 'Beskriv en ändring i exemplet…', changeAction: 'Lägg till testbegäran',
  declineTitle: 'Avböj exemplet', declineLabel: 'Anledning att avböja', declinePlaceholder: 'Ange en kort anledning som exempel…', declineAction: 'Prova att avböja',
  reviewStatus: 'Redo att granskas', changesStatus: 'Ändring begärd · test', declinedStatus: 'Avböjt · test', signedStatus: 'Signerat · test', acceptedStatus: 'Accepterat · test',
  signedNotice: 'Testsignaturen har lagts till lokalt. Inget dokument har signerats eller sparats.', acceptedNotice: 'Acceptans har simulerats lokalt. Inget avtal har accepterats eller sparats.',
  changesNotice: 'Testbegäran syns i chatten. Ingen avsändare har meddelats.', declinedNotice: 'Avböjandet har simulerats lokalt. Ingen mottagar- eller dokumentstatus har ändrats.',
  endingHelp: 'Börja om för att prova ett annat avslut.', activityHelp: 'Det här är lokala teststeg, ingen sparad bevislogg.',
  openedEvent: 'Exempelrummet öppnades', messageEvent: 'Testmeddelande tillagt', changesEvent: 'Teständring begärd', declinedEvent: 'Exemplet avböjdes', signedEvent: 'Testsignatur tillagd', acceptedEvent: 'Exemplet accepterades',
  messageRequired: 'Skriv ett testmeddelande först.', messageLimit: 'Förhandsvisningen har 30 meddelanden. Börja om för att rensa.', reasonRequired: 'Ange en kort anledning som exempel först.',
  signatureRequired: 'Skriv ett namn eller rita en testsignatur först.', confirmationRequired: 'Bekräfta att du har granskat exemplet först.',
};
export function roomPreviewCopy(locale: StaffLocale): RoomPreviewCopy { return locale === 'sv' ? sv : en; }
