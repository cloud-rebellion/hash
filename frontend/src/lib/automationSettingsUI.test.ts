import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { compile, parse } from 'svelte/compiler';

const ts = new Bun.Transpiler({ loader: 'ts' });
function nodes(root: unknown): any[] {
  const found: any[] = [], seen = new WeakSet<object>(); let count = 0;
  function visit(value: any) { if (!value || typeof value !== 'object' || seen.has(value)) return; seen.add(value); if (++count > 200000) throw new Error('AST traversal bound'); found.push(value); for (const child of Object.values(value)) if (Array.isArray(child)) child.forEach(visit); else visit(child); }
  visit(root); return found;
}
function expression(node: any, name: string) { const attribute = node.attributes.find((item: any) => item.type === 'Attribute' && item.name === name); if (!attribute?.value?.[0]?.expression) throw new Error(`Missing real ${name} expression`); return attribute.value[0].expression; }
function bind(source: string, node: any, environment: object) { return new Function('env', `with(env){${ts.transformSync(`const actual = ${source.slice(node.start,node.end)};`)}return actual;}`)(environment); }
const documentSource = readFileSync(resolve(import.meta.dir, '../routes/documents/[id]/+page.svelte'), 'utf8');
const documentTree = parse(documentSource), documentNodes = nodes(documentTree);
const sender = documentNodes.find(node => node.type === 'InlineComponent' && node.name === 'SenderPanel');
const reminder = documentNodes.find(node => node.type === 'InlineComponent' && node.name === 'ReminderPolicySettings');
const reminderSource = readFileSync(resolve(import.meta.dir, 'components/ReminderPolicySettings.svelte'), 'utf8');
const effect = nodes(parse(reminderSource).instance).find(node => node.type === 'CallExpression' && node.callee?.name === '$effect' && node.arguments[0]?.type === 'ArrowFunctionExpression');
const senderSource = readFileSync(resolve(import.meta.dir, 'components/SenderPanel.svelte'), 'utf8');
const send = nodes(parse(senderSource).instance).find(node => node.type === 'FunctionDeclaration' && node.id?.name === 'send');

test('actual reminder state callback reaches actual parent and blocks genuine Send callback', async () => {
  for (const state of [
    { saved: null, authorized: false, busy: 'loading', dirty: false, unconfirmed: false },
    { saved: {}, authorized: true, busy: null, dirty: true, unconfirmed: false },
    { saved: {}, authorized: true, busy: 'saving', dirty: false, unconfirmed: false },
    { saved: {}, authorized: true, busy: null, dirty: true, unconfirmed: true },
  ]) {
    const parent: any = { capturedReminderScope: 'current', reminderScope: 'current', documentScope: {}, isCurrentDocument: () => true,
      reminderApplies: true, reminderBlocked: false, reminderBusy: false, reminderDirty: false, reminderUnconfirmed: false,
      amendmentLookupBlocked: false, amendmentNotice: false, amendmentBusy: false, doc: { has_html_source: false, source_kind: 'pdf' }, htmlRevisionBlocked: false, crmEditable: false, blocksEditorClean: true };
    const callback = bind(documentSource, expression(reminder, 'onStateChange'), parent);
    bind(reminderSource, effect.arguments[0], { $form: state, onStateChange: callback })();
    const blocked = bind(documentSource, expression(sender, 'revisionBlocked'), parent);
    expect(blocked).toBe(true);
    let attempted = 0;
    const environment: any = { captureScope: () => ({ id: 'synthetic' }), preSignMode: 'manual', editable: true, packageUncertain: false,
      packageReviewRequired: false, attachmentsBlocked: false, crmBlocked: false, otherMutationBusy: false, busy: null, saving: false,
      savingLocale: false, removingID: null, reviewRequired: false, revisionBlocked: blocked, generatedPlacementRequired: false,
      generatedPlacementReady: true, loading: false, recipientRefreshError: null, partyConflicts: [],
      recipientDraftChanged: () => { attempted++; return false; }, sendDocument: () => { attempted++; throw new Error('must not dispatch'); } };
    const run = new Function('env', `with(env){${ts.transformSync(senderSource.slice(send.start,send.end))};return send;}`)(environment);
    await run(); expect(attempted).toBe(0);
  }
});
test('late callback from another document cannot clear the reminder Send barrier', () => {
  const env: any = { capturedReminderScope: 'old', reminderScope: 'new', documentScope: {}, isCurrentDocument: () => true, reminderBlocked: true, reminderBusy: false, reminderDirty: false, reminderUnconfirmed: false };
  bind(documentSource, expression(reminder, 'onStateChange'), env)({ blocked: false, busy: false, dirty: false, unconfirmed: false });
  expect(env.reminderBlocked).toBe(true);
});
test('actual policy and preference components compile on both Svelte targets', () => {
  for (const file of ['components/ReminderPolicySettings.svelte','components/AutomationPreferencesSettings.svelte','../routes/settings/automations/+page.svelte']) {
    const filename = resolve(import.meta.dir,file), source = readFileSync(filename,'utf8');
    for (const generate of ['client','server'] as const) expect(compile(source,{filename,generate}).warnings).toEqual([]);
  }
});


test('actual parent keeps the same policy editor across source autosaves but separates document and actor identity',()=>{
 const declaration=documentNodes.find(node=>node.type==='VariableDeclarator'&&node.id?.name==='reminderScope');
 const expression=declaration.init.arguments[0];
 const environment:any={doc:{id:'doc-A',org_id:'org-A',updated_at:'old'},documentRevision:1,viewerUserID:'sender-A',viewerRole:'sender'};
 const before=bind(documentSource,expression,environment);environment.doc.updated_at='new';environment.documentRevision++;
 expect(bind(documentSource,expression,environment)).toBe(before);environment.doc.id='doc-B';expect(bind(documentSource,expression,environment)).not.toBe(before);
});


test('actual clean loaded policy clears only its own Send barrier',()=>{
 const parent:any={capturedReminderScope:'current',reminderScope:'current',documentScope:{},isCurrentDocument:()=>true,reminderApplies:true,reminderBlocked:true,reminderBusy:false,reminderDirty:false,reminderUnconfirmed:false,amendmentLookupBlocked:false,amendmentNotice:false,amendmentBusy:false,doc:{has_html_source:false,source_kind:'pdf'},htmlRevisionBlocked:false,crmEditable:false,blocksEditorClean:true};
 const callback=bind(documentSource,expression(reminder,'onStateChange'),parent);
 bind(reminderSource,effect.arguments[0],{$form:{saved:{},authorized:true,busy:null,dirty:false,unconfirmed:false},onStateChange:callback})();
 expect(bind(documentSource,expression(sender,'revisionBlocked'),parent)).toBe(false);
 parent.amendmentLookupBlocked=true;expect(bind(documentSource,expression(sender,'revisionBlocked'),parent)).toBe(true);
});
