import { describe, test, expect } from 'bun:test';
import { get } from 'svelte/store';
import { createAutomationPreferencesForm, createReminderPolicyForm, reminderSelection, validReminderSelection, type AutomationPreferences, type ReminderSnapshot } from './automationSettings';

const preference = (revision = 0, viewed = false, signed = false): AutomationPreferences => ({ schema_version: 1, revision, notify_viewed: viewed, notify_signed: signed, viewed_scope: 'first_view_per_recipient_per_send', updated_at: revision ? '2026-11-03T12:00:00Z' : null });
function deferred<T>() { let resolve!: (value: T) => void, reject!: (error: unknown) => void; const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; }); return { promise, resolve, reject }; }
const policy = (frozen = false): ReminderSnapshot => ({ scope: 'document', id: 'a7ea9860-5397-47ad-8df4-334f31a75a99', revision: 0, updated_at: '2026-11-03T12:00:00Z', selection: reminderSelection('inherit'), effective_policy: { ...reminderSelection('legacy'), offsets_days: [3,7] }, source: frozen ? 'frozen' : 'legacy', editable: !frozen, frozen });

describe('actual automation form callbacks', () => {
  test('preferences begin opt-out, send exact CAS and acknowledge only matching save', async () => {
    const calls: unknown[] = [];
    const form = createAutomationPreferencesForm({ load: async () => preference(), save: async (saved, draft) => { calls.push([saved.revision, draft]); return preference(1, draft.notify_viewed, draft.notify_signed); } });
    expect(get(form).authorized).toBe(false); await form.load();
    expect(get(form).draft).toEqual({ notify_viewed: false, notify_signed: false });
    form.edit({ notify_viewed: true, notify_signed: false }); expect(await form.save()).toBe(true);
    expect(calls).toEqual([[0, { notify_viewed: true, notify_signed: false }]]); expect(get(form).dirty).toBe(false); form.dispose();
  });
  test('write timeout retains draft and blocks repeat until fresh GET; late success cannot publish', async () => {
    const pending = deferred<AutomationPreferences>(); let writes = 0, saved = preference();
    const form = createAutomationPreferencesForm({ load: async () => saved, save: async () => { writes++; return pending.promise; } }, 10);
    await form.load(); form.edit({ notify_viewed: true, notify_signed: true });
    expect(await form.save()).toBe(false); expect(get(form).busy).toBe(null); expect(get(form).unconfirmed).toBe(true); expect(get(form).dirty).toBe(true);
    expect(await form.save()).toBe(false); expect(writes).toBe(1); expect(form.cancel()).toBe(false);
    pending.resolve(preference(1, true, true)); await Promise.resolve(); expect(get(form).saved?.revision).toBe(0);
    saved = preference(1, true, true); await form.load(); expect(get(form).dirty).toBe(false); expect(get(form).unconfirmed).toBe(false); form.dispose();
  });
  test('stale revision preserves draft; fresh read binds next save to latest revision', async () => {
    let saved = preference(), calls = 0; const revisions: number[] = [];
    const form = createAutomationPreferencesForm({ load: async () => saved, save: async (before, draft) => { revisions.push(before.revision); if (++calls === 1) throw { status: 409 }; return preference(before.revision + 1, draft.notify_viewed, draft.notify_signed); } });
    await form.load(); form.edit({ notify_viewed: true, notify_signed: false }); expect(await form.save()).toBe(false);
    expect(get(form).draft.notify_viewed).toBe(true); expect(await form.save()).toBe(false);
    saved = preference(4); await form.load(); expect(get(form).dirty).toBe(true); expect(await form.save()).toBe(true); expect(revisions).toEqual([0,4]); form.dispose();
  });
  test('live authorization refusal disables all edits until a successful reload', async () => {
    const form = createAutomationPreferencesForm({ load: async () => preference(), save: async () => { throw { status: 403 }; } });
    await form.load(); form.edit({ notify_viewed: true, notify_signed: false }); await form.save();
    expect(get(form).authorized).toBe(false); expect(form.edit({ notify_viewed: false, notify_signed: false })).toBe(false); expect(await form.save()).toBe(false); form.dispose();
  });
  test('unbound server acknowledgement is an unknown write outcome', async () => {
    const form = createAutomationPreferencesForm({ load: async () => preference(), save: async () => preference(1, false, false) });
    await form.load(); form.edit({ notify_viewed: true, notify_signed: false }); expect(await form.save()).toBe(false); expect(get(form).unconfirmed).toBe(true); expect(get(form).draft.notify_viewed).toBe(true); form.dispose();
  });
  test('a frozen reminder policy is visible and cannot be edited or saved', async () => {
    let writes = 0; const form = createReminderPolicyForm('document', { load: async () => policy(true), save: async () => { writes++; return policy(true); } });
    await form.load(); expect(get(form).saved?.effective_policy.offsets_days).toEqual([3,7]); expect(form.edit(reminderSelection('disabled'))).toBe(false); expect(await form.save()).toBe(false); expect(writes).toBe(0); form.dispose();
  });
  test('other native document mutations block the actual policy save callback', async () => {
    let writes = 0; const form = createReminderPolicyForm('document', { load: async () => policy(), save: async (saved, draft) => { writes++; return { ...saved, revision: 1, selection: draft }; } });
    await form.load(); form.edit(reminderSelection('disabled')); expect(await form.save(true)).toBe(false); expect(writes).toBe(0); expect(get(form).dirty).toBe(true); form.dispose();
  });
  test('one write owner remains busy through refresh acknowledgement', async () => {
    const settle = deferred<ReminderSnapshot>(); let writes = 0;
    const form = createReminderPolicyForm('document', { load: async () => policy(), save: async () => { writes++; return settle.promise; } });
    await form.load(); form.edit(reminderSelection('disabled')); const first = form.save(); expect(await form.save()).toBe(false); expect(form.cancel()).toBe(false);
    settle.resolve({ ...policy(), revision: 1, selection: reminderSelection('disabled') }); expect(await first).toBe(true); expect(writes).toBe(1); form.dispose();
  });
  test('disposal aborts its own load and ignores late results', async () => {
    const pending = deferred<AutomationPreferences>(); let signal: AbortSignal | undefined;
    const form = createAutomationPreferencesForm({ load: async input => { signal = input; return pending.promise; }, save: async () => preference() });
    const loading = form.load(); form.dispose(); expect(signal?.aborted).toBe(true); pending.resolve(preference(1,true,true)); expect(await loading).toBe(false); expect(get(form).saved).toBe(null);
  });
});

test('finite reminder choices preserve legacy and reject invalid or overflowing schedules', () => {
  expect(reminderSelection('legacy')).toEqual({ mode: 'legacy', interval_days: 0, max_fires: 2 });
  expect(reminderSelection('disabled')).toEqual({ mode: 'disabled', interval_days: 0, max_fires: 0 });
  expect(validReminderSelection(reminderSelection('inherit'), 'document')).toBe(true); expect(validReminderSelection(reminderSelection('inherit'), 'template')).toBe(false);
  expect(validReminderSelection(reminderSelection('interval', 1, 365), 'document')).toBe(true);
  expect(validReminderSelection(reminderSelection('interval', 365, 1), 'template')).toBe(true);
  for (const [days,count] of [[0,1],[1,0],[1,366],[2,183],[1.5,2],[NaN,2],[Infinity,1]]) expect(validReminderSelection(reminderSelection('interval', days, count), 'document')).toBe(false);
});


test('document source change preserves the policy draft and fences saving until fresh metadata', async () => {
 let saved=policy();const seen:string[]=[];
 const form=createReminderPolicyForm('document',{load:async()=>saved,save:async(before,draft)=>{seen.push(before.updated_at!);return{...before,revision:1,selection:draft};}});
 await form.load();form.edit(reminderSelection('interval',4,3));form.sourceChanged();
 expect(get(form).draft).toEqual(reminderSelection('interval',4,3));expect(get(form).unconfirmed).toBe(true);expect(await form.save()).toBe(false);
 saved={...policy(),updated_at:'2026-11-03T12:01:00Z'};await form.load();expect(get(form).dirty).toBe(true);expect(get(form).unconfirmed).toBe(false);
 expect(await form.save()).toBe(true);expect(seen).toEqual(['2026-11-03T12:01:00Z']);form.dispose();
});
