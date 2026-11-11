import { expect, test } from 'bun:test';
import { get } from 'svelte/store';
import { createRoomPreview, createRoomPreviewAccess, roomPreviewBrand, roomPreviewCopy } from './roomPreview';
import { getBranding, getMe } from './api/client';
import { needsSession, routeSurface } from './routeSurface';

test('room preview is a staff settings route and remains hidden if session verification fails', async () => {
  expect(routeSurface('/settings/room-preview')).toBe('staff');
  expect(needsSession('/settings/room-preview')).toBe(true);
  let branding = 0;
  const access = createRoomPreviewAccess({ identity: async () => { throw { status: 401 }; }, branding: async () => { branding++; return {}; } });
  expect(get(access).status).toBe('loading');
  await access.load();
  expect(get(access).status).toBe('signed-out');
  expect(branding).toBe(0);
  access.dispose();
});

test('verified staff can explore with a neutral fallback, and disposed reads cannot reveal a room', async () => {
  let identityReads = 0;
  const access = createRoomPreviewAccess({ identity: async () => { identityReads++; return { user_id: 'staff', org_id: 'workspace', role: 'member' }; },
    branding: async () => { throw new Error('unavailable'); } });
  await access.load(); await access.load();
  expect(get(access)).toEqual({ status: 'ready', brand: roomPreviewBrand(), fallback: true });
  expect(identityReads).toBe(1);
  let finish!: (identity: { user_id: string; org_id: string; role: string }) => void;
  const pending = createRoomPreviewAccess({ identity: () => new Promise(resolve => { finish = resolve; }), branding: async () => { throw new Error('Must not be called'); } });
  const operation = pending.load(); pending.dispose(); finish({ user_id: 'staff', org_id: 'workspace', role: 'member' }); await operation;
  expect(get(pending).status).toBe('loading');
  access.dispose();
});

test('a session that expires during branding reads does not reveal the simulator', async () => {
  const access = createRoomPreviewAccess({ identity: async () => ({ user_id: 'staff', org_id: 'workspace', role: 'member' }),
    branding: async () => { throw { status: 401 }; } });
  await access.load();
  expect(get(access).status).toBe('signed-out');
  access.dispose();
});

test('chat, change request and decline react locally, validate empty input, and reset completely', () => {
  const room = createRoomPreview();
  expect(room.message('  ')).toBe(false);
  expect(get(room).problem).toBe('messageRequired');
  expect(room.message('  Can we review the timeline?  ')).toBe(true);
  expect(get(room).messages).toEqual([{ id: 1, kind: 'message', text: 'Can we review the timeline?' }]);
  expect(room.requestChanges('Please move the example delivery.')).toBe(true);
  expect(get(room).outcome).toBe('changes');
  expect(get(room).messages[1].kind).toBe('changes');
  expect(room.finish()).toBe(false);
  room.setPage(2); room.setPanel('activity'); room.reset();
  expect(get(room).messages).toEqual([]);
  expect(get(room).events).toEqual(['opened']);
  expect(get(room).outcome).toBe('review'); expect(get(room).page).toBe(1);
  expect(room.decline('')).toBe(false);
  expect(get(room).problem).toBe('reasonRequired');
  expect(room.decline('Only exploring an example.')).toBe(true);
  expect(get(room).outcome).toBe('declined');
  expect(get(room).declineReason).toBe('Only exploring an example.');
  expect(room.requestChanges('Another change')).toBe(false);
  room.reset(); expect(get(room).declineReason).toBe('');
});

test('typed and drawn signing require a local signature and confirmation, then cannot silently sign again', () => {
  const room = createRoomPreview();
  expect(room.finish()).toBe(false); expect(get(room).problem).toBe('confirmationRequired');
  room.setConfirmed(true);
  expect(room.finish()).toBe(false); expect(get(room).problem).toBe('signatureRequired');
  room.setSignatureName('Alex Example');
  expect(room.finish()).toBe(true);
  expect(get(room).outcome).toBe('signed'); expect(get(room).page).toBe(2);
  expect(room.finish()).toBe(false);
  expect(get(room).events).toEqual(['opened', 'signed']);
  room.reset(); room.setSignatureMode('draw'); room.setConfirmed(true);
  room.startStroke({ x: 0.1, y: 0.2 }); expect(room.finish()).toBe(false);
  room.extendStroke({ x: 0.4, y: 0.6 }); expect(room.finish()).toBe(true);
  expect(get(room).outcome).toBe('signed');
  room.reset(); expect(get(room).strokes).toEqual([]); expect(get(room).signatureName).toBe(''); expect(get(room).confirmed).toBe(false);
});

test('acceptance does not create a signature and switching mode starts a clean example', () => {
  const room = createRoomPreview(); room.message('Old conversation'); room.setSignatureName('Old signature');
  room.setMode('acceptance');
  expect(get(room).messages).toEqual([]); expect(get(room).signatureName).toBe('');
  expect(room.finish()).toBe(false); room.setConfirmed(true); expect(room.finish()).toBe(true);
  expect(get(room).outcome).toBe('accepted'); expect(get(room).strokes).toEqual([]);
  expect(get(room).events).toEqual(['opened', 'accepted']);
  room.setMode('signature'); expect(get(room).outcome).toBe('review'); expect(get(room).confirmed).toBe(false);
});

test('local input and drawing stay bounded, page selection cannot leave the synthetic document', () => {
  const room = createRoomPreview();
  room.setPage(3); expect(get(room).page).toBe(1);
  room.setPage(2); expect(get(room).page).toBe(2);
  room.startStroke({ x: Number.NaN, y: 0 }); expect(get(room).strokes).toEqual([]);
  room.startStroke({ x: -2, y: 4 }); expect(get(room).strokes[0][0]).toEqual({ x: 0, y: 1 });
  for (let i = 0; i < 2100; i++) room.extendStroke({ x: 0.5, y: 0.5 });
  expect(get(room).strokes.flat()).toHaveLength(2048);
  room.clearSignature(); expect(get(room).strokes).toEqual([]);
  for (let i = 0; i < 30; i++) expect(room.message('example')).toBe(true);
  expect(room.message('more')).toBe(false); expect(get(room).problem).toBe('messageLimit');
  room.reset(); expect(room.message('x'.repeat(1100))).toBe(true); expect(get(room).messages[0].text).toHaveLength(1000);
});

test('workspace branding cannot introduce network logo requests or arbitrary styles', () => {
  expect(roomPreviewBrand({ primary_hex: 'red; background:url(https://example.invalid)', logo_url: 'https://example.invalid/logo.png' })).toEqual(roomPreviewBrand());
  expect(roomPreviewBrand({ logo_url: '/api/v1/anything' }).logo).toBeNull();
  expect(roomPreviewBrand({ logo_url: 'data:image/svg+xml;base64,AAAA' }).logo).toBeNull();
  expect(roomPreviewBrand({ logo_url: 'data:image/png;base64,AAAA', primary_hex: '#ffffff', logo_alt: 'Example brand' })).toEqual({
    name: 'Example brand', primary: '#ffffff', foreground: '#000000', logo: 'data:image/png;base64,AAAA' });
  expect(roomPreviewBrand({ primary_hex: '#101216' }).foreground).toBe('#ffffff');
});

test('all visible preview copy has Swedish and English variants with synthetic identities and explicit limitations', () => {
  const en = roomPreviewCopy('en'), sv = roomPreviewCopy('sv');
  expect(Object.keys(en)).toEqual(Object.keys(sv));
  expect(en.email).toBe('alex@example.invalid'); expect(sv.email).toBe(en.email);
  expect(en.entryDescription).toContain('links inactive'); expect(sv.entryDescription).toContain('inaktiva');
  expect(en.signedNotice).toContain('No document was signed'); expect(sv.signedNotice).toContain('Inget dokument har signerats');
  expect(en.activityHelp).toContain('not a saved evidence log'); expect(sv.activityHelp).toContain('ingen sparad bevislogg');
  for (const text of Object.values(sv)) expect(text.length).toBeGreaterThan(0);
});

test('production session/branding reads are the only HTTP calls across the entire simulated journey', async () => {
  const original = globalThis.fetch;
  const calls: { path: string; method: string }[] = [];
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input), method = init?.method ?? 'GET'; calls.push({ path, method });
    if (method !== 'GET') throw new Error('The preview must never mutate HTTP state');
    if (path === '/api/v1/me') return Response.json({ user_id: 'staff', org_id: 'workspace', role: 'owner' });
    if (path === '/api/v1/branding') return Response.json({ primary_hex: '#334466', logo_alt: 'Sample workspace' });
    throw new Error('Unexpected preview request');
  }) as typeof fetch;
  const access = createRoomPreviewAccess({ identity: getMe, branding: getBranding });
  try {
    await access.load(); expect(get(access).status).toBe('ready');
    const room = createRoomPreview(); room.message('Question'); room.requestChanges('Example change'); room.reset();
    room.decline('Example decline'); room.reset(); room.setSignatureName('Example Person'); room.setConfirmed(true); room.finish();
    room.setMode('acceptance'); room.setConfirmed(true); room.finish(); room.reset();
    expect(calls).toEqual([{ path: '/api/v1/me', method: 'GET' }, { path: '/api/v1/branding', method: 'GET' }]);
    expect(JSON.stringify(get(room))).not.toContain('staff');
  } finally { access.dispose(); globalThis.fetch = original; }
});
