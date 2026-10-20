// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction
import { expect, test } from 'bun:test';
import { completionArtifactLinks } from './completionArtifacts';

const fresh = 'A'.repeat(43);
const active = 'B'.repeat(43);
const pair = { final_pdf_url: `/sign/${fresh}/final-pdf`, audit_cert_url: `/sign/${fresh}/audit-cert` };

test('completion downloads require one matching rotated credential', () => {
  expect(completionArtifactLinks(pair, active)).toEqual({ finalPDFURL: pair.final_pdf_url, auditCertURL: pair.audit_cert_url });
  for (const value of [null, undefined, [], '', {}, { final_pdf_url: pair.final_pdf_url },
    { audit_cert_url: pair.audit_cert_url }, { ...pair, final_pdf_url: 1 }, { ...pair, audit_cert_url: false },
    { ...pair, audit_cert_url: `/sign/${active}/audit-cert` }]) {
    expect(completionArtifactLinks(value, active)).toBeNull();
  }
  expect(completionArtifactLinks(pair, fresh)).toBeNull();
});

test('completion links refuse external, ambiguous and noncanonical URLs', () => {
  const mutations = [
    (url: string) => 'https://example.test' + url,
    (url: string) => 'http://example.test' + url,
    (url: string) => '//example.test' + url,
    (url: string) => 'javascript:' + url,
    (url: string) => 'data:text/plain,' + url,
    (url: string) => url + '?x=1',
    (url: string) => url + '#fragment',
    (url: string) => ' ' + url,
    (url: string) => url + '\n',
    (url: string) => url + '\r\n',
    (url: string) => url.replace('/sign/', '/sign//'),
    (url: string) => url.replace('/sign/', '/sign/../sign/'),
    (url: string) => url.replace('/sign/', '/sign%2f'),
    (url: string) => url.replace(fresh, '%41' + fresh.slice(1)),
    (url: string) => url.replace(fresh, fresh.slice(1)),
    (url: string) => url.replace(fresh, fresh + 'A'),
    (url: string) => url.replace('/sign/', '/sign\\'),
    (url: string) => url.replace(/final-pdf|audit-cert/, 'other')
  ];
  for (const field of ['final_pdf_url', 'audit_cert_url'] as const) {
    for (const mutate of mutations) {
      expect(completionArtifactLinks({ ...pair, [field]: mutate(pair[field]) }, active)).toBeNull();
    }
  }
});
