import { expect, test } from 'bun:test';
import { checkedSignerPackageDescriptorsV1, signerPackageLocale, signerPackageResponse } from './signerPackage';
import { signerPackageIncorporations, validSignerPackageIncorporation } from './signerPackageIncorporation';

const sha = async (text: string) => [...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)))].map(b => b.toString(16).padStart(2, '0')).join('');
function descriptor(version: keyof typeof signerPackageIncorporations) {
  const copy = signerPackageIncorporations[version];
  return { package: { schema: 'hash-recipient-package-v1', package_id: '10000000-0000-4000-8000-000000000001', revision: '1', manifest_sha256: 'a'.repeat(64), legal_commitment_sha256: 'b'.repeat(64),
    main: { title: 'Customer title <verbatim>', category: '', pdf_sha256: 'c'.repeat(64), bytes: 100, pages: 1 }, annexes: [], incorporation: { version, sha256: copy.sha256, text: copy.text } } };
}

test('only exact closed EN/SV canonical text/version/hash pairs can be presented, even after recomputing a wrong text hash', async () => {
  for (const version of Object.keys(signerPackageIncorporations) as Array<keyof typeof signerPackageIncorporations>) {
    const packet = descriptor(version), copy = packet.package.incorporation, result = checkedSignerPackageDescriptorsV1(packet)!;
    expect(copy.sha256).toBe(await sha(copy.text));
    expect(signerPackageLocale(result)).toBe(signerPackageIncorporations[version].locale);
    expect(result.main.title).toBe('Customer title <verbatim>');
    expect(signerPackageResponse(result)).toEqual({ manifest_sha256: result.manifest_sha256, legal_commitment_sha256: result.legal_commitment_sha256, incorporation_version: version, incorporation_sha256: copy.sha256, consent: true });
    const otherVersion = version === 'hash-package-incorporation-v1' ? 'hash-package-incorporation-sv-v1' : 'hash-package-incorporation-v1';
    const other = signerPackageIncorporations[otherVersion];
    for (const bad of [
      { ...copy, version: 'unsupported' }, { ...copy, version: otherVersion }, { ...copy, sha256: other.sha256 }, { ...copy, text: other.text },
      { ...copy, text: other.text, sha256: other.sha256 }, { ...copy, text: copy.text + ' ', sha256: await sha(copy.text + ' ') },
      { ...copy, text: 'Unapproved statement', sha256: await sha('Unapproved statement') },
    ]) {
      expect(validSignerPackageIncorporation(bad)).toBe(false);
      expect(() => checkedSignerPackageDescriptorsV1({ package: { ...packet.package, incorporation: bad } })).toThrow();
    }
  }
});

test('legacy English response bytes are unchanged and interface language is absent from proof', () => {
  const value = checkedSignerPackageDescriptorsV1(descriptor('hash-package-incorporation-v1'))!;
  expect(JSON.stringify(signerPackageResponse(value))).toBe('{"manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","legal_commitment_sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","incorporation_version":"hash-package-incorporation-v1","incorporation_sha256":"ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670","consent":true}');
  expect(Object.keys(signerPackageResponse(value))).not.toContain('locale');
  expect(Object.keys(signerPackageResponse(value))).not.toContain('canonicalLocale');
  expect(checkedSignerPackageDescriptorsV1({ package: null })).toBeNull();
});
