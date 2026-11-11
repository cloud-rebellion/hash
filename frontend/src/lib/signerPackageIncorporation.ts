// Closed, versioned server statements. These are proof-bound canonical bytes,
// not interface translations. Existing English V1 must never be rewritten.
export const signerPackageIncorporations = {
  'hash-package-incorporation-v1': {
    locale: 'en',
    sha256: 'ed7e8d4a4b7e03bb600f94ccd6328e4f457528eb165f18fd0ca6ccfecb972670',
    text: 'I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments.',
  },
  'hash-package-incorporation-sv-v1': {
    locale: 'sv',
    sha256: '24cfae89a52f479cbce33b71f99faec557ebd573279a9e5184bb51b17505a6de',
    text: 'Jag har granskat och godkänner huvuddokumentet och varje bilaga som anges i detta avtalspaket. Min signatur eller bekräftelse gäller hela paketet som identifieras av de visade kontrollvärdena.',
  },
} as const;

export type SignerPackageIncorporationVersion = keyof typeof signerPackageIncorporations;
export type SignerPackageIncorporation = Readonly<{ version: SignerPackageIncorporationVersion; sha256: string; text: string }>;

export function validSignerPackageIncorporation(value: unknown): value is SignerPackageIncorporation {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const copy = value as Record<string, unknown>;
  if (typeof copy.version !== 'string' || !Object.hasOwn(signerPackageIncorporations, copy.version)) return false;
  const expected = signerPackageIncorporations[copy.version as SignerPackageIncorporationVersion];
  return copy.sha256 === expected.sha256 && copy.text === expected.text;
}

export function signerPackageIncorporationLocale(value: SignerPackageIncorporation): 'en' | 'sv' {
  if (!validSignerPackageIncorporation(value)) throw new Error('The contract package could not be verified. Reload it before continuing.');
  return signerPackageIncorporations[value.version].locale;
}
