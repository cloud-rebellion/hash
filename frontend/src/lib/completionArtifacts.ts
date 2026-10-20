// SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
// Copyright (c) Bright Interaction

export type CompletionArtifactLinks = { finalPDFURL: string; auditCertURL: string;packagePortalURL?:string };

// Completion rotates the ceremony credential. Accept only the exact paired
// application routes; never synthesize a download from the active magic link.
// A dispatched package response requires its exact fresh archive link. Ordinary
// or historical responses can retain their older final/report-only contract.
export function completionArtifactLinks(value: unknown, ceremonyToken: string,requiresPackagePortal=false): CompletionArtifactLinks | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (typeof body.final_pdf_url !== 'string' || typeof body.audit_cert_url !== 'string') return null;
  const match = /^\/sign\/([A-Za-z0-9_-]{43})\/final-pdf$/.exec(body.final_pdf_url);
  const token = match?.[1];
  if (!token || token === ceremonyToken ||
      body.final_pdf_url !== `/sign/${token}/final-pdf` ||
      body.audit_cert_url !== `/sign/${token}/audit-cert`) return null;
  if((requiresPackagePortal||body.package_portal_url!==undefined)&&body.package_portal_url!==`/completed/${token}`)return null;
  return { finalPDFURL: body.final_pdf_url, auditCertURL: body.audit_cert_url,...(body.package_portal_url?{packagePortalURL:body.package_portal_url as string}:{}) };
}
