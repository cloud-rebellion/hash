import {expect,test} from 'bun:test';
import {fetchCompletedPackage,fetchCompletedPackagePDF} from './completedPackage';
import {completionArtifactLinks} from './completionArtifacts';
const token='B'.repeat(43),old='A'.repeat(43),documentID='11111111-1111-1111-1111-111111111111',recipientID='22222222-2222-2222-2222-222222222222';
const raw=new TextEncoder().encode('%PDF-1.7 exact terminal original');
const sha=async(bytes:Uint8Array)=>[...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(b=>b.toString(16).padStart(2,'0')).join('');
test('terminal archive links must share the fresh final/report credential',()=>{
 const pair={final_pdf_url:`/sign/${token}/final-pdf`,audit_cert_url:`/sign/${token}/audit-cert`,package_portal_url:`/completed/${token}`};
 expect(completionArtifactLinks(pair,old)?.packagePortalURL).toBe(pair.package_portal_url);
 for(const bad of [`/completed/${old}`,`https://example.test/completed/${token}`,`/completed/${token}?other=1`])expect(completionArtifactLinks({...pair,package_portal_url:bad},old)).toBeNull();
});
test('ordinary archived absence is explicit and needs no invented package or notice',async()=>{
 const scope=await fetchCompletedPackage(token,new AbortController().signal,(async()=>new Response('{"package":null}',{headers:{'Content-Type':'application/json','X-Hash-Document-Id':documentID,'X-Hash-Recipient-Id':recipientID}})) as typeof fetch);
 expect(scope.value).toBeNull();
 await expect(fetchCompletedPackagePDF(scope,0,new AbortController().signal)).rejects.toThrow();
});
test('terminal downloads verify exact original bytes, pair and recipient scope',async()=>{
 const hash=await sha(raw),copy='I have reviewed and agree to the main document and every attachment listed in this contract package. My signature or acknowledgement applies to the complete package identified by the displayed commitments.';
 const value={schema:'hash-recipient-package-v1',package_id:documentID,revision:'1',manifest_sha256:'a'.repeat(64),legal_commitment_sha256:'b'.repeat(64),main:{title:'Original main',category:'',pdf_sha256:hash,bytes:raw.length,pages:1},annexes:[],incorporation:{version:'hash-package-incorporation-v1',sha256:await sha(new TextEncoder().encode(copy)),text:copy}};
 const packet=await fetchCompletedPackage(token,new AbortController().signal,(async()=>new Response(JSON.stringify({package:value}),{headers:{'Content-Type':'application/json','X-Hash-Document-Id':documentID,'X-Hash-Recipient-Id':recipientID}})) as typeof fetch);
 const headers={'Content-Type':'application/pdf','Content-Length':String(raw.length),'X-Hash-Document-Id':documentID,'X-Hash-Recipient-Id':recipientID,ETag:`"${value.manifest_sha256}.${value.legal_commitment_sha256}"`,'X-Hash-Package-Manifest-SHA256':value.manifest_sha256,'X-Hash-Package-Legal-Commitment-SHA256':value.legal_commitment_sha256,'X-Hash-Package-Member-Position':'0','X-Hash-PDF-SHA256':hash,'X-Hash-PDF-Bytes':String(raw.length),'X-Hash-PDF-Pages':'1'};
 const fetcher=(bytes:Uint8Array,overrides:Record<string,string>={})=>(async(input:RequestInfo|URL,init?:RequestInit)=>{expect(String(input)).toBe(`/sign/${token}/completed-package/members/0/pdf`);expect(new Headers(init?.headers).get('If-Match')).toBe(headers.ETag);return new Response(bytes,{headers:{...headers,...overrides}});}) as typeof fetch;
 expect(await fetchCompletedPackagePDF(packet,0,new AbortController().signal,fetcher(raw))).toEqual(raw);
 const wrong=raw.slice();wrong[0]^=1;
 await expect(fetchCompletedPackagePDF(packet,0,new AbortController().signal,fetcher(wrong))).rejects.toThrow();
 await expect(fetchCompletedPackagePDF(packet,0,new AbortController().signal,fetcher(raw,{'X-Hash-Recipient-Id':documentID}))).rejects.toThrow();
 await expect(fetchCompletedPackagePDF(packet,0,new AbortController().signal,fetcher(raw,{'X-Hash-Materialization-Revision':'1'}))).rejects.toThrow();
});

test('known current package requires its exact archive capability while ordinary historical pairs remain valid',()=>{
 const pair={final_pdf_url:`/sign/${token}/final-pdf`,audit_cert_url:`/sign/${token}/audit-cert`};
 expect(completionArtifactLinks(pair,old,true)).toBeNull();
 expect(completionArtifactLinks(pair,old,false)).toEqual({finalPDFURL:pair.final_pdf_url,auditCertURL:pair.audit_cert_url});
 for(const malformed of [undefined,null,false,'',`/completed/${old}`,`/completed/${token}?other=1`])expect(completionArtifactLinks({...pair,package_portal_url:malformed},old,true)).toBeNull();
 expect(completionArtifactLinks({...pair,package_portal_url:`/completed/${token}`},old,true)?.packagePortalURL).toBe(`/completed/${token}`);
});
