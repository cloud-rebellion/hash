import { checkedSignerPackageDescriptorsV1, readSignerPackagePDFBodyV1, type SignerPackage } from './signerPackage';
import { readBoundedSignerResponse } from './signerPDF';
import { AttachmentPreviewFamily } from './documentAttachmentPreview';

const TOKEN=/^[A-Za-z0-9_-]{43}$/;
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const unavailable='These archived contract files could not be verified. Use a current completion link or contact the sender.';
export type CompletedPackage=Readonly<{token:string;documentID:string;recipientID:string;value:SignerPackage|null}>;
function active(signal:AbortSignal){if(signal.aborted)throw new DOMException('The archive was closed.','AbortError');}
function identity(value:string|null):value is string{return !!value&&ID.test(value)&&value!=='00000000-0000-0000-0000-000000000000';}
export async function fetchCompletedPackage(token:string,signal:AbortSignal,fetcher:typeof fetch=fetch):Promise<CompletedPackage>{
 active(signal);if(!TOKEN.test(token))throw new Error(unavailable);
 const response=await fetcher(`/sign/${token}/completed-package`,{signal,cache:'no-store',credentials:'same-origin',headers:{Accept:'application/json'}});
 try{
  active(signal);
  const documentID=response.headers.get('X-Hash-Document-Id'),recipientID=response.headers.get('X-Hash-Recipient-Id');
  if(!response.ok||response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/json'||!identity(documentID)||!identity(recipientID))throw new Error(unavailable);
  const bytes=await readBoundedSignerResponse(response,64*1024,signal);
  const value=checkedSignerPackageDescriptorsV1(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
  if(value){
   const digest=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value.incorporation.text));active(signal);
   if([...new Uint8Array(digest)].map(b=>b.toString(16).padStart(2,'0')).join('')!==value.incorporation.sha256)throw new Error(unavailable);
  }
  return Object.freeze({token,documentID,recipientID,value});
 }catch(error){await response.body?.cancel().catch(()=>{});throw error;}
}
export async function fetchCompletedPackagePDF(packet:CompletedPackage,position:number,signal:AbortSignal,fetcher:typeof fetch=fetch):Promise<Uint8Array>{
 active(signal);const value=packet.value;
 if(!TOKEN.test(packet.token)||!value||!Number.isInteger(position)||position<0||position>value.annexes.length)throw new Error(unavailable);
 const selected=position===0?value.main:value.annexes[position-1];
 const etag=`"${value.manifest_sha256}.${value.legal_commitment_sha256}"`;
 const response=await fetcher(`/sign/${packet.token}/completed-package/members/${position}/pdf`,{signal,cache:'no-store',credentials:'same-origin',headers:{Accept:'application/pdf','If-Match':etag}});
 try{
  active(signal);
  if(!response.ok||response.headers.get('Content-Type')?.split(';')[0].trim().toLowerCase()!=='application/pdf')throw new Error(unavailable);
  const expected={'X-Hash-Document-Id':packet.documentID,'X-Hash-Recipient-Id':packet.recipientID,ETag:etag,'Content-Length':String(selected.bytes),'X-Hash-Package-Manifest-SHA256':value.manifest_sha256,'X-Hash-Package-Legal-Commitment-SHA256':value.legal_commitment_sha256,'X-Hash-Package-Member-Position':String(position),'X-Hash-PDF-SHA256':selected.pdf_sha256,'X-Hash-PDF-Bytes':String(selected.bytes),'X-Hash-PDF-Pages':String(selected.pages)};
  if(Object.entries(expected).some(([key,want])=>response.headers.get(key)!==want)||response.headers.has('X-Hash-HTML-Source-Commitment')||response.headers.has('X-Hash-Materialization-Revision'))throw new Error(unavailable);
  return await readSignerPackagePDFBodyV1(response,selected,signal);
 }catch(error){await response.body?.cancel().catch(()=>{});throw error;}
}

// One download/hash/temporary URL owner across portal remounts. A new owner
// joins actual predecessor promise retirement before allocating another body.
const downloads=new AttachmentPreviewFamily();
export function serialCompletedDownloadV1(task:()=>Promise<void>):Promise<void>{
 const result=downloads.current().then(task);
 downloads.join(result.catch(()=>{}));
 return result;
}
