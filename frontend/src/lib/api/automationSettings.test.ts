import { afterEach, expect, test } from 'bun:test';
import { getAutomationPreferences, putAutomationPreferences, parseAutomationPreferences, parseReminderPolicy, getReminderPolicy, putReminderPolicy } from './automationSettings';
const originalFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = originalFetch; });
const id='a7ea9860-5397-47ad-8df4-334f31a75a99', stamp='2026-11-03T12:00:00Z';
const legacy={mode:'legacy',interval_days:0,max_fires:2,offsets_days:[3,7]};
const documentPolicy=()=>({schema_version:1,document_id:id,revision:0,updated_at:stamp,selection:{mode:'inherit',interval_days:0,max_fires:0,offsets_days:[]},effective_policy:legacy,source:'legacy',editable:true,frozen:false});
const prefs=()=>({schema_version:1,revision:0,updated_at:null,notify_viewed:false,notify_signed:false,viewed_scope:'first_view_per_recipient_per_send'});

test('preference HTTP requests are current-session only, bounded, no-store and refuse redirects',async()=>{
 const calls:{path:string;init:RequestInit}[]=[];
 globalThis.fetch=(async(path,init)=>{calls.push({path:String(path),init:init!});const body=init?.body?JSON.parse(String(init.body)):null;return Response.json(body?{...prefs(),revision:1,notify_viewed:body.notify_viewed,notify_signed:body.notify_signed}:prefs());}) as typeof fetch;
 const signal=new AbortController().signal, saved=await getAutomationPreferences(signal);
 await putAutomationPreferences(saved,{notify_viewed:true,notify_signed:false},signal);
 expect(calls.map(c=>c.path)).toEqual(['/api/v1/automation-preferences','/api/v1/automation-preferences']);
 for(const {init} of calls){expect(init.credentials).toBe('include');expect(init.cache).toBe('no-store');expect(init.redirect).toBe('error');expect(init.signal).toBe(signal);}
 expect(JSON.parse(String(calls[1].init.body))).toEqual({expected_revision:0,notify_viewed:true,notify_signed:false});
});
test('preferences reject malformed boolean/capability/revision rather than enabling a control',()=>{
 for(const bad of [{notify_viewed:'true'},{notify_signed:1},{viewed_scope:'email-open'},{revision:1.5},{revision:Number.MAX_SAFE_INTEGER+1}])expect(()=>parseAutomationPreferences({...prefs(),...bad})).toThrow();
});
test('real document policy PUT pins actual document observation and returns exact saved selection',async()=>{
 let sent:unknown;
 globalThis.fetch=(async(path,init)=>{expect(String(path)).toBe(`/api/v1/documents/${id}/reminder-policy`);sent=JSON.parse(String(init?.body));return Response.json({...documentPolicy(),revision:1,selection:{mode:'disabled',interval_days:0,max_fires:0,offsets_days:[]},effective_policy:{mode:'disabled',interval_days:0,max_fires:0,offsets_days:[]},source:'document'});}) as typeof fetch;
 const before=parseReminderPolicy(documentPolicy(),'document',id);
 const saved=await putReminderPolicy(before,{mode:'disabled',interval_days:0,max_fires:0},new AbortController().signal);
 expect(sent).toEqual({expected_revision:0,expected_updated_at:stamp,mode:'disabled',interval_days:0,max_fires:0});expect(saved.revision).toBe(1);
});
test('template defaults reject inheritance and do not pretend to require a document timestamp',async()=>{
 let sent:unknown;
 globalThis.fetch=(async(path,init)=>{expect(String(path)).toBe(`/api/v1/templates/${id}/reminder-policy`);sent=JSON.parse(String(init?.body));return Response.json({schema_version:1,template_id:id,revision:1,updated_at:stamp,policy:{mode:'interval',interval_days:5,max_fires:3,offsets_days:[5,10,15]}});}) as typeof fetch;
 const before=parseReminderPolicy({schema_version:1,template_id:id,revision:0,updated_at:null,policy:legacy},'template',id);
 await putReminderPolicy(before,{mode:'interval',interval_days:5,max_fires:3},new AbortController().signal);
 expect(sent).toEqual({expected_revision:0,mode:'interval',interval_days:5,max_fires:3});
 expect(()=>parseReminderPolicy({schema_version:1,template_id:id,revision:0,updated_at:null,policy:{mode:'inherit',interval_days:0,max_fires:0,offsets_days:[]}},'template',id)).toThrow();
});
test('foreign identities, unsafe ranges, wrong offsets and incoherent frozen capability refuse',()=>{
 for(const bad of [
  {...documentPolicy(),document_id:'8a2a3e55-32b3-4f80-a86f-9bb8f4398875'},
  {...documentPolicy(),updated_at:null}, {...documentPolicy(),editable:'true'}, {...documentPolicy(),frozen:true},
  {...documentPolicy(),effective_policy:{...legacy,offsets_days:[3,8]}},
  {...documentPolicy(),effective_policy:{mode:'interval',interval_days:2,max_fires:183,offsets_days:[]}},
 ])expect(()=>parseReminderPolicy(bad,'document',id)).toThrow();
 const frozen=parseReminderPolicy({...documentPolicy(),frozen:true,editable:false},'document',id);expect(frozen.frozen).toBe(true);expect(frozen.editable).toBe(false);
});
test('readonly saved policy never dispatches PUT and an oversized response is rejected',async()=>{
 let calls=0;globalThis.fetch=(async()=>{calls++;return new Response(' '.repeat(65537));}) as typeof fetch;
 const frozen=parseReminderPolicy({...documentPolicy(),source:'frozen',frozen:true,editable:false},'document',id);
 await expect(putReminderPolicy(frozen,{mode:'disabled',interval_days:0,max_fires:0},new AbortController().signal)).rejects.toThrow();expect(calls).toBe(0);
 await expect(getReminderPolicy('document',id,new AbortController().signal)).rejects.toThrow();expect(calls).toBe(1);
});
