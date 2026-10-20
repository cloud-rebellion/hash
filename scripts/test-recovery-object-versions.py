#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Hash-Sustainable-Use-License
# Copyright (c) Bright Interaction

"""Protocol regressions for the actual selected verifier, with no real services.

psql returns controlled canonical13-column rows; SQL grouping is NOT tested here.
aws is a closed local protocol peer. Real jq/hash/base64/awk utilities execute.
This proves neither an S3 provider nor a raw restore preserving VersionIds.
"""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

SYSTEM_PATH='/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin'
KEY='org/protocol/documents/agreement/shared policy Å.pdf'
DEADLINES={'version-A':'2035-01-01T00:00:00Z','version-B':'2038-01-01T00:00:00Z'}
SELECTED_SCRIPT=None
SELECTED_SQL=None
SELECTED_BASH=None
BASH_PIN=None
BASH_VERSION=None
SCRIPT_PIN=None
SQL_PIN=None
OUTPUT=None
HARD_DEADLINE=None
RESULTS=[]


def pin(path):
    p=Path(path)
    raw=p.read_bytes()
    return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':stat.S_IMODE(p.stat().st_mode)}


def bash_version(path):
    remaining=HARD_DEADLINE-time.monotonic()
    assert remaining>0,'whole-suite180s budget exhausted before interpreter verification'
    probe=subprocess.run([str(path),'--noprofile','--norc','--version'],stdin=subprocess.DEVNULL,
                         capture_output=True,timeout=min(5,remaining),
                         env={'PATH':SYSTEM_PATH,'LANG':'C','LC_ALL':'C'})
    assert probe.returncode==0 and len(probe.stdout)+len(probe.stderr)<=4096
    version=re.match(rb'GNU bash, version ([0-9]+)\.([0-9]+)\.([0-9]+)',probe.stdout)
    assert version is not None and int(version.group(1))>=5,'Bash5 or newer is required before case effects'
    return '.'.join(part.decode('ascii') for part in version.groups())


def private_write(path,raw,mode=0o600):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,mode)
    with os.fdopen(fd,'wb') as handle:
        os.fchmod(handle.fileno(),mode)
        handle.write(raw)


def encoded(raw):
    return base64.b64encode(raw).decode('ascii')


def sample(equal=False):
    bodies=[b'original retained policy bytes',b'original retained policy bytes' if equal else b'later independently retained policy bytes']
    versions=[]
    rows=[]
    for version,body in zip(('version-A','version-B'),bodies):
        versions.append({'id':version,'body_b64':encoded(body),'retention_mode':'COMPLIANCE','retain_until':DEADLINES[version]})
        rows.append({'version':version,'sha':hashlib.sha256(body).hexdigest(),'legal':True,'deadline':DEADLINES[version]})
    return {'key':KEY,'versions':versions,'rows':rows,'latest':'version-B','delete_markers':[],'multipart':[]}


def inventory_rows(fixture):
    rows=[]
    for row in fixture['rows']:
        columns=[encoded(fixture['key'].encode()),json.dumps(fixture['key'],ensure_ascii=False),
                 'document_final_pdf','document:protocol','protocol-org',row['sha'],
                 't' if row.get('hash_conflict') else 'f','t' if row.get('legal') else 'f','1',
                 row.get('version') or '-','t' if row.get('version_conflict') else 'f',
                 't' if row.get('legacy') else 'f',row.get('deadline','-')]
        assert len(columns)==13 and all('\t' not in value and '\n' not in value for value in columns)
        rows.append('\t'.join(columns))
    return '\n'.join(rows)+'\n'


# This executable is installed only as private aws/psql PATH entries. It has
# no network/subprocess module and no fallback to a real service executable.
FAKE_CLI=r'''
import base64,hashlib,json,os,sys
from pathlib import Path
fixture_path=Path(os.environ['HASH_RECOVERY_PROTOCOL_FIXTURE'])
fixture=json.loads(fixture_path.read_text())
audit_path=Path(os.environ['HASH_RECOVERY_PROTOCOL_AUDIT'])
program=Path(sys.argv[0]).name
args=sys.argv[1:]
def audit(value):
    with audit_path.open('a') as handle:
        handle.write(json.dumps(value,sort_keys=True)+'\n')
def refuse():
    audit({'program':program,'operation':'UNEXPECTED'})
    raise SystemExit(91)
def option(name):
    if name not in args:return None
    index=args.index(name)
    if index+1>=len(args):refuse()
    return args[index+1]
if program=='psql':
    target=option('--file')
    readonly='SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY; SET LOCAL jit = off;'
    if not target or '--single-transaction' not in args or option('--command')!=readonly:refuse()
    if hashlib.sha256(Path(target).read_bytes()).hexdigest()!=fixture['inventory_sha256']:refuse()
    audit({'program':'psql','operation':'canonical_inventory','readonly':True,'columns':13})
    sys.stdout.write(fixture['inventory_tsv'])
    raise SystemExit(0)
if program!='aws' or len(args)<2 or args[0]!='s3api':refuse()
operation=args[1]
allowed={'list-object-versions','list-multipart-uploads','get-object','head-object','get-object-retention','list-objects-v2'}
if operation not in allowed or option('--bucket')!='hash-recovery-protocol479':refuse()
key=option('--key')
version=option('--version-id')
audit({'program':'aws','operation':operation,'key':key,'version':version,'prefix':option('--prefix') is not None})
versions=fixture['versions']
if operation=='list-object-versions':
    records=[{'Key':fixture['key'],'VersionId':v['id'],'LastModified':'2026-01-01T00:00:00Z'} for v in versions]
    if option('--prefix') is not None:
        if option('--prefix')!=fixture['key'] or option('--max-keys')!='101' or '--no-paginate' not in args:refuse()
    result={'Versions':records,'DeleteMarkers':[{'Key':fixture['key'],'VersionId':v} for v in fixture['delete_markers']],'IsTruncated':False}
elif operation=='list-multipart-uploads':
    result={'Uploads':[{'Key':fixture['key'],'UploadId':v} for v in fixture['multipart']],'IsTruncated':False}
elif operation=='list-objects-v2':
    if option('--query')!='Contents[].Key' or option('--output')!='json':refuse()
    result=[] if fixture.get('latest_unavailable') else [fixture['key']]
else:
    if key!=fixture['key']:refuse()
    if version is None:
        if operation!='head-object':refuse()
        if fixture.get('latest_unavailable'):raise SystemExit(1)
        version=fixture['latest']
    selected=next((v for v in versions if v['id']==version),None)
    if selected is None:raise SystemExit(1)
    if operation=='get-object':
        if selected.get('get_error'):raise SystemExit(1)
        destination=Path(args[-1])
        if destination.parent.resolve()!=Path(os.environ['TMPDIR']).resolve():refuse()
        destination.write_bytes(base64.b64decode(selected['body_b64']))
        result={'VersionId':version}
    elif operation=='head-object':
        if selected.get('head_error'):raise SystemExit(1)
        result={'VersionId':version,'LastModified':'2026-01-01T00:00:00Z','ServerSideEncryption':selected.get('encryption','AES256')}
    elif operation=='get-object-retention':
        if selected.get('retention_error'):raise SystemExit(1)
        result={'Retention':{'Mode':selected.get('retention_mode','COMPLIANCE'),'RetainUntilDate':selected.get('retain_until','2040-01-01T00:00:00Z')}}
    else:refuse()
json.dump(result,sys.stdout)
sys.stdout.write('\n')
'''


class RecoveryVerifierProtocol479(unittest.TestCase):
    def run_case(self,name,fixture):
        self.assertGreater(HARD_DEADLINE-time.monotonic(),5,'whole-suite180s budget exhausted')
        self.assertEqual(pin(SELECTED_SCRIPT),SCRIPT_PIN)
        self.assertEqual(pin(SELECTED_SQL),SQL_PIN)
        self.assertEqual(pin(SELECTED_BASH),BASH_PIN)
        root=Path(tempfile.mkdtemp(prefix=name+'-',dir=OUTPUT/'work'))
        process=None
        joined=False
        group_absent=False
        retirement_attempted=False
        stdout=b'';stderr=b''
        result={'name':name,'exit_code':None,'assertions_completed':False}
        def group_gone():
            if process is None:return True
            try:os.killpg(process.pid,0)
            except ProcessLookupError:return True
            return False
        def receive(seconds):
            nonlocal stdout,stderr,joined
            if joined:return
            try:
                stdout,stderr=process.communicate(timeout=max(0.001,seconds))
                joined=True
            except subprocess.TimeoutExpired as exc:
                stdout=exc.output or b'';stderr=exc.stderr or b''
                raise
        def retire():
            nonlocal retirement_attempted
            if process is None or retirement_attempted:return
            retirement_attempted=True
            for sig in (signal.SIGTERM,signal.SIGKILL):
                until=time.monotonic()+2
                if not group_gone():
                    try:os.killpg(process.pid,sig)
                    except ProcessLookupError:pass
                if not joined:
                    try:receive(until-time.monotonic())
                    except subprocess.TimeoutExpired:pass
                while not group_gone() and time.monotonic()<until:time.sleep(0.01)
                if joined and group_gone():return
        try:
            for directory in ('bin','tmp','package/scripts','package/ops'):
                (root/directory).mkdir(mode=0o700,parents=True,exist_ok=True)
            verifier=root/'package/scripts/verify-recovery-objects.sh'
            inventory=root/'package/ops/recovery-object-inventory.sql'
            private_write(verifier,SELECTED_SCRIPT.read_bytes(),0o700)
            private_write(inventory,SELECTED_SQL.read_bytes())
            fixture=copy.deepcopy(fixture)
            fixture['inventory_tsv']=inventory_rows(fixture)
            fixture['inventory_sha256']=SQL_PIN['sha256']
            fixture_path=root/'fixture.json'
            private_write(fixture_path,(json.dumps(fixture,ensure_ascii=False)+'\n').encode())
            self.assertFalse(any(ch.isspace() for ch in sys.executable),'private fake shebang requires a whitespace-free interpreter path')
            executable=('#!'+sys.executable+' -I\n'+FAKE_CLI).encode()
            for command in ('aws','psql'):
                private_write(root/'bin'/command,executable,0o700)
            audit_path=root/'calls.jsonl'
            private_write(audit_path,b'')
            environment={'PATH':str(root/'bin')+':'+SYSTEM_PATH,'TMPDIR':str(root/'tmp'),
                         'LANG':'C','LC_ALL':'C','AWS_EC2_METADATA_DISABLED':'true',
                         'AWS_CONFIG_FILE':str(root/'nonexistent-aws-config'),'AWS_SHARED_CREDENTIALS_FILE':str(root/'nonexistent-aws-credentials'),
                         'PGHOST':'127.0.0.1','PGPORT':'1','PGDATABASE':'protocol479','PGUSER':'protocol479','PGPASSFILE':str(root/'nonexistent-pgpass'),
                         'HASH_RECOVERY_PROTOCOL_FIXTURE':str(fixture_path),'HASH_RECOVERY_PROTOCOL_AUDIT':str(audit_path)}
            command=[str(SELECTED_BASH),str(verifier),'--bucket','hash-recovery-protocol479','--database','protocol479','--output',str(root/'evidence')]
            started=time.monotonic()
            process=subprocess.Popen(command,env=environment,cwd=root,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:receive(min(20,HARD_DEADLINE-time.monotonic()-4))
            except subprocess.TimeoutExpired:
                result['timed_out']=True
                retire()
                self.fail('actual verifier exceeded case20s/shared180s budget')
            group_absent=group_gone()
            result.update(exit_code=process.returncode,wall_seconds=round(time.monotonic()-started,3),group_absent=group_absent)
            self.assertTrue(joined and group_absent,'verifier child/group retirement was not confirmed')
            self.assertLessEqual(len(stdout)+len(stderr),1<<20,'post-capture verifier output assertion exceeded1MiB')
            self.assertEqual(list((root/'tmp').iterdir()),[],'actual verifier EXIT trap left private scratch files')
            report={}
            for line in (root/'evidence/recovery-object-verification-report.txt').read_text().splitlines():
                key,value=line.split('=',1)
                self.assertNotIn(key,report)
                report[key]=value
            calls=[json.loads(line) for line in audit_path.read_text().splitlines()]
            self.assertFalse(any(call['operation']=='UNEXPECTED' for call in calls),'actual script attempted an unsupported service command')
            self.assertEqual([c['operation'] for c in calls if c['program']=='psql'],['canonical_inventory'])
            self.assertEqual(sum(c['operation']=='list-object-versions' and not c.get('prefix') for c in calls),2)
            self.assertEqual(sum(c['operation']=='list-multipart-uploads' for c in calls),2)
            files={p.name:p.read_text() for p in (root/'evidence').iterdir() if p.is_file()}
            result.update(report=report,calls=calls,files=files,verifier_scratch_absent=True)
            self.assertEqual(pin(SELECTED_SCRIPT),SCRIPT_PIN)
            self.assertEqual(pin(SELECTED_SQL),SQL_PIN)
            self.assertEqual(pin(SELECTED_BASH),BASH_PIN)
            result['assertions_completed']=True
            return result
        except BaseException as exc:
            result['exception_type']=type(exc).__name__
            raise
        finally:
            try:
                if process is not None and not (joined and group_gone()):retire()
            except BaseException as exc:
                result['retirement_error']=type(exc).__name__
            group_absent=group_gone()
            safe_remove=process is None or (joined and group_absent)
            result.update(group_absent=group_absent,direct_child_joined=joined if process is not None else None,
                          stdout_sha256=hashlib.sha256(stdout).hexdigest(),stderr_sha256=hashlib.sha256(stderr).hexdigest())
            if process is not None:result['exit_code']=process.returncode
            if safe_remove:
                try:shutil.rmtree(root)
                except BaseException as exc:result['sandbox_cleanup_error']=type(exc).__name__
            else:result['retained_sandbox']=str(root)
            result['case_sandbox_absent']=not root.exists()
            RESULTS.append(result)
            private_write(OUTPUT/(name+'.stdout'),stdout)
            private_write(OUTPUT/(name+'.stderr'),stderr)
            private_write(OUTPUT/(name+'.json'),(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode())
            self.assertTrue(safe_remove,'unconfirmed child/group retirement: private sandbox retained')
            self.assertTrue(result['case_sandbox_absent'],'case sandbox was not removed')

    def assert_result(self,result,code,kind,**counts):
        self.assertEqual(result['exit_code'],code)
        self.assertEqual(result['report']['RESULT'],kind)
        for key,value in counts.items():self.assertEqual(int(result['report'][key]),value,key)

    def assert_exact_calls(self,result,versions=('version-A','version-B'),retention=('version-A','version-B')):
        for version in versions:
            for operation in ('get-object','head-object'):
                self.assertGreaterEqual(sum(c['operation']==operation and c.get('version')==version for c in result['calls']),1,(operation,version))
        for version in retention:
            self.assertGreaterEqual(sum(c['operation']=='get-object-retention' and c.get('version')==version for c in result['calls']),1,version)
        self.assertTrue(all(c.get('version') is not None for c in result['calls'] if c['operation'] in ('get-object','get-object-retention')))

    def test_two_pinned_versions_verify_both_equal_and_changed_bytes(self):
        for equal in (True,False):
            with self.subTest(equal=equal):
                result=self.run_case('both-verified-equal' if equal else 'both-verified-changed',sample(equal))
                self.assert_result(result,0,'PASS',SHADOWED_REFERENCED_OBJECTS=0,ADDITIONAL_PROVIDER_VERSIONS=0,HASH_MISMATCHES=0,INVALID_LEGAL_EVIDENCE_RETENTION=0)
                self.assert_exact_calls(result)
                self.assertEqual(set(result['files']['verified-reference-versions.tsv'].splitlines()),
                                 {encoded(KEY.encode())+'\t'+encoded(version.encode()) for version in ('version-A','version-B')})

    def test_same_tuple_hash_conflict_refuses(self):
        fixture=sample();fixture['versions']=fixture['versions'][:1];fixture['rows']=fixture['rows'][:1];fixture['latest']='version-A';fixture['rows'][0]['hash_conflict']=True
        result=self.run_case('same-tuple-conflict',fixture)
        self.assert_result(result,1,'FAIL',DB_HASH_CONFLICTS=1)
        self.assertEqual(result['files']['verified-reference-versions.tsv'],'')

    def test_unreferenced_latest_and_historical_versions_require_review(self):
        for latest in (True,False):
            with self.subTest(latest=latest):
                fixture=sample();fixture['versions'].append({'id':'extra-version','body_b64':encoded(b'unreferenced bytes')})
                if latest:fixture['latest']='extra-version'
                result=self.run_case('extra-latest' if latest else 'extra-historical',fixture)
                self.assert_result(result,2,'REVIEW',ADDITIONAL_PROVIDER_VERSIONS=1)
                self.assertEqual(int(result['report']['SHADOWED_REFERENCED_OBJECTS']),2 if latest else 0)
                self.assert_exact_calls(result)

    def test_delete_marker_and_multipart_require_review(self):
        for marker in (True,False):
            with self.subTest(delete_marker=marker):
                fixture=sample()
                if marker:fixture['delete_markers']=['delete-marker'];fixture['latest_unavailable']=True
                else:fixture['multipart']=['unfinished-upload']
                result=self.run_case('delete-marker' if marker else 'multipart',fixture)
                self.assert_result(result,2,'REVIEW',**({'PROVIDER_DELETE_MARKERS':1} if marker else {'PROVIDER_MULTIPART_UPLOADS':1}))
                self.assert_exact_calls(result)

    def test_referenced_latest_with_failed_proof_keeps_shadow(self):
        for fault in ('wrong-bytes','db-hash-conflict','short-retention','retention-read-error','head-error','encryption'):
            with self.subTest(fault=fault):
                fixture=sample();later=fixture['versions'][1]
                if fault=='wrong-bytes':later['body_b64']=encoded(b'wrong returned bytes')
                elif fault=='db-hash-conflict':fixture['rows'][1]['hash_conflict']=True
                elif fault=='short-retention':later['retain_until']='2030-01-01T00:00:00Z'
                elif fault=='retention-read-error':later['retention_error']=True
                elif fault=='head-error':later['head_error']=True
                else:later['encryption']='aws:kms'
                result=self.run_case('latest-'+fault,fixture)
                self.assert_result(result,1,'FAIL')
                counter='DB_HASH_CONFLICTS' if fault=='db-hash-conflict' else 'INVALID_LEGAL_EVIDENCE_RETENTION' if fault in ('short-retention','retention-read-error') else 'HASH_MISMATCHES'
                self.assertEqual(int(result['report'][counter]),1)
                self.assertGreaterEqual(int(result['report']['SHADOWED_REFERENCED_OBJECTS']),1)
                self.assertNotIn(encoded(KEY.encode())+'\t'+encoded(b'version-B'),result['files']['verified-reference-versions.tsv'].splitlines())
                self.assert_exact_calls(result,versions=('version-A',) if fault=='wrong-bytes' else ('version-A','version-B'),
                                        retention=('version-A','version-B') if fault in ('db-hash-conflict','short-retention','retention-read-error') else ('version-A',))
                self.assertTrue(any(c['operation']=='get-object' and c.get('version')=='version-B' for c in result['calls']))

    def test_referenced_latest_without_digest_keeps_shadow(self):
        fixture=sample();fixture['rows'][1].update(sha='-',legal=False,deadline='-')
        result=self.run_case('latest-without-digest',fixture)
        self.assert_result(result,2,'REVIEW',SHADOWED_REFERENCED_OBJECTS=1)
        self.assertNotIn(encoded(KEY.encode())+'\t'+encoded(b'version-B'),result['files']['verified-reference-versions.tsv'].splitlines())
        self.assert_exact_calls(result,retention=('version-A',))

    def test_mixed_legacy_reference_does_not_mask_retention_failure(self):
        fixture=sample();legacy=dict(fixture['rows'][1]);legacy.update(version=None,legal=False,deadline='-',legacy=True)
        fixture['rows'].append(legacy);fixture['versions'][1]['retain_until']='2030-01-01T00:00:00Z'
        result=self.run_case('mixed-legacy-retention',fixture)
        self.assert_result(result,1,'FAIL',INVALID_LEGAL_EVIDENCE_RETENTION=1)
        self.assertGreaterEqual(int(result['report']['SHADOWED_REFERENCED_OBJECTS']),1)
        self.assert_exact_calls(result)
        self.assertEqual(sum(c['operation']=='get-object' and c.get('version')=='version-B' for c in result['calls']),2)

    def test_missing_required_pin_and_legacy_search_cap_refuse(self):
        fixture=sample();fixture['rows'][1].update(version=None,version_conflict=True)
        result=self.run_case('required-missing-pin',fixture)
        self.assert_result(result,1,'FAIL',DB_VERSION_ID_CONFLICTS=1)
        self.assertFalse(any(c['operation']=='get-object' and c.get('version')=='version-B' for c in result['calls']))
        fixture=sample();fixture['versions']=[{'id':'history-'+str(i),'body_b64':encoded(('other-'+str(i)).encode())} for i in range(101)]
        fixture['latest']='history-100';fixture['rows']=[{'version':None,'sha':hashlib.sha256(b'absent expected bytes').hexdigest(),'legal':False,'legacy':True}]
        result=self.run_case('legacy-cap101',fixture)
        self.assert_result(result,1,'FAIL',HASH_MISMATCHES=1)
        self.assertIn('VERSION_SEARCH_EXCEEDS_100',result['files']['hash-mismatches.tsv'])
        self.assertTrue(any(c['operation']=='list-object-versions' and c['prefix'] for c in result['calls']))


def main():
    global SELECTED_SCRIPT,SELECTED_SQL,SELECTED_BASH,BASH_PIN,BASH_VERSION,SCRIPT_PIN,SQL_PIN,OUTPUT,HARD_DEADLINE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verifier',type=Path,required=True)
    parser.add_argument('--verifier-sha256',required=True)
    parser.add_argument('--inventory',type=Path,required=True)
    parser.add_argument('--inventory-sha256',required=True)
    parser.add_argument('--bash',type=Path,required=True)
    parser.add_argument('--bash-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    HARD_DEADLINE=time.monotonic()+180
    os.umask(0o077)
    SELECTED_SCRIPT=args.verifier;SELECTED_SQL=args.inventory;OUTPUT=args.output
    for path,digest in ((SELECTED_SCRIPT,args.verifier_sha256),(SELECTED_SQL,args.inventory_sha256)):
        assert path.is_absolute() and path.is_file() and not path.is_symlink() and re.fullmatch('[0-9a-f]{64}',digest)
        assert pin(path)['sha256']==digest
    SCRIPT_PIN=pin(SELECTED_SCRIPT);SQL_PIN=pin(SELECTED_SQL)
    SELECTED_BASH=args.bash
    assert SELECTED_BASH.is_absolute() and SELECTED_BASH.resolve()==SELECTED_BASH and SELECTED_BASH.is_file() and not SELECTED_BASH.is_symlink()
    assert re.fullmatch('[0-9a-f]{64}',args.bash_sha256)
    BASH_PIN=pin(SELECTED_BASH)
    assert BASH_PIN['sha256']==args.bash_sha256 and BASH_PIN['mode']&0o111
    BASH_VERSION=bash_version(SELECTED_BASH)
    assert OUTPUT.is_absolute() and OUTPUT.resolve()==OUTPUT and not OUTPUT.exists() and OUTPUT.parent.is_dir()
    OUTPUT.mkdir(mode=0o700);(OUTPUT/'work').mkdir(mode=0o700)
    tools={}
    for tool in ('jq','awk','sort','comm','base64','tr','wc','cmp','stat','mktemp','dirname','basename','mkdir','rm','cat','date'):
        selected=shutil.which(tool,path=SYSTEM_PATH);assert selected,tool
        tools[tool]=pin(Path(selected).resolve())
    selected=shutil.which('sha256sum',path=SYSTEM_PATH) or shutil.which('shasum',path=SYSTEM_PATH)
    assert selected;tools['sha256']=pin(Path(selected).resolve())
    tools['bash']=BASH_PIN
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RecoveryVerifierProtocol479)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    work_empty=not list((OUTPUT/'work').iterdir())
    bash_after=None;interpreter_error=None
    try:
        bash_after=pin(SELECTED_BASH)
        assert bash_after==BASH_PIN and bash_version(SELECTED_BASH)==BASH_VERSION
    except Exception as exc:interpreter_error=type(exc).__name__
    accepted=result.wasSuccessful() and result.testsRun==8 and len(RESULTS)==17 and not result.skipped and work_empty and interpreter_error is None
    summary={'schema':'hash-recovery-versions479-protocol-result-v1','passed':accepted,'unittest_tops':result.testsRun,'case_count':len(RESULTS),
             'failures':len(result.failures),'errors':len(result.errors),'skips':len(result.skipped),'verifier':SCRIPT_PIN,'inventory':SQL_PIN,'tools':tools,
             'all_case_sandboxes_absent':all(row['case_sandbox_absent'] for row in RESULTS),'scope':'actual verifier command/protocol only; controlled psql rows and fake read-only S3 API, no real SQL grouping, provider, credentials, raw restore or release acceptance'}
    summary['all_case_process_groups_absent']=all(row['group_absent'] for row in RESULTS)
    summary['all_case_work_removed']=work_empty
    summary['bash_before']=dict(BASH_PIN,version=BASH_VERSION)
    summary['bash_after']=bash_after
    summary['bash_version_after']=BASH_VERSION if interpreter_error is None else None
    summary['interpreter_error']=interpreter_error
    private_write(OUTPUT/'result.json',(json.dumps(summary,indent=2)+'\n').encode())
    return 0 if accepted else 1


if __name__=='__main__':
    raise SystemExit(main())
