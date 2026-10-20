#!/usr/bin/env python3
"""Finite host peer of the one-App logging delta and exact bounded packet."""
import ast
import hashlib
import importlib.util
import io
import json
import pathlib
import plistlib
import re
import shlex
import struct
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def main():
    out = N/'independent27-unbuffered-log-composition-peer-v1-attempt1'
    assert not out.exists()
    pins, checks = {}, []
    def exact(row):
        core = {k: row[k] for k in ('path', 'bytes', 'sha256')}
        assert pin(row['path']) == core, row['path']
        pins[row['path']] = core
        return pathlib.Path(row['path'])
    def load(name):
        path = N/name/'candidate.json'
        exact(pin(path)); exact(pin(path.parent/'freeze.json'))
        return path, json.loads(path.read_bytes())
    def check(value, label):
        assert value, label
        checks.append(label)
    packet_path, packet = load('independent27-unbuffered-log-device-v1-attempt1')
    check(pin(packet_path)['sha256'] == '3ec0d11a058bf0d1b39bcbcf50c5984ce0cb2383ad4a05cc69394221ba4624fd', 'exact concrete next packet')
    source_path, source = load('independent27-app-unbuffered-log-source-v9-attempt1')
    app_path, app = load('independent27-signed-app-unbuffered-log-product-v4-attempt1')
    old_app_path, old_app = load('independent27-signed-app-external-signature-product-v3-attempt1')
    runtime_path, runtime = load('independent27-signed-runtime-product-v4-attempt1')
    scope = json.loads(exact(packet['scope']).read_bytes())
    old_scope = json.loads(exact(scope['oldScope']).read_bytes())
    check(packet['runtimeCandidate'] == pin(runtime_path) and packet['appCandidate'] == pin(app_path), 'actual unchanged Runtime4 and fresh App9 joined')
    before = json.loads(exact(source['priorSourceCandidate']).read_bytes())
    old_text = exact(before['source']).read_text()
    new_text = exact(source['source']).read_text()
    insertion = '''    if (VZIndependent27SourceRouteSelected()) {
        int stderrStatus = setvbuf(stderr, NULL, _IONBF, 0);
        printf("[Independent27] startup-log uid=%u euid=%u stderrUnbufferedStatus=%d\\n",
            (unsigned)getuid(), (unsigned)geteuid(), stderrStatus);
    }
'''
    expected = old_text.replace('    setvbuf(stdout, NULL, _IONBF, 0);\n', '    setvbuf(stdout, NULL, _IONBF, 0);\n'+insertion, 1)
    statement = '                    BOOL loaded = VM27IndependentAppRuntimeLoadV1(startupRoot, &runtimeError);\n'
    added = '''                    printf("[Independent27] runtime-startup before-load uid=%u euid=%u\\n",
                        (unsigned)getuid(), (unsigned)geteuid());
'''+statement+'''                    printf("[Independent27] runtime-startup after-load uid=%u euid=%u\\n",
                        (unsigned)getuid(), (unsigned)geteuid());
'''
    check(old_text.count(statement) == 1 and expected.replace(statement, added, 1) == new_text, 'exact source delta: stderr buffering and three actual UID/eUID logs only')
    exact(source['sourceDiff']); exact(source['backendSource']); exact(source['preparer'])
    linked = json.loads(exact(app['sourceCandidate']).read_bytes())
    old_linked = json.loads(exact(old_app['sourceCandidate']).read_bytes())
    check(linked['sourceCandidate'] == pin(source_path) and linked['builder'] == old_linked['builder'], 'same actual source builder and new exact App9 source')
    exact(linked['builder'])
    check(len(linked['objects']) == len(old_linked['objects']) == 31, 'actual same31 compiled objects')
    changed_objects = []
    for i, (new, old) in enumerate(zip(linked['objects'], old_linked['objects'], strict=True)):
        if exact(new).read_bytes() != exact(old).read_bytes(): changed_objects.append(i)
    check(changed_objects == [0], 'only compiled App main object changed; Runtime4/finder/anchor/display/input exact')
    m = module('unbuffered_macho', exact(pin(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')))
    signing = module('unbuffered_signature', exact(pin(B/'review-independent27-signed-runtime-product-v2.py')))
    actual = exact(app['binary']).read_bytes(); unsigned = exact(linked['binary']).read_bytes()
    a, u = m.MachO(actual), m.MachO(unsigned)
    check(all(getattr(a,k) == getattr(u,k) for k in ('uuid','sections','exports','imports','binds','loads')), 'signing preserves actual UUID/geometry/exports/imports/PAC bindings/load commands')
    for sec in a.sections:
        if (sec['flags'] & 0xff) in (1, 12, 18): continue  # Mach-O zero-fill has no file bytes.
        start, size = sec['fileoff'], sec['size']
        check(actual[start:start+size] == unsigned[start:start+size], 'actual signing preserves file-backed section '+sec['segment']+':'+sec['name'])
    signature = signing.signed_image(pathlib.Path(app['binary']['path']), app['actualSignature'], {1:(pathlib.Path(app['app'])/'Info.plist').read_bytes(),3:(pathlib.Path(app['app'])/'_CodeSignature/CodeResources').read_bytes()})
    check(signature['cdhash'] == '72f455cd75b2c149c204f358188a820518fd1fba' and signature['actualCodePages'] == 53, 'only new App actual53 primary pages and all actual external/embedded slots rehashed')
    check(signature['embeddedEntitlements'] == old_app['actualSignature']['embeddedEntitlements'], 'exact original privileges retained')
    manifest = exact(runtime['manifest']).read_bytes()
    for symbol, data in [('VM27IndependentRuntimeManifestSHA256V1', hashlib.sha256(manifest).digest()), ('VM27IndependentRuntimeManifestBytesV1', struct.pack('<Q',len(manifest)))]:
        offset = a.file(a.base+a.exports['_'+symbol]['address'])
        check(a.data[offset:offset+len(data)] == data, 'actual unchanged Runtime4 strong anchor '+symbol)
    changed = []
    old_cd, new_cd = set(old_scope['trustCacheCDHashes']), set(scope['trustCacheCDHashes'])
    for new, old in zip(scope['files'],old_scope['files'],strict=True):
        check((new['archivePath'],new['devicePath']) == (old['archivePath'],old['devicePath']), 'same precise owned path '+new['archivePath'])
        if exact(new['local']).read_bytes() != exact(old['local']).read_bytes(): changed.append(new['devicePath'])
    check(len(scope['files']) == 252 and changed == [scope['deviceAppMain']] and len(new_cd) == len(old_cd) == 140 and len(new_cd & old_cd) == 139 and new_cd-old_cd == {signature['cdhash']} and scope['newTrustCacheCDHashes'] == [signature['cdhash']], 'exact one changed main/one new CD; other251 files and139 signed images unchanged')
    raw = exact(packet['archive']).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:') as archive:
        members = archive.getmembers();check(len(members)==1,'one canonical ordinary member')
        item=members[0]
        check(item.name=='new-0' and item.isreg() and not item.linkname and not item.pax_headers and item.uid==item.gid==item.mtime==0 and item.mode==0o600 and archive.extractfile(item).read()==actual,'actual one-main USTAR bytes only')
    controller = exact(packet['controller']).read_text(); old_controller = exact(packet['priorController']).read_text()
    trees=[ast.parse(x) for x in (controller,old_controller)]
    for name in ('run_remote','prior_receipt'):
        nodes=[next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name==name) for tree in trees]
        check(ast.dump(nodes[0],include_attributes=False)==ast.dump(nodes[1],include_attributes=False),'original transport and receipt AST '+name)
    process=[next(x.value.value for x in tree.body if isinstance(x,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='PROCESS_FUNCTIONS' for t in x.targets)) for tree in trees]
    check(process[0]==process[1],'exact original PID/UID/path/PPID/start-time signal guards')
    base=module('unbuffered_original_controller',N/'independent27-device-bootstrap-controller-v3-attempt1/control.py')
    fast=module('unbuffered_fast',B/'independent27_device_product_verify_fast_v1.py')
    check(process[0]==base.PROCESS_FUNCTIONS,'original process functions unchanged bytes')
    scripts={name:exact(row).read_text() for name,row in packet['scripts'].items()}
    for name,text in scripts.items():
        subprocess.run(['/bin/sh','-n'],input=text.encode(),check=True)
        limit=20 if name=='close-current-own' else 45
        check(f'timeout --signal=TERM --kill-after=3 {limit} /var/jb/bin/sh -c ' in text,'actual remote wall bound '+name)
        check(len((('sudo -k -S -p "" ' if name!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(text)).encode())+10000<262144,'actual quoted ARG_MAX margin '+name)
    base.DEVICE_STAGE=scope['deviceStage']; originals=base.make_scripts(scope,base.HEALTH.read_text())
    inside=lambda text:text.replace("'","'\"'\"'")
    check(scripts['launch']==originals['launch'].replace(inside(base.verify_products(scope)),inside(fast.batch_check(scope)),1),'launch process cleanup and real45 bound unchanged except already-reviewed finite verification')
    for name in ('register','post'):
        check(shlex.split(scripts[name])[-1]==originals[name].replace(base.verify_products(scope,include_cd=True),fast.batch_check(scope),1),'original '+name+' body except finite product verification')
    close=shlex.split(scripts['close-current-own'])[-1]
    tail=close.split(process[0],1)[1]
    check(tail.count('scan_own')==2 and tail.count('[ "$own_child_pid" = 0 ]')==2 and 'signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app' in tail and 'signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app' in tail and 'sleep 1' in tail,'close dynamically captures one exact current own App and refuses any child before TERM/KILL')
    check('cleanup_own' not in tail and 'signal_own' not in tail.replace('signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app','').replace('signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app','') and '70f9b69228485464b87966668ccaf34f314f0783c13fb431057b9ad1c89e935e' in tail,'close signals only captured App, leaves child/system/files/log untouched and checks actual old log')
    stage=shlex.split(scripts['stage'])[-1]
    check(stage.index('backup-0')<stage.index('backup-app-log')<stage.index('mv -f') and 'set -C' in stage and 'stage-complete' in stage,'actual old main and log full SHA backups precede same-parent atomic replacement and once-complete marker')
    trust=shlex.split(scripts['trust'])[-1]
    check(trust.count('jbctl trustcache add ')==1 and 'jbctl trustcache add '+signature['cdhash'] in trust and trust.index('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT')<trust.index('trust-dispatched')<trust.index('jbctl trustcache add '),'only one new TC after full actual252 SHA/meta/newCD and exclusive marker')
    for text in ["auth['scope'] == pin(packet/'scope.json')","auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']","auth['trustCacheRegistrationCount'] == 1","auth['initializationExternalWallSeconds'] == 45",'os.O_EXCL',"need(not output.exists(), 'serial action never repeated')","'preflight': 'close-current-own'"]:
        check(text in controller,'specific new authorization/once/predecessor gate '+text)
    startup=pathlib.Path(runtime['runtimeRoot'])/'parent-flat/VM27OwnedAppStartupV3.dylib'
    assembly=subprocess.run(['xcrun','llvm-objdump','--macho','--disassemble','--symbolize-operands',str(startup)],capture_output=True,check=True,timeout=20).stdout.decode()
    diagnostics=[]
    for name in ('RegistryCreateDiagnosticV4','RegistryRegisterDiagnosticV4','ConsumerCreateDiagnosticV4','ConsumerSpawnDiagnosticV4'):
        body=re.search(r'^_'+name+r':\n(.*?)(?=^_[A-Za-z_]|\Z)',assembly,re.M|re.S)[0]
        caller=[line for line in assembly.splitlines() if re.search(r'\bbl\s+_'+name+'$',line)]
        check(len(caller)==1 and 'symbol stub for: _fprintf' in body and '___stderrp' in body and 'status=%d' in body,'actual signed real caller/fprintf diagnostic '+name)
        diagnostics.append(dict(name=name,caller=caller[0],body=body))
    exact(pin(startup));exact(pin(N/'owned-startup-eacces-host-localization-v1-attempt1/report.json'));exact(pin(N/'independent27-startup13-ancestors-readonly-v1/receipt.json'))
    out.mkdir(mode=0o700)
    (out/'actual-startup-diagnostics.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
    report=dict(schema='Finite App9 real logging one-main and bounded packet independent peer v1',controllerPacketCandidate=pin(packet_path),finiteLocalScopePassed=True,findings=[],sourceCandidate=pin(source_path),actualAppCandidate=pin(app_path),unchangedRuntimeCandidate=pin(runtime_path),actualNewSignature=signature,checks=checks,deviceOperations=0,trustCacheOperations=0,actualGuestExecuted=False,boundaries=['Exact actual ancestor metadata disproved group-write as the previous device EACCES cause; no permission gate changed.','The current actual EACCES root cause remains unknown; this packet requests actual unbuffered diagnostic initialization only.','All four current signed Startup diagnostics call actual typed callees and real stderr fprintf; App9 preserves Runtime4, existing native/signature gates and worker/main queue lifecycle.','No139 signature-page repetition, CPU model repetition or device execution.','A prior local diagnostic harness incorrectly sliced zerofill __bss as file data; retained incomplete output is not a product finding.'])
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    for p in out.iterdir():exact(pin(p))
    exact(pin(__file__))
    (out/'freeze.json').write_text(json.dumps(dict(files=list(pins.values()),deviceOperations=0,findings=[]),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),actualChecks=len(checks))))


if __name__=='__main__':main()
