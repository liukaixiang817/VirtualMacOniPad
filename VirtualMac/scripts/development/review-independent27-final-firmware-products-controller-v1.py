#!/usr/bin/env python3
"""Host-only finite final manifest/App/controller composition review."""
from pathlib import Path
import argparse, ast, difflib, hashlib, importlib.util, json, plistlib, re, shlex, struct, subprocess, sys
sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = R/'VirtualMac/scripts/development'
S = R/'VirtualMac/vz/host'

def need(v, m):
    if not v: raise ValueError(m)

def pin(p):
    p = Path(p); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def check(p):
    need(pin(p['path']) == p, 'actual pin '+p['path'])

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result

def save(path, data):
    path.write_text(json.dumps(data, indent=2)+'\n')

def main():
    a = argparse.ArgumentParser(); a.add_argument('--output', required=True, type=Path); out = a.parse_args().output.resolve()
    need(out.parent == N and not out.exists(), 'fresh local output'); out.mkdir()
    packet = N/'independent27-device-bootstrap-controller-v3-attempt1'
    c = json.loads((packet/'candidate.json').read_bytes()); scope = json.loads((packet/'scope.json').read_bytes())
    frozen = json.loads((packet/'freeze.json').read_bytes())
    for row in frozen['files']: check(row)
    need(pin(packet/'candidate.json')['sha256'] == '7813905dd96f9e704e7f128a0ac36aeed241b21aecec62b0fa640ec589a2456b', 'specific current concrete packet')
    app = json.loads(Path(scope['appCandidate']['path']).read_bytes()); runtime = json.loads(Path(scope['runtimeCandidate']['path']).read_bytes())
    linked = json.loads(Path(app['sourceCandidate']['path']).read_bytes())
    check(app['sourceCandidate']); check(app['runtimeCandidate']); check(linked['sourceCandidate']); check(runtime['anchorSource']); check(runtime['manifest'])
    oldlinked = json.loads((N/'independent27-actual-app-linked-v8-attempt1/candidate.json').read_bytes())
    need(linked['sourceCandidate'] == oldlinked['sourceCandidate'], 'same frozen App8 source, no new source model')
    old_sources = [x for x in oldlinked['sourceFiles'] if not x['path'].endswith('vm27_independent_runtime_product_anchor_v1.c')]
    sources = [x for x in linked['sourceFiles'] if not x['path'].endswith('vm27_independent_runtime_product_anchor_v1.c')]
    need(old_sources == sources and len(sources) == 29, 'all actual 29 App translation-unit sources unchanged')
    need(len(linked['objects']) == 30 and len(linked['sourceFiles']) == 30 and runtime['anchorSource'] in linked['sourceFiles'], 'actual thirty units with fresh true anchor')
    for row in linked['sourceFiles'] + linked['objects']: check(row)
    raw = Path(runtime['manifest']['path']).read_bytes(); manifest = plistlib.loads(raw)
    need(runtime['files'] == len(manifest['files']) == 148, 'new manifest truly includes five firmware data files')
    firmware = [x for x in manifest['files'] if x['role'] == 'firmware']
    original = json.loads((N/'original27-firmware-resource-layout-data-v1-attempt1/candidate.json').read_bytes())
    need(len(firmware) == 5 and {x['path'] for x in firmware} == {x['relativePath'] for x in original['resources']}, 'five actual canonical firmware rows')
    for row in firmware:
        source = next(x for x in original['resources'] if x['relativePath'] == row['path'])
        p = Path(runtime['runtimeRoot'])/row['path']; b = p.read_bytes()
        need(row['kind'] == 'resource' and len(b) == row['bytes'] == source['local']['bytes'] and
             hashlib.sha256(b).hexdigest() == row['sha256'] == source['local']['sha256'], 'actual manifest bound firmware bits')
    # Source delta stays outside all existing signing and process-isolation code.
    v1 = (B/'build-independent27-signed-runtime-product-v1.py').read_text()
    v2 = (B/'build-independent27-signed-runtime-product-v2.py').read_text()
    functions = lambda text: {n.name: ast.dump(n, include_attributes=False) for n in ast.parse(text).body if isinstance(n, ast.FunctionDef)}
    f1, f2 = functions(v1), functions(v2)
    need(set(f1) == set(f2) and {k for k in f1 if f1[k] != f2[k]} == {'read_inputs','assemble','main'}, 'only firmware input/copy/freeze functions changed')
    diff = ''.join(difflib.unified_diff(v1.splitlines(True), v2.splitlines(True), fromfile='builder-v1', tofile='builder-v2'))
    (out/'runtime-builder-source-diff.patch').write_text(diff)
    need("kind='resource',role='firmware'" in v2 and "len(firmware)==5" in v2 and "'Firmware27/'+n" in v2, 'finite genuine data resource construction')
    validate = (S/'vm27_independent_app_runtime_v1.m').read_text()
    need('64*1024*1024' in validate and '[parsed[@"files"] count]>256' in validate and
         'data.length!=[row[@"bytes"] unsignedLongLongValue]' in validate and
         '! [row[@"kind"] isEqual:@"resource"]' not in validate and '[row[@"kind"] isEqual:@"resource"]' in validate,
         'actual inherited loader reads and hashes bounded ordinary firmware data')
    image_reader = module('finite_final_macho', N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py')
    signed = image_reader.MachO(Path(app['binary']['path']).read_bytes()); unsigned = image_reader.MachO(Path(linked['binary']['path']).read_bytes())
    for key in ('uuid','sections','imports','binds','exports'):
        need(getattr(signed,key) == getattr(unsigned,key), 'actual sign preserves '+key)
    for sec in unsigned.sections:
        at, size = sec['fileoff'], sec['size']
        if at and size and sec['flags'] & 255 not in (1,12,18):
            need(signed.data[at:at+size] == unsigned.data[at:at+size], 'actual signed section bytes unchanged '+sec['name'])
    digest_rva = signed.exports['_VM27IndependentRuntimeManifestSHA256V1']['address']
    length_rva = signed.exports['_VM27IndependentRuntimeManifestBytesV1']['address']
    need(signed.data[signed.file(signed.base+digest_rva):][:32] == hashlib.sha256(raw).digest() and
         struct.unpack_from('<Q',signed.data,signed.file(signed.base+length_rva))[0] == len(raw), 'actual signed main carries this manifest digest and 42427 size')
    need(app['realCompiledManifestAnchor'] == runtime['anchorSource'] and len(signed.data) <= 2*1024*1024, 'true fresh anchor and bounded Runtime3 self inspector')
    signatures = module('finite_final_signature', B/'review-independent27-signed-runtime-product-v1.py')
    app_reader = module('finite_final_der', B/'review-independent27-app8-signed-main-v1.py')
    root = Path(app['app']); sig = signatures.signed_image(Path(app['binary']['path']), app['actualSignature'],
                   {1:(root/'Info.plist').read_bytes(),3:(root/'_CodeSignature/CodeResources').read_bytes()})
    need(json.loads(json.dumps(sig)) == app['actualSignature'], 'actual 53 primary pages and all real special slots independently parsed')
    slots = app_reader.signature_slots(signed.data)
    need(plistlib.loads(slots[5][8:]) == app_reader.der_entitlements(slots[7]) == plistlib.loads((S/'VirtualMac.entitlements').read_bytes()), 'actual XML/DER true permissions')
    app_report = dict(schema='Finite new firmware builder and actual App anchor signature review v1',
        appCandidate=scope['appCandidate'], runtimeCandidate=scope['runtimeCandidate'], linkedCandidate=app['sourceCandidate'],
        manifest=runtime['manifest'], compiledAnchor=runtime['anchorSource'], actualSignedMain=app['binary'], actualSignature=sig,
        unchangedAppSources=29, actualCompiledUnits=30, builderSourceDiff=pin(out/'runtime-builder-source-diff.patch'),
        builderV2=pin(B/'build-independent27-signed-runtime-product-v2.py'), actualFirmwareFiles=firmware,
        actualManifestFileCount=148, finiteLocalScopePassed=True, findings=[],
        priorApp8SourceReview=pin(N/'app8-signed-main-independent-review-v1-attempt1/review.json'),
        resourceRecipeReview=pin(N/'original27-firmware-layout-independent-review-v1-attempt1/review.json'),
        runtime139ImageSignatureRepetitionPerformed=False, deviceOperations=0, trustCacheOperations=0)
    save(out/'app-and-runtime-review.json',app_report)
    control = module('finite_final_controller',packet/'control.py')
    prior_control = module('finite_prior_controller',N/'independent27-device-bootstrap-controller-v2-attempt1/control.py')
    need(control.PROCESS_FUNCTIONS == prior_control.PROCESS_FUNCTIONS, 'all five already passed exact process models inherited unchanged')
    prior_review = N/'independent27-controller-v2-finite-local-review-v1-attempt1/review.json'
    inherited = json.loads(prior_review.read_bytes()); need(inherited['hostProcessModelCasesPassed'] == 5, 'actual prior shell model evidence')
    check(inherited['processModels']); control.validate_archive((packet/'products.tar').read_bytes(),scope)
    scripts = control.make_scripts(scope, control.HEALTH.read_text())
    sizes=[]; registered=[]
    for action,row in c['scripts'].items():
        check(row); text=Path(row['path']).read_text(); need(scripts[action] == text, 'actual full shell regenerated '+action)
        result=subprocess.run(['/bin/sh','-n'],input=text.encode(),capture_output=True,timeout=10); need(result.returncode==0, 'actual shell syntax '+action)
        command=('sudo -k -S -p "" 'if action!='launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(text)
        sizes.append(dict(action=action,scriptBytes=len(text.encode()),SSHCommandBytes=len(command.encode())))
    for i,action in enumerate(control.TRUST_ACTIONS):
        body=shlex.split(scripts[action])[-1]
        selected=re.findall(r'^jbctl trustcache add ([a-f0-9]{40})$',body,re.M)
        need(selected==scope['trustCacheCDHashes'][20*i:20*(i+1)] and len(selected)==20, 'actual fixed exact trust additions '+action)
        registered.extend(selected)
        if i==0:
            pre=body[:body.index('jbctl trustcache add ')]
            verify=control.verify_products(scope,include_cd=True)
            need(verify in pre and sum(line.startswith('verify_file ')for line in verify.splitlines()) == 252 and
                 sum(line.startswith('verify_cd ')for line in verify.splitlines()) == 140, 'all final bytes and all CD before first TC addition')
    need(registered==scope['trustCacheCDHashes'] and len(set(registered))==140, 'true once-only unique set, not firmware trust entries')
    stage=scripts['stage']
    need('own_app_identity' not in stage and 'own_runtime_identity' in stage and
         'verify_dir "$OWN_APP" 755' in stage and 'mv "$OWN_STAGE/VirtualMacIndependent27.app" "$OWN_APP"' in stage,
         'cross-volume copy allowed only App, same-volume Runtime inode still checked')
    fs=N/'independent27-staging-filesystems-readonly-v1/receipt.json'; fp=json.loads(fs.read_bytes());check(fp['stdout'])
    actual_fs=Path(fp['stdout']['path']).read_text()
    need(fp['transportExit']==0 and 'OWN_DATA_PARENT_STAT 16777220:'in actual_fs and
         'OWN_PREBOOT_PARENT_STAT 16777223:'in actual_fs and 'OWN_ROOT_ENV_BYTES 4514'in actual_fs and
         'OWN_SUDO_COMMAND_BYTES 4111'in actual_fs, 'actual cross-volume and bounded sudo environment evidence')
    argmax=N/'independent27-kernel-argmax-readonly-v1/receipt.json'; ap=json.loads(argmax.read_bytes());check(ap['stdout'])
    need('OWN_KERNEL_ARG_MAX 262144'in Path(ap['stdout']['path']).read_text(), 'actual kernel argument budget')
    need(max(x['SSHCommandBytes'] for x in sizes)+4514+4096 <262144, 'all concrete argv plus measured truncated sudo environment fit with extra4KiB')
    src=(packet/'control.py').read_text(); old=(N/'independent27-device-bootstrap-controller-v2-attempt1/control.py').read_text()
    (out/'controller-source-diff.patch').write_text(''.join(difflib.unified_diff(old.splitlines(True),src.splitlines(True),fromfile='controller-v2',tofile='controller-v3')))
    for name in ('ready_gate','run_remote','prior_receipt','dispatch'):
        need(functions(src)[name]==functions(old)[name], 'exact prior authorization/once/remote/receipt behavior '+name)
    review=dict(schema='Finite final exact independent27 bootstrap controller peer v1',
        controllerPacketCandidate=pin(packet/'candidate.json'), packetFreeze=pin(packet/'freeze.json'),
        appAndRuntimeReview=pin(out/'app-and-runtime-review.json'), scope=c['scope'], archive=c['archive'], controller=c['controller'],
        freezePinsChecked=len(frozen['files']), canonicalUSTARExact=True, archiveBytes=c['archive']['bytes'],
        actualFiles=252, actualFirmwareFiles=5, actualTrustCacheCDHashes=scope['trustCacheCDHashes'], actualTrustCacheCount=140,
        actualFixedTrustBatches=[20]*7, allFinalFileHashesAndAllCDBeforeFirstTC=True,
        inheritedProcessModels=inherited['processModels'], inheritedProcessFunctionsUnchanged=True,
        processModelsRepeated=False, concreteCommandSizes=sizes, actualFilesystemAndEnvironmentReceipt=pin(fs), actualArgmaxReceipt=pin(argmax),
        controllerSourceDiff=pin(out/'controller-source-diff.patch'),finiteLocalScopePassed=True,findings=[],
        readyForRootSerialDispatchAfterExactNewHumanAuthorization=True, authorizationGenerated=False,
        boundaries=['This review grants no persistent trust-cache authorization. Exact new human authorization remains required by the unchanged controller gate.',
                    'Only library launch and actual parent/child initialization are requested, not guest start.',
                    'Failure retains isolated products, exact log and trust entries; deletion is not individual trust withdrawal.',
                    'Unexpected/unobserved process identities fail without unverified signal; successful cleanup still needs the real device receipt.',
                    'No guest execution/display/network or device result is claimed.'], deviceOperations=0,trustCacheOperations=0)
    save(out/'controller-review.json',review)
    rows=[pin(p)for p in out.iterdir()if p.is_file()]+[pin(__file__),pin(packet/'candidate.json'),pin(packet/'freeze.json'),pin(prior_review)]
    save(out/'freeze.json',dict(files=rows,deviceOperations=0))
    print(json.dumps(dict(appReview=pin(out/'app-and-runtime-review.json'),controllerReview=pin(out/'controller-review.json'),freeze=pin(out/'freeze.json'))))

if __name__=='__main__': main()
