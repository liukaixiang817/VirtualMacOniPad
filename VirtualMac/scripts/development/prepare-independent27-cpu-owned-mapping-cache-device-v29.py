#!/usr/bin/env python3
"""HOST prepare an exact GPU-only successor of an actually installed packet.

Root supplies previous packet, successful current-products post and all new SHA256
pins. Only the two existing CPU providers, their VMM seal, and App anchor may change. All265 paths,
146 entitlement sets, exact CPU29 delta, Main38, genuine GPU193 and the inherited seven-action
backup/trust/initialization/cleanup protocol remain required. This command writes
only a fresh HOST packet; it does not sign, dispatch, make ready or boot a guest.
"""
import argparse
import copy
import difflib
import importlib.util
import io
import hashlib
import json
import pathlib
import re
import shlex
import subprocess
import struct
import sys
import tarfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = STAGE = base = fast = pin = dump = None
MAIN = 'VirtualMacIndependent27.app/VirtualMacIndependent27'
BOOT = 1792161312
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
MAIN32_PLAN_SHA256 = '935ba7a6209cfc0fe9d4dc12939cbb0bd595a537ed2218e9f87b55cd24ed0866'
HISTORICAL_RUNTIME86_SHA256 = 'aa5e5cb6f067639257f2e13b8d788250e9277f09b94f9b6e2066b664dbcc803b'
EXTENDED_VA_KEY = 'com.apple.developer.kernel.extended-virtual-addressing'
LOG_ID = '16777223:48200252'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def need(value, message):
    if not value:
        raise ValueError(message)


def bootstrap_pin(path):
    path=pathlib.Path(path).resolve()
    raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def unwrap(script):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    values = shlex.split(script[at:])
    need(len(values) == 1, 'one inherited bounded action')
    return values[0]


def rewrap(script, body):
    start = script.index('/var/jb/usr/bin/timeout')
    at = script.index('/var/jb/bin/sh -c ', start)+len('/var/jb/bin/sh -c ')
    need(script[at:] == shlex.quote(unwrap(script))+'\n', 'exact previous packet single quoted body/tail')
    return script[:at]+shlex.quote(body)+'\n'


def trust_check(hashes):
    # Same exact membership parser as the executed previous packet trust action.
    values = ';'.join('expected["'+value+'"]=1' for value in hashes)
    awk = ('BEGIN {'+values+'} {v=tolower($NF);if(length(v)==40 && '
           'v~/^[[:xdigit:]]+$/ && (v in expected))found[v]=1} '
           'END {for(v in found)print v}')
    return '''own_actual_trust_exit=0
own_actual_trust_info=$(jbctl trustcache info) || own_actual_trust_exit=$?
printf 'OWN_ACTUAL_TRUST_NATIVE_EXIT %s\n' "$own_actual_trust_exit"
printf '%s\n' "$own_actual_trust_info"
[ "$own_actual_trust_exit" = 0 ]
own_actual_present=$(printf '%s\n' "$own_actual_trust_info" | awk '''+shlex.quote(awk)+''' | sort)
[ "$own_actual_present" = '''+shlex.quote('\n'.join(sorted(hashes)))+''' ]
printf 'INDEPENDENT27_ACTUAL_ALL_ACTIVE_OWN_TRUST_MEMBERSHIP_EXACT\n'
'''


GPU_REL = 'gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc/Contents/MacOS/com.apple.gpusw.ParavirtualizedGraphicsGPUTask'

def gpu_off_check():
    path = '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/'+GPU_REL
    return """own_gpu_off=0
for own_gpu_wait in 1 2 3; do
 own_gpu_rows=$(ps -axo pid=,ppid=,uid=,comm=)
 if printf '%s\n' "$own_gpu_rows" | awk -v g="""+shlex.quote(path)+""" 'NF<4 {bad=1} {n++;if($4==g)bad=1} END {exit bad || !n}'; then own_gpu_off=1;break;fi
 sleep 1
done
[ "$own_gpu_off" = 1 ]
printf 'INDEPENDENT27_EXACT_NATIVE_GPU_TASK_OFF\n'
"""


def stage_body(scope, archive):
    baseline = json.loads(base.exact(scope['oldScope']).read_bytes())
    main_change = next(item for item in scope['deltaFiles'] if item['archivePath'] == MAIN)
    old_main, main_mode = main_change['old'], main_change['mode']
    prior_main = next(item['old'] for item in baseline['deltaFiles'] if item['archivePath'] == MAIN)
    original_stage = unwrap((OLD/'stage.sh').read_text())
    lead = original_stage[:original_stage.index('check_own_file() {')]
    need(lead.count(prior_main['sha256']) == 1 and
         lead.count(f'501:501:{main_mode:o}:1:{prior_main["bytes"]}') == 1,
         'one original previous packet UI-only close Main byte/metadata guard')
    lead = lead.replace(baseline['deviceStage'], STAGE).replace(prior_main['sha256'], old_main['sha256'])
    lead = lead.replace(f'501:501:{main_mode:o}:1:{prior_main["bytes"]}', f'501:501:{main_mode:o}:1:{old_main["bytes"]}')
    stage = lead+'''check_own_file() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "501:501:$4:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
dd of="$OWN_STAGE/products.tar" bs=65536 2>/dev/null
'''+f'''[ "$(stat -c %u:%g:%h:%s "$OWN_STAGE/products.tar")" = 0:0:1:{len(archive)} ]
[ "$(sha256sum "$OWN_STAGE/products.tar" | cut -d ' ' -f1)" = {base.digest(archive)} ]
tar -xpf "$OWN_STAGE/products.tar" -C "$OWN_STAGE"
'''
    # Exact old backups and absence markers precede all product writes.
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        if old is not None:
            stage += f'''check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
cp -p {path} "$OWN_STAGE/backup-{index}"
[ "$(sha256sum "$OWN_STAGE/backup-{index}" | cut -d ' ' -f1)" = {old['sha256']} ]
'''
        else:
            stage += f'''[ ! -e {path} ] && [ ! -L {path} ]
(umask 077; set -C; : > "$OWN_STAGE/backup-new-absent-{index}")
'''
        stage += f'''[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/new-{index}")" = 0:0:600:1:{new['bytes']} ]
[ "$(sha256sum "$OWN_STAGE/new-{index}" | cut -d ' ' -f1)" = {new['sha256']} ]
'''
    stage += '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
'''+f'''[ "$(stat -c %d:%i "$OWN_LOG")" = {LOG_ID} ]
'''+'''[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
own_log_meta=$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")
own_log_sha=$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = "$own_log_sha" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
printf 'OWN_PRIOR_LOG_BACKUP metadata=%s sha256=%s\n' "$own_log_meta" "$own_log_sha"
'''
    stage += gpu_off_check()
    for directory in scope['newOwnDirectories']:
        path = shlex.quote(directory['devicePath']); parent = shlex.quote(str(pathlib.PurePosixPath(directory['devicePath']).parent))
        stage += f'''[ -d {parent} ] && [ ! -L {parent} ]
[ "$(realpath {parent})" = {parent} ]
[ ! -e {path} ] && [ ! -L {path} ]
mkdir -m {directory['mode']:o} {path}
chown 501:501 {path}
[ "$(stat -c %u:%g:%a {path})" = 501:501:{directory['mode']:o} ]
[ "$(realpath {path})" = {path} ]
'''
    for row in scope['deltaFiles']:
        path = shlex.quote(row['devicePath']); old, new, mode, index = row['old'], row['new'], row['mode'], row['index']
        pending = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-'+scope['packetName']+'-'+str(index)+'.pending')))
        stage += f'''[ ! -e {pending} ] && [ ! -L {pending} ]
cp "$OWN_STAGE/new-{index}" {pending}
chown 501:501 {pending}
chmod {mode:o} {pending}
check_own_file {pending} {new['sha256']} {new['bytes']} {mode:o}
'''
        if old is not None:
            stage += f'''check_own_file {path} {old['sha256']} {old['bytes']} {mode:o}
mv -f {pending} {path}
'''
        else:
            stage += f'''[ ! -e {path} ] && [ ! -L {path} ]
mv -n {pending} {path}
[ ! -e {pending} ] && [ ! -L {pending} ]
'''
        stage += f'''check_own_file {path} {new['sha256']} {new['bytes']} {mode:o}
printf 'OWN_EXACT_PRODUCT_UPDATED {index} {row['archivePath']}\n'
'''
    return stage+'''[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = "$own_log_meta" ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = "$own_log_sha" ]
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
(umask 077; set -C; : > "$OWN_STAGE/stage-complete")
printf 'INDEPENDENT27_ALL_DELTA_INSTALLED_EXACT_BACKUPS_RETAINED_NO_TRUST_OR_GUEST\n'
'''


def main():
    global OLD, STAGE, base, fast, pin, need, dump
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=pathlib.Path, required=True)
    ap.add_argument('--previous-device-packet',type=pathlib.Path,required=True)
    ap.add_argument('--expected-post-sha256',required=True)
    ap.add_argument('--app-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--runtime-candidate', type=pathlib.Path, required=True)
    ap.add_argument('--current-installed-post',type=pathlib.Path,required=True)
    ap.add_argument('--runtime-candidate-sha256', required=True)
    ap.add_argument('--app-candidate-sha256', required=True)
    ap.add_argument('--app-source-sha256', required=True)
    ap.add_argument('--gpu-candidate-sha256', required=True)
    ap.add_argument('--gpu-source-plan-sha256', required=True)
    ap.add_argument('--gpu-expected-changed-instruction-words',type=int,default=19)
    args = ap.parse_args()
    need(all(re.fullmatch('[0-9a-f]{64}', value) for value in
         (args.runtime_candidate_sha256,args.app_candidate_sha256,args.app_source_sha256,
          args.gpu_candidate_sha256,args.gpu_source_plan_sha256,args.expected_post_sha256)),
         'Root supplies actual post and new signed product/source SHA256 pins')
    need(args.gpu_expected_changed_instruction_words == 22,
         'actual reviewed Task192 retains exactly nineteen changed instruction words')
    need(args.gpu_source_plan_sha256 == '6266fee642cee4a417574921cec22c0951fb95d09eada59546810a1d20bd7f12',
         'exact reviewed Plan18 native ordinary texture Managed compatibility')
    OLD=args.previous_device_packet.resolve()
    out,app_path=args.output.resolve(),args.app_candidate.resolve()
    packet_pattern=r'independent27-gpu-[a-z0-9]+(?:-[a-z0-9]+)*-device-v[0-9]+-attempt[0-9]+'
    need(OLD.parent==N and OLD.is_dir() and re.fullmatch(packet_pattern,OLD.name) and
         out.parent==N and not out.exists() and re.fullmatch(packet_pattern,out.name) and
         len(out.name)<=120 and out!=OLD,
         'existing previous GPU packet and fresh bounded same-root successor name')
    STAGE='/private/var/mobile/Library/.VM27-'+out.name
    prior=json.loads((OLD/'candidate.json').read_bytes())
    need(prior['controller']==bootstrap_pin(OLD/'control.py') and
         prior['scope']==bootstrap_pin(OLD/'scope.json'),
         'previous candidate pins exact inherited controller and scope before import')
    base=load(OLD/'control.py','exact_previous_gpu_controller')
    fast=load(B/'independent27_device_product_verify_fast_v1.py','exact_gpu_successor_fast')
    pin,need,dump=base.pin,base.need,base.dump
    need(tuple(prior['actions'])==tuple(base.ACTIONS)==
         ('close-current-own','preflight','stage','verify','trust','launch','post'),
         'previous packet retains exact seven standard actions')
    POST=args.current_installed_post.resolve()
    need(POST.is_relative_to(N) and POST.name=='receipt.json' and
         POST.parent.name=='post' and pin(POST)['sha256']==args.expected_post_sha256,
         'Root exact successful standard current-products post receipt')
    for row in prior['scripts'].values():
        base.exact(row)
    prior_receipt_pins=[]
    for action in prior['actions']:
        path=OLD/'device-receipts'/action/'receipt.json'
        receipt=json.loads(path.read_bytes()); request=json.loads(base.exact(receipt['request']).read_bytes())
        need(receipt['transportExit']==0 and request['packetCandidate']==pin(OLD/'candidate.json') and request['script']==prior['scripts'][action], 'actual all7 previous packet phases '+action)
        base.exact(receipt['stdout']);base.exact(receipt['stderr'])
        prior_receipt_pins += [pin(path),receipt['request'],receipt['stdout'],receipt['stderr']]
    old = json.loads((OLD/'scope.json').read_bytes())
    need(old['bootSeconds'] == BOOT and old['bootSessionUUID'] == UUID and
         old['fixedOwnedLogIdentity'] == LOG_ID+':501:501:600:1', 'same current boot and owned log')
    post = json.loads(POST.read_bytes())
    text = base.exact(post['stdout']).read_text()
    base.exact(post['stderr']); base.exact(post['request'])
    post_request=json.loads(base.exact(post['request']).read_bytes())
    post_packet_pin=pin(POST.parents[2]/'candidate.json')
    need(post['action']=='post' and post['transportExit']==0 and
         post_request['packetCandidate']==post_packet_pin,
         'actual post0 binds its own exact packet candidate')
    current_post_pins=[post_packet_pin]
    preceding_stop=None
    if post_packet_pin==pin(OLD/'candidate.json'):
        post_kind='previous-initialization-post'
        terminal='INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED'
    else:
        post_packet=json.loads(base.exact(post_packet_pin).read_bytes())
        need(post_packet['initializerCandidate']==pin(OLD/'candidate.json'),
             'normal post belongs to the same actually installed initializer')
        stop_path=POST.parents[2]/'device-receipts/stop/receipt.json'
        if stop_path.exists():
            preceding_stop=pin(stop_path)
            normal_stop=json.loads(stop_path.read_bytes())
            need(normal_stop['action']=='stop' and normal_stop['transportExit']==0 and
                 json.loads(base.exact(normal_stop['request']).read_bytes())['packetCandidate']==post_packet_pin,
                 'normal current-products post follows actual stop0 of the same packet')
            base.exact(normal_stop['stdout']);base.exact(normal_stop['stderr'])
            current_post_pins.extend((preceding_stop,normal_stop['request'],normal_stop['stdout'],normal_stop['stderr']))
            post_kind='normal-post-after-stop'
        else:
            failed_start=POST.parents[2]/'device-receipts/start/receipt.json'
            fs=json.loads(failed_start.read_bytes())
            need(fs['action']=='start' and fs['transportExit']!=0 and not (failed_start.parent/'handoff-ack.json').exists() and
                 json.loads(base.exact(fs['request']).read_bytes())['packetCandidate']==post_packet_pin,
                 'failed uncommitted start with actual OFF-first post0, no lease transfer')
            base.exact(fs['stdout']);base.exact(fs['stderr'])
            current_post_pins.extend((pin(failed_start),fs['request'],fs['stdout'],fs['stderr']))
            post_kind='normal-post-after-uncommitted-failed-start'
        terminal='OWN_NORMAL_POST_HEALTH_PRODUCTS_AND_OWN_OFF'
    need(all(marker in text for marker in ('INDEPENDENT27_OWN_APP_AND_CHILD_OFF',
             'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT','PRODUCTION_6_CODE_HASHES_PRESERVED',terminal)),
         'actual same-product off/health/full-product post0 markers')
    need(prior['runtimeCandidate']==old['runtimeCandidate'] and
         prior['appCandidate']==old['appCandidate'] and STAGE!=old['deviceStage'],
         'previous scope/candidate products join and successor stage is distinct')
    base.exact(old['runtimeCandidate'])
    runtime_path = args.runtime_candidate.resolve()
    runtime_pin = pin(runtime_path)
    need(runtime_pin['sha256'] == args.runtime_candidate_sha256 and pin(app_path)['sha256'] == args.app_candidate_sha256,
         'actual installed previous runtime and Root actual signed new runtime/new App products')
    runtime = json.loads(runtime_path.read_bytes()); app = json.loads(app_path.read_bytes())
    previous_app = json.loads(base.exact(old['appCandidate']).read_bytes())
    need(app['actualCodeSigned'] is True and app['actualPrimaryPagesAndExternalSlotsVerified'] is True and
         app['runtimeCandidate'] == runtime_pin and app['runtimeRoot'] == runtime['canonicalDeviceRoot'] and
         app['actualBundleID'] == previous_app['actualBundleID'] and app['actualURLScheme'] == previous_app['actualURLScheme'],
         'actual signed new App with new runtime and unchanged application identity')
    need(app['sourceCandidate']['sha256'] == args.app_source_sha256, 'actual Root-linked new App source candidate')
    source = json.loads(base.exact(app['sourceCandidate']).read_bytes())
    inherited_source = json.loads(base.exact(source['inheritedCompiledAppCandidate']).read_bytes())
    prior_source = json.loads(base.exact(previous_app['sourceCandidate']).read_bytes())
    need(source['actualRuntimeCandidate']==runtime_pin and runtime['incrementalBaselineRuntimeCandidate']==old['runtimeCandidate'] and len(source['objects'])==35,
         'actual Runtime107 is direct signed successor of installed Runtime106')
    need(source['inheritedCompiledAppCandidate']==previous_app['sourceCandidate'] and source['actualChangedAppObjectIndices']==[34] and
         source['actualNewAppCompilations']==0 and source['actualUnchangedCompiledObjects']==34 and
         source['objects'][34]==runtime['anchorIOSObject'] and all(source['objects'][i]==prior_source['objects'][i] and source['sourceFiles'][i]==prior_source['sourceFiles'][i] for i in range(34)),
         'only actual Runtime114 anchor34 changes; all34 functional App144 objects whole')
    need(pathlib.Path(source['sourceFiles'][16]['path']).name=='vm27_uikit_guest_display_v11.mm' and
         source[source['mainSourceContractKey']]['allDisplay11MD32PGGuardMetal15GPU193Whole'],
         'Display11 actual per-frame completion/ACK/leases and sampled logging whole')
    prior_rt=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    need(runtime['localCodeSigned'] and runtime['actualProductPreflightPassed'] and
         runtime['baselineRuntimeCandidate']==old['runtimeCandidate'] and runtime['incrementalBaselineRuntimeCandidate']==old['runtimeCandidate'] and
         runtime['allNonCPUProviderFilesWholeRuntime113'] and runtime['allMD32PGGuardAndCoreMediaAMXFixesWholeRuntime113'] and
         runtime['nativeOwnedGPUTaskProduct']==prior_rt['nativeOwnedGPUTaskProduct'] and runtime['actualGPUParentSource']==base.pin(R/'VirtualMac/vz/host/vm27_owned_gpu_task_parent_v4.inc'),
         'direct Runtime113 successor changes only CPU providers/seal; all proven graphics whole')
    cpu=json.loads(base.exact(runtime['cpu29SourceProof']).read_bytes())
    need(cpu['baselineCPU']==prior['actualCPUCurrentSource'] and cpu['actualIOSCompileStrictLinkAndDyldValidatePassed'] and
         cpu['noNativeImportsAdded'] and cpu['actualExports']==155 and cpu['actualLoads']==4 and
         cpu['cpuOwnedMappingCacheV1Contract']==runtime['cpuOwnedMappingCacheV1Contract'] and
         len(cpu['actualChangedObjects'])==3 and len(cpu['inheritedWholeObjects'])==26 and
         runtime['cpu29Objects']==cpu['actualChangedObjects']+cpu['inheritedWholeObjects'],
         'actual strict Life66 Production11 cache CPU29 source, three replacements and26whole')
    old_names={'modern_cpu_native_self_memory_v2.o','modern_cpu_kernel_lifecycle_v65.o','modern_cpu_production_native_ops_v10.o'}
    inherited_cpu={r['path']:r for r in prior_rt['cpu29Objects'] if pathlib.Path(r['path']).name not in old_names}
    need(len(inherited_cpu)==26 and inherited_cpu=={r['path']:r for r in cpu['inheritedWholeObjects']},'exact other26 installed CPU objects whole')
    for row in runtime['cpu29Objects']:base.exact(row)
    fp=json.loads(base.exact(runtime['framebufferReadSourceContract']).read_bytes())
    proof=json.loads(base.exact(fp['actualNativeProbeReceipt']).read_bytes())
    base.exact(fp['actualNativeProbeReadback'])
    need(fp['all256ReadModifyWritePixelsActuallyVerified'] and fp['onlyFramebufferReadCapability8Changed'] and
         proof['transportExit']==0 and proof['actualNativeReadbackPassed'] and proof['actualProcessAndFileCleanup'],
         'actual bounded native framebuffer fetch completed and256 pixels correctly read back; no speculative capability')
    base.exact(runtime['nativeCoreMediaDefinitionProof']);base.exact(runtime['guestAMXAdvertisementProof'])
    need(runtime['nativeOwnedGPUTaskProduct']['sha256']==args.gpu_candidate_sha256 and runtime['nativeOwnedGPUTaskSourcePlan']['sha256']==args.gpu_source_plan_sha256,'exact reviewed GPU193 product/source')
    gpu=json.loads(base.exact(runtime['nativeOwnedGPUTaskProduct']).read_bytes());gpu_source_plan=json.loads(base.exact(runtime['nativeOwnedGPUTaskSourcePlan']).read_bytes())
    need(gpu['actualCurrentTaskImportRows']==193 and gpu['nativeTaskPort']['exactChangedInstructionWordCount']==22 and
         gpu['nativeTaskPort']['nativeLinearPitchDelegation']['returnRVA']==0x57698 and
         json.loads(base.exact(gpu['actualImportClosure']).read_bytes())['unresolved']==[], 'actual native pitch query adapter and closed193 import definitions')
    task_raw=base.exact(gpu['task']).read_bytes()
    need(all(struct.unpack_from('<I',task_raw,at)[0]==0x52800042 for at in (0xc294,0x51964)) and gpu['residentResourceV20Contract']['onlyOptionalVolatileDiscardDeferred'], 'two exact native NonVolatile operands, optional discard optimization deferred')
    need(struct.unpack_from('<I',task_raw,0x57694)[0]==0x94000000|((0x8e6a0-0x57694)//4),'exact new native pitch call route')
    signature_pin = runtime['signatureVerification']
    signature = json.loads(base.exact(signature_pin).read_bytes())
    need(signature['allCodePagesAndSpecialSlotsActuallyVerified'] is True, 'actual runtime signature pages and slots')
    base.exact(runtime['manifest']) # Actual runtime binary-plist anchor manifest.
    manifest_path = runtime_path.parent/'manifest.json' # Builder's signed-file metadata JSON.
    manifest = json.loads(manifest_path.read_bytes())
    cds = {'runtime/'+row['path']:row['cdhash'] for row in manifest['files'] if row['kind'] == 'mach-o'}
    signature_rows = {'runtime/'+row['relativePath']:row for row in signature['actualSignedFiles']}
    need(set(cds) == set(signature_rows) and all(signature_rows[name]['cdhash'] == value and
         signature_rows[name]['allPrimaryPagesAndSpecialSlotsVerified'] is True for name,value in cds.items()),
         'each actual new runtime manifest Mach-O joins its actual complete signature proof')
    prior_runtime=json.loads(base.exact(old['runtimeCandidate']).read_bytes())
    prior_signature=json.loads(base.exact(prior_runtime['signatureVerification']).read_bytes())
    prior_signature_rows={row['relativePath']:row for row in prior_signature['actualSignedFiles']}
    need(runtime['baselineRuntimeCandidate']==old['runtimeCandidate'], 'new runtime is exact direct installed Runtime113 successor')
    task_relative=GPU_REL
    entitlement_changes=[]
    need(set(prior_signature_rows)=={row['relativePath']for row in signature['actualSignedFiles']},
         'same actual145 runtime signed paths before exact whole-entitlement comparison')
    for row in signature['actualSignedFiles']:
        original=prior_signature_rows[row['relativePath']]
        before=original.get('embeddedEntitlements');after=row.get('embeddedEntitlements')
        need(after==before, 'every runtime image entitlement set whole installed previous runtime')
        if row['relativePath']==task_relative:
            need(isinstance(after,dict) and len(after)==9 and after.get(EXTENDED_VA_KEY)is True and
                 after.get('com.apple.private.security.no-container')is True and
                 after.get('com.apple.private.security.no-sandbox')is True and
                 after.get('com.apple.private.amfi.can-execute-cdhash')is True,
                 'actual GPU Task nine permissions including proven extended VA remain whole')
    need(entitlement_changes==[], 'no runtime entitlement change')
    sig = app['actualSignature']; old_sig = previous_app['actualSignature']
    need(re.fullmatch('[0-9a-f]{40}', sig['cdhash']) is not None and
         sig['embeddedEntitlements'] == old_sig['embeddedEntitlements'] and
         sig['actualPlatform'] == old_sig['actualPlatform'], 'one actual Main CD; no permission/platform change')
    app_root = pathlib.Path(app['app'])
    base.regular_tree(app_root)
    actual_names = {MAIN.rsplit('/', 1)[0]+'/'+p.relative_to(app_root).as_posix()
                    for p in app_root.rglob('*') if p.is_file()}
    old_rows = {row['archivePath']: row for row in old['files']}
    need(actual_names == {name for name in old_rows if name.startswith('VirtualMacIndependent27.app/')},
         'exact same104 ordinary App file paths')
    app_dirs = {'VirtualMacIndependent27.app'} | {'VirtualMacIndependent27.app/'+p.relative_to(app_root).as_posix()
                                                for p in app_root.rglob('*') if p.is_dir()}
    need(app_dirs == {name for name in old['directories'] if name == 'VirtualMacIndependent27.app' or
                     name.startswith('VirtualMacIndependent27.app/')}, 'exact existing App directories')
    files = []; changes = []; directories = dict(old['directories']); runtime_root = pathlib.Path(runtime['runtimeRoot'])
    base.regular_tree(runtime_root)
    roots = [(runtime_root,'runtime'),(app_root,'VirtualMacIndependent27.app')]
    for root, top in roots:
        for path in sorted(root.rglob('*')):
            name = top+'/'+path.relative_to(root).as_posix()
            if path.is_dir():
                directories[name] = old['directories'].get(name,0o700 if top=='runtime' else 0o755)
                continue
            original = old_rows.get(name); local = pin(path)
            mode = original['mode'] if original else 0o700 if name in cds else 0o600
            device = (old['deviceRuntime'] if top=='runtime' else old['deviceApp'])+'/'+path.relative_to(root).as_posix()
            row = dict(archivePath=name,devicePath=device,mode=mode,local=local)
            if name in cds:
                row['cdhash'] = cds[name]
                need(local == signature_rows[name]['actualSignedFile'], 'every runtime signed file joins actual signature')
            elif name == MAIN:
                need(local == sig['file'], 'actual signed Main joins signature'); row['cdhash'] = sig['cdhash']
            elif top != 'runtime':
                need(original is not None and local['bytes']==original['local']['bytes'] and local['sha256']==original['local']['sha256'], 'all103 App resources whole')
            if original is None or local['sha256'] != original['local']['sha256']:
                changes.append(dict(index=len(changes),archivePath=name,devicePath=device,mode=mode,
                    old=original['local'] if original else None,new=local,newResource=original is None))
            files.append(row)
    need(set(old_rows) <= {r['archivePath'] for r in files}, 'no installed file deletion')
    new_dirs = [dict(archivePath=name,devicePath=old['deviceRuntime']+name[len('runtime'):],mode=directories[name])
                for name in sorted(set(directories)-set(old['directories']),key=lambda n:(n.count('/'),n))]
    need(new_dirs==[] and set(old_rows)=={r['archivePath']for r in files}, 'all265 installed paths/modes/directories remain; no additions/deletions')
    change = next(row for row in changes if row['archivePath']==MAIN)
    full = sorted(row['cdhash'] for row in files if 'cdhash' in row)
    new_cd = sorted(set(full)-set(old['trustCacheCDHashes']))
    runtime_files = [row for row in files if row['archivePath'].startswith('runtime/')]
    runtime_cd_count = sum('cdhash' in row for row in runtime_files)
    manifest_rows = {row['id']:row for row in manifest['files']}
    expected_changes={MAIN,'runtime/'+manifest_rows['child:VM27HVVMProduction.dylib']['path'],'runtime/'+manifest_rows[manifest['childEntryContract']['childID']]['path'],
        'runtime/'+manifest_rows['child-coderesources']['path'],'runtime/'+manifest_rows[manifest['dependencyProofID']]['path'],
        'runtime/'+pathlib.Path(runtime['manifest']['path']).relative_to(pathlib.Path(runtime['runtimeRoot'])).as_posix()}
    cpu_parent_name='runtime/'+manifest_rows['parent:VM27HVVMProduction.dylib']['path']
    expected_changes.add(cpu_parent_name)
    guard_proof=json.loads(base.exact(runtime['originalPGNullConnectionGuard']).read_bytes())
    guarded=pathlib.Path(runtime['runtimeRoot'])/manifest_rows['child:ParavirtualizedGraphics27.dylib']['path']
    guarded_raw=guarded.read_bytes()
    need(guard_proof['onlyFourNativeWordsChanged'] and guard_proof['nullUsesOriginalReleaseSelfAndReturnNil'] and
         guard_proof['noSPFPOrPACOrUnwindChanges'] and all(struct.unpack_from('<I',guarded_raw,r['rva'])[0]==r['newWord'] for r in guard_proof['patches']),
         'actual four-word native null-connection guard and original nil-return failure path; no fabricated native connection or success')
    need(len(manifest['files'])==160 and len(files)==265 and len(full)==len(set(full))==146 and
         runtime_cd_count==145 and len(changes)==len(expected_changes) and sig['cdhash']in new_cd and
         all(row['old']is not None for row in changes)and {row['archivePath']for row in changes}==expected_changes,
         'actual same160 runtime rows/265files/146CD; only exact diagnostic product delta paths, no new paths')
    changed_cd_names={row['archivePath']for row in changes if row['archivePath']in {f['archivePath']for f in files if 'cdhash'in f}}
    actual_new_cd_by_changed_files={row['cdhash']for row in files if row['archivePath']in changed_cd_names}-set(old['trustCacheCDHashes'])
    need(set(new_cd)==actual_new_cd_by_changed_files and len(new_cd)==len(changed_cd_names),
         'new TC membership/count derived from actual changed signed files, not predicted nine/five counts')
    old_code_names = {row['cdhash']:row['archivePath'] for row in old['files'] if 'cdhash' in row}
    new_code_hashes = {row['archivePath']:row['cdhash'] for row in files if 'cdhash' in row}
    native_subset = [new_code_hashes[old_code_names[value]] for value in old['actualNativeCDSubset']]
    scope = {key: copy.deepcopy(old[key]) for key in ('deviceRuntime', 'deviceApp', 'deviceAppMain', 'deviceChildMain',
             'directories', 'continuingHumanAuthorization', 'sandboxProfileApplied', 'nativeSandboxApplyUnavailable',
             'nativeSandboxInitSuccessFabricated', 'fixedOwnedLogIdentity', 'bootSeconds', 'bootMicroseconds', 'bootSessionUUID')
             if key in old}
    scope.update(schema='Actual Runtime114 real native6 owned CPU mapping cache and App145 anchor',packetName=out.name,bootSeconds=BOOT,bootMicroseconds=47253,
        oldScope=pin(OLD/'scope.json'), currentInstalledProductsPost=pin(POST), oldActualPost=pin(POST),
        baselinePreviousInitializationSucceeded=True,
        baselinePreviousAllSevenActionsSucceeded=True,
        baselineInstalledProductsHealthProvenByActualCurrentPost=True,
        precedingNormalStop=preceding_stop, currentInstalledPostKind=post_kind,
        baselineControllerInheritedFromPreviousPacket=True,
        deviceStage=STAGE, files=files, directories=directories, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        actualPreviousRuntimeVerification=dict(deviceCandidate=pin(OLD/'candidate.json'),scope=pin(OLD/'scope.json'),freeze=pin(OLD/'freeze.json'),runtimeCandidate=old['runtimeCandidate']),
        actualPreviousAppCandidate=old['appCandidate'], inheritedPreviousAppCompiledSource=source['inheritedCompiledAppCandidate'],
        actualAll29CPUObjectsWholeRuntime86=False, actualChangedCPUObjects=3, actualUnchangedCPUObjects=26, allOther26CPUObjectsWholeRuntime113=True,
        inheritedActualSignedRuntimeCDProof=signature_pin,
        actualMain36AndOther33CompiledObjectsWholePreviousApp=False,actualOther33FunctionalAppObjectsWholePreviousApp=False,actualAll34FunctionalAppObjectsWholePreviousApp=True,actualChangedAppObjectIndices=[34],actualOnlyRelinkedRuntimeAnchor=True,actualUnchangedCompiledObjects=34,actualNewAppCompilations=0,
        ownedPGRemoteTaskParentTransportV1Contract=runtime['ownedPGRemoteTaskParentTransportV1Contract'],
        callbacksInterposedButSemanticsWhole=True, scopedOnlyExactOwnedPGInstanceMethodObservation=True, noFoundationOrMetalClassMutation=True,
        nativeOwnedGPUTaskProduct=runtime['nativeOwnedGPUTaskProduct'],
        nativeOwnedGPUTaskSourcePlan=runtime['nativeOwnedGPUTaskSourcePlan'],
        nativeOrdinaryTextureManagedToSharedV1Contract=gpu_source_plan['metalContract']['nativeOrdinaryTextureManagedToSharedV1'],
        nativePagingCommandBufferObserverV1Contract=gpu_source_plan['metalContract']['nativePagingCommandBufferObserverV1'],
        softwareKeyboardAndOptionalQGADiagnosticV1Contract=inherited_source['softwareKeyboardAndOptionalQGADiagnosticV1Contract'],
        gpuTaskExecutableRelativePath=GPU_REL, ownGPUHelperMustBeAbsentAfterParentCleanup=True,
        trustCacheCDHashes=full, newTrustCacheCDHashes=new_cd, trustCacheRegistrationCount=len(new_cd),
        trustCacheFixedBatchCounts=[len(new_cd)], actualFullCodeDirectoryHashes=len(full),
        actualRuntimeManifestFiles=len(manifest['files']), actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count,
        deltaFiles=changes, existingOwnFilesUpdated=sum(r['old'] is not None for r in changes), actualChangedFiles=len(changes),
        unchangedFiles=len(files)-len(changes), unchangedSignedImages=len(full)-len(new_cd),
        newOwnFilesAdded=0, newOwnDirectories=new_dirs, newOwnResourceFiles=[r['archivePath'] for r in changes if r['old'] is None],
        runtimeAllWholebytesUnchanged=False, runtimeProductAndAllFilesWholeUnchanged=False,
        originalMainAppResourcesAllWholebytesUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, backupOldOwnFilesAndLog=True,
        missingOwnLogMayBeCreated=False, cleanupRequiresExactPIDUIDPathPPIDAndStartTimeHash=True,
        initializationExternalWallSeconds=45, currentAppCloseExternalWallSeconds=20, updateExternalWallSeconds=90,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        nonStageTransportTimeoutSeconds=55, nonStageNonCloseExternalWallSeconds=45,
        actualNativeCDSubset=native_subset, actualNativeCDSubsetCount=len(native_subset),
        actualNativeCDsQueriedThisDelta=new_cd, actualNativeCDsQueriedThisDeltaCount=len(new_cd),
        actualFullCodeTrustMembershipVerifiedAfterAddRequired=True, trustMembershipKnownBeforeDispatch=False,
        trustCacheMayRemainUntilReboot=True, perPIDKernelPrivilegeModification=False,
        deviceSystemFilesModified=False, systemSandboxFilesModified=False, noExistingImagePermissionsChanged=True, onlyGPUProductAndSignedParentPinsChanged=False, onlyGuestAMXAdvertisementAndAppAnchorChanged=False,onlyLinearPitchAndParentIdentityAndAppMainAnchorChanged=False,onlyOwnedMainMetalDiagnosticFlagChanged=False,onlyOwnedChildMetalEnvironmentChanged=False,onlyOwnedGPUChildValidationEnvironmentChanged=False,onlyNativeVolatileDiscardOptimizationDeferred=False,onlyMissingFramebufferReadCapabilityMapped=False,onlyLiveCPUOwnedMappingCacheAndAppAnchorChanged=True, actualRuntimeEntitlementChanges=entitlement_changes, all146RuntimeAndAppEntitlementsWholePreviousProducts=True, noNewCPUOrHVPermissions=True,
        initializationOnly=False, productInstallationPerformed=False, productUpdatesPlanned=True,
        productUpdatesPerformed=False, guestBootRequested=False, guestSSHDeferredUntilAfterBasicGuestBoot=False,guestPersistentSSHJobConfiguredAndAutomaticBridgeEnabled=True,
        deviceOperations=0, trustCacheOperations=0, readyForDeviceExecution=False)
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for changed in changes:
            data = base.exact(changed['new']).read_bytes(); item = tarfile.TarInfo('new-'+str(changed['index']))
            item.uid = item.gid = item.mtime = 0; item.mode = 0o600; item.size = len(data)
            archive.addfile(item, io.BytesIO(data))
    archive = stream.getvalue()
    scope.update(deltaArchiveBytes=len(archive), deltaArchiveSHA256=base.digest(archive),
                 archive=dict(path=str(out/'products.tar'), bytes=len(archive), sha256=base.digest(archive)))
    base.DEVICE_STAGE = STAGE
    previous_prefix=base.prefix
    base.prefix=lambda uid:previous_prefix(uid).replace('= 1792161311 ]','= 1792161312 ]')
    wrap = lambda body, uid, seconds=45: base.prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 '+str(seconds)+' /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    scripts = {}; operations = {}; before = fast.batch_check(old); after = fast.batch_check(scope)
    old_before = fast.batch_check(json.loads(base.exact(old['oldScope']).read_bytes()))
    main_cd = fast.cd_check(scope, [sig['cdhash']])
    all_new_cds = fast.cd_check(scope, new_cd)

    def inherited(action):
        raw = (OLD/(action+'.sh')).read_text()
        need(old['deviceStage'] in raw, 'actual previous packet action stage identity')
        return raw.replace(old['deviceStage'], STAGE).replace('= 1792161311 ]','= 1792161312 ]')

    def replace_once(body, before_value, after_value, reason):
        need(body.count(before_value) == 1, 'one exact previous packet block: '+reason)
        operations.setdefault(action, []).append(dict(reason=reason, beforeBytes=len(before_value.encode()),
            beforeSHA256=base.digest(before_value.encode()), afterBytes=len(after_value.encode()),
            afterSHA256=base.digest(after_value.encode())))
        return body.replace(before_value, after_value, 1)

    for action in ('close-current-own', 'preflight', 'verify', 'trust', 'launch', 'post'):
        raw = inherited(action)
        if action == 'close-current-own':
            scripts[action]=raw; operations[action]=[dict(reason='stage identity only; original precise cleanup and GPU absence gates whole')]; continue
        body = unwrap(raw)
        need(rewrap(raw, body) == raw,
             'actual previous packet outer wrapper byte-whole after stage substitution: '+action)
        # Only the nested UI-close guard changes here, never batch SHA rows.
        guard_lines = [line for line in body.splitlines()
                       if 'sha256sum "$OWN_APP_MAIN"' in line]
        expected_count = 1 if action in ('preflight', 'verify', 'trust', 'launch') else 0
        need(len(guard_lines) == expected_count, 'exact captured nested Main guard count: '+action)
        if expected_count:
            previous_main = next(item['old'] for item in old['deltaFiles'] if item['archivePath'] == MAIN)
            expected = previous_main if action == 'preflight' else old_rows[MAIN]['local']
            target = old_rows[MAIN]['local'] if action == 'preflight' else change['new']
            metadata = f'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_APP_MAIN")" = 501:501:{change["mode"]:o}:1:{expected["bytes"]} ] || exit 8'
            sha_line = guard_lines[0]
            need(sha_line.count(expected['sha256']) == 1 and
                 sha_line.endswith(' = '+expected['sha256']+' ] || exit 8'),
                 'one exact expected nested Main SHA guard: '+action)
            guard = metadata+'\n'+sha_line+'\n'
            replacement = (metadata.replace(':'+str(expected['bytes'])+' ]', ':'+str(target['bytes'])+' ]')+
                           '\n'+sha_line.replace(expected['sha256'], target['sha256'])+'\n')
            body = replace_once(body, guard, replacement, 'nested UI-close Main metadata/SHA binding only')
        body = replace_once(body, old_before if action == 'preflight' else before,
                            before if action == 'preflight' else after, 'actual full-product batch')
        if action == 'verify':
            body = replace_once(body, fast.cd_check(old, old['actualNativeCDsQueriedThisDelta']), all_new_cds,
                                'all actual changed native CD queries')
            body = body.replace('ALL_SHA_AND'+str(len(old['actualNativeCDsQueriedThisDelta']))+'_NATIVE_CD_EXACT',
                                'ALL_SHA_AND'+str(len(new_cd))+'_NATIVE_CD_EXACT')
        elif action in ('launch', 'post'):
            body = replace_once(body, fast.cd_check(old, [old_rows[MAIN]['cdhash']]), main_cd, 'new Main native CD query')
        elif action == 'trust':
            at = body.index('(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")')
            old_tail = body[at:]
            need(old_tail.count(trust_check(old['trustCacheCDHashes'])) == 1 and
                 re.findall(r'^jbctl trustcache add ([0-9a-f]{40})$', old_tail, re.M) == old['newTrustCacheCDHashes'],
                 'exact executed previous packet trust adds and whole membership parser')
            tail = '(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
            for index,value in enumerate(new_cd, 1):
                tail += 'jbctl trustcache add '+value+"\nprintf 'OWN_NEW_PRODUCT_TC_ADDED "+str(index)+' '+value+"\\n'\n"
            tail += trust_check(full)+"printf 'INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE\\n'\n"
            body = replace_once(body, old_tail, tail, 'actual new trust adds and exact all146 actual membership')
        scripts[action] = rewrap(raw, body)
    scripts['stage'] = wrap(stage_body(scope, archive), 0, 90).replace('= 1792161311 ]','= 1792161312 ]')
    actions = list(base.ACTIONS); scripts = {action: scripts[action] for action in actions}
    controller = (OLD/'control.py').read_text().replace(old['deviceStage'], STAGE).replace('1792161311','1792161312')
    need(controller.replace(STAGE,old['deviceStage']) == (OLD/'control.py').read_text(),
         'previous packet controller protocol/ready/auth/once/cleanup byte-whole except stage name')
    compile(controller, str(out/'control.py'), 'exec')
    out.mkdir(mode=0o700); (out/'control.py').write_text(controller); (out/'products.tar').write_bytes(archive)
    (out/'health-root.sh').write_text((OLD/'health-root.sh').read_text().replace('= 1792161311 ]','= 1792161312 ]')); dump(out/'scope.json', scope)
    clock=load(B/'independent27_boot_clock_binding_v2.py','owned_device127_clock')
    generation=dict(bootSeconds=BOOT,bootSessionUUID=UUID)
    def bind_current_clock(script):
        if any(line.startswith('[ "$(sysctl -n kern.boottime | sed -n ') and line.endswith('" = '+str(BOOT)+' ]') for line in script.splitlines()):
            return clock.bind(script,generation)
        measured='case "$(sysctl -n kern.boottime)" in "{ sec = 179216131"[123],*) ;;*)exit 77;;esac'
        need(measured in script and generation['bootSessionUUID']==clock.UUID,'exact inherited same-UUID clock allowance')
        return script
    scripts={action:bind_current_clock(script) for action,script in scripts.items()}
    health=(out/'health-root.sh').read_text()
    (out/'health-root.sh').write_text(bind_current_clock(health))
    rows = {}; sizes = {}; diff = []; unwrapped_diff = []
    for action, script in scripts.items():
        result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True)
        need(result.returncode == 0, 'actual sh-n '+action)
        path = out/(action+'.sh'); path.write_text(script); rows[action] = pin(path)
        (out/(action+'-syntax.stderr')).write_bytes(result.stderr)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        sizes[action] = len(command.encode()); need(sizes[action]+10000 < 262144, 'ARG_MAX reserve '+action)
        diff.extend(difflib.unified_diff((OLD/(action+'.sh')).read_text().splitlines(True), script.splitlines(True),
                    fromfile=OLD.name+'/'+action+'.sh', tofile=out.name+'/'+action+'.sh'))
        unwrapped_diff.extend(difflib.unified_diff(unwrap((OLD/(action+'.sh')).read_text()).splitlines(True),
                    unwrap(script).splitlines(True), fromfile=OLD.name+'/'+action+'.body', tofile=out.name+'/'+action+'.body'))
    diff.extend(difflib.unified_diff((OLD/'control.py').read_text().splitlines(True), controller.splitlines(True),
                fromfile=OLD.name+'/control.py', tofile=out.name+'/control.py'))
    (out/'scripts-from-previous.diff').write_text(''.join(diff))
    (out/'scripts-unwrapped-from-previous.diff').write_text(''.join(unwrapped_diff))
    dump(out/'script-delta.json', dict(schema='Exact previous GPU packet to successor finite script delta v1',
         baseline=pin(OLD/'candidate.json'), baselineScope=pin(OLD/'scope.json'),
         controllerBefore=pin(OLD/'control.py'), controllerAfter=pin(out/'control.py'),
         controllerOnlyStageNameChanged=False,sameUUIDMeasuredBootClockSecondsUpdated=True, closeOnlyStageNameChanged=False, originalCloseSignalIdentityProtocolWhole=True,
         samePreviousTimeoutsAndProcessProtocol=True, transformations=operations,
         stageGeneratedFrom='Executed previous packet bounded stage and exact backup/pending/rename/log protocol',
         stageOnlyListedOwnedDeltaFilesAndExistingLogWritten=True,
         fullActualScriptsDiff=pin(out/'scripts-from-previous.diff'),
         fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-previous.diff'),
         scriptPairs={action:dict(before=pin(OLD/(action+'.sh')), after=rows[action]) for action in actions}))
    candidate = dict(schema='Actual exact GPU-only successor device packet v1',packetName=out.name, preparer=pin(__file__),
        scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'), scripts=rows,
        actions=actions, runtimeCandidate=runtime_pin, appCandidate=pin(app_path),
        currentInstalledProductsPost=pin(POST), oldDeviceCandidate=pin(OLD/'candidate.json'),
        scriptDelta=pin(out/'script-delta.json'), fullActualScriptsDiff=pin(out/'scripts-from-previous.diff'),
        fullUnwrappedBodiesDiff=pin(out/'scripts-unwrapped-from-previous.diff'),
        actualFullFiles=len(files), actualFullCodeDirectoryHashes=len(full), actualChangedFiles=len(changes), actualExistingFilesUpdated=sum(r['old'] is not None for r in changes),
        actualNewFilesAdded=0, actualNewDirectoriesAdded=len(new_dirs), actualNewTrustEntries=len(new_cd),
        onlyGPUProductParentIdentityAndAppAnchorChanged=False, actualCPUCurrentSource=runtime['cpu29SourceProof'], all29CPUObjectsWholeRuntime86=False, actualChangedCPUObjects=3, actualUnchangedCPUObjects=26, allOther26CPUObjectsWholeRuntime113=True, actualRuntimeProductFiles=len(runtime_files),
        actualRuntimeCodeImages=runtime_cd_count, all103AppResourcesWholeUnchanged=True,
        all265ExistingDevicePathsModesAndDirectoriesSame=True, continuingHumanAuthorization=scope['continuingHumanAuthorization'],
        bootSeconds=BOOT, bootSessionUUID=UUID, closeOwnExternalWallSeconds=20,
        deploymentStageExternalWallSeconds=90, deploymentStageTransportTimeoutSeconds=100,
        allOtherRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        exactPreviousControllerOnlyStageNameChanged=False,measuredSameUUIDBootClockSecondsUpdated=True, repeatedRuntime65To66SourceAdmissionNotApplied=True,
        baselinePreviousInitializationSucceeded=True,
        baselineInstalledProductsHealthProvenByActualCurrentPost=True,
        precedingNormalStop=preceding_stop, currentInstalledPostKind=post_kind,
        newPacketRequiresAllSevenStandardActionsAndContinuingDerivedAuthorization=True,
        allChangedOldFilesAndLogBackedUpBeforeFirstReplacement=True, sameDirectoryTemporaryReplacements=True,
        originalStable2sReadinessAndProcessCleanupRetained=True, noExistingPermissionsChanged=True, onlyGPUProductAndSignedParentPinsChanged=False, onlyGuestAMXAdvertisementAndAppAnchorChanged=False,onlyLinearPitchAndParentIdentityAndAppMainAnchorChanged=False,onlyOwnedMainMetalDiagnosticFlagChanged=False,onlyOwnedChildMetalEnvironmentChanged=False,onlyOwnedGPUChildValidationEnvironmentChanged=False,onlyNativeVolatileDiscardOptimizationDeferred=False,onlyMissingFramebufferReadCapabilityMapped=False,onlyLiveCPUOwnedMappingCacheAndAppAnchorChanged=True, noNewCPUOrHVPermissions=True,
        rootReadyAndDerivedAuthorizationNotGenerated=True, guestBootRequested=False,
        deviceOperations=0, trustCacheOperations=0, codeSigningOperations=0, readyForDeviceExecution=False)
    dump(out/'candidate.json', candidate)
    pins = [pin(p) for p in sorted(out.iterdir()) if p.is_file()]
    pins += [pin(__file__), pin(B/'independent27_device_product_verify_fast_v1.py'),
             pin(OLD/'candidate.json'), pin(OLD/'scope.json'), pin(OLD/'freeze.json'), pin(OLD/'control.py'),
             pin(OLD/'health-root.sh'), old['runtimeCandidate'], old['appCandidate'],
             runtime_pin, signature_pin, pin(manifest_path),
             pin(app_path), app['sourceCandidate'], source['inheritedCompiledAppCandidate'], runtime['nativeOwnedGPUTaskProduct'], runtime['nativeOwnedGPUTaskSourcePlan'],
             scope['continuingHumanAuthorization'], pin(POST), post['request'], post['stdout'], post['stderr']]
    pins += [pin(B/'independent27_boot_clock_binding_v2.py'),pin(clock.PROOF)]
    pins += current_post_pins + prior_receipt_pins + list(prior['scripts'].values())+[row['local'] for row in files]+[changed['old'] for changed in changes if changed['old'] is not None]
    dump(out/'freeze.json', dict(files=list({row['path']:row for row in pins}.values()),
         deviceOperations=0, codeSigningOperations=0, repeatedHistoricalSourceDeltaAdmission=False))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), scope=pin(out/'scope.json'),
         freeze=pin(out/'freeze.json'), delta=pin(out/'script-delta.json'),
         files=len(files), CDs=len(full), changedFiles=len(changes), newTC=len(new_cd), maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
