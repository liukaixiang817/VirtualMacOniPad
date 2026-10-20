#!/usr/bin/env python3
"""Prepare a sealed genuine macOS27 sandbox resource delta from actual signed bytes."""
import argparse
import copy
import importlib.util
import io
import json
import pathlib
import shlex
import subprocess
import sys
import tarfile
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
OLD = N/'independent27-owned-bundle-device-v3-attempt1'
CONTROLLER_BASE = N/'independent27-device-bootstrap-recovery-v4-attempt1'


def module(name, path):
    sp = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(value)
    return value


base = module('frozen_original_bootstrap', N/'independent27-device-bootstrap-controller-v3-attempt1/control.py')
fast = module('frozen_fast_verification', B/'independent27_device_product_verify_fast_v1.py')
pin, need, dump = base.pin, base.need, base.dump


def exact_freeze(directory):
    value = json.loads((directory/'freeze.json').read_bytes())
    rows = value.get('files', value.get('pins', []))
    need(rows, 'actual nonempty frozen input')
    for row in rows:
        path = pathlib.Path(row['path'])
        need(path.is_absolute() and path.is_file() and not path.is_symlink(), 'regular frozen read-only source')
        data = path.read_bytes()
        actual = dict(path=str(path), bytes=len(data), sha256=base.digest(data))
        need(actual == row, 'unchanged actual frozen source: '+str(path))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True, type=pathlib.Path)
    ap.add_argument('--app-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--runtime-candidate', required=True, type=pathlib.Path)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh own delta packet')
    app_path = args.app_candidate.resolve()
    runtime_path = args.runtime_candidate.resolve()
    old_scope_path = OLD/'scope.json'
    for path in (app_path, runtime_path):
        exact_freeze(path.parent)
    app = json.loads(app_path.read_bytes())
    runtime = json.loads(runtime_path.read_bytes())
    old_scope = json.loads(old_scope_path.read_bytes())
    need(runtime['actualProductPreflightPassed'] and app['actualCodeSigned'], 'actual completed products')
    old_post = OLD/'device-receipts/post/receipt.json'
    old_receipt = json.loads(old_post.read_bytes())
    need(old_receipt['transportExit'] == 0, 'actual current installed products readonly success')
    need(b'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in base.exact(old_receipt['stdout']).read_bytes(),
         'actual last installed products verified after accurate owned cleanup')
    manifest = json.loads((runtime_path.parent/'manifest.json').read_bytes())
    cd_by_path = {'runtime/'+row['path']: row['cdhash'] for row in manifest['files'] if row['kind'] == 'mach-o'}
    cd_by_path['VirtualMacIndependent27.app/VirtualMacIndependent27'] = app['actualSignature']['cdhash']
    scope = copy.deepcopy(old_scope)
    scope['historicalPriorOwnedBundleDeltaOnly'] = dict(oldScope=pin(old_scope_path), oldActualPost=scope['oldActualPost'])
    scope['oldActualPost'] = pin(old_post)
    # Scope describes this delta; inherited bootstrap metadata stays historical.
    scope['historicalPriorOwnedBundleArchiveOnly'] = {
        key: scope.pop(key) for key in ('archive', 'trustCacheFixedBatchCounts')}
    scope['trustCacheFixedBatchCounts'] = [2]
    scope['actualFullCodeInventoryForVerificationOnly'] = True
    scope['ownedEndpointAuthenticationContract'] = dict(
        mode='explicit-owned-bundle-v1', originalStrictNativeAndRawUnmodified=True,
        originalNativeResultAndValidatedFlagPreserved=True, noNativeFailureFallback=True,
        reviewedWholeFileAndCodeDirectoryPinsRequired=True, fullBundlePagesAndSlotsRequired=True,
        actualSpawnedAuditPIDAndStickyVersionRequired=True, kernelCDAndCS_VALIDRequired=True,
        genuineNativePluginBooleanRequired=True, nativeTrustFlagWrites=0, kernelWrites=0)

    scope['deltaReplacementsUseExactSameDirectoryTemporaryFiles'] = True
    scope['schema'] = 'Actual independent27 sealed sandbox resource five-file delta scope v1'
    scope['deviceStage'] = '/private/var/mobile/Library/.VM27-independent27-sandbox-resource-stage-v1'
    changes = []
    for row, prior in zip(scope['files'], old_scope['files'], strict=True):
        name = row['archivePath']
        if name.startswith('runtime/'):
            local = pathlib.Path(runtime['runtimeRoot'])/name[len('runtime/'):]
        else:
            need(name.startswith('VirtualMacIndependent27.app/'), 'exact own product member')
            local = pathlib.Path(app['app'])/name[len('VirtualMacIndependent27.app/'):]
        row['local'] = pin(local)
        if name in cd_by_path:
            row['cdhash'] = cd_by_path[name]
        else:
            row.pop('cdhash', None)
        if row['local']['sha256'] != prior['local']['sha256']:
            changes.append(dict(index=len(changes), devicePath=row['devicePath'], mode=row['mode'],
                                old=prior['local'], new=row['local'], archivePath=name))
    sandbox_rel = 'child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb'
    sandbox_name = 'runtime/'+sandbox_rel
    sandbox_directory = str(pathlib.PurePosixPath(sandbox_name).parent)
    sandbox_device = scope['deviceRuntime']+'/'+sandbox_rel
    sandbox_device_directory = str(pathlib.PurePosixPath(sandbox_device).parent)
    need(sandbox_directory not in old_scope['directories'] and
         all(row['archivePath'] != sandbox_name for row in old_scope['files']), 'new exact resource was absent from actual installed products')
    sandbox_local = pin(pathlib.Path(runtime['runtimeRoot'])/sandbox_rel)
    need(sandbox_local['bytes'] == 32301 and sandbox_local['sha256'] ==
         '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504', 'genuine same-build profile bytes')
    need(len(changes) == 4, 'only four existing own product files change')
    scope['directories'][sandbox_directory] = 0o700
    scope['files'].append(dict(archivePath=sandbox_name,devicePath=sandbox_device,mode=0o600,local=sandbox_local))
    changes.append(dict(index=len(changes),devicePath=sandbox_device,mode=0o600,old=None,
                        new=sandbox_local,archivePath=sandbox_name,newResource=True))
    scope['newOwnDirectories'] = [dict(archivePath=sandbox_directory,devicePath=sandbox_device_directory,mode=0o700)]
    scope['newOwnResourceFiles'] = [sandbox_name]
    scope['systemSandboxFilesModified'] = False
    scope['nativeSandboxAPIIsUnmodified'] = True
    scope['nativeSandboxProfileFlags'] = 3
    scope['nativeSandboxAcceptanceVerified'] = False
    scope['nativeSandboxAppliesOnlyInsideOwnedChild'] = True
    old_cd = set(old_scope['trustCacheCDHashes'])
    full_cd = sorted(cd_by_path.values())
    delta_cd = sorted(set(full_cd)-old_cd)
    need(len(scope['files']) == 253 and len(changes) == 5 and len(full_cd) == len(set(full_cd)) == 140,
         'actual four updated files plus one new resource and same finite140 full code set')
    need(len(delta_cd) == 2 and len(set(full_cd)&old_cd) == 138, 'only child and App two new actual code hashes')
    scope.update(trustCacheCDHashes=full_cd, trustCacheRegistrationCount=2,
        actualFullCodeDirectoryHashes=140, newTrustCacheCDHashes=delta_cd,
        deltaFiles=changes, unchangedFiles=248, unchangedSignedImages=138, existingOwnFilesUpdated=4, newOwnFilesAdded=1,
        oldScope=pin(old_scope_path), currentInstalledProductsPost=pin(old_post), appCandidate=pin(app_path),
        runtimeCandidate=pin(runtime_path), backupOldOwnFilesAndLog=True,
        deviceSystemFilesModified=False, guestBootRequested=False,
        initializationExternalWallSeconds=45, updateExternalWallSeconds=45)
    archive_io = io.BytesIO()
    with tarfile.open(fileobj=archive_io, mode='w:', format=tarfile.USTAR_FORMAT) as archive:
        for row in changes:
            info = tarfile.TarInfo('new-'+str(row['index']))
            info.mode = 0o600
            info.uid = info.gid = info.mtime = 0
            data = base.exact(row['new']).read_bytes()
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    archive = archive_io.getvalue()
    scope['deltaArchiveBytes'] = len(archive)
    scope['deltaArchiveSHA256'] = base.digest(archive)
    scope['archive'] = dict(path=str(out/'products.tar'), bytes=len(archive), sha256=base.digest(archive))
    base.DEVICE_STAGE = scope['deviceStage']
    prefix, off = base.prefix, base.off_check
    wrap = lambda body, uid: prefix(uid)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c '+shlex.quote(body)+'\n'
    before_fast, after_fast = fast.batch_check(old_scope), fast.batch_check(scope)
    resource_absent = f'[ ! -e {shlex.quote(sandbox_device_directory)} ] && [ ! -L {shlex.quote(sandbox_device_directory)} ]\n'
    stage_check = '''
[ -d "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(realpath "$OWN_STAGE")" = "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a "$OWN_STAGE")" = 0:0:700 ]
'''
    file_functions = '''
check_own_file() {
 [ -f "$1" ] && [ ! -L "$1" ]
 [ "$(realpath "$1")" = "$1" ]
 [ "$(stat -c %u:%g:%a:%h:%s "$1")" = "501:501:$4:1:$3" ]
 [ "$(sha256sum "$1" | cut -d ' ' -f1)" = "$2" ]
}
'''
    scripts = {}
    health = base.HEALTH.read_text()
    scripts['preflight'] = wrap(prefix(0)+off()+health+before_fast+resource_absent+'''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2199 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128 ]
printf 'INDEPENDENT27_DELTA_OLD_EXACT_AND_HEALTHY\n'
''', 0)
    stage_body = prefix(0)+off()+file_functions+resource_absent+'''
[ ! -e "$OWN_STAGE" ] && [ ! -L "$OWN_STAGE" ]
mkdir -m 700 "$OWN_STAGE"
chown 0:0 "$OWN_STAGE"
'''+stage_check+f'''
dd of="$OWN_STAGE/products.tar" bs=65536 2>/dev/null
[ "$(stat -c %u:%g:%h:%s "$OWN_STAGE/products.tar")" = 0:0:1:{len(archive)} ]
[ "$(sha256sum "$OWN_STAGE/products.tar" | cut -d ' ' -f1)" = {base.digest(archive)} ]
tar -xpf "$OWN_STAGE/products.tar" -C "$OWN_STAGE"
'''
    # Back up all four old files and log; record the new resource's absence before any own product mutation.
    for row in changes:
        path = shlex.quote(row['devicePath'])
        old, new = row['old'], row['new']
        index = row['index']
        if old is not None:
            stage_body += f'check_own_file {path} {old["sha256"]} {old["bytes"]} {row["mode"]:o}\n'
            stage_body += f'cp -p {path} "$OWN_STAGE/backup-{index}"\n'
            stage_body += f'[ "$(sha256sum "$OWN_STAGE/backup-{index}" | cut -d \' \' -f1)" = {old["sha256"]} ]\n'
        else:
            stage_body += f'[ ! -e {path} ] && [ ! -L {path} ]\n'
            stage_body += f'(umask 077; set -C; : > "$OWN_STAGE/backup-new-absent-{index}")\n'
        stage_body += f'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/new-{index}")" = 0:0:600:1:{new["bytes"]} ]\n'
        stage_body += f'[ "$(sha256sum "$OWN_STAGE/new-{index}" | cut -d \' \' -f1)" = {new["sha256"]} ]\n'
    stage_body += '''
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2199 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128 ]
cp -p "$OWN_LOG" "$OWN_STAGE/backup-app-log"
[ "$(sha256sum "$OWN_STAGE/backup-app-log" | cut -d ' ' -f1)" = ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128 ]
own_log_identity=$(stat -c %d:%i "$OWN_LOG")
'''
    parent_resource = str(pathlib.PurePosixPath(sandbox_device_directory).parent)
    stage_body += resource_absent
    stage_body += f'[ -d {shlex.quote(parent_resource)} ] && [ ! -L {shlex.quote(parent_resource)} ]\n'
    stage_body += f'[ "$(realpath {shlex.quote(parent_resource)})" = {shlex.quote(parent_resource)} ]\n'
    stage_body += f'[ "$(stat -c %u:%g:%a {shlex.quote(parent_resource)})" = 501:501:700 ]\n'
    stage_body += f'mkdir -m 700 {shlex.quote(sandbox_device_directory)}\nchown 501:501 {shlex.quote(sandbox_device_directory)}\n'
    stage_body += f'[ -d {shlex.quote(sandbox_device_directory)} ] && [ ! -L {shlex.quote(sandbox_device_directory)} ]\n'
    stage_body += f'[ "$(realpath {shlex.quote(sandbox_device_directory)})" = {shlex.quote(sandbox_device_directory)} ]\n'
    stage_body += f'[ "$(stat -c %u:%g:%a {shlex.quote(sandbox_device_directory)})" = 501:501:700 ]\n'
    stage_body += f'[ "$(find {shlex.quote(sandbox_device_directory)} -mindepth 1 | wc -l | tr -d \' \')" = 0 ]\n'
    for row in changes:
        path = shlex.quote(row['devicePath'])
        temporary = shlex.quote(str(pathlib.PurePosixPath(row['devicePath']).parent/('.VM27-sandbox-resource-v1-'+str(row['index'])+'.pending')))
        old, new = row['old'], row['new']
        index = row['index']
        stage_body += f'[ ! -e {temporary} ] && [ ! -L {temporary} ]\n'
        stage_body += f'cp "$OWN_STAGE/new-{index}" {temporary}\nchown 501:501 {temporary}\nchmod {row["mode"]:o} {temporary}\n'
        stage_body += f'check_own_file {temporary} {new["sha256"]} {new["bytes"]} {row["mode"]:o}\n'
        if old is not None:
            stage_body += f'check_own_file {path} {old["sha256"]} {old["bytes"]} {row["mode"]:o}\n'
            stage_body += f'mv -f {temporary} {path}\n'
        else:
            stage_body += f'[ ! -e {path} ] && [ ! -L {path} ]\n'
            stage_body += f'mv -n {temporary} {path}\n'
            stage_body += f'[ ! -e {temporary} ] && [ ! -L {temporary} ]\n'
        stage_body += f'check_own_file {path} {new["sha256"]} {new["bytes"]} {row["mode"]:o}\n'
        stage_body += f"printf 'OWN_EXACT_FILE_UPDATED {index} {row['archivePath']}\\n'\n"
    stage_body += '''
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2199 ]
: > "$OWN_LOG"
[ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_identity" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
(umask 077; set -C; : > "$OWN_STAGE/stage-complete")
printf 'INDEPENDENT27_ALL_OWN_DELTA_FILES_UPDATED_BACKUPS_RETAINED_NO_TRUST_OR_EXECUTION\n'
'''
    scripts['stage'] = wrap(stage_body, 0)
    complete_check = stage_check+'[ "$(stat -c %u:%g:%a:%h:%s "$OWN_STAGE/stage-complete")" = 0:0:600:1:0 ]\n'
    new_cd_check = fast.cd_check(scope, delta_cd)
    scripts['verify'] = wrap(prefix(0)+off()+complete_check+after_fast+new_cd_check+
                             "printf 'INDEPENDENT27_ALL253_AND_NEW_DELTA_CD_EXACT\\n'\n", 0)
    trust_body = prefix(0)+off()+complete_check+after_fast+new_cd_check
    trust_body += '(umask 077; set -C; : > "$OWN_STAGE/trust-dispatched")\n'
    for index, cd in enumerate(delta_cd, 1):
        trust_body += f'jbctl trustcache add {cd}\nprintf \'OWN_TC_ADDED {index} {cd}\\n\'\n'
    scripts['trust'] = wrap(trust_body+"printf 'INDEPENDENT27_ONLY_NEW_DELTA_TRUST_ENTRIES_COMPLETE\\n'\n", 0)
    original = base.make_scripts(scope, health)
    slow_plain = base.verify_products(scope)
    slow_cd = base.verify_products(scope, include_cd=True)
    inside = lambda text: text.replace("'", "'\"'\"'")
    need(original['launch'].count(inside(slow_plain)) == 1, 'one original bounded launch verification')
    scripts['launch'] = original['launch'].replace(inside(slow_plain), inside(after_fast), 1)
    for action in ('register', 'post'):
        need(original[action].count(slow_cd) == 1, 'one original full verification '+action)
        scripts[action] = wrap(original[action].replace(slow_cd, after_fast), 0)
    close_body = prefix(0)+health+before_fast+resource_absent+base.PROCESS_FUNCTIONS+"""
scan_own
[ "$own_child_pid" = 0 ]
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2199 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128 ]
if [ "$own_app_pid" -gt 1 ]; then
 scan_own
 [ "$own_child_pid" = 0 ]
 signal_own TERM "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
 sleep 1
 signal_own KILL "$own_app_pid" "$OWN_APP_MAIN" "$own_app_start" app
fi
"""+off()+"""
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:2199 ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ec516dca7b9fd299f369a067f788bc88cfb0fe1fb5b62daa53bd8962dd4f7128 ]
printf 'INDEPENDENT27_CURRENT_EXACT_OWN_APP_OFF_NO_CHILD_SIGNAL_NO_FILE_WRITE\\n'
"""
    scripts['close-current-own'] = prefix(0)+'/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c '+shlex.quote(close_body)+'\n'
    source = (CONTROLLER_BASE/'control.py').read_text()
    head = source[:source.index('\ndef ready_gate(')]
    head = head.replace("DEVICE_STAGE = '/private/var/mobile/Library/.VM27-independent27-bootstrap-stage-v1'",
                        'DEVICE_STAGE = '+repr(scope['deviceStage']))
    start = head.index('TRUST_ACTIONS = ')
    end = head.index('\n\n\ndef need(', start)
    head = head[:start]+"TRUST_ACTIONS = ('trust',)\nACTIONS = ('close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post')"+head[end:]
    ready_function = '''
def ready_gate(packet, ready_path):
    ready = json.loads(ready_path.read_bytes())
    need(ready.get('readyForRootSerialDispatch') is True, 'actual Root ready gate required')
    need(ready['packetCandidate'] == pin(packet/'candidate.json') and ready['packetFreeze'] == pin(packet/'freeze.json'), 'exact packet')
    for row in json.loads(exact(ready['packetFreeze']).read_bytes())['files']:
        exact(row)
    need(ready['controller'] == pin(packet/'control.py') == pin(__file__), 'exact reviewed controller')
    need(ready['independentReviews'], 'concrete independent review required')
    for row in ready['independentReviews']:
        review = json.loads(exact(row).read_bytes())
        need(review.get('findings') == [] and review.get('controllerPacketCandidate') == pin(packet/'candidate.json'), 'exact peer review')
    scope = json.loads((packet/'scope.json').read_bytes())
    auth = json.loads(exact(ready['specificUserAuthorization']).read_bytes())
    need(auth.get('authorized') is True and auth.get('humanUserAuthorization') is True and auth['scope'] == pin(packet/'scope.json') and
         auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes'] and auth['trustCacheRegistrationCount'] == 2 and
         auth['initializationExternalWallSeconds'] == 45, 'actual new exact human two-entry resource authorization')
    raw = (packet/'products.tar').read_bytes()
    need(len(raw) == scope['deltaArchiveBytes'] and digest(raw) == scope['deltaArchiveSHA256'], 'exact delta archive')
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        members = archive.getmembers()
        need(len(members) == 5 and [item.name for item in members] == ['new-'+str(i) for i in range(5)], 'exact five ordinary delta members')
        for item, row in zip(members, scope['deltaFiles'], strict=True):
            need(item.isreg() and not item.linkname and not item.pax_headers and item.uid == item.gid == item.mtime == 0 and
                 item.mode == 0o600 and item.size == row['new']['bytes'], 'exact ordinary archive shape')
            need(digest(archive.extractfile(item).read()) == row['new']['sha256'], 'actual delta bytes')
    return ready, scope
'''
    tail = source[source.index('\ndef run_remote('):]
    start = tail.index('    previous = ')
    end = tail.index('    if previous:', start)
    tail = tail[:start]+"    previous = {'preflight': 'close-current-own', 'stage': 'preflight', 'verify': 'stage', 'trust': 'verify', 'launch': 'trust', 'post': 'launch'}.get(args.action)\n"+tail[end:]
    need(tail.count("        data = b''") == 1, 'one genuine action payload')
    tail = tail.replace("        data = b''", "        data = (packet/'products.tar').read_bytes() if args.action == 'stage' else b''", 1)
    controller = head+ready_function+tail
    compile(controller, str(out/'control.py'), 'exec')
    out.mkdir(mode=0o700)
    dump(out/'scope.json', scope)
    (out/'products.tar').write_bytes(archive)
    (out/'control.py').write_text(controller)
    script_rows, sizes = {}, {}
    for action, script in scripts.items():
        subprocess.run(['/bin/sh', '-n'], input=script.encode(), check=True)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '')+'/var/jb/bin/sh -c '+shlex.quote(script)
        need(len(command.encode())+10000 < 262144, 'actual iPad ARG_MAX with environment reserve: '+action)
        path = out/(action+'.sh')
        path.write_text(script)
        script_rows[action] = pin(path)
        sizes[action] = len(command.encode())
    candidate = dict(schema='Prepared actual independent27 sealed sandbox resource five-file delta device packet v1',
        preparer=pin(__file__), scope=pin(out/'scope.json'), archive=pin(out/'products.tar'), controller=pin(out/'control.py'),
        scripts=script_rows, actions=['close-current-own', 'preflight', 'stage', 'verify', 'trust', 'launch', 'post'],
        priorController=pin(CONTROLLER_BASE/'control.py'), currentInstalledProductsPost=pin(old_post),
        runtimeCandidate=pin(runtime_path), appCandidate=pin(app_path),
        actualChangedFiles=5, actualExistingFilesUpdated=4, actualNewFilesAdded=1, actualNewDirectoriesAdded=1, actualUnchangedFiles=248, actualNewTrustEntries=2,
        actualUnchangedSignedImages=138, maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
        processIdentityCleanupAndTransportFunctionsUnchanged=True,
        closeOwnAppExternalWallSeconds=20, allOriginalRemoteActionsExternalWallSeconds=45, transportTimeoutSeconds=55,
        retainedBackupOldOwnFourFilesAndLogAndNewResourceAbsence=True, individualTrustCacheWithdrawalProven=False,
        deviceOperations=0, trustCacheOperations=0, guestBootRequested=False, readyForDeviceExecution=False)
    dump(out/'candidate.json', candidate)
    files = [pin(path) for path in out.iterdir() if path.is_file()]
    files += [pin(__file__), pin(CONTROLLER_BASE/'control.py'), pin(OLD/'control.py'), pin(old_scope_path), pin(old_post),
              old_receipt['stdout'], old_receipt['stderr'], pin(base.HEALTH),
              pin(B/'independent27_device_product_verify_fast_v1.py'), pin(app_path), pin(runtime_path),
              pin(app_path.parent/'freeze.json'), pin(runtime_path.parent/'freeze.json')]
    files += [row['local'] for row in scope['files']]+[row['old'] for row in changes if row['old'] is not None]
    dump(out/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps({'candidate': pin(out/'candidate.json'), 'scope': pin(out/'scope.json'),
                      'newTrustEntries': delta_cd, 'maximumQuotedCommandBytes': max(sizes.values())}))


if __name__ == '__main__':
    main()
