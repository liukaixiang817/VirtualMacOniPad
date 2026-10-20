#!/usr/bin/env python3
"""HOST-only rebase of the unexecuted Dev60 R64 update to a real new-boot inventory.

No live fact or ready authorization is produced here. Root alone obtains the
readonly inventory, reviews this concrete packet, and executes its controller.
"""
import argparse
import copy
import importlib.util
import json
import pathlib
import re
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
B = pathlib.Path(__file__).resolve().parent
R = B.parents[2]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SOURCE = N / 'independent27-borrowed-host-input-device-v60-attempt1'
INSTALLED = N / 'independent27-serialized-wake-device-v59-attempt1'
STAGE = '/private/var/mobile/Library/.VM27-independent27-borrowed-host-input-newboot-stage-v61'
BOOT = 1792161311
USEC = 643083
UUID = 'C7D63D1F-86E9-4224-A1C7-108F02E91942'
MARKER = 'VM27_REBASE_ACTUAL_STAGE_LOG_IDENTITY'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


prior = load(B / 'prepare-independent27-borrowed-host-input-device-v60.py', 'borrowed_input_prior')
base = prior.base
pin, need, dump = base.pin, base.need, base.dump


def replace_once(text, before, after):
    need(text.count(before) == 1, 'one exact inherited fragment: ' + before[:100])
    return text.replace(before, after, 1)


def evidence(path):
    inventory = json.loads(path.read_bytes())
    receipt = json.loads(base.exact(inventory['actualReadonly']).read_bytes())
    request = json.loads(base.exact(receipt['request']).read_bytes())
    text = base.exact(receipt['stdout']).read_text()
    base.exact(receipt['stderr'])
    old = json.loads((INSTALLED / 'scope.json').read_bytes())
    expected = sorted(old['trustCacheCDHashes'])
    need(receipt['transportExit'] == 0 and
         inventory['bootSeconds'] == request['bootSeconds'] == BOOT and
         inventory['bootMicroseconds'] == request['bootMicroseconds'] == USEC and
         inventory['bootSessionUUID'] == request['bootSessionUUID'] == UUID,
         'actual successful current-boot readonly receipt and exact boot identity')
    need(request['historicalInstalledCandidate'] == pin(INSTALLED / 'candidate.json') and
         request['historicalInstalledScope'] == pin(INSTALLED / 'scope.json') and
         inventory['actualInstalledProductsWholeExact'] is True and
         inventory['actualFullFiles'] == 259 and inventory['expectedActiveCDHashes'] == expected,
         'actual installed R63 App75 full259 readonly proof, not historical post')
    need(request['source']['sha256'] == 'bcc56821f58b2b1a325d09984ce3450c020b928bd2a9f7aaca0be03a8d09da82',
         'actual Root-reviewed current-boot readonly capturer v3')
    base.exact(request['source']); base.exact(request['script'])
    base.exact(request['actualCurrentSession']); base.exact(request['actualCurrentSessionStdout'])
    need(text.count('INDEPENDENT27_NEWBOOT_INSTALLED_PRODUCTS_AND_TRUST_READONLY_COMPLETE') == 1 and
         'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in text and
         'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in text and
         'OWN_NEWBOOT_TRUST_NATIVE_EXIT 0' in text,
         'actual full product, own OFF and native trust query completion markers')
    info = text.split('OWN_NEWBOOT_TRUST_INFO_BEGIN\n', 1)[1].split('\nOWN_NEWBOOT_TRUST_INFO_END', 1)[0]
    present = {line.split()[-1].lower() for line in info.splitlines()
               if line.split() and re.fullmatch('[0-9a-fA-F]{40}', line.split()[-1])}
    need(sorted(present) == inventory['allActualPresentNativeTrustCDHashes'] and
         sorted(set(expected) & present) == inventory['actualPresentExpectedCDHashes'] and
         sorted(set(expected) - present) == inventory['actualMissingCDHashes'],
         'independently parsed complete actual native trust output')
    logs = [line for line in text.splitlines() if line.startswith('OWN_NEWBOOT_LOG_')]
    need(logs == inventory['ownLogObservation'] and len(logs) == 1,
         'one actual readonly log observation')
    if logs == ['OWN_NEWBOOT_LOG_ABSENT']:
        log = dict(present=False, identity=None)
    else:
        match = re.fullmatch(r'OWN_NEWBOOT_LOG_PRESENT ([0-9:]+) ([0-9a-f]{64})', logs[0])
        need(match is not None, 'actual ordinary owned log metadata and SHA')
        fields = match[1].split(':')
        need(len(fields) == 9 and fields[2:6] == ['501', '501', '600', '1'] and
             all(v.isdigit() for v in fields) and 0 <= int(fields[6]) <= 2097152,
             'actual current ordinary owned bounded log')
        log = dict(present=True, identity=':'.join(fields[:6]), metadata=match[1], sha256=match[2])
    return inventory, receipt, request, present, log


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--inventory', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    args = ap.parse_args()
    out, inv_path = args.output.resolve(), args.inventory.resolve()
    need(out.parent == N and not out.exists() and inv_path.is_relative_to(N), 'fresh HOST packet and real local inventory')
    prior.frozen(SOURCE)
    prior.frozen(INSTALLED)
    need(not any(SOURCE.glob('*-dispatched.json')) and not (SOURCE / 'device-receipts').exists(),
         'old-boot Dev60 was never dispatched')
    inventory, receipt, request, present, log = evidence(inv_path)
    source_candidate = json.loads((SOURCE / 'candidate.json').read_bytes())
    source_scope = json.loads((SOURCE / 'scope.json').read_bytes())
    old = json.loads((INSTALLED / 'scope.json').read_bytes())
    need(source_scope['runtimeCandidate']['sha256'] == '6bed55cbc7aa8e79b307eb83d4c0d6417da706da7d5719446dbd0e2839eac749' and
         source_scope['appCandidate']['sha256'] == '39b8003128236d535cb4c271940b385fef601d9735ff1ab772a8d0fc74984427',
         'exact actual Root-signed R64 and App76 products')
    final = sorted(source_scope['trustCacheCDHashes'])
    missing = sorted(set(final) - present)
    need(len(final) == 144 and len(source_scope['deltaFiles']) == 7 and
         all(row['old'] is not None for row in source_scope['deltaFiles']),
         'unchanged actual7 existing-file update and final144 code set')
    scope = copy.deepcopy(source_scope)
    scope.update(schema='Actual R64 App76 newboot trust restoration and seven-file update v61',
                 deviceStage=STAGE, bootSeconds=BOOT, bootMicroseconds=USEC, bootSessionUUID=UUID,
                 currentBootTrustInventory=pin(inv_path), currentDeviceFacts=request['actualCurrentSession'],
                 currentInstalledProductsPost=None, oldActualPost=None,
                 historicalPriorBootInstalledProductsPost=source_scope['currentInstalledProductsPost'],
                 currentInstalledProductsActualReadonly=inventory['actualReadonly'],
                 currentInstalledProductScope=pin(INSTALLED / 'scope.json'),
                 newTrustCacheCDHashes=missing, trustCacheRegistrationCount=len(missing),
                 trustCacheFixedBatchCounts=([len(missing)] if missing else []),
                 restoredExistingProductCDHashes=sorted(set(missing) & set(old['trustCacheCDHashes'])),
                 newProductCodeHashes=sorted(set(missing) - set(old['trustCacheCDHashes'])),
                 trustMembershipAssumedFromPriorBoot=False, trustMembershipKnownBeforeDispatch=True,
                 allActualTrustAlreadyRegistered=not missing, fixedOwnedLogIdentity=None,
                 missingOwnLogMayBeCreated=not log['present'], actualReadonlyOwnLogObservation=log,
                 newLogIdentityMustBeActuallyCapturedBeforeLaunch=True,
                 existingOwnLogMustBeBackedUpBeforeTruncation=True,
                 currentBootAndLogBindingReplacesHistoricalInitializerGeneration=True,
                 initialCurrentBootNativePresentCodeHashes=sorted(present))
    scope['historicalPriorBootInitializerLogGeneration'] = scope.pop('actualInitializerLogGeneration')
    archive = base.exact(source_candidate['archive']).read_bytes()
    scope['archive'] = dict(path=str(out / 'products.tar'), bytes=len(archive), sha256=base.digest(archive))
    old_sec, old_uuid = str(source_scope['bootSeconds']), source_scope['bootSessionUUID']
    old_identity = source_scope['fixedOwnedLogIdentity']
    old_devino = ':'.join(old_identity.split(':')[:2])

    def rebase(text):
        return text.replace(source_scope['deviceStage'], STAGE).replace(old_sec, str(BOOT)).replace(old_uuid, UUID)

    log_check = '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
[ "$(stat -c %d:%i "$OWN_LOG")" = ''' + old_devino + ''' ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
'''
    if log['present']:
        actual_log_check = '''[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %d:%i:%u:%g:%a:%h:%s:%Y:%Z "$OWN_LOG")" = ''' + shlex.quote(log['metadata']) + ''' ]
[ "$(sha256sum "$OWN_LOG" | cut -d ' ' -f1)" = ''' + log['sha256'] + ''' ]
'''
        stage_log_check = actual_log_check
    else:
        actual_log_check = '[ ! -e "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]\n'
        stage_log_check = actual_log_check + '''(umask 077; set -C; : > "$OWN_LOG")
chown 501:501 "$OWN_LOG"
chmod 600 "$OWN_LOG"
[ -f "$OWN_LOG" ] && [ ! -L "$OWN_LOG" ]
[ "$(stat -c %u:%g:%a:%h:%s "$OWN_LOG")" = 501:501:600:1:0 ]
printf 'OWN_NEWBOOT_EXCLUSIVE_EMPTY_LOG_CREATED\n'
'''
    scripts = {}
    for action in source_candidate['actions']:
        body = rebase(prior.unwrap((SOURCE / (action + '.sh')).read_text()))
        if action == 'preflight':
            body = replace_once(body, log_check, actual_log_check)
        elif action == 'stage':
            body = replace_once(body, log_check, stage_log_check)
            # Record the real newly-created or retained inode only after the
            # unchanged product replacements and log-preservation checks finish.
            body += "printf 'OWN_REBASE_LOG_READY %s\\n' \"$(stat -c %d:%i:%u:%g:%a:%h \"$OWN_LOG\")\"\n"
        elif action == 'trust':
            old_adds = ''.join('jbctl trustcache add ' + value + "\nprintf 'OWN_NEW_PRODUCT_TC_ADDED " + str(i) + ' ' + value + "\\n'\n"
                               for i, value in enumerate(source_scope['newTrustCacheCDHashes'], 1))
            new_adds = ''.join('jbctl trustcache add ' + value + "\nprintf 'OWN_CURRENT_BOOT_PRODUCT_TC_ADDED " + str(i) + ' ' + value + "\\n'\n"
                               for i, value in enumerate(missing, 1))
            body = replace_once(body, old_adds, new_adds)
            body = body.replace('INDEPENDENT27_ONLY_ACTUAL_NEW_PRODUCT_TC_ENTRIES_COMPLETE',
                                'INDEPENDENT27_ACTUAL_CURRENT_BOOT_MISSING_PRODUCT_TC_ENTRIES_COMPLETE')
        elif action == 'launch':
            needle = 'own_prior_log_inode=$(stat -c %d:%i "$OWN_LOG")'
            body = replace_once(body, needle,
                                '[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = ' + MARKER + ' ]\n' + needle)
        elif action == 'post':
            body = replace_once(body, old_identity, MARKER)
        uid = 501 if action == 'launch' else 0
        # The inherited prefix has the same exact Root/mobile, device, and boot
        # checks; only its real boot/UUID/stage values change.
        inherited = load(SOURCE / 'control.py', 'newboot_inherited_prefix_' + action)
        prefix = rebase(inherited.prefix(uid))
        seconds = 20 if action == 'close-current-own' else 90 if action == 'stage' else 45
        scripts[action] = prefix + '/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 ' + str(seconds) + ' /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
        need(old_identity not in scripts[action] and old_devino not in scripts[action] and
             old_uuid not in scripts[action] and old_sec not in scripts[action],
             'no historical boot or log execution gate retained: ' + action)
    controller = rebase((SOURCE / 'control.py').read_text())
    gate = '''    inventory=json.loads(exact(scope['currentBootTrustInventory']).read_bytes())
    actual_read=json.loads(exact(inventory['actualReadonly']).read_bytes())
    exact(actual_read['request']);exact(actual_read['stdout']);exact(actual_read['stderr'])
    need(actual_read['transportExit']==0 and inventory['actualInstalledProductsWholeExact'] is True and
         inventory['actualFullFiles']==259 and inventory['bootSeconds']==scope['bootSeconds']==1792161311 and
         inventory['bootMicroseconds']==scope['bootMicroseconds']==643083 and
         inventory['bootSessionUUID']==scope['bootSessionUUID']=='C7D63D1F-86E9-4224-A1C7-108F02E91942' and
         sorted(set(scope['trustCacheCDHashes'])-set(inventory['allActualPresentNativeTrustCDHashes']))==scope['newTrustCacheCDHashes'],
         'actual current boot installed products and exact final-product native missing trust set')
'''
    controller = replace_once(controller, '    return ready, scope\n', gate + '    return ready, scope\n')
    needle = "        script = (packet/(args.action+'.sh')).read_text()"
    rendered = needle + '''
        if args.action in ('launch','post'):
            prior+=prior_receipt(packet,'stage',success=True)
            staged=(packet/'device-receipts/stage/stdout').read_text()
            log_ids=re.findall(r'^OWN_REBASE_LOG_READY ([0-9:]+)$',staged,re.M)
            need(len(log_ids)==1 and re.fullmatch(r'[0-9]+:[0-9]+:501:501:600:1',log_ids[0]),
                 'one actual same-packet stage-owned log identity')
            need(all(int(value)>0 for value in log_ids[0].split(':')[:2]),'actual positive log device and inode')
            need(script.count('VM27_REBASE_ACTUAL_STAGE_LOG_IDENTITY')==1,'one dynamic exact own log identity gate')
            script=script.replace('VM27_REBASE_ACTUAL_STAGE_LOG_IDENTITY',log_ids[0])
            (output/'actual-rendered-script.sh').write_text(script)
'''
    controller = replace_once(controller, needle, rendered)
    controller = replace_once(controller, "'ready': pin(args.ready.resolve()), 'script': pin(packet/(args.action+'.sh'))",
                              "'ready': pin(args.ready.resolve()), 'script': pin(output/'actual-rendered-script.sh') if args.action in ('launch','post') else pin(packet/(args.action+'.sh')), 'sourceScript': pin(packet/(args.action+'.sh'))")
    compile(controller, str(out / 'control.py'), 'exec')
    health = rebase((SOURCE / 'health-root.sh').read_text())
    out.mkdir(mode=0o700)
    (out / 'control.py').write_text(controller)
    (out / 'health-root.sh').write_text(health)
    (out / 'products.tar').write_bytes(archive)
    dump(out / 'scope.json', scope)
    rows, sizes = {}, {}
    for action, text in scripts.items():
        result = subprocess.run(['/bin/sh', '-n'], input=text.encode(), capture_output=True)
        need(result.returncode == 0, 'actual shell syntax: ' + action)
        path = out / (action + '.sh')
        path.write_text(text)
        rows[action] = pin(path)
        (out / (action + '-syntax.stderr')).write_bytes(result.stderr)
        command = ('sudo -k -S -p "" ' if action != 'launch' else '') + '/var/jb/bin/sh -c ' + shlex.quote(text)
        sizes[action] = len(command.encode())
        need(sizes[action] + 10000 < 262144, 'actual quoted ARG_MAX: ' + action)
    candidate = copy.deepcopy(source_candidate)
    candidate.update(schema='Actual R64 App76 current-boot missing trust restoration and update packet v61',
                     preparer=pin(__file__), scope=pin(out / 'scope.json'), archive=pin(out / 'products.tar'),
                     controller=pin(out / 'control.py'), scripts=rows, bootSeconds=BOOT, bootMicroseconds=USEC,
                     bootSessionUUID=UUID, actualNewTrustEntries=len(missing), currentInstalledProductsPost=None,
                     currentInstalledProductsActualReadonly=inventory['actualReadonly'], currentBootTrustInventory=pin(inv_path),
                     maximumQuotedCommandBytes=max(sizes.values()), quotedCommandBytes=sizes,
                     priorAllInstalledProductsAndCurrentHealthActualPassed=True,
                     readyForDeviceExecution=False, deviceOperations=0, trustCacheOperations=0)
    dump(out / 'candidate.json', candidate)
    pins = [pin(p) for p in out.iterdir() if p.is_file()]
    pins += json.loads((SOURCE / 'freeze.json').read_bytes())['files']
    pins += [pin(__file__), pin(SOURCE / 'freeze.json'), pin(inv_path), inventory['actualReadonly'],
             receipt['request'], receipt['stdout'], receipt['stderr'], request['actualCurrentSession'],
             request['actualCurrentSessionStdout'], request['source'], request['script']]
    pins += request['frozenInputs']
    dump(out / 'freeze.json', dict(files=list({p['path']: p for p in pins}.values()), deviceOperations=0, codeSigningOperations=0))
    print(json.dumps(dict(candidate=pin(out / 'candidate.json'), scope=pin(out / 'scope.json'),
                         freeze=pin(out / 'freeze.json'), actualChangedFiles=7, finalCDHashes=144,
                         actualMissingCurrentBootTrustEntries=len(missing), priorLogPresent=log['present'],
                         maximumQuotedCommandBytes=max(sizes.values()))))


if __name__ == '__main__':
    main()
