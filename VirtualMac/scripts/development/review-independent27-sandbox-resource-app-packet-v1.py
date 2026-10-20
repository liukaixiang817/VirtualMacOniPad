#!/usr/bin/env python3
"""Finite HOST review of Root's actual App anchor relink and resource delta packet.

The Runtime7 builder was authored by this reviewer. Its signatures require
separate Root/transport review; this report does not self-review that product.
No dispatch, device access, code signing or guest execution is performed.
"""
import argparse
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
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent
checks = []


def need(value, label):
    if not value:
        raise ValueError(label)
    if not label.startswith(('actual pinned input:', 'unchanged installed bytes and device metadata:', 'other App resource/seal unchanged:')):
        checks.append(label)


def pin(path):
    path = pathlib.Path(path).resolve()
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def exact(row):
    need(pin(row['path']) == row, 'actual pinned input: ' + row['path'])
    return pathlib.Path(row['path'])


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze(path):
    rows = json.loads(path.read_bytes())['files']
    for row in rows:
        exact(row)
    return len(rows)


def function(tree, name):
    return ast.dump(next(x for x in tree.body if isinstance(x, ast.FunctionDef) and x.name == name),
                    include_attributes=False)


def constant(tree, name):
    node = next(x for x in tree.body if isinstance(x, ast.Assign) and
                any(isinstance(t, ast.Name) and t.id == name for t in x.targets))
    return ast.literal_eval(node.value)


def shell_body(script):
    tokens = shlex.split(script[script.index('/var/jb/usr/bin/timeout '):])
    need(tokens[-2] == '-c', 'one bounded remote shell body')
    return tokens[-1]


def signature_slots(image):
    command = next(c for c in image.commands if c['cmd'] == 0x1d)
    start, size = struct.unpack_from('<II', image.data, command['at'] + 8)
    raw = image.data[start:start + size]
    count = struct.unpack_from('>I', raw, 8)[0]
    slots = {}
    for i in range(count):
        kind, at = struct.unpack_from('>II', raw, 12 + 8 * i)
        length = struct.unpack_from('>I', raw, at + 4)[0]
        slots[kind] = raw[at:at + length]
    return slots


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh HOST review output')
    packet_path = args.packet_candidate.resolve()
    packet = json.loads(packet_path.read_bytes())
    packet_dir = packet_path.parent
    freeze_count = freeze(packet_dir / 'freeze.json')
    scope = json.loads(exact(packet['scope']).read_bytes())
    need(scope['actualRuntimeManifestFiles'] == 149, 'scope correctly counts the actual 149 resource-bearing manifest rows')
    old_scope = json.loads(exact(scope['oldScope']).read_bytes())
    app_path = exact(packet['appCandidate'])
    app = json.loads(app_path.read_bytes())
    freeze_count += freeze(app_path.parent / 'freeze.json')
    linked_path = exact(app['sourceCandidate'])
    linked = json.loads(linked_path.read_bytes())
    freeze_count += freeze(linked_path.parent / 'freeze.json')
    old_linked_path = exact(linked['inheritedActualObjectCompilationEvidence'])
    old_linked = json.loads(old_linked_path.read_bytes())
    runtime_path = exact(packet['runtimeCandidate'])
    runtime = json.loads(runtime_path.read_bytes())
    need(linked['actualRuntimeCandidate'] == packet['runtimeCandidate'] == app['runtimeCandidate'],
         'App and packet bind the same actual Runtime7')
    need(len(linked['objects']) == 31 and linked['objects'][:30] == old_linked['objects'][:30] and
         linked['sourceFiles'][:30] == old_linked['sourceFiles'][:30], 'all thirty old App objects and sources reused wholebyte')
    for row in linked['objects'] + linked['sourceFiles']:
        exact(row)
    need(linked['objects'][30] == runtime['anchorIOSObject'] and
         linked['sourceFiles'][30] == runtime['anchorSource'], 'only anchor object uses actual Runtime7 anchor')
    before_link = next(row for row in old_linked['commands'] if row['label'] == 'link-app')['argv']
    after_link = next(row for row in linked['commands'] if row['label'] == 'link-app')['argv']
    expected_link = list(before_link)
    expected_link[expected_link.index(old_linked['objects'][30]['path'])] = runtime['anchorIOSObject']['path']
    expected_link[expected_link.index(old_linked['binary']['path'])] = linked['binary']['path']
    need(after_link == expected_link, 'actual strong link command changes only anchor object and output destination')
    need(all(row['exit'] == 0 for row in linked['commands']), 'actual relink and dyld validate/import/export commands passed')
    reader_path = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    reader = load_module('resource_app_macho', reader_path)
    signature_reader_path = B / 'review-independent27-signed-runtime-product-v1.py'
    signatures = load_module('resource_app_signature_reader', signature_reader_path)
    main_path = exact(app['binary'])
    main_image = reader.MachO(main_path.read_bytes())
    unsigned_image = reader.MachO(exact(linked['binary']).read_bytes())
    sig = signatures.signed_image(main_path, app['actualSignature'], {
        1:(pathlib.Path(app['app'])/'Info.plist').read_bytes(),
        3:(pathlib.Path(app['app'])/'_CodeSignature/CodeResources').read_bytes()})
    need(sig['actualCodePages'] == 53 and sig['cdhash'] == 'f6b070867fb556634f4043de6d6d1860a739ef0a',
         'actual new App primary fifty-three pages and exact CD hash')
    need(sig['embeddedEntitlements'] == plistlib.loads((R/'VirtualMac/vz/host/VirtualMac.entitlements').read_bytes()),
         'actual App fourteen original entitlement values unchanged')
    need(main_image.uuid == unsigned_image.uuid and main_image.sections == unsigned_image.sections and
         main_image.imports == unsigned_image.imports and main_image.binds == unsigned_image.binds and
         main_image.exports == unsigned_image.exports, 'App signing retains actual UUID/sections/imports/PAC fixups/exports')
    for section in main_image.sections:
        at, size = section['fileoff'], section['size']
        if at and size and section['flags'] & 255 not in (1, 12, 18):
            need(main_image.data[at:at + size] == unsigned_image.data[at:at + size],
                 'actual linked App section preserved: ' + section['name'])
    manifest_raw = exact(runtime['manifest']).read_bytes()
    digest_export = main_image.exports['_VM27IndependentRuntimeManifestSHA256V1']
    size_export = main_image.exports['_VM27IndependentRuntimeManifestBytesV1']
    digest_at = main_image.file(main_image.base + digest_export['address'])
    size_at = main_image.file(main_image.base + size_export['address'])
    need(digest_export['flags'] == size_export['flags'] == 0 and
         main_image.data[digest_at:digest_at + 32] == hashlib.sha256(manifest_raw).digest() and
         struct.unpack_from('<Q', main_image.data, size_at)[0] == len(manifest_raw),
         'actual strong exported anchor digest and size join complete Runtime7 manifest')
    old_app = json.loads(exact(old_scope['appCandidate']).read_bytes())
    old_main = reader.MachO(exact(old_app['binary']).read_bytes())
    old_slots, new_slots = signature_slots(old_main), signature_slots(main_image)
    need(old_slots[5] == new_slots[5] and old_slots[7] == new_slots[7], 'actual XML and DER entitlement blobs wholebyte unchanged')
    old_app_files = {str(pathlib.Path(row['path']).relative_to(old_app['app'])):row for row in old_app['appFiles']}
    for row in app['appFiles']:
        rel = str(pathlib.Path(row['path']).relative_to(app['app']))
        if rel != 'VirtualMacIndependent27':
            need(row['sha256'] == old_app_files[rel]['sha256'] and row['bytes'] == old_app_files[rel]['bytes'],
                 'other App resource/seal unchanged: ' + rel)
    new_by_device = {row['devicePath']:row for row in scope['files']}
    old_by_device = {row['devicePath']:row for row in old_scope['files']}
    need(len(old_by_device) == 252 and len(new_by_device) == 253, 'actual full 252 to 253 product inventory')
    changes = scope['deltaFiles']
    need(len(changes) == 5 and sum(row['old'] is None for row in changes) == 1 and
         sum(row['old'] is not None for row in changes) == 4, 'four existing updates and one new genuine data file')
    changed_paths = {row['devicePath'] for row in changes}
    for device_path, old in old_by_device.items():
        new = new_by_device[device_path]
        if device_path not in changed_paths:
            need({k:v for k,v in old.items() if k != 'local'} == {k:v for k,v in new.items() if k != 'local'} and
                 old['local']['bytes'] == new['local']['bytes'] and old['local']['sha256'] == new['local']['sha256'],
                 'unchanged installed bytes and device metadata: ' + device_path)
    need(len(old_by_device) - len(changed_paths & old_by_device.keys()) == 248, 'actual two hundred forty-eight old files unchanged')
    new_row = next(row for row in changes if row['old'] is None)
    need(new_row['new']['bytes'] == 32301 and new_row['new']['sha256'] ==
         '59e239c49d6fefab06e56faeb284929853c7457f84b1b54faabd30857d7d1504', 'only added resource has original Mac27 profile bits')
    need(len(scope['newOwnDirectories']) == 1 and scope['newOwnDirectories'][0]['mode'] == 0o700 and
         new_row['mode'] == 0o600 and new_row['devicePath'].endswith('/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb'),
         'one exact owned Resources directory and restrictive data mode')
    actual_delta_cd = sorted(set(scope['trustCacheCDHashes']) - set(old_scope['trustCacheCDHashes']))
    need(actual_delta_cd == scope['newTrustCacheCDHashes'] ==
         ['54fc26d0ed8c9f4e4560aad7f0e266f152b1fd4a', sig['cdhash']] and
         scope['trustCacheRegistrationCount'] == 2 and scope['trustCacheFixedBatchCounts'] == [2] and
         len(set(scope['trustCacheCDHashes'])) == 140, 'only two new exact hashes and 138 inherited code hashes')
    archive_raw = exact(packet['archive']).read_bytes()
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:') as archive:
        members = archive.getmembers()
        need([row.name for row in members] == ['new-' + str(i) for i in range(5)], 'exact five finite USTAR members')
        for member, row in zip(members, changes, strict=True):
            need(member.isreg() and not member.linkname and not member.pax_headers and
                 member.uid == member.gid == member.mtime == 0 and member.mode == 0o600 and
                 archive.extractfile(member).read() == exact(row['new']).read_bytes(), 'archive member actual signed/data bytes: ' + member.name)
    new_control_raw = exact(packet['controller']).read_text()
    new_tree = ast.parse(new_control_raw)
    old_control_path = N / 'independent27-device-bootstrap-recovery-v4-attempt1/control.py'
    old_tree = ast.parse(old_control_path.read_bytes())
    for name in ('run_remote', 'prior_receipt', 'prefix', 'off_check'):
        need(function(new_tree, name) == function(old_tree, name), 'unchanged exact transport/receipt function: ' + name)
    process = constant(new_tree, 'PROCESS_FUNCTIONS')
    need(process == constant(old_tree, 'PROCESS_FUNCTIONS'), 'exact original PID/UID/path/PPID/lstart capture and signals')
    need("os.O_EXCL" in new_control_raw and "serial action never repeated" in new_control_raw,
         'exclusive local once markers and serial dispatch guard')
    ready_source = ast.get_source_segment(new_control_raw, next(x for x in new_tree.body if isinstance(x, ast.FunctionDef) and x.name == 'ready_gate'))
    for marker in ("auth.get('humanUserAuthorization') is True", "auth['scope'] == pin(packet/'scope.json')",
                   "auth['trustCacheCDHashes'] == scope['newTrustCacheCDHashes']", "auth['trustCacheRegistrationCount'] == 2",
                   "auth['initializationExternalWallSeconds'] == 45", "review.get('controllerPacketCandidate') == pin(packet/'candidate.json')"):
        need(marker in ready_source, 'specific human and independent review ready gate: ' + marker)
    bodies = {}
    for action, row in packet['scripts'].items():
        script = exact(row).read_text()
        result = subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True, timeout=5)
        need(result.returncode == 0, 'actual shell syntax: ' + action)
        bodies[action] = shell_body(script)
        timeout_tokens = shlex.split(script[script.index('/var/jb/usr/bin/timeout '):])
        need(timeout_tokens[3] == ('20' if action == 'close-current-own' else '45') and
             timeout_tokens[1] == '--signal=TERM' and timeout_tokens[2] in ('--kill-after=1','--kill-after=3'),
             'actual remote wall timeout and hard kill: ' + action)
        quoted = ('sudo -k -S -p "" ' if action != 'launch' else '') + '/var/jb/bin/sh -c ' + shlex.quote(script)
        need(len(quoted.encode()) == packet['quotedCommandBytes'][action] and len(quoted.encode()) + 10000 < 262144,
             'actual ARG_MAX plus environment reserve: ' + action)
    need(re.findall(r'jbctl trustcache add ([a-f0-9]{40})', bodies['trust']) == actual_delta_cd,
         'actual remote trust action has exactly two specific additions')
    need(bodies['trust'].index('trust-dispatched') < bodies['trust'].index('jbctl trustcache add'),
         'exclusive remote trust marker before first addition; no partial retry')
    stage = bodies['stage']
    first_mv = stage.index('mv -f ')
    need(all(stage.index('backup-' + str(row['index'])) < first_mv for row in changes if row['old'] is not None) and
         stage.index('backup-app-log') < first_mv and stage.index('backup-new-absent-4') < first_mv,
         'all four old file backups/log/new absence recorded before first replacement')
    need(stage.index('mkdir -m 700', stage.index('backup-app-log')) < first_mv and
         'chown 501:501' in stage and '0:0:700' in stage and 'set -C' in stage,
         'new owned resource directory only; exact root stage and exclusive same-parent temporary files')
    close = bodies['close-current-own']
    need(process in close and close[close.index(process) + len(process):].count('[ "$own_child_pid" = 0 ]') == 2 and
         'signal_own TERM "$own_app_pid"' in close and 'signal_own KILL "$own_app_pid"' in close and
         'signal_own TERM "$own_child_pid"' not in close[close.index(process) + len(process):], 'close only exact captured own App; requires no child')
    need('killall' not in ''.join(bodies.values()) and 'chmod /' not in stage and
         packet['allOriginalRemoteActionsExternalWallSeconds'] == 45 and packet['transportTimeoutSeconds'] == 55,
         'no broad process/system mutation and declared 45/55 boundaries preserved')
    v1 = N/'independent27-sandbox-resource-device-v1-attempt1'
    for name in ['control.py','products.tar'] + [action+'.sh' for action in packet['scripts']]:
        need((v1/name).read_bytes() == (packet_dir/name).read_bytes(), 'metadata correction preserves whole actual controller/archive/script: ' + name)
    prior = json.loads(exact(packet['currentInstalledProductsPost']).read_bytes())
    need(prior['transportExit'] == 0 and b'INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT' in exact(prior['stdout']).read_bytes(),
         'actual installed predecessor post0, not invented initialization success')
    out.mkdir(mode=0o700)
    report = dict(schema='Independent finite Root App anchor and sandbox resource packet review v1',
        controllerPacketCandidate=pin(packet_path),controllerPacketFreeze=pin(packet_dir/'freeze.json'),
        reviewedAppCandidate=pin(app_path),reviewedLinkedCandidate=pin(linked_path),actualAppSignature=sig,
        inheritedRuntimeCandidateReferenceOnly=pin(runtime_path),runtime7SelfAuthorshipExcludedFromSignatureReview=True,
        actualNewHashes=actual_delta_cd,actualUpdateFiles=4,actualNewDataFiles=1,actualNewDirectories=1,
        resolvedPriorMetadataFinding=dict(field='actualRuntimeManifestFiles',old=148,actual=149,
            controllerArchiveAndAllEightScriptsWholebyteUnchanged=True),
        verifiedFrozenPins=freeze_count,checks=checks,findings=[],finiteLocalScopePassed=True,
        readyForSpecificHumanTwoEntryAuthorization=True,readyForDeviceExecution=False,
        nativeSandboxAcceptanceVerified=False,guestBoot=False,deviceOperations=0,trustCacheOperations=0,
        sources=[pin(__file__),pin(reader_path),pin(signature_reader_path),pin(old_control_path),
                 packet['preparer'],linked['builder'],pin(B/'sign-independent27-actual-app-product-v2.py')])
    (out/'review.json').write_text(json.dumps(report,indent=2)+'\n')
    files = [pin(path) for path in out.iterdir() if path.is_file()]
    files += report['sources'] + [pin(packet_path),pin(packet_dir/'freeze.json'),pin(app_path),pin(app_path.parent/'freeze.json'),
                                pin(linked_path),pin(linked_path.parent/'freeze.json'),pin(runtime_path),runtime['manifest']]
    (out/'freeze.json').write_text(json.dumps(dict(files=list({row['path']:row for row in files}.values()),deviceOperations=0),indent=2)+'\n')
    print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))


if __name__ == '__main__':
    main()
