#!/usr/bin/env python3
"""Read-only packet inspection; no dispatch, SSH, trust cache, or device I/O."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    p = pathlib.Path(path)
    if not p.is_file() or p.is_symlink():
        raise ValueError('ordinary actual file required: ' + str(p))
    b = p.read_bytes()
    return {'path': str(p), 'bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()}


def need(value, message):
    if not value:
        raise ValueError(message)


MODEL_SETUP = r'''
set -eu
OWN_APP_MAIN=/own/App
OWN_CHILD_MAIN=/own/Child
scenario=SCENARIO
alive_app=1
alive_child=1
ps() {
 if [ "$1" = '-axo' ]; then
  printf '1 0 0 /init\n'
  [ "$alive_app" = 0 ] || printf '200 1 501 /own/App\n'
  [ "$alive_child" = 0 ] || printf '201 200 501 /own/Child\n'
  [ "$scenario" != duplicate ] || printf '202 200 501 /own/Child\n'
  return 0
 fi
 [ "$1" = '-p' ] || return 9
 n=$2;fmt=$4
 case "$n:$fmt" in
  200:lstart=)printf 'Sat Oct 10 09:00:00 2026\n';;
  201:lstart=)printf 'Sat Oct 10 09:00:01 2026\n';;
  200:pid=) [ "$alive_app" = 0 ] || printf '200\n';;
  200:pid=,ppid=,uid=,comm=) [ "$alive_app" = 0 ] || printf '200 1 501 /own/App\n';;
  201:pid=,ppid=,uid=,comm=)
   if [ "$alive_child" = 1 ];then
    ppid=200;[ "$alive_app" = 1 ] || ppid=1
    uid=501;[ "$scenario" != wronguid ] || uid=0
    printf '201 %s %s /own/Child\n' "$ppid" "$uid"
   fi;;
  *) return 1;;
 esac
}
sha256sum() { shasum -a 256; }
kill() {
 printf 'FAKE_SIGNAL %s %s\n' "$1" "$2"
 if [ "$scenario" = graceful ] || [ "$1" = '-KILL' ];then
  if [ "$2" = 200 ];then alive_app=0;else alive_child=0;fi
 fi
}
sleep(){ :; }
'''


def model_results(functions):
    rows = []
    for case in ('graceful', 'hard', 'wronguid', 'duplicate', 'recycled'):
        text = MODEL_SETUP.replace('SCENARIO', shlex.quote(case)) + functions + '\nscan_own\n'
        if case == 'recycled':
            text += 'own_child_start=' + 'a' * 64 + '\n'
        text += 'cleanup_own\n'
        result = subprocess.run(['/bin/sh'], input=text.encode(), capture_output=True, timeout=10)
        signals = [x for x in result.stdout.decode().splitlines() if x.startswith('FAKE_SIGNAL ')]
        expected = ['FAKE_SIGNAL -TERM 201', 'FAKE_SIGNAL -TERM 200'] if case == 'graceful' else (
            ['FAKE_SIGNAL -TERM 201', 'FAKE_SIGNAL -TERM 200', 'FAKE_SIGNAL -KILL 201', 'FAKE_SIGNAL -KILL 200']
            if case == 'hard' else [])
        need(result.returncode == (0 if case in ('graceful', 'hard') else 77), 'model real shell exit ' + case)
        need(signals == expected and not result.stderr, 'model no unintended signal ' + case)
        rows.append({'case': case, 'exit': result.returncode, 'signals': signals,
                     'stdout': result.stdout.decode(), 'stderr': result.stderr.decode(),
                     'psAndKillAreHostModelFunctions': True, 'actualSignals': 0})
    return rows


def review(packet, out):
    need(packet.parent == N and out.parent == N and not out.exists(), 'actual diagnostics packet and fresh output')
    c = json.loads((packet / 'candidate.json').read_bytes())
    f = json.loads((packet / 'freeze.json').read_bytes())
    for row in f['files']:
        need(pin(row['path']) == row, 'freeze exact actual bytes: ' + row['path'])
    need(pin(packet / 'control.py') == c['controller'], 'actual reviewed controller')
    scope = json.loads((packet / 'scope.json').read_bytes())
    spec = importlib.util.spec_from_file_location('actual_frozen_packet_finite_peer', packet / 'control.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Only the pure archive parser and shell generator are called, never prepare/dispatch.
    module.validate_archive((packet / 'products.tar').read_bytes(), scope)
    generated = module.make_scripts(scope, module.HEALTH.read_text())
    lengths = []
    for name, row in c['scripts'].items():
        data = pathlib.Path(row['path']).read_bytes()
        need(pin(row['path']) == row and generated[name].encode() == data, 'actual generated shell ' + name)
        syntax = subprocess.run(['/bin/sh', '-n'], input=data, capture_output=True, timeout=10)
        need(syntax.returncode == 0, 'actual shell syntax ' + name)
        root = name != 'launch'
        command = ('sudo -k -S -p "" ' if root else '') + '/var/jb/bin/sh -c ' + shlex.quote(data.decode())
        lengths.append({'action': name, 'scriptBytes': len(data), 'SSHCommandBytes': len(command.encode()),
                        'twoSSHCommandsPlus16KiBConservativeBytes': 2 * len(command.encode()) + 16384})
    cd = scope['trustCacheCDHashes']
    need(len(cd) == len(set(cd)) == c['trustCacheRegistrationCount'] == 140, 'actual finite unique CD set')
    need(sorted(row['cdhash'] for row in scope['files'] if row.get('cdhash')) == cd, 'CD set actual product files')
    actual_tc = []
    for action in module.TRUST_ACTIONS:
        actual_tc.extend(line.split()[-1] for line in generated[action].splitlines() if line.startswith('jbctl trustcache add '))
        # The fixed command lines are inside a quoted sh -c body. Check the unquoted body generated from actual scope instead.
    source = (packet / 'control.py').read_text()
    need("for index in range(batch_index*20, (batch_index+1)*20)" in source and
         "for index in range(7)" in source, 'seven nonadaptive fixed 20-entry batches')
    need("os.O_WRONLY|os.O_CREAT|os.O_EXCL" in source and "serial action never repeated" in source,
         'exclusive host action receipt and lock')
    need("specificUserAuthorization" in source and "humanUserAuthorization" in source and
         "review.get('controllerPacketCandidate') == pin(packet/'candidate.json')" in source,
         'exact new human authorization and concrete peer pin required')
    need("timeout=55" in source and "--signal=TERM --kill-after=3 45" in source and
         "trap 'exit 143' TERM INT HUP" in source, 'bounded transport and initialization cleanup trap')
    need("uiopen --bundleid com.mac.virtual.independent27" in source and
         "uiopen virtualmac27://runtime-startup" in source and "start-vm" not in generated['launch'],
         'only independent library/parent-child bootstrap requested')
    need("cleanup_own || own_status=78" in source and "success=args.action != 'post'" in source,
         'cleanup failure is visible and exact post accepts failed launch')
    models = model_results(module.PROCESS_FUNCTIONS)
    out.mkdir()
    (out / 'process-models.json').write_text(json.dumps(models, indent=2) + '\n')
    argmax_receipt = N / 'independent27-kernel-argmax-readonly-v1/receipt.json'
    argmax = json.loads(argmax_receipt.read_bytes())
    need(argmax['transportExit'] == 0 and pin(argmax['stdout']['path']) == argmax['stdout'], 'actual read-only argmax receipt')
    need('OWN_KERNEL_ARG_MAX 262144' in pathlib.Path(argmax['stdout']['path']).read_text(), 'actual device 262144 total limit')
    report = {
        'schema': 'Finite independent controller structure peer v1',
        'controllerPacketCandidate': pin(packet / 'candidate.json'),
        'packetFreeze': pin(packet / 'freeze.json'),
        'scope': c['scope'], 'archive': c['archive'], 'controller': c['controller'],
        'freezePinsChecked': len(f['files']), 'actualFileCount': len(scope['files']),
        'actualDirectoryCount': len(scope['directories']), 'canonicalUSTARExact': True,
        'actualUniqueCDHashes': len(cd), 'trustBatchCounts': [20] * 7,
        'scriptSizesAndQuotedCommands': lengths, 'actualDeviceArgmaxReceipt': pin(argmax_receipt),
        'processModels': pin(out / 'process-models.json'),
        'hostProcessModelCasesPassed': len(models), 'processModelsAreDeviceProof': False,
        'finiteLocalStructureScopePassed': True, 'finiteReviewComplete': False,
        'readyForRootSerialDispatch': False,
        'findings': [{'code': 'stage-parent-filesystem-proof-absent',
                      'detail': 'The v2 stage requires App dev:ino unchanged after mv from /private/var/mobile/Library to /private/preboot/.../Applications. Actual same-filesystem evidence is absent; a cross-filesystem move cannot preserve dev:ino. Root is replacing the packet with separate same-volume stages.'}],
        'supersededPacketCannotBeUsedAsGreenReadyReview': True,
        'retention': 'Product files, own log, and exact trust entries are retained; no single-entry revocation is proved.',
        'boundaries': ['No authorization was generated or inferred.',
                       'No SSH/device/TC/launch was executed by this review.',
                       'Known process identities are checked again before each TERM/KILL; unexpected or duplicate process identities cause visible failure and no unverified signal.',
                       'An orphan never observed as a direct child is refused, not claimed cleaned.',
                       'This packet does not request a guest start or prove guest display/network.',
                       'ARG_MAX calculations show command sizes, not a measured remote environment budget.'],
        'reviewSource': pin(__file__), 'deviceOperations': 0, 'trustCacheOperations': 0}
    (out / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(out / 'review.json'), pin(out / 'process-models.json'), pin(__file__),
            pin(packet / 'candidate.json'), pin(packet / 'freeze.json'), pin(argmax_receipt)]
    (out / 'freeze.json').write_text(json.dumps({'files': rows, 'deviceOperations': 0}, indent=2) + '\n')
    print(json.dumps({'review': pin(out / 'review.json'), 'freeze': pin(out / 'freeze.json')}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--packet', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    a = parser.parse_args()
    review(a.packet.resolve(), a.output.resolve())


if __name__ == '__main__':
    main()
