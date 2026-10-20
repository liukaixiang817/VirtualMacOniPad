#!/usr/bin/env python3
"""Read only the fixed owned log while the exact App and Child identities remain live."""
import argparse, datetime, getpass, hashlib, importlib.util, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, d): p.write_text(json.dumps(d, indent=2) + '\n')
def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--normal-packet', required=True, type=pathlib.Path)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    a = ap.parse_args(argv); packet = a.normal_packet.resolve(); outdir = a.output.resolve()
    assert packet.parent == N and outdir.parent == N and not outdir.exists()
    candidate = json.loads((packet/'candidate.json').read_bytes())
    request = packet/'device-receipts/start/request.json'
    assert request.is_file()
    normal_controller_pin=candidate['controller']
    assert pin(normal_controller_pin['path'])==normal_controller_pin
    normal_spec=importlib.util.spec_from_file_location('root_owned_normal_read',normal_controller_pin['path'])
    nc=importlib.util.module_from_spec(normal_spec);normal_spec.loader.exec_module(nc)
    common,checked_candidate=nc.load_common(packet)
    assert checked_candidate==candidate
    nc.gate(common,packet,candidate,packet/'ready-root-normal.json')
    start_receipt=json.loads((packet/'device-receipts/start/receipt.json').read_bytes())
    assert start_receipt['transportExit']==0 and start_receipt['handoffACKSent'] is True and start_receipt['handoffCommitObserved'] is True and start_receipt['owningRootTask']=='/root'
    lease_data,lease_pin=nc.lease_data(common,packet,candidate,packet/'device-receipts/start/handoff-ledger.json')
    ledger=json.loads((packet/'device-receipts/start/handoff-ledger.json').read_bytes())
    assert not (packet/'device-receipts/stop').exists()
    assert not (packet/'device-receipts/post').exists()
    assert json.loads(request.read_bytes())['packetCandidate'] == pin(packet/'candidate.json')
    assert json.loads((packet/'device-receipts/preflight/receipt.json').read_bytes())['transportExit'] == 0
    initializer_pin = candidate['initializerCandidate']
    assert pin(initializer_pin['path']) == initializer_pin
    initializer = json.loads(pathlib.Path(initializer_pin['path']).read_bytes())
    controller_pin = candidate['inheritedController']
    assert controller_pin == initializer['controller'] and pin(controller_pin['path']) == controller_pin
    controller_path = pathlib.Path(controller_pin['path'])
    assert controller_path.parent.parent == N and controller_path.name == 'control.py'
    assert pin(initializer['scope']['path']) == initializer['scope']
    spec = importlib.util.spec_from_file_location('owned_child_stack_transport', controller_path)
    c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
    scope = json.loads(pathlib.Path(initializer['scope']['path']).read_bytes())
    app = next(r for r in scope['files'] if r['archivePath']=='VirtualMacIndependent27.app/VirtualMacIndependent27')
    child = next(r for r in scope['files'] if r['archivePath'].endswith('/Contents/MacOS/com.apple.Virtualization.VirtualMachine'))
    # Same kernel boot UUID and live Root lease, measured boottime moved by
    # 64.935 milliseconds across an integer-second boundary after clock slewing.
    # Keep every UUID/model/build/PID/PPID/UID/start-hash/file/lease check.
    clock_proof=N/'independent27-normal138-current-device-identity-read-v2-attempt1/stdout'
    assert pin(clock_proof)['sha256']=='3be98759d25b96dbe4532bc89e35d87cd624df18abfb5d8f5f246baeb615bf73'
    original_prefix=c.prefix(0)
    assert original_prefix.count('= 1792161311 ]')==1
    current_prefix=original_prefix.replace('= 1792161311 ]','= 1792161312 ]')
    assert 'C7D63D1F-86E9-4224-A1C7-108F02E91942' in current_prefix
    body = current_prefix + '''
'''
    for row in (app, child):
        body += '[ "$(sha256sum ' + shlex.quote(row['devicePath']) + ' | cut -d \' \' -f1)" = ' + row['local']['sha256'] + ' ]\n'
    body += '''
rows=$(ps -axo pid=,ppid=,uid=,comm=)
app_rows=$(printf '%s\\n' "$rows" | awk -v p="$OWN_APP_MAIN" '$4==p {print $1,$2,$3,$4}')
child_rows=$(printf '%s\\n' "$rows" | awk -v p="$OWN_CHILD_MAIN" '$4==p {print $1,$2,$3,$4}')
[ "$(printf '%s\\n' "$app_rows" | awk 'NF {n++} END {print n+0}')" = 1 ]
[ "$(printf '%s\\n' "$child_rows" | awk 'NF {n++} END {print n+0}')" = 1 ]
set -- $app_rows
[ "$#" = 4 ] && [ "$1" -gt 1 ] && [ "$2" = 1 ] && [ "$3" = 501 ] && [ "$4" = "$OWN_APP_MAIN" ]
apid=$1
set -- $child_rows
[ "$#" = 4 ] && [ "$1" -gt 1 ] && [ "$2" = "$apid" ] && [ "$3" = 501 ] && [ "$4" = "$OWN_CHILD_MAIN" ]
cpid=$1
start_hash() { ps -p "$1" -o lstart= | sha256sum | cut -d ' ' -f1; }
astart=$(start_hash "$apid")
cstart=$(start_hash "$cpid")
verify_target() {
 [ "$(ps -p "$apid" -o pid=,ppid=,uid=,comm= | awk '{$1=$1;print}')" = "$app_rows" ]
 [ "$(ps -p "$cpid" -o pid=,ppid=,uid=,comm= | awk '{$1=$1;print}')" = "$child_rows" ]
 [ "$(start_hash "$apid")" = "$astart" ]
 [ "$(start_hash "$cpid")" = "$cstart" ]
}
verify_target
printf 'OWN_LOG_READ_TARGET_APP %s %s\\nOWN_LOG_READ_TARGET_CHILD %s %s\\n' "$app_rows" "$astart" "$child_rows" "$cstart"
ps -p "$cpid" -o pid=,ppid=,uid=,stat=,pcpu=,cputime=,wchan=
sudo -n -u mobile /var/jb/usr/bin/uiopen 'virtualmac27://keyboard-show'
sleep 1
printf 'OWN_LOG_READ_REPORT_BEGIN\\n'
rc=0
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = VM27_CURRENT_LOG_IDENTITY ]
[ "$(stat -c %s "$OWN_LOG")" -le 67108864 ]
LC_ALL=C tail -c 2097152 "$OWN_LOG" || rc=$?
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = VM27_CURRENT_LOG_IDENTITY ]
printf '\\nOWN_LOG_READ_REPORT_END status=%s\\n' "$rc"
verify_target
printf 'OWN_LOG_READ_EXACT_TARGET_STILL_SAME_AFTER_SAMPLE\\n'
exit "$rc"
'''
    body=body.replace('verify_target\nprintf', '[ \"$apid\" = '+str(ledger['actualIdentities']['APP']['pid'])+' ]\n[ \"$cpid\" = '+str(ledger['actualIdentities']['CHILD']['pid'])+' ]\n[ \"$astart\" = '+ledger['actualIdentities']['APP']['startHash']+' ]\n[ \"$cstart\" = '+ledger['actualIdentities']['CHILD']['startHash']+' ]\nverify_target\nprintf',1)
    identity=scope['fixedOwnedLogIdentity']
    assert identity=='16777223:48200252:501:501:600:1' and body.count('VM27_CURRENT_LOG_IDENTITY')==2
    body=body.replace('VM27_CURRENT_LOG_IDENTITY',identity)
    script = 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    assert subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True).returncode == 0
    outdir.mkdir(mode=0o700); (outdir/'read-root.sh').write_text(script)
    save(outdir/'request.json', dict(source=pin(__file__), actualClockSlewProof=pin(clock_proof), originalBootSeconds=1792161311, actualBootSeconds=1792161312, kernelBootUUIDUnchanged=True, controller=pin(controller_path), normalPacket=pin(packet/'candidate.json'),
        activeNormalStart=pin(request), script=pin(outdir/'read-root.sh'), target='exact owned log with exact App and Child identity before and after',
        actualRootLease=lease_pin, maximumLogBytes=67108864, maximumRawBytes=2097152, externalTimeoutSeconds=20, readOnly=True,
        newProbeInstalled=False, trustCacheOperations=0, reportFileRequested=False, appSignalsRequested=False,fixedKeyboardShowURLRequested=True))
    password = getpass.getpass('iPad password: ')
    try: rc, stdout, stderr, error = c.run_remote(script, b'', True, password)
    finally: password = None
    (outdir/'stdout').write_bytes(stdout); (outdir/'stderr').write_bytes(stderr)
    result = dict(transportExit=rc, transportError=error, finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        request=pin(outdir/'request.json'), stdout=pin(outdir/'stdout'), stderr=pin(outdir/'stderr'),
        newProbeInstalled=False, trustCacheOperations=0, appSignalsRequested=False,fixedKeyboardShowURLRequested=True)
    save(outdir/'receipt.json', result); print(json.dumps(result)); raise SystemExit(rc)
if __name__ == '__main__': main()
