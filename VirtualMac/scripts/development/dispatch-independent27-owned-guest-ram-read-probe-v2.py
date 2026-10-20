#!/usr/bin/env python3
"""Run one pinned read-only owned-VMM RAM diagnostic after exact committed Root handoff."""
import argparse, datetime, getpass, hashlib, importlib.util, json, pathlib, re, shlex, subprocess, sys
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
    body = c.prefix(0) + '''
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
printf 'OWN_LOG_READ_REPORT_BEGIN\\n'
rc=0
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = VM27_CURRENT_LOG_IDENTITY ]
[ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
LC_ALL=C awk '/VM27_READONLY_GUEST_BOOT_V8/ {diagnostic=160} diagnostic>0 {if(++observed<=512)print;--diagnostic;next} /Independent27GPU|VM27OwnedGPUTaskParentV1|Independent27BitmapRGBV7|GuestTools|Independent27DisplayObserverV3|Independent27DisplayBitmapV6|input |keyboard|key|mouse|pointer|failed|VM27OwnedPGDisplayHandshake|production10-|watch-summary|guest-process-row|guest-process-result|guest-thread-row|frames=|frameCount=|guestRunning=|stage=guest-|actual-hvc|failed stage=/ {if (++observed<=512)print} END {printf "OWN_LOG_FILTER_TOTAL_MATCHED %d LIMIT512\\n",observed}' "$OWN_LOG" || rc=$?
[ "$(stat -c %d:%i:%u:%g:%a:%h "$OWN_LOG")" = VM27_CURRENT_LOG_IDENTITY ]
printf '\\nOWN_LOG_READ_REPORT_END status=%s\\n' "$rc"
verify_target
printf 'OWN_LOG_READ_EXACT_TARGET_STILL_SAME_AFTER_SAMPLE\\n'
exit "$rc"
'''
    body=body.replace('verify_target\nprintf', '[ \"$apid\" = '+str(ledger['actualIdentities']['APP']['pid'])+' ]\n[ \"$cpid\" = '+str(ledger['actualIdentities']['CHILD']['pid'])+' ]\n[ \"$astart\" = '+ledger['actualIdentities']['APP']['startHash']+' ]\n[ \"$cstart\" = '+ledger['actualIdentities']['CHILD']['startHash']+' ]\nverify_target\nprintf',1)
    signed=N/'owned-guest-ram-read-probe-v2-attempt1/candidate.json'
    assert pin(signed)['sha256']=='08f7a5720d6da495c311dbcc867d6e8c1d73116d14df779dd63f416762896fea'
    probe=json.loads(signed.read_bytes())
    for key in ['source','binary','entitlements']:assert pin(probe[key]['path'])==probe[key]
    actual_stdout=packet/'device-receipts/start/stdout'
    assert pin(actual_stdout)==start_receipt['stdout']
    text=actual_stdout.read_text(errors='strict')
    mappings=re.findall(r'diagnostic-wake-code id=\d+ label=PC known=1 reason=0 GPA=(0x[0-9a-f]+) HVA=(0x[0-9a-f]+) ',text)
    biases={int(h,16)-int(g,16) for g,h in mappings};assert mappings and len(biases)==1
    headers=re.findall(r'guest-msgbuf known=1 reason=0 .*?headerGPA=(0x[0-9a-f]+) headerVA=(0x[0-9a-f]+) freshSlide=(0x[0-9a-f]+) ',text)
    assert len(headers)==1
    header_gpa,header_va,slide_value=[int(v,16)for v in headers[0]]
    assert header_va==0xfffffe0007004000+slide_value
    banks=re.findall(r'diagnostic-wake-sys id=\d+ known=0x3f .*?TCR=([0-9a-f]+) .*?TTBR1=([0-9a-f]+) ',text)
    roots={int(ttbr,16)&0x0000ffffffffc000 for tcr,ttbr in banks if int(tcr,16)==0x000800226511a511}
    assert banks and len(roots)==1
    target_pid=ledger['actualIdentities']['CHILD']['pid']
    arguments=[str(target_pid),hex(next(iter(biases))),hex(next(iter(roots))),hex(slide_value),hex(header_gpa)]
    assert target_pid>1 and all(re.fullmatch(r'(?:0x)?[0-9a-f]+',x) for x in arguments)
    auth=N/'independent27-continuing-human-authorization-v2/authorization.json'
    assert pin(auth)['sha256']=='878098e7d8bd61afb129584c9e1d5dc6a83525ba0bf6232f4350610f305455e8'
    authorization=json.loads(auth.read_bytes());assert authorization['necessaryHashesProbesAndOwnedProcessPermissionsAuthorized'] and authorization['preserveIPadOSStability']
    start=body.index("printf 'OWN_LOG_READ_REPORT_BEGIN")
    end=body.index("verify_target\nprintf 'OWN_LOG_READ_EXACT_TARGET",start)
    stage='/private/var/mobile/Library/.VM27-owned-guest-ram-read-probe-v2-'+packet.name
    device=stage+'/VM27OwnedGuestRAMReadProbeV2'
    cd=probe['CDHash'];binary=pathlib.Path(probe['binary']['path'])
    action=f"""
[ ! -e {stage} ] && [ ! -L {stage} ]
mkdir -m 700 {stage}
trap 'rm -f {device}; rmdir {stage}' EXIT
cat > {device}
[ -f {device} ] && [ ! -L {device} ]
[ "$(sha256sum {device} | cut -d ' ' -f1)" = {probe['binary']['sha256']} ]
[ "$(stat -c %s {device})" = {probe['binary']['bytes']} ]
chmod 700 {device}
actual_cd=$(ldid -h {device} 2>&1)
[ "$(printf '%s\\n' "$actual_cd" | sed -n 's/^CDHash=//p')" = {cd} ]
trust_before=$(jbctl trustcache info)
if printf '%s\\n' "$trust_before" | awk 'tolower($NF)=="{cd}" {{{{found=1}}}} END {{{{exit !found}}}}'; then
 printf 'OWN_RAM_READ_PROBE_NEW_TRUST_ENTRIES 0\\n'
else
 jbctl trustcache add {cd}
 printf 'OWN_RAM_READ_PROBE_NEW_TRUST_ENTRIES 1\\n'
fi
jbctl trustcache info | awk 'tolower($NF)=="{cd}" {{{{found=1}}}} END {{{{exit !found}}}}'
verify_target
printf 'OWN_RAM_READ_PROBE_TRUST_PRESENT {cd}\\n'
rc=0
/var/jb/usr/bin/timeout -s TERM -k 2 20 {device} {' '.join(arguments)} || rc=$?
printf 'OWN_RAM_READ_PROBE_EXIT %s\\n' "$rc"
rm -f {device}
rmdir {stage}
trap - EXIT
"""
    action=action.replace('{{','{').replace('}}','}')
    body=body[:start]+action+body[end:]
    script = 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 45 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    assert subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True).returncode == 0
    outdir.mkdir(mode=0o700); (outdir/'read-root.sh').write_text(script)
    save(outdir/'request.json', dict(source=pin(__file__), controller=pin(controller_path), normalPacket=pin(packet/'candidate.json'),
        activeNormalStart=pin(request), script=pin(outdir/'read-root.sh'), target='one pinned bounded read-only probe of exact owned current VMM guest RAM',
        actualRootLease=lease_pin, signedDiagnosticCandidate=pin(signed), actualCurrentStartOutput=pin(actual_stdout), actualGuestRAMArguments=arguments, continuingHumanAuthorization=pin(auth), newTrustCacheCDHashes=[cd], physicalReadMaximumBytes=1048576, physicalReadMaximumCalls=16384, probeTimeoutSeconds=20, externalTimeoutSeconds=45, readOnly=True,
        newProbeInstalled=True, maximumTrustCacheOperations=1, reportFileRequested=False, appSignalsRequested=False))
    password = getpass.getpass('iPad password: ')
    try: rc, stdout, stderr, error = c.run_remote(script, binary.read_bytes(), True, password)
    finally: password = None
    (outdir/'stdout').write_bytes(stdout); (outdir/'stderr').write_bytes(stderr)
    result = dict(transportExit=rc, transportError=error, finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        request=pin(outdir/'request.json'), stdout=pin(outdir/'stdout'), stderr=pin(outdir/'stderr'),
        newProbeInstalled=True, maximumTrustCacheOperations=1, appSignalsRequested=False)
    save(outdir/'receipt.json', result); print(json.dumps(result)); raise SystemExit(rc)
if __name__ == '__main__': main()
