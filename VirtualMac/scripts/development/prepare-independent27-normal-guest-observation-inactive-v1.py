#!/usr/bin/env python3
"""HOST-only gated normal guest observation source; no device dispatcher.

The fragment deliberately does not own App startup or process teardown.
Root must supply a separately reviewed lifetime controller before execution.
"""
import argparse,datetime,hashlib,json,pathlib,plistlib,re,shlex,subprocess
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
GUEST='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle'
SIZES={'MachineIdentifier':68,'HardwareModel':150,'VirtualMac.plist':1415,
       'AuxiliaryStorage':33570816,'Disk.img':274877906944}
SMALL=('MachineIdentifier','HardwareModel','VirtualMac.plist')


def pin(path):
    path=pathlib.Path(path).resolve();raw=path.read_bytes()
    return dict(path=str(path),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def exact(row):
    path=pathlib.Path(row['path'])
    assert pin(path)=={k:row[k] for k in ('path','bytes','sha256')}
    return path


def receipt(path):
    value=json.loads(path.read_bytes());assert value['transportExit']==0
    text=exact(value['stdout']).read_text();exact(value['stderr'])
    return value,text


def prepare(a):
    out=a.output.resolve();assert out.parent==N and not out.exists()
    p=a.initializer_candidate.resolve();packet=json.loads(p.read_bytes())
    scope=json.loads(exact(packet['scope']).read_bytes())
    launch,launch_text=receipt(a.initializer_launch.resolve())
    post,post_text=receipt(a.initializer_post.resolve())
    for rec,action in ((launch,'launch'),(post,'post')):
        request=json.loads(exact(rec['request']).read_bytes())
        assert request['action']==action and request['packetCandidate']==pin(p)
    assert 'INDEPENDENT27_TRUE_PARENT_CHILD_BOOTSTRAP_READY_GUEST_NOT_REQUESTED' in launch_text
    assert '[Independent27] runtime-startup result=1 errorDomain= errorCode=0 error=' in launch_text
    assert 'OWN_APP_ID ' in launch_text and 'OWN_CHILD_ID ' in launch_text
    assert 'INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in post_text
    assert 'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in post_text
    guest,guest_text=receipt(a.guest_readonly.resolve())
    assert datetime.datetime.fromisoformat(guest['finishedUTC'])>=datetime.datetime.fromisoformat(post['finishedUTC'])
    assert guest.get('deviceWrites')==guest.get('processSignals')==guest.get('trustCacheOperations')==0
    assert 'INDEPENDENT27_GUEST_CONFIG_READONLY_COMPLETE_NO_GUEST_EXECUTION' in guest_text
    assert re.findall(r'^GUEST_CANONICAL_PATH (.+)$',guest_text,re.M)==[GUEST]
    metadata={}
    for name,size in SIZES.items():
        matches=re.findall(r'^GUEST_FILE_META '+re.escape(name)+r' ([0-9:]+)$',guest_text,re.M)
        assert len(matches)==1
        fields=[int(v) for v in matches[0].split(':')];assert len(fields)==7
        dev,ino,uid,gid,mode,nlink,length=fields
        assert dev>0 and ino>0 and uid==gid==501 and nlink==1 and length==size
        assert mode==(644 if name in ('MachineIdentifier','HardwareModel') else 600)
        metadata[name]=matches[0]
    # Root's fresh read-only configuration stores actual small-file copies.
    facts=json.loads(a.guest_configuration.read_bytes())
    small={}
    for name in SMALL:
        raw=exact(facts['sourceFiles'][name]).read_bytes()
        hashes=re.findall(r'^GUEST_SMALL_SHA256 '+re.escape(name)+r' ([a-f0-9]{64})$',guest_text,re.M)
        assert len(hashes)==1 and len(raw)==SIZES[name] and hashlib.sha256(raw).hexdigest()==hashes[0]
        small[name]=hashes[0]
    saved=plistlib.loads(exact(facts['sourceFiles']['VirtualMac.plist']).read_bytes())
    assert saved==facts['actualParsedSavedOptions'] and isinstance(saved,dict)
    # Report saved CPU/RAM values without substituting guessed runtime defaults.
    owner=scope['deviceAppMain'];child=scope['deviceChildMain']
    observation=observation_fragment(a.observe_seconds)
    subprocess.run(['/bin/sh','-n'],input=observation.encode(),check=True)
    out.mkdir(mode=0o700)
    (out/'observation-owner-fragment.sh').write_text(observation)
    plan=dict(schema='Inactive actual normal guest observation source v1',
        initializerCandidate=pin(p),initializerLaunch=pin(a.initializer_launch),
        initializerPost=pin(a.initializer_post),freshGuestReadonly=pin(a.guest_readonly),
        freshGuestConfiguration=pin(a.guest_configuration),builder=pin(__file__),
        actualGuestPath=GUEST,guestMetadata=metadata,actualSmallSHA256=small,
        actualSavedOptions=saved,actualSavedCPUCount=saved.get('CPUCount'),
        actualSavedMemorySize=saved.get('MemorySize'),ownerAppMain=owner,ownerChildMain=child,
        absoluteStartURL='virtualmac27://start-vm?path='+__import__('urllib.parse',fromlist=['quote']).quote(GUEST,safe=''),
        observation=pin(out/'observation-owner-fragment.sh'),observeSeconds=a.observe_seconds,
        requiresNewLongerRemoteAndTransportBounds=True,deviceOperations=0,
        trustCacheOperations=0,readyForDeviceExecution=False,
        actualVMRunning=False,actualGuestVisible=False,actualSSHAvailable=False,
        missingConcreteController=['Fresh exact products/App-child-off preflight; current log backup before App freopen.',
          'Inherited actual PROCESS_FUNCTIONS and exclusive once-only URL dispatch.',
          'Root-selected whole lifecycle: longer remote/SSH deadlines, bound PID/start identities and log inode.',
          'Native USB screenshot during observation with actual UDID; Metal completion alone is not visible guest proof.',
          'Explicit teardown on failure; successful visible progress needs declared owner handoff or a new bounded observation.',
          'No implicit reuse of initialization45/55 limits, shared stop/screenshot markers or old13 scripts.'])
    (out/'candidate.json').write_text(json.dumps(plan,indent=2,default=str)+'\n')
    (out/'freeze.json').write_text(json.dumps(dict(files=[pin(__file__),pin(out/'candidate.json'),
        pin(out/'observation-owner-fragment.sh'),pin(p),pin(a.initializer_launch),
        pin(a.initializer_post),pin(a.guest_readonly),pin(a.guest_configuration)],
        deviceOperations=0,trustCacheOperations=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'))))


def observation_fragment(seconds):
    assert 30<=seconds<=180
    return """# Inactive owner fragment: Root's reviewed outer controller owns all cleanup.
[ "$own_app_pid" -gt 1 ] && [ "$own_child_pid" -gt 1 ]
[ "$OWN_LOG" = /tmp/VirtualMacIndependent27.log ]
[ -n "$own_log_inode" ]
own_observe=0
while [ "$own_observe" -lt """+str(seconds)+""" ]; do
 scan_own
 [ -n "$app_rows" ] && [ -n "$child_rows" ]
 [ "$(stat -c %d:%i "$OWN_LOG")" = "$own_log_inode" ]
 [ "$(stat -c %u:%g:%a:%h "$OWN_LOG")" = 501:501:600:1 ]
 [ "$(stat -c %s "$OWN_LOG")" -le 2097152 ]
 own_accept=$(awk '/^\\[Independent27\\] start-vm accepted path=/ {n++} END {print n+0}' "$OWN_LOG")
 own_started=$(awk '/^\\[VirtualMac\\] VM STARTED state=1$/ {n++} END {print n+0}' "$OWN_LOG")
 own_frames=$(awk '/^\\[Independent27Display\\] completed actual IOSurface frame=/ {n++} END {print n+0}' "$OWN_LOG")
 [ "$own_accept" -le 1 ] && [ "$own_started" -le 1 ]
 if grep -E '^\\[Independent27\\] (explicit action|start-vm) rejected:|^\\[VirtualMac\\] (Configuration failed:|Validation failed:|Virtual Mac start failed:|Virtual Mac stopped:)' "$OWN_LOG"; then
  printf 'OWN_ACTUAL_NORMAL_START_FAILURE_NOT_RECOVERED\\n'
  return 81
 fi
 printf 'OWN_OBSERVE seconds=%s accept=%s state1=%s actualMetalFrames=%s\\n' "$own_observe" "$own_accept" "$own_started" "$own_frames"
 sleep 1
 own_observe=$((own_observe+1))
done
[ "$own_accept" = 1 ] && [ "$own_started" = 1 ]
printf 'OWN_NORMAL_OBSERVATION_COMPLETE_VISIBLE_GUEST_AND_SSH_REQUIRE_SEPARATE_ACTUAL_EVIDENCE\\n'
"""


def main():
    p=argparse.ArgumentParser()
    for name in ('initializer-candidate','initializer-launch','initializer-post','guest-readonly','guest-configuration','output'):
        p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--observe-seconds',type=int,required=True)
    prepare(p.parse_args())


if __name__=='__main__':main()

