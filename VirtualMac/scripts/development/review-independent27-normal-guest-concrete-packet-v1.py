#!/usr/bin/env python3
"""HOST-only finite review of a real-facts normal guest ownership packet."""
import argparse,ast,hashlib,importlib.util,json,pathlib,shlex,struct,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';B=R/'VirtualMac/scripts/development'
def need(v,m):
 if not v:raise ValueError(m)
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def actual(row):
 need(pin(row['path'])=={k:row[k]for k in ('path','bytes','sha256')},'actual pin '+row['path']);return pathlib.Path(row['path'])
def load(p,n):
 spec=importlib.util.spec_from_file_location(n,p);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def function(t,n):return ast.get_source_segment(t,next(v for v in ast.parse(t).body if isinstance(v,ast.FunctionDef)and v.name==n))
def main():
 a=argparse.ArgumentParser();a.add_argument('--candidate',type=pathlib.Path,required=True);a.add_argument('--output',type=pathlib.Path,required=True);a=a.parse_args();out=a.output.resolve();need(out.parent==N and not out.exists(),'fresh finite normal peer')
 c=json.loads(a.candidate.read_bytes());fp=a.candidate.parent/'freeze.json'
 for row in json.loads(fp.read_bytes())['files']:actual(row)
 sys.path.insert(0,str(B));common=load(actual(c['common']),'normal_concrete_common');builder=load(actual(c['builder']),'normal_concrete_builder');inherited=load(actual(c['inheritedController']),'normal_concrete_initializer')
 packet,scope,launch,post=common.initializer_success(c['initializerCandidate']['path'],actual(c['initializerLaunch']),actual(c['initializerPost']))
 facts=common.guest_success(actual(c['freshGuestReadonly']),actual(c['freshGuestConfiguration']),c['initializerPost'])
 need(facts==c['guestFacts']and facts['CPUCountSaved']==4 and facts['MemorySizeSaved']==8589934592 and facts['actualParsedSavedOptions']['VirtualMacGuestToolsEnabled']is True,'true fresh five-file metadata/config from actual bytes; 4CPU/8GiB/tools')
 need(c['guestPath']==common.GUEST=='/private/var/mobile/Media/VirtualMac/Tahoe3.bundle'and c['ownAppMain']==scope['deviceAppMain']and c['ownChildMain']==scope['deviceChildMain'],'actual guest and exact current own product paths')
 screen=json.loads(actual(c['foregroundUSBScreenReceipt']).read_bytes());image=actual(screen['screenshot']).read_bytes();actual(screen['request']);actual(screen['stdout']);actual(screen['stderr'])
 need(screen['transportExit']==0 and screen['actualNativeUSBScreenCapture']is True and screen['actualUDID']=='00008112-001E48300207401E'and screen['guestVerified']is False and screen['inputCalibrationVerified']is False,'true native USB context only, not guest/input proof')
 need(image[:8]==b'\x89PNG\r\n\x1a\n'and struct.unpack('>II',image[16:24])==(2732,2048)and screen['finishedUTC']>=json.loads(actual(c['freshGuestReadonly']).read_bytes())['finishedUTC'],'actual2732x2048 PNG after fresh facts')
 need(c['trustCacheOperations']==c['nativeKernelWrites']==c['deviceOperations']==0 and c['actualVisibleGuest']is False and c['actualGuestStarted']is False and c['actualSSHAvailable']is False and c['networkAvailable']is False,'no invented guest/SSH/network/input acceptance or extra trust')
 control=actual(c['controller']).read_text();need(control==(B/'independent27_normal_guest_lifecycle_v1.py').read_text(),'actual copied lifecycle source unchanged')
 gate=function(control,'gate');stream=function(control,'stream_start');lease=function(control,'lease_data');dispatch=function(control,'dispatch');dump=function(actual(c['common']).read_text(),'dump')
 for token in ['controllerPacketCandidate','owningRootTask','/root','noNewTrustCacheEntries','packetCandidate','packetFreeze','initializer_success','guest_success']:
  need(token in gate,'actual ready/facts gate '+token)
 need('os.fsync(stream.fileno())'in dump and 'os.fsync(fd)'in dump and 'O_EXCL'in dump and 'O_NOFOLLOW'in dump,'durable exclusive ledger and directory fsync')
 need(stream.index("common.dump(output / 'handoff-ledger.json'")<stream.index("common.dump(output / 'handoff-ack.json'")<stream.index("child.stdin.write(('ACK '")and "os.fsync(stream.fileno())"in stream,'actual stdout prefix/ledger/ACK records persisted before unique ACK')
 for token in ['one actual handoff offer','offered identities must equal captured actual direct App/child','0 < int(fields[7]) < int(fields[8])','if not confirm:','child.stdin.close()','Root retains exact ownership from this attempted ACK','145 - (time.monotonic() - started)']:
  need(token in stream,'real offer/explicit ACK/timeout identity boundary '+token)
 for token in ["lease_path == start / 'handoff-ledger.json'","ack['ledger'] == common.pin(lease_path)","ledger['nonce'] == candidate['sessionNonce']",'immutable actual direct captures',"common.identity_rows(stdout"]:
  need(token in lease,'actual durable lease, not caller numeric PID '+token)
 for token in ['O_EXCL','bounded phase never repeated','normal preflight must be fresh','args.sequence >= 1','lease cannot resume after stop attempt','post after failed start only when actual cleanup proved off and no ACK ownership','SSH returned0 without the exact real ownership commit','uncertain transport never releases owner']:
  need(token in dispatch,'exclusive phase/owner-retention gate '+token)
 scripts={k:actual(v).read_text()for k,v in c['actions'].items()};bodies={k:shlex.split(t)[-1]for k,t in scripts.items()}
 for k,t in scripts.items():
  need(subprocess.run(['/bin/sh','-n'],input=t.encode(),capture_output=True).returncode==0,'actual shell syntax '+k)
  need(common.quoted_size(t,k in ('preflight','post'))+10000<262144,'actual argv reserve '+k)
  need('jbctl trustcache add'not in t and 'killall 'not in t and 'reboot 'not in t,'no new trust or unknown cleanup '+k)
  if k in ('start','observe','stop'):need(inherited.PROCESS_FUNCTIONS.strip()in bodies[k],'exact PID UID path PPID startHash signal guards '+k)
 need(hashlib.sha256(inherited.PROCESS_FUNCTIONS.encode()).hexdigest()==c['inheritedProcessFunctionsSHA256'],'true exact process helper provenance')
 need(scripts['start']==builder.render_start(inherited,scope,facts,c['sessionNonce']),'actual full start recipe uses current facts and exclusive nonce')
 for k in ['observe','stop']:need(scripts[k]==builder.render_owned(inherited,k).replace('@NONCE@',shlex.quote(c['sessionNonce'])),'exact current owned followup recipe '+k)
 start=bodies['start'];opens=[shlex.split(line)for line in start.splitlines()if line.startswith('/var/jb/usr/bin/uiopen ')]
 need(len(opens)==2 and opens[0]==['/var/jb/usr/bin/uiopen','--bundleid','com.mac.virtual.independent27']and opens[1]==['/var/jb/usr/bin/uiopen','virtualmac27://start-vm?path=%2Fprivate%2Fvar%2Fmobile%2FMedia%2FVirtualMac%2FTahoe3.bundle']and start.count('OWN_NORMAL_START_URL_REQUESTED_ONCE')==1,'one actual foreground open and one normal start URL')
 for token in ['while [ "$own_second" -lt 90 ]','[ "$own_started" = 1 ]','[ "$own_frames" -ge 2 ]','[ "$own_last" -gt "$own_first" ]','[ "$own_late_progress" = 1 ]','[ "$own_second" = 45 ]','[ "$own_second" -gt 45 ]','IFS= read -r own_ack','[ "$own_ack" = "ACK $OWN_NORMAL_NONCE" ]','trap finish_normal EXIT']:
  need(token in start,'real90s observed state/frame/identity handoff condition '+token)
 need(start.index('[ "$own_late_progress" = 1 ]')<start.index("printf 'OWN_HANDOFF_OFFER")<start.index('IFS= read -r own_ack')<start.index('own_handoff=1\n'),'no premature handoff; owner only after exact ACK and real rescan')
 need('cleanup_own || own_status=78'in start and '[ "$own_handoff" != 1 ]'in start and 'OWN_EXACT_CLEANUP_FAILED_RETAIN_OWNERSHIP'in start,'no ACK/failure exact cleanup; rejected identity never falsely off')
 need('completed actual IOSurface frame='in start and 'n<=0 || (f && n<=last)'in start and 'VM STARTED state=1'in start and 'own_log_inode'in start,'actual source markers and monotonic frame/log generation checks')
 presenter=R/'VirtualMac/vz/host/vm27_uikit_guest_display_v1.mm';text=presenter.read_text();need('done.status==MTLCommandBufferStatusCompleted'in text and '[command presentDrawable:drawable];[command commit];'in text and 'completed actual IOSurface frame='in text,'true Metal completion producer, not URL acceptance or mock frames')
 pre=bodies['preflight'];need('INDEPENDENT27_ALL_ACTUAL_PRODUCTS_EXACT'in pre and 'OWN_PRIOR_LOG_BACKED_UP'in pre and '0:0:600:1'in pre and facts['priorLogSHA256']in pre,'full current products and genuine prior log backup before start')
 for name in ['MachineIdentifier','HardwareModel','AuxiliaryStorage','Disk.img','VirtualMac.plist']:need(name in pre and facts['metadata'][name]in pre,'exact current five-file guest metadata '+name)
 need(all(h in pre for h in facts['smallSHA256'].values())and 'sha256sum "$OWN_GUEST/Disk.img"'not in pre,'hash only genuine small files, no whole256GiB disk')
 need('own_handoff=1'in bodies['observe']and 'scan_own'in bodies['observe']and 'cleanup_own\n'not in bodies['observe'].replace(inherited.PROCESS_FUNCTIONS,'',1),'observation failure keeps actual Root ledger ownership')
 need('cleanup_own\nscan_own\n[ -z "$app_rows" ] && [ -z "$child_rows" ]'in bodies['stop'],'stop requires seeded exact identities and real off proof')
 need(c['observeSeconds']==90 and c['remoteTERMSeconds']==132 and c['remoteKILLSeconds']==135 and c['startTransportSeconds']==145 and c['shortTransportSeconds']==55,'explicit90/132+3/145/55 lifetime bounds')
 out.mkdir(mode=0o700);cp=pin(a.candidate);report=dict(schema='Independent concrete normal guest lifecycle finite HOST peer v1',normalPacketCandidate=cp,controllerPacketCandidate=cp,packetFreeze=pin(fp),initializerLaunch=c['initializerLaunch'],initializerPost=c['initializerPost'],freshGuestReadonly=c['freshGuestReadonly'],freshGuestConfiguration=c['freshGuestConfiguration'],foregroundUSBScreenReceipt=c['foregroundUSBScreenReceipt'],actualInitAndPostSucceeded=True,actualFreshFiveFileFactsRequired=True,CPUCountSaved=4,MemorySizeSaved=8589934592,savedOptionsNotRuntimeMergedDefaults=True,screenshotContextOnly=True,actualOnceNormalStartURL=True,actualMonotonicMetalCompletionAndState1BeforeOffer=True,lateFrameProgressAfter45SecondsRequired=True,RootTaskOwnsFsyncLedgerBeforeUniqueACK=True,ACKAttemptOrUncertainTransportKeepsRootOwnershipUntilStop=True,noACKOrFailureKeepsExactCleanupArmed=True,stopRequiresActualPIDUIDPathPPIDStartHash=True,observationSeconds=90,remoteTERMSeconds=132,remoteKILLSeconds=135,startSSHSeconds=145,shortSSHSeconds=55,guestBootExecuted=False,actualVisibleGuest=False,actualGuestLogin=False,actualGuestSSHAuthenticated=False,guestHelperInstalled=False,inputAcceptanceVerified=False,fullNATNetworkAvailable=False,sandboxProfileApplied=False,nativeSandboxApplyUnavailable=45,deviceOperations=0,trustCacheOperations=0,findings=[],finiteLocalScopePassed=True)
 (out/'review.json').write_text(json.dumps(report,indent=2)+'\n');rows=[pin(__file__),cp,pin(fp),c['builder'],c['common'],c['controller'],c['inheritedController'],c['initializerCandidate'],c['initializerLaunch'],launch['request'],launch['stdout'],launch['stderr'],c['initializerPost'],post['request'],post['stdout'],post['stderr'],c['freshGuestReadonly'],c['freshGuestConfiguration'],c['foregroundUSBScreenReceipt'],screen['request'],screen['stdout'],screen['stderr'],screen['screenshot'],pin(presenter)]+list(c['actions'].values())+[pin(out/'review.json')]
 (out/'freeze.json').write_text(json.dumps(dict(files=list({r['path']:r for r in rows}.values()),deviceOperations=0),indent=2)+'\n');print(json.dumps(dict(review=pin(out/'review.json'),freeze=pin(out/'freeze.json'),findings=[])))
if __name__=='__main__':main()
