#!/usr/bin/env python3
"""One bounded initializer retry; already installed products and trust unchanged."""
import pathlib,json,hashlib,importlib.util,datetime,getpass,re,shlex,os
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';OLD=N/'independent27-guest-thread-device-v82-attempt1';O=N/'independent27-guest-thread-device-v82-initretry1'
def need(v,w):
 if not v:raise ValueError(w)
def pin(p):
 p=pathlib.Path(p).resolve();need(p.is_file()and not p.is_symlink(),'ordinary file');b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()
need(not O.exists(),'one fresh retry; no repeats');spec=importlib.util.spec_from_file_location('root_exact_transport',OLD/'control.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
c.ready_gate(OLD,OLD/'ready-root-device82.json')
need(pin(OLD/'candidate.json')['sha256']=='63ea3eeb69f528ec31e83ad8570be0172f62626e0a5cd1bfe894d8fe008cc011','exact installed product transaction')
prior=[]
for action,expected in [('stage',0),('verify',0),('trust',0),('launch',8),('post',0)]:
 f=OLD/'device-receipts'/action/'receipt.json';d=json.loads(f.read_text());need(d['transportExit']==expected and not d['transportError'],'actual prior phase '+action)
 for k in ['request','stdout','stderr']:need(pin(d[k]['path'])==d[k],'actual prior '+k)
 need(json.loads(pathlib.Path(d['request']['path']).read_text())['packetCandidate']==pin(OLD/'candidate.json'),'same actual prior productpacket');prior.append(pin(f))
need('INDEPENDENT27_POST_HEALTH_OWN_PRODUCTS_LOG_AND_TRUST_RETAINED' in (OLD/'device-receipts/post/stdout').read_text(),'actual prioroff/productshealthy')
O.mkdir(mode=0o700);scope=json.loads((OLD/'scope.json').read_text());scope.update(schema='Existing R80 App97 bounded initialization retry; no product or trust changes',newTrustCacheCDHashes=[],trustCacheRegistrationCount=0,trustCacheFixedBatchCounts=[],deltaFiles=[],existingOwnFilesUpdated=0,actualChangedFiles=0,unchangedFiles=259,unchangedSignedImages=144,productUpdatesPlanned=False,initializationOnly=True,sourceInstalledScope=pin(OLD/'scope.json'))
for k in ['archive','deltaArchiveBytes','deltaArchiveSHA256']:scope.pop(k,None)
save(O/'scope.json',scope)
raw=(OLD/'launch.sh').read_text();at=raw.index('/var/jb/bin/sh -c ',raw.index('/var/jb/usr/bin/timeout'))+len('/var/jb/bin/sh -c ');body=shlex.split(raw[at:]);need(len(body)==1,'one outer launchbody');body=body[0]
a=body.index('own_ui_close_status=0\n')+len('own_ui_close_status=0\n');b=body.index(' >/dev/null 2>&1 || own_ui_close_status=$?',a)
body=body[:a]+'own_ui_close_debug=$('+body[a:b]+ ' 2>&1) || own_ui_close_status=$?\nprintf \'%s\\n\' "$own_ui_close_debug" | sed \'s/^/OWN_UI_CLOSE_DEBUG /\'\n'+body[b+len(' >/dev/null 2>&1 || own_ui_close_status=$?\n'):]
(O/'launch.sh').write_text(raw[:at]+shlex.quote(body)+'\n');(O/'post.sh').write_bytes((OLD/'post.sh').read_bytes())
# Only nested-close output capture/prefix changes; execution checks/timeouts remain.
launch=pin(O/'launch.sh');post=pin(O/'post.sh');candidate=dict(schema='Root existing R80 App97 bounded initializer retry1',scope=pin(O/'scope.json'),controller=pin(__file__),scripts=dict(launch=launch,post=post),actions=['launch','post'],oldDeviceCandidate=pin(OLD/'candidate.json'),priorActualReceipts=prior,continuingHumanAuthorization=scope['continuingHumanAuthorization'],actualChangedFiles=0,actualNewTrustEntries=0,actualExistingFilesUpdated=0,rootIsSoleDeviceOperator=True,guestBootRequested=False,initializationExternalWallSeconds=45,transportTimeoutSeconds=55)
save(O/'candidate.json',candidate);files=[pin(__file__),pin(OLD/'control.py'),pin(OLD/'freeze.json'),pin(OLD/'scope.json'),pin(OLD/'candidate.json'),pin(O/'candidate.json'),pin(O/'scope.json'),launch,post,*prior];save(O/'freeze.json',dict(files=files,trustCacheOperations=0,productUpdates=0));password=getpass.getpass('iPad password: ');result=1
try:
 for action in ['launch','post']:
  for row in files:need(pin(row['path'])==row,'frozen input unchanged')
  out=O/'device-receipts'/action;out.mkdir(parents=True,mode=0o700);marker=O/(action+'-dispatched.json');need(not marker.exists(),'one action only');save(marker,dict(action=action,startedUTC=stamp(),packetCandidate=pin(O/'candidate.json')))
  data=b''
  if action=='post':
   t=(O/'device-receipts/launch/stdout').read_text(errors='replace');found={}
   for kind,pid,ppid,start,path in re.findall(r'^OWN_(APP|CHILD)_ID ([0-9]+) ([0-9]+) 501 ([a-f0-9]{64}) (\S+)$',t,re.M):
    need(kind not in found and int(pid)>1 and path==(c.APP_MAIN if kind=='APP'else c.CHILD_MAIN),'exact actual capture');found[kind]=(pid,ppid,start)
   parent=found.get('APP',('0','1','none'));child=found.get('CHILD',('0','0','none'));need(parent[1]=='1'and(child[0]=='0'or child[1]==parent[0]),'own PPID');data=f'{parent[0]} {parent[2]} {child[0]} {child[2]}\n'.encode()
  script=O/(action+'.sh');save(out/'request.json',dict(action=action,packetCandidate=pin(O/'candidate.json'),script=pin(script),priorPins=prior,inputBytes=len(data),inputSHA256=hashlib.sha256(data).hexdigest(),root=action=='post',guestBootRequested=False))
  status,stdout,stderr,error=c.run_remote(script.read_text(),data,action=='post',password,transport_timeout=55);(out/'stdout').write_bytes(stdout);(out/'stderr').write_bytes(stderr);save(out/'receipt.json',dict(action=action,finishedUTC=stamp(),transportExit=status,transportError=error,request=pin(out/'request.json'),stdout=pin(out/'stdout'),stderr=pin(out/'stderr'),guestBootRequested=False,trustCacheOperations=0));print(action,status,stdout.decode(errors='replace')[-10000:],stderr.decode(errors='replace'),flush=True)
  if action=='launch':result=status
  else:need(status==0,'actual post cleanup failed')
finally:password=None
need(result==0,'initializer retry failed; exact post retained')
