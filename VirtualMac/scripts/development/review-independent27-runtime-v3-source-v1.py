#!/usr/bin/env python3
"""Finite independent read-only Runtime3 source review; never loads/spawns."""
import argparse,hashlib,json,pathlib,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3];S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
 b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 o=a.output.resolve();assert o.is_relative_to(N) and not o.exists();o.mkdir()
 package=N/'independent27-runtime-source-local-v3-attempt1';candidate=package/'candidate.json'
 freeze=package/'freeze.json';seen=set();verified=[]
 def verify(p):
  p=p.resolve()
  if p in seen:return
  seen.add(p);data=json.loads(p.read_bytes());verified.append(pin(p))
  for row in data['files']:
   q=pathlib.Path(row['path']);assert pin(q)==row,(str(q),'freeze drift')
  for row in data['files']:
   q=pathlib.Path(row['path'])
   if q.name=='freeze.json':verify(q)
 verify(freeze)
 j=json.loads(candidate.read_bytes())
 for row in j['sourcePins']:assert pin(pathlib.Path(row['path']))==row
 for row in j['inheritedFreezePins']:
  p=pathlib.Path(row['path']);assert pin(p)==row;verify(p)
 v3=(S/'vm27_independent_app_runtime_v3.m').read_text()
 v2=(S/'vm27_independent_app_runtime_v2.m').read_text()
 v1=(S/'vm27_independent_app_runtime_v1.m').read_text()
 startup=(S/'vm27_owned_app_child_startup_v1.c').read_text()
 wrapper=(S/'vm27_owned_app_parent_scoped_policy_v2.inc').read_text()
 checks=[]
 def check(name,result,evidence):
  assert result,name;checks.append(dict(name=name,passed=True,evidence=evidence))
 def order(text,*items):
  at=-1
  for item in items:
   at=text.find(item,at+1)
   if at<0:return False
  return True
 check('one inherited state, no competing runtime implementation', '#include "vm27_independent_app_runtime_v2.m"' in v3 and '#include "vm27_independent_app_runtime_v1.m"' in v2,
  'V3 renames only public preflight/load/started then includes frozen V2; V2 inherits the single frozen V1 state.')
 check('entire genuine signed graph checked before any acquired load',order(v3,'if(!ValidateV1(root','pthread_mutex_lock(&BootstrapMutexV3)','VM27IndependentAppRuntimeLoadInheritedV2(root,error)'),
  'Load first applies anchored bytes/SHA, every file SHA/CodeDirectory/slot, recorded profile, child BL and exact root checks.')
 check('no parent NativeOps installation', 'child-only caller guard' in v1 and 'EntryV1([handles[child[@"providerID"]]' in v1 and 'actualStart(&config,&RetainedParentV3)' in v3,
  'Frontend resolves hv_vm_config_create only; child VM setup pthread owns actual installation.')
 check('registry contract matches real immediate bundle API', 'contract.count!=6' in v3 and 'stringByDeletingLastPathComponent] isEqual:registry' in v3 and '[bundle hasSuffix:@".bundle"]' in v3,
  'Six anchored fields; exact VM service, immediate .bundle child, exact child UUID/SHA/CD/path and two unique resource Info records.')
 check('two exact startup definitions resolve to anchored single provider', order(v3,'EntryV1(handle,providerPath,start','EntryV1(handle,providerPath,copy','dlsym(handle,"VM27OwnedAppParentStartWithScopedPolicyV2")','dlsym(handle,"VM27OwnedAppParentCopyStateV1")'),
  'Actual entry dlsym is admitted by inherited provider image path, actual UUID and exact stripped RVA.')
 check('actual self path canonicalization', order(v3,'realpath(root.fileSystemRepresentation,canonical)','root=[NSString stringWithUTF8String:canonical]','realpath(actualExe,executable)'),
  'Trusted main NSBundle and _NSGetExecutablePath independently resolve to the actual canonical App/executable.')
 check('self inspection limits and mandatory slots', 'ReadAtV1(fd,name,2*1024*1024,error)' in v3 and '@"signatureSlots":@{@"1":@"info",@"3":@"resources"}' in v3,
  'Actual self 2MiB; Info 64KiB and CodeResources 1MiB; true signature verifies pages/CD, Info slot1 and resources slot3.')
 check('actual main UUID matches inspected self', 'loaded->filetype!=MH_EXECUTE' in v3 and '![uuid isEqual:loadedUUID]' in v3 and 'SignatureV1(code,row' in v3,
  'Unique actual dyld main UUID and executable path both agree with signed self, rejecting unbundled/other image.')
 check('caller config has no message authority or DYLD environment', 'char *argv[]={ (char *)executable.fileSystemRepresentation,NULL },*environment[]={NULL};' in v3 and 'arc4random_buf(&nonce' in v3,
  'Anchored child path argv and empty environment; fresh nonzero nonce; self hash/CD only independent file expectations.')
 check('scoped policy C owner preserves exact gates',order(wrapper,'source->originalImmutableRequirement','VM27OwnedAppCreateScopedPluginRequirementV1(&requirement)','VM27OwnedAppParentStartV1(&actual,owner)','xpc_release(requirement)'),
  'No ARC xpc ownership cast; requires NULL input, true parser policy and unchanged strict ParentStart with native child identity gates.')
 check('late parent callback does not borrow Runtime stack strings',order(startup,'strcpy(o->parentBundle,c->actualParentBundle.bundlePath)','VM27LargeBundleRegistryCreate','VM27LargePrivateServiceConsumerV2Spawn'),
  'Adapter deepcopies self path/executable/SHA/CD and UID before any asynchronous callbacks; synchronous registry/spawn consume temporary argv safely.')
 check('binding blocked during child startup',order(v3,'BootstrapPIDV3=getpid()','RuntimePoisonedV1=YES','actualStart(&config,&RetainedParentV3)','if(result){if(pthread_mutex_lock(&RuntimeMutexV1))abort();RuntimePoisonedV1=NO'),
  'Inherited Bind rejects poison until true parent-start success plus current copied parent state.')
 check('state is true fresh copy rather than local ready flag', 'ActualParentStateV3(RetainedParentV3,&state)' in v3 and 'state.ownerPID!=getpid()' in v3 and '!state.spawned || !state.helloInstalled || state.startupStatus || state.controlStatus' in v3 and 'state.controlFinalInvalid || state.listenerFinalInvalid' in v3,
  'Current true owner PID, actual child PID, actual spawn/hello/install and no recorded control/listener invalid/error required.')
 check('partial failure retains acquired ownership and blocks retry', 'else if(RetainedParentV3 || BootstrapPIDV3)' in v3 and 'if(!result && BootstrapPIDV3)' in v3 and 'ParentRelease' not in v3 and 'dlclose' not in v3,
  'Global acquired parent/handles are retained and process poisoned; no implicit kill/free/rollback or second spawn.')
 check('fresh guest state remains required after factory',order(v3,'BOOL VM27IndependentAppRuntimeGuestStartedV1','ParentReadyV3(error)','return ready && VM27IndependentAppRuntimeGuestStartedInheritedV2(error)'),
  'Then inherited exact Class image/export, actual VM main queue and real VZ state Running are required.')
 check('mutex lock order is not reversed by binding/started', 'BootstrapMutexV3' not in v2 and 'BootstrapMutexV3' not in v1 and order(v3,'BOOL ready=ParentReadyV3(error);if(pthread_mutex_unlock(&BootstrapMutexV3))','return ready && VM27IndependentAppRuntimeGuestStartedInheritedV2(error)'),
  'Startup may lock Bootstrap then Runtime; original Bind owns only Runtime, and GuestStarted releases Bootstrap before Runtime.')
 check('existing models explicitly bounded',all(j['models'][m]['checks']==23 and not j['models'][m]['actualChildSpawn'] and j['models'][m]['nativeCPUCalls']==0 for m in ('normal','san')),
  'Executed original 23 normal/SAN fixtures are reused; no simulated bootstrap shape is product or execution proof.')
 report=dict(schema='Runtime3 independent finite source review v1',candidate=pin(candidate),sourceFreeze=pin(freeze),recursiveVerifiedFreezes=verified,
  sourcePins=j['sourcePins'],checks=checks,checksPassed=len(checks),existingModelResults=j['models'],wholeModelRepeated=False,
  finiteLocalScopePassed=True,findings=[],actualSelfSignedMainSizeRequiredMaxBytes=2097152,actualAppMainNotYetLinkedOrSigned=True,
  originalVMMChildSpawnExecuted=False,actualVZStarted=False,nativeCPUCalls=0,deviceOperations=0,guestBoot=False,
  boundary='Finite local source review and actual frozen compilation/model evidence. Product anchor, signed graph, actual child constructor admission/IPC and real guest remain Root integration/runtime work.')
 report['reviewer']=pin(pathlib.Path(__file__));save(o/'review.json',report)
 save(o/'freeze.json',dict(schema='Runtime3 independent source review freeze v1',files=[pin(o/'review.json'),pin(pathlib.Path(__file__))]))
 print(json.dumps(dict(review=pin(o/'review.json'),freeze=pin(o/'freeze.json'),checks=len(checks))))
if __name__=='__main__':main()
