"""Build the explicit NIC0 failure provider, without signing/device actions."""
import argparse,hashlib,importlib.util,json,pathlib,subprocess,sys
sys.dont_write_bytecode=True
R=pathlib.Path(__file__).resolve().parents[3]
S=R/'VirtualMac/vz/host';N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
SDKHEADER=pathlib.Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/System/Library/Frameworks/vmnet.framework/Versions/A/Headers/vmnet.h')
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
 d=a.output.resolve();need(d.is_relative_to(N) and not d.exists(),'fresh diagnostic output');d.mkdir()
 commands=[]
 def run(label,argv):
  cp=subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
  (d/(label+'.stdout')).write_bytes(cp.stdout);(d/(label+'.stderr')).write_bytes(cp.stderr)
  commands.append(dict(label=label,argv=list(map(str,argv)),status=cp.returncode))
  (d/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
  need(cp.returncode==0,label+' '+cp.stderr.decode(errors='replace'));return cp.stdout
 sources=[S/'vm27_vmnet_unavailable_v2.c',S/'vm27_vmnet_unavailable_v2.h',
  S/'vm27_vmnet_unavailable_v1.c',S/'vm27_vmnet_unavailable_v1.h',
  S/'test-vm27-vmnet-unavailable-v2.c',pathlib.Path(__file__).resolve(),SDKHEADER]
 before=[pin(p)for p in sources]
 ios=run('sdk-ios',['xcrun','--sdk','iphoneos','--show-sdk-path']).decode().strip()
 mac=run('sdk-mac',['xcrun','--sdk','macosx','--show-sdk-path']).decode().strip()
 provider=d/'VM27VMNetUnavailableV2.unsigned.dylib'
 common=['-O2','-fblocks','-std=c11','-Wall','-Wextra','-Werror','-I',S]
 run('ios-provider',['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',ios]+common+
  ['-dynamiclib',S/'vm27_vmnet_unavailable_v2.c','-Wl,-install_name,@rpath/VM27VMNetUnavailableV2.dylib',
   '-Wl,-no_adhoc_codesign','-o',provider])
 run('ios-validate',['xcrun','dyld_info','-validate_only',provider])
 run('ios-metadata',['xcrun','dyld_info','-platform','-dependents','-imports','-exports',provider])
 models=[]
 for label,flags in [('normal',[]),('sanitizers',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
  exe=d/('contract-'+label)
  run('build-'+label,['xcrun','clang','-isysroot',mac]+common+flags+
   [S/'test-vm27-vmnet-unavailable-v2.c',S/'vm27_vmnet_unavailable_v2.c','-o',exe])
  model=json.loads(run('run-'+label,[exe]));need(model['actualFailureCallbacks']==2 and
   model['callbacksUsedRequestedQueue'] and model['failedIOPreservedBuffers'],'true queue and packet contract')
  models.append(dict(label=label,**model))
 reader=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
 spec=importlib.util.spec_from_file_location('macho_vmnet2',reader);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 image=m.MachO(provider.read_bytes())
 old=json.loads((N/'vmnet-unavailable-contract-v1/candidate.json').read_bytes())
 inventory=json.loads((N/'independent27-runtime-strong-inventory-v3/inventory.json').read_bytes())['proposed']
 required={r['actualImport']['name']for r in inventory['unresolvedStrongImportRows']
  if r.get('dependencyPath')=='/System/Library/Frameworks/vmnet.framework/Versions/A/vmnet'}
 need(len(required)==21 and required<=set(image.exports),'all21 exact required exports')
 need(len(image.exports)==26 and len(image.loads)==1 and image.loads[0]['path']=='/usr/lib/libSystem.B.dylib','one true native dependency')
 need(before==[pin(p)for p in sources],'source unchanged')
 result=dict(schema='Own explicit disabled vmnet provider v2',provider=pin(provider),sources=before,
  sdkPublicABIWidthsUsed=True,requiredOriginalVMMExports=sorted(required),actualExports=sorted(image.exports),
  actualIOSStrictLinkAndValidatePassed=True,models=models,
  disabledDictionaryKeysAreOwnIdentities=True,appleProtocolKeyValuesClaimed=False,
  privatePropertyGetterReturnABIClaimed=False,privateGettersNeverReturnInventedProperty=True,
  inheritedV1BodyBytePreserved=True,networkOperations=0,functionalNetworkingImplemented=False,
  requiresRealVMConfigurationNICCount=0,nic0EnforcedInThisProvider=False,
  packetBuffersAndCountsPreservedOnFailure=True,deviceOperations=0,signingCalls=0,guestBoot=False,
  limitations=['Only the App with enforced zero NICs may use this deferred network provider.',
   'The final objective still requires a real Ethernet/network backend and guest SSH.',
   'Private getters deliberately trap unsupported instead of returning an invented property.'])
 (d/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
 rows=[pin(p)for p in sorted(d.rglob('*'))if p.is_file()]+before+[pin(reader),pin(N/'independent27-runtime-strong-inventory-v3/inventory.json')]
 (d/'freeze.json').write_text(json.dumps(dict(candidate=pin(d/'candidate.json'),pins=rows),indent=2)+'\n')
 print(json.dumps(dict(candidate=pin(d/'candidate.json'),freeze=pin(d/'freeze.json'),provider=pin(provider),models=models)))
if __name__=='__main__':main()
