"""Versioned exact selected provider plan; no candidate mutation or device action."""
import pathlib,json,hashlib
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'independent27-runtime-strong-inventory-plan-v3'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def need(v,w):
 if not v:raise ValueError(w)
def main():
 need(not D.exists(),'fresh output only');basis=[]
 def read(rel,sha=None):
  p=N/rel;r=pin(p);need(sha is None or r['sha256']==sha,'exact basis');basis.append(r);return json.loads(p.read_bytes())
 old=read('independent27-runtime-strong-inventory-plan-v2/plan.json','0d50ae3c867510fc41742568ce238f93f68ecf8bf602ca13d7b860aa8b9e97e1');sources=dict(old['catalogueProvenance']);maps=dict(old['proposedLoadPathMap'])
 for v in sources.values():need(pin(v['pin']['path'])==v['pin'],'old selected provider unchanged')
 def add(key,row,reason):
  actual=pin(row['path']);need(actual==row,'exact candidate pin');sources[key]=dict(pin=actual,basis=reason)
 hv=read('vm-hv-public-bootstrap-integration-local-v16-adoption1/candidate.json','b8cf12f3d98e6a0bcefe1925aa2188fd1706d3fcf04f8c7f609494ed2526868e');add('VM27HVVMProduction.dylib',hv['provider'],'Root16 byte-identical adoption of actual single-registry Factory20 whole provider')
 cxx=read('independent27-cxx-stateless-leaf-local-v1/candidate.json','975d4b000db9d7ae8bfc036c25c93e3a34f39fea76b0cf71ef236eb2cdfff049')
 for key in ['CP','VM27CxxProvider.dylib']:add(key,cxx['provider'],'new exact CP native libc++ and bounded stateless source leaf reexports; no old CPU registry')
 add('VM27CxxStatelessLeafV1.dylib',cxx['leaf'],'exact unchanged bounded C++ helper source compiled into a new registry-free leaf')
 pvg=R/'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/modern-pvg-ui-profile-tool-repro-2026-10-08-v1/from-original-final/ParavirtualizedGraphics';pv=pin(pvg);need(pv['bytes']==665056 and pv['sha256']=='7c052a43cf26b232b114d787f6b3f9133c0646db953858717645895ab0ef5065','exact Root-selected original27 PVG');add('ParavirtualizedGraphics27.dylib',pv,'Root exact original27 PVG catalog pin; full byte-preserved product; no GPU execution claim')
 native=read('current-native-header-export-index-v3/index.json','60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019')['images'];need(len(native)==67,'actual67')
 def mp(old,target,reason):
  need(old!=target,'explicit differing load path')
  need(target.split('/',1)[1] in sources if target.startswith('@loader_path/') else target in native,'explicit true selected target')
  maps[old]=dict(target=target,status='proposed; no LC_LOAD bytes changed',basis=reason,symbolClosureComputedSeparately=True,ABICompatibilityClaimed=False)
 for old,target in [
 ('/System/Library/Frameworks/AudioToolbox.framework/Versions/A/AudioToolbox','/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox'),
 ('/System/Library/Frameworks/CoreAudio.framework/Versions/A/CoreAudio','/System/Library/Frameworks/CoreAudio.framework/CoreAudio'),
 ('/System/Library/PrivateFrameworks/CoreBrightness.framework/Versions/A/CoreBrightness','/System/Library/PrivateFrameworks/CoreBrightness.framework/CoreBrightness'),
 ('/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/Versions/A/IOSurfaceAccelerator','/System/Library/PrivateFrameworks/IOSurfaceAccelerator.framework/IOSurfaceAccelerator'),
 ('/System/Library/PrivateFrameworks/RemoteServiceDiscovery.framework/Versions/A/RemoteServiceDiscovery','/System/Library/PrivateFrameworks/RemoteServiceDiscovery.framework/RemoteServiceDiscovery'),
 ('/System/Library/PrivateFrameworks/RemoteXPC.framework/Versions/A/RemoteXPC','/System/Library/PrivateFrameworks/RemoteXPC.framework/RemoteXPC'),
 ('/System/Library/Frameworks/Combine.framework/Versions/A/Combine','/System/Library/Frameworks/Combine.framework/Combine'),
 ('/System/Library/PrivateFrameworks/HID.framework/Versions/A/HID','/System/Library/PrivateFrameworks/HID.framework/HID')]:mp(old,target,'explicit desktop path to actual current captured LC_ID/UUID/export extent; never automatic Versions normalization')
 mp('/System/Library/Frameworks/ParavirtualizedGraphics.framework/Versions/A/ParavirtualizedGraphics','@loader_path/ParavirtualizedGraphics27.dylib','Root selected byte-identical original27 PVG product; full dependency graph remains audited')
 D.mkdir();(D/'catalog.json').write_text(json.dumps({k:v['pin'] for k,v in sorted(sources.items())},indent=2)+'\n')
 result=dict(schema='Independent27 explicit offline inventory provider and proposed load map v3',catalogueProvenance=sources,proposedLoadPathMap=maps,forbiddenOldCPURegistry='ModernCPURuntimeCompat.dylib',originalV2CandidatePinsRetainedExceptExplicitProviderSelections=True,networkUnavailableIsNotFunctionalNetworking=True,retargetingPerformed=False,sourcePins=basis,deviceOperations=0,guestBoot=False)
 (D/'plan.json').write_text(json.dumps(result,indent=2)+'\n');(D/'freeze.json').write_text(json.dumps(dict(catalog=pin(D/'catalog.json'),plan=pin(D/'plan.json'),builder=pin(__file__),basisPins=basis,cataloguePins=[v['pin'] for v in sources.values()]),indent=2)+'\n')
 print(json.dumps(dict(catalog=pin(D/'catalog.json'),plan=pin(D/'plan.json'),freeze=pin(D/'freeze.json'),providers=len(sources),proposedLoadMaps=len(maps))))
if __name__=='__main__':main()
