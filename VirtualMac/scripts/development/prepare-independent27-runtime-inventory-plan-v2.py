"""Prepare an offline, explicit catalogue and proposed load-path plan; mutate no candidate."""
import pathlib,json,hashlib
R=pathlib.Path(__file__).resolve().parents[3];N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';D=N/'independent27-runtime-strong-inventory-plan-v2'
def pin(p):
 p=pathlib.Path(p).resolve();b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def main():
 D.mkdir(exist_ok=True);basis=[];sources={}
 def read(rel):
  p=N/rel;basis.append(pin(p));return json.loads(p.read_text())
 def add(key,row,reason,override=False):
  actual=pin(row['path']);assert all(actual[k]==row[k] for k in ['path','bytes','sha256'])
  if key=='ModernCPURuntimeCompat.dylib':return
  if key in sources and not override:return
  sources[key]={'pin':actual,'basis':reason}
 old=read('independent27-runtime-strong-inventory-v1/inventory.json')
 for k,v in old['selectedCatalog'].items():add(k,v,'frozen exact current selected catalogue v1')
 read('continuation-20261011-state-v33.json');read('continuation-20261010-state-v28.json')
 front=read('universalhid-current-exact-frontier-audit-v25/audit.json')
 for row in front['auditedImages']:
  if row['name'] in ['Virtualization','UniversalHIDKit','UniversalHID']:continue
  assert row['path'].startswith('@loader_path/')
  add(row['path'].split('/',1)[1],row['image'],'actual auditedImages path/image pair in exact frontier v25')
 cn=read('universalhid-static-cn-real-reexport-data-v1/candidate.json')
 for row in cn['images']:
  if row['name']=='UniversalHID':add('UniversalHID27.dylib',row['candidate'],'latest UHK keyboard source explicitly retains this genuine UniversalHID',True)
 add('AR',cn['modifiedArrayReexportProvider']['candidate'],'staticCN exact true reexport AR ordinal12 to CN',True)
 add('CN',cn['unchangedProvider']['candidate'],'staticCN exact owned original provider unchanged',True)
 uk=read('uhk-own-uikit-keyboard-property-source-port-data-v3/candidate.json')
 uh=next(x for x in uk['unchangedGenuineProviders'] if x['name']=='UniversalHID')['candidate'];assert uh==sources['UniversalHID27.dylib']['pin']
 startup=read('owned-vmm-xpc-v9-provider-build-v1/candidate.json')
 for row in startup['libraries']:
  if row['name']=='VM27StartupV9.dylib':add(row['name'],row,'actual VMM current load path and real V9 libraries pin; later parent/child adapter may supersede')
 native=read('current-native-header-export-index-v2/index.json')['images'];maps={}
 def mp(old,target,reason):
  assert old!=target
  if target.startswith('@loader_path/'):assert target.split('/',1)[1] in sources
  else:assert target in native
  maps[old]={'target':target,'status':'proposed; no LC_LOAD bytes changed','basis':reason,'symbolClosureComputedSeparately':True,'ABICompatibilityClaimed':False}
 for old,target in [
 ('/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation','/System/Library/Frameworks/Foundation.framework/Foundation'),
 ('/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation','/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation'),
 ('/System/Library/Frameworks/CoreGraphics.framework/Versions/A/CoreGraphics','/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics'),
 ('/System/Library/Frameworks/Security.framework/Versions/A/Security','/System/Library/Frameworks/Security.framework/Security'),
 ('/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration','/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration'),
 ('/System/Library/Frameworks/Metal.framework/Versions/A/Metal','/System/Library/Frameworks/Metal.framework/Metal'),
 ('/System/Library/Frameworks/IOSurface.framework/Versions/A/IOSurface','/System/Library/Frameworks/IOSurface.framework/IOSurface'),
 ('/System/Library/PrivateFrameworks/CoreAnalytics.framework/Versions/A/CoreAnalytics','/System/Library/PrivateFrameworks/CoreAnalytics.framework/CoreAnalytics'),
 ('/System/Library/Frameworks/IOKit.framework/IOKit','/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit')]:mp(old,target,'explicit original desktop dependency to exact current captured native LC_ID; no automatic alias normalization')
 for old,key in [
 ('/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization','VZ27.dylib'),
 ('/System/Library/Frameworks/Hypervisor.framework/Versions/A/Hypervisor','VM27HVVMProduction.dylib'),
 ('/System/Library/PrivateFrameworks/DiskImages2.framework/Versions/A/DiskImages2','DiskImages227.dylib'),
 ('/System/Library/PrivateFrameworks/EfiSupport.framework/Versions/A/EfiSupport','EfiSupport27.dylib'),
 ('/System/Library/Frameworks/vmnet.framework/Versions/A/vmnet','VM27VMNetUnavailable.dylib'),
 ('/System/Library/Frameworks/IOUSBHost.framework/Versions/A/IOUSBHost','VM27USBUnavailable.dylib'),
 ('/System/Library/PrivateFrameworks/SkyLight.framework/Versions/A/SkyLight','XF'),
 ('@rpath/VM27SwiftLookupCompat.dylib','VM27SwiftLookup.dylib')]:mp(old,'@loader_path/'+key,'explicit selected original/own source provider proposal; actual exported symbols and unresolved ones remain independently enumerated')
 (D/'catalog.json').write_text(json.dumps({k:v['pin'] for k,v in sorted(sources.items())},indent=2)+'\n')
 (D/'plan.json').write_text(json.dumps({'schema':'Independent27 explicit offline inventory provider and proposed load map v2','catalogueProvenance':sources,'proposedLoadPathMap':maps,'forbiddenOldCPURegistry':'ModernCPURuntimeCompat.dylib','retargetingPerformed':False,'sourcePins':basis,'deviceOperations':0,'guestBoot':False},indent=2)+'\n')
 (D/'freeze.json').write_text(json.dumps({'catalog':pin(D/'catalog.json'),'plan':pin(D/'plan.json'),'builder':pin(__file__),'basisPins':basis,'cataloguePins':[v['pin'] for v in sources.values()]},indent=2)+'\n')
 print(json.dumps({'catalog':pin(D/'catalog.json'),'plan':pin(D/'plan.json'),'providers':len(sources),'proposedLoadMaps':len(maps)}))
if __name__=='__main__':main()
