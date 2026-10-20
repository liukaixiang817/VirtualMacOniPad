"""Freeze corrected source and bind the complete actual53 current-name proof."""
from pathlib import Path
import hashlib,json
S=Path(__file__).resolve().parent;R=S.parents[2]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D=N/'cpu-owned-brk-device-unsigned-local-v2';H=N/'cpu-owned-brk-device-host-faults-v2'
def pin(p):
 p=Path(p).absolute();b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def main():
 if (D/'freeze.json').exists():raise ValueError('completed immutable freeze')
 rows={}
 def exact(row):
  if pin(row['path'])!=row:raise ValueError('input drift '+row['path'])
  rows[row['path']]=row
 def frozen(p):
  for row in json.loads(p.read_bytes())['files']:exact(row)
  rows[str(p)]=pin(p)
 c=json.loads((D/'candidate.json').read_bytes());h=json.loads((H/'host-results.json').read_bytes())
 for row in c['inputs']+h['inputs']:exact(row)
 exact(c['binary'])
 if h['normalModes']!=12 or h['sanitizedModes']!=12 or not h['finiteMockScopePassed']:
  raise ValueError('actual host faults')
 binding=N/'cpu-owned-brk-current-definitions-binding-v2/binding.json'
 b=json.loads(binding.read_bytes())
 if not b['all53ActualEntriesExactlyUnchanged'] or not b['all53CurrentDefinitionsJoined'] or b['provider']!=c['binary']:
  raise ValueError('actual new53 definition binding')
 frozen(N/'vm-hv-public-bootstrap-integration-local-v4/freeze.json')
 frozen(N/'cpu-owned-brk-current-definitions-readonly-v1/freeze.json')
 frozen(N/'cpu-owned-brk-current-definitions-binding-v2/freeze.json')
 f=json.loads((D/'source-finalization.json').read_bytes())
 for key in ['candidate','binary','hostFaultReceipts','provenance','completeScope','staleNative8BRKCounterexample']:exact(f[key])
 if not f['staleNative8BRKRejectedInNormalAndSAN'] or not f['freshSyndromeRecheckedAtFinalNative9Boundary']:
  raise ValueError('fresh oracle gate')
 final=dict(schema='Root corrected BRK v2 complete source and current definitions binding',
  sourceFinalization=pin(D/'source-finalization.json'),currentDefinitions=pin(binding),
  sourceCandidate=pin(D/'candidate.json'),binary=c['binary'],normalFaultModes=12,sanitizedFaultModes=12,
  oldFrozenV1Preserved=True,staleNative8BRKRejectedBeforeActual9=True,
  actual53CurrentDefinitionNamesJoined=True,requiresSpecificSignedAndControllerReview=True,
  native0CapabilityQueryMaximum=1,native9Maximum=1,providerSigned=False,
  deviceOperations=0,nativeOperationsExecuted=0,guestBooted=False,full27Backend=False)
 with (D/'root-finalization.json').open('x') as stream:json.dump(final,stream,indent=2);stream.write('\n')
 for folder in [D,H]:
  for p in folder.iterdir():
   if p.is_file() and p.name!='freeze.json':rows[str(p.absolute())]=pin(p)
 p=json.loads((D/'provenance.json').read_bytes())
 for key in ['originalReset','savedProduction']:exact(p[key])
 for path in [Path(__file__),S/'finalize-cpu-owned-brk-device-v2.py',
  N/'boot-priority-20261011-v1.json',N/'boot-priority-device-readonly-v3/receipt.json']:
  rows[str(path.absolute())]=pin(path)
 with (D/'freeze.json').open('x') as stream:
  json.dump(dict(schema='Corrected BRK source v2 immutable full actual definition freeze',files=list(rows.values())),stream,indent=2);stream.write('\n')
 print(json.dumps(dict(finalization=pin(D/'root-finalization.json'),freeze=pin(D/'freeze.json'),pins=len(rows),nativeCalls=0)))
if __name__=='__main__':main()
