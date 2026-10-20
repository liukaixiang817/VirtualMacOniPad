#!/usr/bin/env python3
"""Correct V3 native import admission count from actual binary; no build/sign/device."""
from pathlib import Path
import hashlib,json,runpy
R=Path('/Users/liukaixiang/Documents/VirtualMacOniPad');N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm';old=N/'owned-usbh-avp-nullable-queue-source-local-v3-attempt1';out=N/'owned-usbh-avp-nullable-queue-source-local-v3-attempt2'
def pin(p):
 p=Path(p).resolve();b=p.read_bytes();return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def checked(p):
 assert pin(p['path'])==p;return Path(p['path'])
def dump(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
assert not out.exists();c=json.loads((old/'candidate.json').read_bytes());f=json.loads((old/'freeze.json').read_bytes())
for row in f['files']:checked(row)
M=runpy.run_path(str(N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'))['MachO'];image=M(checked(c['newProvider']).read_bytes());graph=json.loads(checked(c['graph']).read_bytes())
actual=len(image.imports);assert actual==45 and len(graph['actualProviderNativeRows'])==actual and graph['strongRows']==actual
assert len(image.exports)==c['actualProviderExportCount']==19
assert all(not q['weak'] for q in image.imports)
assert [q['actualImport']['name'] for q in graph['actualProviderNativeRows']]==[q['name'] for q in image.imports]
assert c['actualProviderNativeImportCount']==44
c['actualProviderNativeImportCount']=actual;c['originalAdmissionMetadata']=pin(old/'candidate.json');c['builder']=pin(__file__)
c['admissionCorrection']='Native import count derived from exact reused binary and matching graph rows; no code/build/sign/device change'
out.mkdir();dump(out/'candidate.json',c)
files=[v for v in f['files'] if v['path']!=str(old/'candidate.json')]
files.extend([pin(out/'candidate.json'),pin(old/'candidate.json'),pin(__file__)])
dump(out/'freeze.json',dict(schema='Truthful V3 metadata admission correction; exact compiled binary/source/graph retained',candidate=pin(out/'candidate.json'),files=list({v['path']:v for v in files}.values()),actualNativeImportCount=actual,compileRepeated=False,actualDeviceOperations=0))
print(json.dumps(dict(candidate=pin(out/'candidate.json'),freeze=pin(out/'freeze.json'),actualProvider=c['newProvider'],actualNativeImportCount=actual),indent=2))
