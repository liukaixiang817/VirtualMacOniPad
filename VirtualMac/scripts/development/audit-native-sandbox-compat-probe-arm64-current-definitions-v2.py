"""Resolve the actual ordinary arm64 probe's 39 imports through captured native reexports."""
import hashlib,json,re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT=NODE/'native-sandbox-compat-probe-arm64-current-definitions-v2-attempt1'
def pin(path):
    p=Path(path).resolve(); b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(path,value):
    with path.open('x') as stream: json.dump(value,stream,indent=2);stream.write('\n')
def main():
    candidate=NODE/'native-sandbox-apply-compat-probe-unsigned-local-v2-arm64-attempt1/candidate.json'
    assert pin(candidate)['sha256']=='e6ae0097f855822585f7672559b13f4a6369dfcbd3b77eb9f17c333cd85ffe4d'
    c=json.loads(candidate.read_bytes()); assert pin(c['binary']['path'])==c['binary']
    imports=candidate.parent/'ios-imports.stdout'
    index=NODE/'current-native-header-export-index-v3/index.json'
    assert pin(index)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    images=json.loads(index.read_bytes())['images']
    used=set()
    def resolve(path,name,seen=()):
        if (path,name) in seen or path not in images: return None
        v=images[path]; used.add(path); seen=(*seen,(path,name))
        definition=v['definitions'].get(name)
        if definition is not None:
            step=dict(image=path,UUID=v['UUID'],symbol=name,definition=definition)
            if definition['flags'] & 8:
                dependency=next(x for x in v['dependencies'] if x['ordinal']==definition['ordinal'])
                rest=resolve(dependency['path'],definition.get('alias') or name,seen)
                return None if rest is None else [dict(**step,reexportDependency=dependency)]+rest
            return [step]
        for dependency in v['dependencies']:
            if dependency['command']==0x8000001f:
                rest=resolve(dependency['path'],name,seen)
                if rest is not None: return [dict(image=path,UUID=v['UUID'],symbol=name,wholeDylibReexport=dependency)]+rest
        return None
    symbols=re.findall(r'^\s*0x[0-9A-Fa-f]+\s+(\S+)\s+\(from libSystem\)',imports.read_text(),re.M)
    assert len(symbols)==39 and len(set(symbols))==39
    rows=[]
    for name in symbols:
        route=resolve('/usr/lib/libSystem.B.dylib',name)
        assert route is not None,name
        rows.append(dict(importName=name,actualRoute=route,finalCurrentDefinition=route[-1]))
    inputs=[pin(Path(__file__)),pin(candidate),c['binary'],pin(imports),pin(index)]
    for path in sorted(used):
        for key in ['actualCompleteCommands','actualCompleteExportSource']:
            entry=images[path].get(key)
            if entry and isinstance(entry,dict) and 'path' in entry:
                actual=pin(entry['path'])
                assert all(actual[k]==entry[k] for k in ['path','bytes','sha256'])
                inputs.append(actual)
    OUT.mkdir(exist_ok=False)
    save(OUT/'report.json',dict(schema='Ordinary arm64 sandbox compatibility probe actual current native imports closure v2',
        finiteLocalScopePassed=True,findings=[],candidate=pin(candidate),actualStrongImportCount=39,
        actualReexportRoutes=rows,unresolved=[],nativeAPIIdentitiesStillValidatedByProbe=True,
        capturedNativeIndex=pin(index),deviceOperations=0,nativeApplyCalls=0,inputs=inputs))
    save(OUT/'freeze.json',dict(schema='Ordinary arm64 sandbox compatibility probe actual native closure freeze v2',
        files=inputs+[pin(OUT/'report.json')]))
    print(json.dumps(dict(report=pin(OUT/'report.json'),freeze=pin(OUT/'freeze.json'))))
if __name__=='__main__':main()
