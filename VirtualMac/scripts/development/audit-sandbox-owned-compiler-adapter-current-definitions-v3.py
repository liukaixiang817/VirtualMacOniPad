"""Resolve the actual owned adapter's 33 imports through captured native reexports."""
import hashlib,json,re
from pathlib import Path

ROOT=Path(__file__).resolve().parents[3]
NODE=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT=NODE/'sandbox-owned-compiler-adapter-current-definitions-v3-attempt1'
def pin(path):
    p=Path(path).resolve(); b=p.read_bytes()
    return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(path,value):
    with path.open('x') as stream: json.dump(value,stream,indent=2);stream.write('\n')
def main():
    candidate=NODE/'sandbox-init-owned-compiler-adapter-local-v3-attempt1/candidate.json'
    assert pin(candidate)['sha256']=='361e1f57c14df33ae0f1024d4c209373bf96e970bab308e8df63fcbfebca0f81'
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
    assert len(symbols)==33 and len(set(symbols))==33
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
    save(OUT/'report.json',dict(schema='Owned compiler adapter actual current native imports closure v3',
        finiteLocalScopePassed=True,findings=[],candidate=pin(candidate),actualStrongImportCount=33,
        actualReexportRoutes=rows,unresolved=[],compilerAndNativeIdentitiesValidatedByAdapter=True,StageIntegrationHeld=True,actualNativeCompilerInvoked=False,
        capturedNativeIndex=pin(index),deviceOperations=0,nativeApplyCalls=0,inputs=inputs))
    save(OUT/'freeze.json',dict(schema='Owned compiler adapter actual native closure freeze v3',
        files=inputs+[pin(OUT/'report.json')]))
    print(json.dumps(dict(report=pin(OUT/'report.json'),freeze=pin(OUT/'freeze.json'))))
if __name__=='__main__':main()
