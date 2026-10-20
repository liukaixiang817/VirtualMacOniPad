#!/usr/bin/env python3
"""Resolve the actual SSH component imports against captured iPad definitions."""
import argparse, hashlib, json, pathlib, re, struct
R=pathlib.Path(__file__).resolve().parents[3]
N=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    b=p.read_bytes();return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def save(p,v):p.write_text(json.dumps(v,indent=2)+'\n')
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--component-candidate',type=pathlib.Path,required=True)
    ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args()
    o=a.output.resolve();assert o.is_relative_to(N) and not o.exists()
    c=json.loads(a.component_candidate.read_bytes());binary=pathlib.Path(c['unsignedSSHAggregate']['path'])
    assert pin(binary)==c['unsignedSSHAggregate']
    b=binary.read_bytes();assert struct.unpack_from('<I',b)[0]==0xfeedfacf
    count=struct.unpack_from('<I',b,16)[0];off=32;dependencies=[]
    for _ in range(count):
        cmd,size=struct.unpack_from('<II',b,off);assert size>=8 and off+size<=len(b)
        if cmd in (0xc,0x80000018,0x8000001f,0x80000023):
            pos=struct.unpack_from('<I',b,off+8)[0]
            path=b[off+pos:off+size].split(b'\0',1)[0].decode()
            dependencies.append(dict(ordinal=len(dependencies)+1,path=path,command=cmd))
        off+=size
    index=N/'current-native-header-export-index-v3/index.json'
    assert pin(index)['sha256']=='60576c3f1a84351b5e252a5a4b1cd99f7b5b5ffa203eda57f9b945e8f5c5b019'
    images=json.loads(index.read_bytes())['images'];used=set()
    def resolve(path,name,seen=()):
        if (path,name)in seen or path not in images:return None
        v=images[path];used.add(path);seen=(*seen,(path,name));d=v['definitions'].get(name)
        if d is not None:
            step=dict(image=path,UUID=v['UUID'],symbol=name,definition=d)
            if d['flags']&8:
                dep=next(x for x in v['dependencies']if x['ordinal']==d['ordinal'])
                rest=resolve(dep['path'],d.get('alias')or name,seen)
                return None if rest is None else[dict(**step,reexportDependency=dep)]+rest
            return[step]
        for dep in v['dependencies']:
            if dep['command']==0x8000001f:
                rest=resolve(dep['path'],name,seen)
                if rest is not None:return[dict(image=path,UUID=v['UUID'],symbol=name,wholeDylibReexport=dep)]+rest
        return None
    imports=a.component_candidate.parent/'imports-ssh.stdout'
    parsed=re.findall(r'^\s*0x[0-9A-Fa-f]+\s+(\S+)\s+\(from ([^)]+)\)',imports.read_text(),re.M)
    roots={'CoreFoundation':'/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
        'Foundation':'/System/Library/Frameworks/Foundation.framework/Foundation',
        'libobjc':'/usr/lib/libobjc.A.dylib','libSystem':'/usr/lib/libSystem.B.dylib'}
    rows=[]
    assert len(parsed)==101 and len({name for name,label in parsed})==101
    for name,label in parsed:
        actual=roots[label];assert any(d['path']==actual for d in dependencies),(label,dependencies)
        route=resolve(actual,name);assert route is not None,(name,actual)
        assert '_VZ' not in name and '$__VZ' not in name
        rows.append(dict(symbol=name,actualDependency=actual,actualRoute=route))
    inputs=[pin(pathlib.Path(__file__)),pin(a.component_candidate),pin(binary),pin(imports),pin(index)]
    for path in sorted(used):
        for key in ('actualCompleteCommands','actualCompleteExportSource'):
            p=images[path].get(key)
            if isinstance(p,dict)and'path'in p:
                q=pin(pathlib.Path(p['path']));assert all(q[k]==p[k]for k in('path','bytes','sha256'));inputs.append(q)
    o.mkdir()
    save(o/'report.json',dict(schema='App10 genuine SSH component actual current import closure',
        finiteLocalScopePassed=True,findings=[],actualStrongImportCount=101,unresolved=[],
        actualDependencies=dependencies,actualNativeRoutes=rows,inputs=inputs,
        appleVZClassImports=0,guestSSHVerified=False,actualAppFinalLinkPendingRuntime8=True,
        deviceOperations=0,actualVZCallbackExecuted=False))
    save(o/'freeze.json',dict(files=inputs+[pin(o/'report.json')]))
    print(json.dumps(dict(report=pin(o/'report.json'),freeze=pin(o/'freeze.json'))))
if __name__=='__main__':main()
