#!/usr/bin/env python3
"""Build exact-owner genuine27 HID inert data and a 104-import frontend route.

Only export/reexport contracts and Mach-O bytes are inspected. Incomplete Swift
relative metadata and stock iPad provider availability remain explicit gates.
No image loading, platform stamping, signing, device work or fallback backend.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
ORIGINAL = NODE / 'universalhid-original-contract-v1'
REBUILT = NODE / 'universalhid-genuine-provider-data-v2'
READER = ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
sys.path.insert(0, str(READER))
from compiler_image import commands, imports, segments, chain_entries, export_trie
sys.path.insert(0, str(Path(__file__).parent))
spec = importlib.util.spec_from_file_location('hid_contract', Path(__file__).with_name('extract-modern-universalhid-contract-v1.py'))
contract_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract_reader)
VZ_READER = NODE/'vz-typed-routes-independent-review-v1/review.py'
assert hashlib.sha256(VZ_READER.read_bytes()).hexdigest()=='a9dc92b4bb4d732b02df7b6ac9b91ce3c0a5dacd43f675d6fefcff261fb6aae4'
spec = importlib.util.spec_from_file_location('vz_reader',VZ_READER)
vz_reader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vz_reader)
from swift_relative_metadata import RelativeMetadata
from DyldExtractor.dyld.dyld_context import DyldContext
from DyldExtractor.dyld.dyld_trie import ReadExports

CACHE = contract_reader.CACHE
SHA = {'UniversalHID': '7297bab2e3536f00de51cd5cdb836b478d063c7f92f9bdd85748fe51693396d5',
       'UniversalHIDKit': '3eb3af23640be6c3c1e27a082322af035239c0de3cc5c2bacb7a4de3fa438b0e'}
VZ = NODE / 'vz-unused-hypervisor-pruned-data-v2/VZ27.no-unused-hypervisor.inert.macho-data'
VZ_SHA = '7114c5ae28e7f3283b9fdb8e73fbf98ff1acbd27d9f241331122cde94adf7746'
CONTRACT_SHA = '98a3853f3a3355b151c3f07863f63944a4dae66c661451f84c495fda29f15803'
DYLIB_COMMANDS = (12,13,0x80000018,0x8000001f,0x80000023)


def pin(path):
    assert path.is_file() and not path.is_symlink()
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def dependencies(data):
    result = []
    for cmd, at, size in commands(data):
        if cmd not in DYLIB_COMMANDS or cmd == 13: continue
        no = struct.unpack_from('<I', data, at+8)[0]
        path = data[at+no:at+size].split(b'\0')[0].decode()
        result.append(dict(ordinal=len(result)+1, command=cmd, path=path, at=at, size=size))
    return result


def set_path(data, at, size, path):
    no = struct.unpack_from('<I', data, at+8)[0]
    encoded = path.encode()+b'\0'
    assert len(encoded) <= size-no
    data[at+no:at+size] = encoded + b'\0'*(size-no-len(encoded))


def append_dependency(data, path):
    oldcount, oldsize = struct.unpack_from('<II', data, 16)
    encoded = path.encode()+b'\0'
    size = (24+len(encoded)+7)&~7
    at = 32+oldsize
    first = min(s['fileoff'] for g in segments(data) for s in g['sections'] if s['fileoff'] and s['size'])
    assert at+size <= first and not any(data[at:at+size]), ('no unused header space',path,at,size,first)
    struct.pack_into('<6I', data, at, 12, size, 24, 0, 0x10000, 0x10000)
    data[at+24:at+24+len(encoded)] = encoded
    struct.pack_into('<II', data, 16, oldcount+1, oldsize+size)
    return len(dependencies(data))


def compact_dylib_header(data):
    """Reclaim path-command padding only; no section or linkedit is moved."""
    count,oldsize = struct.unpack_from('<II',data,16)
    records = []
    for cmd,at,size in commands(data):
        raw = bytes(data[at:at+size])
        if cmd in DYLIB_COMMANDS:
            no = struct.unpack_from('<I',raw,8)[0]
            end = raw.index(0,no)+1
            newsize = (end+7)&~7
            raw = bytearray(raw[:newsize])
            struct.pack_into('<I',raw,4,newsize)
            raw[end:] = b'\0'*(newsize-end)
        records.append(raw)
    merged = b''.join(records)
    assert len(merged)<=oldsize
    data[32:32+oldsize] = merged+b'\0'*(oldsize-len(merged))
    struct.pack_into('<II',data,16,count,len(merged))


class GenuineCacheExports:
    def __init__(self, cache):
        self.cache = cache
        self.paths = {cache.readString(i.pathFileOffset).rstrip(b'\0').decode(): i for i in cache.images}
        self.images = {}

    def image(self, path):
        if path in self.images: return self.images[path]
        image = self.paths[path]
        off, ctx = self.cache.convertAddr(image.address)
        size = struct.unpack_from('<I', ctx.getBytes(off,32),20)[0]
        header = ctx.getBytes(off,32+size)
        parsed = contract_reader.parse(header)
        link = self.cache.convertAddr(parsed['linkeditAddress'])[1]
        exports = {e.name.rstrip(b'\0').decode():e for e in ReadExports(link.file,*parsed['exportTrie'])}
        result = dict(path=path, UUID=parsed['UUID'], base=image.address, exports=exports,
                      deps=parsed['dependencies'], headerSHA256=hashlib.sha256(header).hexdigest())
        self.images[path] = result
        return result

    def resolve(self, path, name, seen=()):
        if (path,name) in seen or len(seen)>12: return None
        image = self.image(path)
        entry = image['exports'].get(name)
        seen = seen+((path,name),)
        if entry:
            if entry.flags&8:
                assert 1<=entry.other<=len(image['deps'])
                next_name = entry.importName.rstrip(b'\0').decode() or name
                nested = self.resolve(image['deps'][entry.other-1]['path'],next_name,seen)
                if nested: return {**nested, 'route':[dict(path=path, UUID=image['UUID'], symbol=name,
                        kind='named reexport',ordinal=entry.other)]+nested['route']}
                return None
            address = entry.address if entry.flags&3==2 else image['base']+entry.address
            return dict(exportPath=path, exportUUID=image['UUID'], exportedSymbol=name,
                        exportAddress=address, exportFlags=entry.flags,
                        route=[dict(path=path, UUID=image['UUID'], symbol=name,kind='direct original export')])
        for dep in image['deps']:
            if dep['command']==0x8000001f:
                nested = self.resolve(dep['path'],name,seen)
                if nested: return {**nested, 'route':[dict(path=path, UUID=image['UUID'],symbol=name,
                        kind='LC_REEXPORT_DYLIB',ordinal=dep['ordinal'])]+nested['route']}
        return None


def canonical(name):
    if name.startswith('__got.'): name = name[6:]
    if name.startswith('_ptr.'): name = name[5:]
    if name.startswith('__branch.'):
        name = name[9:]
        if name.startswith('_objc_msgSend$'): name = '_objc_msgSend'
    return name


def provider(name, facts, cache_exports, output):
    source = REBUILT/'reconstructed'/f'{name}.strong-flat.mac.inert.macho-data'
    original = ORIGINAL/'raw'/name
    before = source.read_bytes()
    assert pin(source)['sha256']==SHA[name] and pin(original)==facts['extractedRaw']
    parsed = contract_reader.parse(before)
    assert parsed['UUID']==facts['UUID'] and parsed['dependencies']==facts['originalDependencies']
    oldimports = imports(before)['imports']
    assert len(oldimports)==(528 if name=='UniversalHID' else 195)
    assert all(r['ordinal']==-2 and not r['weak'] and r['name']!='?' for r in oldimports)
    dep = dependencies(before)
    nlist = {}
    for row in facts['originalNlistImports']: nlist.setdefault(row['name'],[]).append(row)
    memo = json.loads((ORIGINAL/f'{name}-symbols.a2s.batch.json').read_text())['symbols']
    owners = {}
    for address,(symbol,path) in memo.items():
        if symbol and path: owners.setdefault(canonical(symbol),set()).add(path)
    routes = []
    data = bytearray(before)
    for cmd,at,size in commands(data):
        if cmd==13: set_path(data,at,size,'@loader_path/'+name+'27.dylib')
    if name=='UniversalHIDKit':
        first = dep[0]
        assert 'UniversalHID.framework' in first['path']
        set_path(data,first['at'],first['size'],'@loader_path/UniversalHID27.dylib')
    compact_dylib_header(data)
    actualdep = dependencies(data)
    # Cache owner contracts keep the original paths even where the inert
    # runtime path now targets our separately preserved genuine provider.
    dep = [{**d,'at':actualdep[i]['at'],'size':actualdep[i]['size']} for i,d in enumerate(dep)]
    for row in oldimports:
        candidates = nlist.get(row['name'],[])
        assert len({x['originalProvider'] for x in candidates})<=1
        preferred = candidates[0]['originalProvider'] if candidates else None
        choices = ([d for d in dep if d['path']==preferred] if preferred else [])
        choices += [d for d in dep if d not in choices and d['path'] in owners.get(row['name'],set())]
        choices += [d for d in dep if d not in choices]
        selected = None
        for candidate in choices:
            proof = cache_exports.resolve(candidate['path'],row['name'])
            if proof:
                selected = candidate; break
        if selected is None:
            exact = [(path,cache_exports.resolve(path,row['name'])) for path in sorted(owners.get(row['name'],set()))]
            exact = [(path,proof) for path,proof in exact if proof]
            assert len(exact)==1, ('no unique genuine export owner',name,row['name'],owners.get(row['name']))
            path,proof = exact[0]
            ordinal = append_dependency(data,path)
            selected = dependencies(data)[ordinal-1]
            dep.append(selected)
        oldword = struct.unpack_from('<I',data,row['command'])[0]
        struct.pack_into('<I',data,row['command'],(oldword&~255)|selected['ordinal'])
        routes.append(dict(index=row['index'],name=row['name'],ordinal=selected['ordinal'],
            path=selected['path'],weak=False,originalUndefinedContract=candidates, genuineProof=proof))
    final = bytes(data)
    assert list(chain_entries(final))==list(chain_entries(before)), 'ordinal-only routing changed pointer/auth contracts'
    assert imports(final)['header']==imports(before)['header']
    for g in segments(before):
        for s in g['sections']:
            if s['fileoff'] and s['size'] and s['flags']&255 not in(1,12):
                assert before[s['fileoff']:s['fileoff']+s['size']]==final[s['fileoff']:s['fileoff']+s['size']]
    assert all(r['ordinal']>0 and not r['weak'] for r in imports(final)['imports'])
    outfile = output/(name+'27.genuine-positive-ordinal.mac.inert.macho-data')
    outfile.write_bytes(final)
    metadata = RelativeMetadata(original.read_bytes(),final)
    metadata.singletons();metadata.conformances();metadata.reflection()
    auditpath = output/(name+'.swift-relative-audit.json')
    save(auditpath,dict(schemas=metadata.schemas,relativePointers=metadata.rows,unresolved=metadata.unresolved,
                       applied=False,fullSwiftRelocationProven=False))
    return dict(name=name,source=pin(source),original=pin(original),candidate=pin(outfile),
        originalUUID=facts['UUID'],positiveOrdinalImports=len(routes),routes=routes,
        addedDependencies=[d for d in dependencies(final) if d['ordinal']>len(facts['originalDependencies'])],
        metadataAudit=pin(auditpath),unresolvedSwiftRelativeEdges=len(metadata.unresolved),
        sectionsAndInstructionsUnchangedFromReconstructedSource=True,
        pointerAuthenticationAndChainWordsUnchanged=True,stockTransitiveClosureProven=False)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output',type=Path,required=True)
    args = p.parse_args()
    output = args.output.resolve()
    assert output.is_relative_to(NODE) and not output.exists()
    assert pin(ORIGINAL/'original-contract.json')['sha256']==CONTRACT_SHA
    contract = json.loads((ORIGINAL/'original-contract.json').read_text())
    output.mkdir()
    with CACHE.open('rb') as stream:
        cache = DyldContext(stream); cache.addSubCaches(CACHE)
        assert bytes(cache.header.uuid).hex()==contract['cacheUUID']
        oracle = GenuineCacheExports(cache)
        providers = [provider(facts['name'],facts,oracle,output)for facts in contract['providers']]
        images = [dict(path=v['path'],UUID=v['UUID'],headerSHA256=v['headerSHA256'],
                       originalExports=len(v['exports']))for v in oracle.images.values()]
    before = VZ.read_bytes()
    assert pin(VZ)['sha256']==VZ_SHA
    data = bytearray(before)
    deps = dependencies(data)
    for ordinal,name in ((3,'UniversalHIDKit'),(7,'UniversalHID')):
        chosen = deps[ordinal-1]
        assert name+'.framework' in chosen['path'] and chosen['command']==0x80000018
        set_path(data,chosen['at'],chosen['size'],'@loader_path/'+name+'27.dylib')
    oldvz,newvz = vz_reader.parse(before),vz_reader.parse(bytes(data))
    assert newvz['imports']==oldvz['imports'] and newvz['words']==oldvz['words']
    # The 104 original VZ imports retain exact names/ordinals/weak flags/addends;
    # each definition is original provider code/metadata, never a fabricated ABI.
    required = []
    for facts,result in zip(contract['providers'],providers):
        binary = Path(result['candidate']['path']).read_bytes()
        trie = next((at for cmd,at,_ in commands(binary) if cmd==0x80000033),None)
        start,size = struct.unpack_from('<II',binary,trie+8)
        actual = {e['symbol']:e for e in export_trie(binary[start:start+size])}
        mapper = RelativeMetadata((ORIGINAL/'raw'/facts['name']).read_bytes(),binary)
        for row in facts['exactVZStrongRequirements']:
            e = row['genuineExport']; assert e['name'] in actual and e['flags']==actual[e['name']]['flags']
            assert mapper.mapped(e['address'])==0x100000000+actual[e['name']]['address']
            required.append(dict(index=row['index'],name=row['name'],ordinal=row['ordinal'],
                genuineProviderUUID=facts['UUID'],genuineOriginalAddress=e['address'],
                rebuiltDefinitionAddress=mapper.mapped(e['address']),weak=False))
    assert len(required)==104
    vzout = output/'VZ27.genuine-hid-private-route.inert.macho-data';vzout.write_bytes(data)
    validation = []
    for path in [Path(p['candidate']['path'])for p in providers]+[vzout]:
        run = subprocess.run(['xcrun','dyld_info','-validate_only',str(path)],capture_output=True,text=True)
        validation.append(dict(path=str(path),exitCode=run.returncode,stdout=run.stdout,stderr=run.stderr))
        assert run.returncode==0
    report = dict(schema='Genuine27 HID exact-owner provider and 104 frontend import route inert v1',
        originalContract=pin(ORIGINAL/'original-contract.json'),cacheUUID=contract['cacheUUID'],
        providers=providers,genuineCacheOwnerImages=images,frontendSource=pin(VZ),frontendCandidate=pin(vzout),
        exactOriginalStrongImportsRouted=required,dyldStaticValidation=validation,
        allProviderImportsPositiveAndStrong=True,originalProviderCodeAndWitnessExportsRetained=True,
        fullSwiftMetadataRelocationProven=False,stockTransitiveClosureProven=False,
        macOSPlatformRetained=True,platformConverted=False,codeSigned=False,nativeExecuted=False,
        deviceOperations=0,originalVZLoaded=False,originalVMMExecuted=False,guestInstructions=0,full27Backend=False)
    reportpath = output/'candidate.json';save(reportpath,report)
    files = [Path(__file__),Path(__file__).with_name('extract-modern-universalhid-contract-v1.py'),
             ROOT/'VirtualMac/vz/uncache.py',ROOT/'VirtualMac/scripts/tests/test-modern-got-definition-lifetime.py',
             READER/'compiler_image.py',VZ_READER,Path(__file__).with_name('swift_relative_metadata.py'),
             ORIGINAL/'original-contract.json',VZ,reportpath,vzout]
    for result in providers:
        files += [Path(result[x]['path'])for x in('source','original','candidate','metadataAudit')]
    save(output/'freeze.json',dict(files=[pin(path)for path in files],nativeExecuted=False,deviceOperations=0))
    print(json.dumps(dict(candidate=pin(reportpath),frontend=pin(vzout),
                         providers=[dict(name=p['name'],imports=p['positiveOrdinalImports'],
                                         unresolvedMetadata=p['unresolvedSwiftRelativeEdges'])for p in providers])))


if __name__=='__main__': main()
