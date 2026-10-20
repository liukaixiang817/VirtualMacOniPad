#!/usr/bin/env python3
"""Replace only startup diagnostics, keeping the other72 genuine images."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import struct
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def need(value, reason):
    if not value:
        raise ValueError(reason)

def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--provider-candidate', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh Stage9 directory')
    base = N/'independent27-external-signature-stage-v8-attempt1/candidate.json'
    need(pin(base)['sha256'] == 'd80fbf270fcc0331ed9737a5e4c4e90e041cb76cd86c5cb24a2df5d209af3f1e',
         'exact actual Stage8 input')
    provider_candidate = args.provider_candidate.resolve()
    for path in [base.parent/'freeze.json', provider_candidate.parent/'freeze.json']:
        value = json.loads(path.read_bytes())
        for row in value['files']:
            need(pin(row['path']) == row, 'unchanged real frozen input: '+row['path'])
    provider = json.loads(provider_candidate.read_bytes())
    need(provider['singleNativeStrictIdentity'] and provider['nativeAuditAndKernelCodeGatesUnchanged'] and
         provider['originalFlatParentInspectionUnchanged'] and provider['originalChildBootstrapV3Unchanged'],
         'existing genuine authority and original startup ABI')
    replacements = {'VM27OwnedAppStartupV3.dylib': provider['adapter']}
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('external_stage_macho', reader)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    stage = json.loads(base.read_bytes())
    out.mkdir(mode=0o700)
    flat = out/'flat'
    flat.mkdir(mode=0o700)
    rows, unchanged, replaced = [], [], []
    keys = {row['key'] for row in stage['stagedImages']}
    for old in stage['stagedImages']:
        need(pin(old['staged']['path']) == old['staged'], 'exact inherited image')
        source = replacements.get(old['key'], old['staged'])
        need(pin(source['path']) == source, 'exact selected provider bytes')
        target = flat/old['key']
        raw = pathlib.Path(source['path']).read_bytes()
        changes = []
        if old['key'] in replacements:
            original = m.MachO(raw)
            commands = []
            for command in original.commands:
                value = command['raw']
                if command['cmd'] in [12, 0x80000018, 0x8000001f, 0x80000023]:
                    at = struct.unpack_from('<I', value, 8)[0]
                    name = value[at:].split(b'\0', 1)[0].decode()
                    if name.startswith('@rpath/'):
                        key = name[len('@rpath/'):]
                        need(key in keys, 'actual known dependency for new provider: '+name)
                        new_name = '@loader_path/'+key
                        payload = new_name.encode()+b'\0'
                        size = (at+len(payload)+7)&~7
                        need(not any(value[at+len(name.encode())+1:]), 'actual zero string padding')
                        amended = bytearray(value[:at]+payload+bytes(size-at-len(payload)))
                        struct.pack_into('<I', amended, 4, size)
                        value = bytes(amended)
                        changes.append(dict(oldPath=name, newPath=new_name))
                commands.append(value)
            body = b''.join(commands)
            old_end, new_end = 32+original.sizeofcmds, 32+len(body)
            first = min([section['fileoff'] for section in original.sections
                if section['size'] and section['fileoff']>0 and (section['flags']&255) not in [1, 12]]+
                [segment['fileoff'] for segment in original.segments if segment['filesize'] and segment['fileoff']>0])
            need(new_end <= first, 'genuine existing header capacity')
            if new_end > old_end:
                need(not any(raw[old_end:new_end]), 'only zero header padding consumed')
            amended = bytearray(raw)
            amended[32:max(old_end,new_end)] = body+bytes(max(old_end,new_end)-new_end)
            struct.pack_into('<II', amended, 16, len(commands), len(body))
            actual = bytes(amended)
            changed_image = m.MachO(actual)
            need(changed_image.uuid == original.uuid and changed_image.sections == original.sections and
                 changed_image.segments == original.segments and changed_image.exports == original.exports and
                 changed_image.binds == original.binds and changed_image.imports == original.imports,
                 'all genuine code geometry, public entries and fixup/import words retained')
            allowed = set(range(16,24))|set(range(32,max(old_end,new_end)))
            need(len(actual) == len(raw) and all(index in allowed
                for index,(before,after) in enumerate(zip(raw,actual)) if before != after),
                'exact dependency-header-only mutation extent')
            raw = actual
        target.write_bytes(raw)
        target.chmod(0o600)
        image = m.MachO(target.read_bytes())
        rows.append(dict(key=old['key'], source=source, staged=pin(target), UUID=image.uuid,
                         loadPathChanges=changes,
                         codeSignatureStaleUntilFinalSigning=True))
        if old['key'] in replacements:
            replaced.append(old['key'])
        else:
            need(target.read_bytes() == pathlib.Path(old['staged']['path']).read_bytes(), 'unchanged other image')
            unchanged.append(old['key'])
    need(len(rows) == 73 and len(unchanged) == 72 and set(replaced) == set(replacements), 'exact one diagnostic leaf change')
    child = m.MachO((flat/'com.apple.Virtualization.VirtualMachine').read_bytes())
    need(child.uuid == '4a6a588d1afd30f5a64d6304eb79be0b' and
         struct.unpack_from('<I', child.data, child.file(child.base+0x2e9d4c))[0] == 0x9404a45a,
         'original whole VMM main and exact original bootstrap BL retained')
    stage.pop('actualOther71ImagesByteIdentical', None)
    stage.update(schema='Actual independent27 postspawn diagnostic Stage9', builder=pin(__file__),
        reader=pin(reader), baseStage=pin(base), prior=pin(base), stagedImages=rows,
        postspawnDiagnosticProviderCandidate=pin(provider_candidate),
        actualOnlyReplacedImages=sorted(replaced), actualUnchangedOtherImages=72,
        actualOther72ImagesByteIdentical=True, actualRetainedImageKeys=unchanged,
        originalVMMMainAndFirmwareDataBytesUnchanged=True,
        finalStrongDefinitionGraphClosed=False, finalSignedProductManifestGenerated=False,
        codeSigned=False, readyForDeviceExecution=False, loaderExecuted=False,
        deviceOperations=0, nativeCPUOperations=0, guestBoot=False)
    save(out/'candidate.json', stage)
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += [pin(__file__), pin(reader), pin(base), pin(base.parent/'freeze.json'),
        pin(provider_candidate), pin(provider_candidate.parent/'freeze.json')]
    files += list(replacements.values())+[row['staged'] for row in json.loads(base.read_bytes())['stagedImages']]
    save(out/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), actualImages=73,
                          replacedImages=1, unchangedOtherImages=72)))

if __name__ == '__main__':
    main()
