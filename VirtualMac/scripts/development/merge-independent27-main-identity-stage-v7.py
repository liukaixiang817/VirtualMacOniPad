#!/usr/bin/env python3
"""Replace only two true main-identity consumers in the complete Stage6 graph."""
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


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True, type=pathlib.Path)
    ap.add_argument('--root19-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--main-identity-candidate', required=True, type=pathlib.Path)
    ap.add_argument('--premain', required=True, type=pathlib.Path)
    args = ap.parse_args()
    out = args.output.resolve()
    need(out.parent == N and not out.exists(), 'fresh Stage7 output')
    prior_path = N/'independent27-firmware-stage-v6-attempt1/candidate.json'
    need(pin(prior_path)['sha256'] == '13b5db187e788e038980d7af8ff3291f9d42e80cca4c64418c8b0d8bfc47c845', 'exact actual Stage6')
    candidates = [prior_path, args.root19_candidate.resolve(), args.main_identity_candidate.resolve()]
    frozen = {}
    for path in candidates:
        value = json.loads((path.parent/'freeze.json').read_bytes())
        rows = value.get('files', value.get('pins', []))
        need(rows, 'nonempty real input freeze')
        for row in rows:
            need(pin(row['path']) == row, 'unchanged actual frozen input')
            frozen[row['path']] = row
    root = json.loads(args.root19_candidate.read_bytes())
    need(root['actualExports'] == 153 and root['singleCPURegistry'] and root['nativeAcquisitionUnchanged'],
         'actual full unchanged CPU owner and public ABI')
    premain = pin(args.premain)
    need(frozen.get(premain['path']) == premain, 'actual child-only premain is independently frozen')
    sources = {'VM27HVVMProduction.dylib': root['provider'], 'VM27OwnedAppChildPreMainV3.dylib': premain}
    for row in sources.values():
        need(pin(row['path']) == row, 'actual new source bytes')
    reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    sp = importlib.util.spec_from_file_location('stage7_macho', reader)
    m = importlib.util.module_from_spec(sp)
    sp.loader.exec_module(m)
    stage = json.loads(prior_path.read_bytes())
    out.mkdir(mode=0o700)
    flat = out/'flat'
    flat.mkdir(mode=0o700)
    rows = []
    unchanged = []
    replaced = []
    for old in stage['stagedImages']:
        need(pin(old['staged']['path']) == old['staged'], 'actual inherited staged image')
        source = sources.get(old['key'], old['staged'])
        data = pathlib.Path(source['path']).read_bytes()
        target = flat/old['key']
        target.write_bytes(data)
        target.chmod(0o600)
        image = m.MachO(data)
        rows.append(dict(key=old['key'], source=source, staged=pin(target), UUID=image.uuid,
                         codeSignatureStaleUntilFinalSigning=True))
        if old['key'] in sources:
            replaced.append(old['key'])
        else:
            need(data == pathlib.Path(old['staged']['path']).read_bytes(), 'exact unchanged other image')
            unchanged.append(old['key'])
    need(len(rows) == 73 and len(unchanged) == 71 and set(replaced) == set(sources), 'exact two leaves in original73')
    child = m.MachO((flat/'com.apple.Virtualization.VirtualMachine').read_bytes())
    need(child.uuid == '4a6a588d1afd30f5a64d6304eb79be0b' and
         struct.unpack_from('<I', child.data, child.file(child.base+0x2e9d4c))[0] == 0x9404a45a,
         'original child main and exact native bootstrap BL preserved')
    new_premain = m.MachO(pathlib.Path(premain['path']).read_bytes())
    need(not new_premain.exports and '_VM27OwnedAppChildBootstrapBeforeMainV3' in {row['name'] for row in new_premain.imports},
         'hidden finder and unchanged actual V3 bootstrap import')
    stage.update(schema='Actual independent27 main executable identity Stage7', builder=pin(__file__),
        reader=pin(reader), baseStage=pin(prior_path), prior=pin(prior_path), stagedImages=rows,
        CPUProductionRootVersion=19, actualCPUCurrentNativeImports=root['actualNativeImports'],
        mainIdentityCandidate=pin(args.main_identity_candidate), root19Candidate=pin(args.root19_candidate),
        actualRoot19Provider=root['provider'], actualOnlyReplacedImages=sorted(replaced),
        actualUnchangedOtherImages=71, actualOther71ImagesByteIdentical=True,
        originalVMMMainAndFirmwareDataBytesUnchanged=True, actualRetainedImageKeys=unchanged,
        finalStrongDefinitionGraphClosed=False, finalSignedProductManifestGenerated=False,
        codeSigned=False, readyForDeviceExecution=False, loaderExecuted=False,
        deviceOperations=0, nativeCPUOperations=0, guestBoot=False)
    # Historical single-leaf fields remain in the immutable prior candidate.
    for key in ('actualOnlyReplacedImage', 'actualOther72ImagesByteIdentical', 'actualRoot18Provider'):
        stage.pop(key, None)
    save(out/'candidate.json', stage)
    files = [pin(path) for path in out.rglob('*') if path.is_file()]
    files += [pin(__file__), pin(reader)]+[pin(path) for path in candidates]
    files += [pin(path.parent/'freeze.json') for path in candidates]+list(sources.values())
    files += [row['staged'] for row in json.loads(prior_path.read_bytes())['stagedImages']]
    save(out/'freeze.json', dict(files=list({row['path']: row for row in files}.values()), deviceOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), actualImages=73,
                          actualReplacedImages=2, byteIdenticalOtherImages=71)))


if __name__ == '__main__':
    main()
