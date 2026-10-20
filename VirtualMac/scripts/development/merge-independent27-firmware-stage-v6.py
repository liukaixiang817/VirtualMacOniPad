#!/usr/bin/env python3
"""Adopt the exact original27 firmware path port into a fresh complete stage."""
import argparse
import hashlib
import json
import pathlib
import shutil
import sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
B = pathlib.Path(__file__).resolve().parent

def need(value, reason):
    if not value:
        raise ValueError(reason)

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def exact(row):
    need(pin(row['path']) == row, 'exact frozen input: '+row['path'])
    return pathlib.Path(row['path'])

def dump(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')

def replacement(source, before, after):
    need(source.count(before) == 1, 'unique fresh builder replacement')
    return source.replace(before, after, 1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', required=True, type=pathlib.Path)
    out = ap.parse_args().output.resolve()
    need(out.parent == N and not out.exists(), 'fresh output')
    prior = N/'independent27-mobile-capability-stage-v5-attempt1/candidate.json'
    recipe_path = N/'original27-firmware-resource-layout-data-v1-attempt1/patch-recipe.json'
    for path in (prior, recipe_path):
        frozen = json.loads((path.parent/'freeze.json').read_bytes())
        for row in frozen.get('files', frozen.get('pins', [])):
            exact(row)
    need(pin(prior)['sha256'] == '605b1821bd2ebce3a9e1e63d8539889240d09e5ca480e45c7bd6ce13528745c7', 'actual Stage5')
    need(pin(recipe_path)['sha256'] == '84ec1818bf8f0ff295b06fcdb346463292b503f37199c853e6dc1c559377fee6', 'actual firmware port')
    stage = json.loads(prior.read_bytes())
    recipe = json.loads(recipe_path.read_bytes())
    need(recipe['inheritedStage'] == pin(prior), 'same actual stage')
    before, after = exact(recipe['sourceImage']).read_bytes(), exact(recipe['candidate']).read_bytes()
    expected = bytearray(before)
    for patch in recipe['patches']:
        at, size = patch['fileOffset'], patch['bytes']
        old, new = bytes.fromhex(patch['beforeHex']), bytes.fromhex(patch['afterHex'])
        need(len(old) == len(new) == size == 74 and before[at:at+size] == old, 'fixed actual CString span')
        need(new[:-1].find(b'\0') == -1 and new[-1:] == b'\0' and patch['explicitInsertCount'] == 73, 'actual explicit string count')
        expected[at:at+size] = new
    need(bytes(expected) == after, 'only the exact firmware path bytes changed')
    out.mkdir(mode=0o700)
    flat = out/'flat'
    flat.mkdir(mode=0o700)
    changed = 0
    for row in stage['stagedImages']:
        source = exact(row['staged'])
        target = flat/row['key']
        if row['staged'] == recipe['sourceImage']:
            shutil.copyfile(exact(recipe['candidate']), target)
            changed += 1
        else:
            shutil.copyfile(source, target)
            need(pin(target)['sha256'] == row['staged']['sha256'], 'other complete image unchanged')
        row['staged'] = pin(target)
    need(changed == 1 and len(stage['stagedImages']) == 73, 'one original VMM changed in actual73 stage')
    resources = recipe['resources']
    need(len(resources) == 5 and all(r['kind'] == 'resource' and r['role'] == 'firmware' and
         r['hostMachO'] is False and r['addsTrustCacheHash'] is False for r in resources), 'five real firmware data resources')
    for row in resources:
        local, actual = exact(row['local']), exact(row['sourceReadOnly'])
        need(local.read_bytes() == actual.read_bytes(), 'actual current27 firmware bytes')
    stage.update(schema='Independent27 actual73 stage6 with real firmware resource paths',
        prior=pin(prior), firmwarePathRecipe=pin(recipe_path), firmwareResources=resources,
        firmwareDeviceDirectory=recipe['canonicalDeviceDirectory'],
        actualUnchangedOtherImages=72, firmwarePathOnlyDataPort=True,
        firmwareSourceVersion='27.0.1/26A434', originalInstructionBytesUnchanged=True,
        actualCodeSigned=False, deviceOperations=0, trustCacheOperations=0, guestBoot=False)
    dump(out/'candidate.json', stage)
    # Fresh signer supports only these five actual, pinned ordinary resources.
    old_builder = B/'build-independent27-signed-runtime-product-v1.py'
    builder = B/'build-independent27-signed-runtime-product-v2.py'
    need(not builder.exists(), 'fresh runtime signer source')
    text = old_builder.read_text()
    marker = "    parent=closure(roots);children=closure([child,premain])"
    text = replacement(text, marker, """    firmware=stage.get('firmwareResources',[])
    need(len(firmware)==5,'actual five firmware resources required')
    expected_firmware={'AVPBooter.vmapple2.bin','AVPBooter.vresearch1.bin','AVPSEPBooter.vresearch1.bin','VZG11.fd','VZG21.fd'}
    need({r['relativePath']for r in firmware}=={'Firmware27/'+n for n in expected_firmware},'exact genuine firmware layout')
    for resource in firmware:
        data=regular_bytes(resource['local']['path'])
        need(pin(resource['local']['path'])==resource['local'] and resource['kind']=='resource' and resource['role']=='firmware',
             'actual frozen firmware source')
        need(resource['hostMachO'] is False and resource['addsTrustCacheHash'] is False,'data resources only')
"""+marker)
    text = replacement(text,
        '    return dict(stage=stage,proof=proof,proofRaw=proof_raw,files=files,images=images,parent=parent,child=children,',
        '    return dict(stage=stage,firmware=firmware,proof=proof,proofRaw=proof_raw,files=files,images=images,parent=parent,child=children,')
    text = replacement(text, '        load_order=[ids[(\'parent\',key)]for key in inputs[\'roots\']]', """        for resource in inputs['firmware']:
            rel=resource['relativePath'];p=runtime/rel;p.parent.mkdir(mode=0o700,exist_ok=True)
            shutil.copyfile(resource['local']['path'],p);p.chmod(0o600)
            need(pin(p)['sha256']==resource['local']['sha256'] and p.stat().st_size==resource['local']['bytes'],'actual copied firmware')
            rows.append(dict(id=resource['id'],path=rel,kind='resource',role='firmware',bytes=p.stat().st_size,sha256=pin(p)['sha256']))
        load_order=[ids[('parent',key)]for key in inputs['roots']]""")
    text = replacement(text, '        files+=result[\'sources\']+list(inputs[\'files\'].values())',
        "        files+=result['sources']+list(inputs['files'].values())+[r['local']for r in inputs['firmware']]\n        for r in inputs['firmware']:need(pin(r['local']['path'])==r['local'],'frozen firmware unchanged after signing')")
    builder.write_text(text)
    old_review = B/'review-independent27-signed-runtime-product-v1.py'
    new_review = B/'review-independent27-signed-runtime-product-v2.py'
    need(not new_review.exists(), 'fresh complete148 resource inspector')
    text = replacement(old_review.read_text(),
        "    require(len(files) == len(manifest['files']) == 143, 'actual unique finite product')",
        "    require(len(files) == len(manifest['files']) == candidate['files'] == 148, 'actual unique finite product with five genuine firmware resources')")
    new_review.write_text(text)
    frozen = [pin(p) for p in sorted(out.rglob('*')) if p.is_file()]
    frozen += [pin(__file__), pin(prior), pin(recipe_path), pin(old_builder), pin(builder), pin(old_review), pin(new_review)]
    frozen += [r['local'] for r in resources]+[r['sourceReadOnly'] for r in resources]
    dump(out/'freeze.json', dict(files=list({r['path']:r for r in frozen}.values()), deviceOperations=0, trustCacheOperations=0))
    print(json.dumps(dict(candidate=pin(out/'candidate.json'), freeze=pin(out/'freeze.json'),
        actualImages=73, actualChangedImages=1, actualFirmwareResources=5, deviceOperations=0)))

if __name__ == '__main__':
    main()
