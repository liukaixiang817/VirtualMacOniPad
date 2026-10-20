#!/usr/bin/env python3
"""Close exactly nine DI2 current MediaKit definitions, no graph rewrite."""
import importlib.util
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE))
spec=importlib.util.spec_from_file_location('mkf',HERE/'audit-modern-genuine-hid-current-frontier-v19.py')
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f);p,s,n=f.p,f.s,f.NODE
from current_mediakit_capture_v1 import join
from macho_chained_import_records_v1 import read as import_records

def main():
    out=n/'current-mediakit-nine-definitions-readonly-v1';assert not out.exists()
    graph={};pins,proof=join(s,graph)
    frontier=n/'universalhid-current-exact-frontier-audit-v25/audit.json';j=json.loads(frontier.read_bytes())
    di2=[row for row in j['privateDefinitions']if row['path']=='@loader_path/DI2'];assert len(di2)==1
    image=di2[0]['image'];assert p.pin(Path(image['path']))==image
    body=Path(image['path']).read_bytes();deps={row['ordinal']:row['path']for row in p.dependencies(body)}
    imports=[row for row in import_records(body,p.commands)['imports']if deps.get(row['ordinal'])==proof['actualPath']]
    assert len(imports)==9 and not any(row['weak']for row in imports)
    rows=[]
    for row in imports:
        definition=s.primary.resolve(graph,proof['actualPath'],row['name']);assert definition['status']=='actualDirectExport',(row,definition)
        assert definition['owner']==proof['actualPath']and definition['UUID']==proof['actualUUID']and not definition['export']['flags']&8
        rows.append(dict(importRecord=row,actualDefinition=definition))
    out.mkdir()
    p.save(out/'audit.json',dict(schema='Nine exact current DI2 MediaKit strong definitions supplement v1',
       currentMediaKit=proof,unchangedDI2=image,supersededFrontier=p.pin(frontier),strongDefinitions=rows,newlyClosedUnknownOwnerRows=9,
       actualProviderFunctionABIsValidated=False,completeTransitiveLoadGraph=False,originalDI2Executed=False,deviceOperations=0,nativeCPUCalls=0,full27Backend=False))
    pins += [p.pin(Path(__file__)),p.pin(frontier),image,p.pin(out/'audit.json')]
    p.save(out/'freeze.json',dict(files=list({row['path']:row for row in pins}.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),exportCount=proof['exportCount'],definitions=len(rows))))
if __name__=='__main__':main()
