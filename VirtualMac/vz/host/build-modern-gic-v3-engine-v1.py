#!/usr/bin/env python3
"""Offline CPU/controller model and inert iOS compilation; never signs/runs a device."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

def pin(path):
    p=Path(path).resolve();data=p.read_bytes()
    return {'path':str(p),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}

def run(out,name,args):
    result=subprocess.run(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=90)
    (out/(name+'.stdout')).write_bytes(result.stdout)
    (out/(name+'.stderr')).write_bytes(result.stderr)
    record={'argv':args,'returncode':result.returncode,
            'stdout':pin(out/(name+'.stdout')),'stderr':pin(out/(name+'.stderr'))}
    (out/(name+'.json')).write_text(json.dumps(record,indent=2)+'\n')
    if result.returncode:
        raise RuntimeError(f'{name}: exit {result.returncode}; {result.stderr.decode(errors="replace")}')
    return record,result.stdout

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).resolve().parent
    clang=subprocess.check_output(['xcrun','--find','clang'],text=True).strip()
    macsdk=subprocess.check_output(['xcrun','--sdk','macosx','--show-sdk-path'],text=True).strip()
    iossdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
    c=str(source/'modern_gic_v3_engine_v1.c');fixture=str(source/'test-modern-gic-v3-engine-v1.c')
    records=[];models={}
    for mode,extra in [('normal',[]),('san',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        binary=out/('gic-'+mode)
        args=[clang,'-std=c11','-Wall','-Wextra','-Werror','-O1','-g','-isysroot',macsdk,*extra,c,fixture,'-o',str(binary)]
        record,_=run(out,'build-'+mode,args);records.append(record)
        record,stdout=run(out,'run-'+mode,[str(binary)]);records.append(record);models[mode]=json.loads(stdout)
    for arch in ['arm64','arm64e']:
        objectfile=out/('gic-'+arch+'.o')
        record,_=run(out,'ios-'+arch,[clang,'-target',arch+'-apple-ios16.0','-isysroot',iossdk,
                        '-std=c11','-Wall','-Wextra','-Werror','-O2','-fvisibility=hidden','-c',c,'-o',str(objectfile)])
        records.append(record)
    if models['normal']!=models['san'] or not models['normal']['finiteGICModelPassed']:
        raise RuntimeError('model result mismatch')
    report={'schema':'independent27 real software GIC controller finite model v1','models':models,'commands':records,
            'sourcePins':[pin(c),pin(fixture),pin(source/'modern_gic_v3_engine_v1.h'),pin(__file__)],
            'controllerModelPassed':True,'deviceExecuted':False,'publicGICProviderBound':False,
            'fullPublicRunEquivalent':False,'fullIndependent27GuestBoot':False,
            'limitations':['scheduler and retain/wake callbacks are local mocks in this fixture',
             'not yet bound to real factory or SDK config/VM creation',
             'no original VMM Save/Restore callsite executed','snapshot serialization not implemented']}
    with (out/'candidate.json').open('x') as f:json.dump(report,f,indent=2);f.write('\n')
    print(json.dumps({'candidate':pin(out/'candidate.json'),'models':models},indent=2))

if __name__=='__main__':main()
